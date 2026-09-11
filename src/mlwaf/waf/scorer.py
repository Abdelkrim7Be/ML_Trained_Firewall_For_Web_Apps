"""The serving path.

Training uses a scikit-learn pipeline because that is the right tool for getting
the model correct. Serving one request at a time through that same pipeline is a
different problem: pandas DataFrame construction, ColumnTransformer dispatch and
sklearn's input validation all cost roughly the same per call whether the batch
holds one row or three thousand, and measured on a single request they dominate
everything the model actually does.

So this extracts the fitted pieces, the vectoriser, the scaler, the selection mask
and the booster, and calls them directly on plain numpy and scipy structures. It is
the same arithmetic on the same fitted parameters, and `tests/waf/test_scorer.py`
asserts the scores are identical to the pipeline's.
"""

from __future__ import annotations

import threading

import numpy as np
from scipy import sparse

from mlwaf.features import NUMERIC_COLS, _row_features
from mlwaf.model import CLASSES

# LightGBM's Booster.predict is not safe to call concurrently from multiple
# native threads: under request concurrency (asyncio.to_thread per request),
# simultaneous predict() calls into the same booster can hang inside the C++
# side indefinitely rather than raise, which surfaces as the whole request
# never completing. One lock, shared with Explainer since it wraps the same
# booster, serializes just the predict call; everything around it (vectorising,
# feature assembly) still runs concurrently.
BOOSTER_LOCK = threading.Lock()


class FastScorer:
    def __init__(self, pipeline):
        features = pipeline.named_steps["features"]

        # Read the fitted layout rather than assuming it. The vectoriser has had
        # more than one shape during development (one n-gram space over the whole
        # request, and a variant with separate ones for URL and body), and a
        # serving path that silently assumes the wrong one is worse than no
        # serving path at all.
        self._text_blocks: list[tuple[object, str]] = []
        self._numeric: object | None = None

        for name, transformer, columns in features.transformers_:
            if transformer in ("drop", None):
                continue
            if name == "nums" or columns == NUMERIC_COLS:
                self._numeric = transformer
            else:
                self._text_blocks.append((transformer, columns))

        if self._numeric is None:
            raise ValueError("fitted pipeline has no numeric block")

        self._booster = pipeline.named_steps["clf"].booster_
        select = pipeline.named_steps.get("select")
        self._support = None if select is None else select.get_support(indices=True)

        # MaxAbsScaler is a division by a constant per column. Doing it inline
        # avoids another validated sklearn call on a one row array.
        self._scale = np.asarray(self._numeric.scale_, dtype=np.float64)

    def numeric_vector(self, text: str, query: str, path: str,
                       decode_depth: int, body: str) -> np.ndarray:
        feats = _row_features(text, query, path, decode_depth, body)
        return np.fromiter((feats[c] for c in NUMERIC_COLS),
                           dtype=np.float64, count=len(NUMERIC_COLS))

    def matrix(self, text: str, url_text: str, body_text: str, query: str,
               path: str, decode_depth: int):
        """Assemble the feature row in the column order the model was fitted on."""
        values = {"text": text, "text_url": url_text, "text_body": body_text}

        blocks = [
            transformer.transform([values[column]])
            for transformer, column in self._text_blocks
        ]
        nums = self.numeric_vector(text, query, path, decode_depth, body_text)
        blocks.append(sparse.csr_matrix((nums / self._scale).reshape(1, -1)))

        matrix = sparse.hstack(blocks, format="csr")
        if self._support is not None:
            matrix = matrix[:, self._support]
        return matrix

    def score(self, text: str, url_text: str, body_text: str, query: str,
              path: str, decode_depth: int) -> np.ndarray:
        """Class probabilities in `mlwaf.model.CLASSES` order."""
        matrix = self.matrix(text, url_text, body_text, query, path, decode_depth)
        # num_threads=1 matters more than it looks: for a single row the thread
        # pool costs more to start than the trees cost to walk.
        with BOOSTER_LOCK:
            proba = self._booster.predict(matrix, num_threads=1)
        return np.asarray(proba, dtype=np.float64).reshape(len(CLASSES))
