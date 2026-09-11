"""Why a request was refused.

Most firewalls answer "blocked" and stop there, which leaves an operator with no
way to tell a real attack from a false positive. This one can do better, because
the model was built to be inspectable.

Two artefacts:

- The decode trace. The normalisation chain peels encoding layers one at a time,
  so recording each round turns obfuscation into an audit trail the operator can
  read top to bottom.
- Feature contributions. LightGBM computes exact per feature SHAP values via
  `predict(..., pred_contrib=True)`, which is fast enough to run inline. Mapping
  the largest ones back to their n-gram names says which fragments of the payload
  actually drove the decision.
"""

from __future__ import annotations

import html
import unicodedata
from urllib.parse import unquote_plus

import numpy as np

from mlwaf.decode import (
    MAX_ROUNDS,
    _js_unescape,
    collapse_whitespace,
    decode_char_calls,
    decode_hex_literals,
    strip_sql_comments,
    unwrap_mysql_comments,
)
from mlwaf.waf.scorer import BOOSTER_LOCK

TOP_FEATURES = 8


def decode_trace(raw: str) -> list[dict[str, str]]:
    """Each normalisation round, in order, with the step that produced it."""
    if not raw:
        return []

    trace = [{"step": "raw", "value": raw}]
    current = raw

    for i in range(MAX_ROUNDS):
        step = unquote_plus(current)
        step = html.unescape(step)
        step = _js_unescape(step)
        if step == current:
            break
        current = step
        trace.append({"step": f"decode round {i + 1}", "value": current})

    after_comments = collapse_whitespace(
        strip_sql_comments(unwrap_mysql_comments(current))
    )
    if after_comments != current:
        current = after_comments
        trace.append({"step": "comments and whitespace", "value": current})

    after_literals = decode_hex_literals(decode_char_calls(current))
    if after_literals != current:
        current = after_literals
        trace.append({"step": "encoded literals", "value": current})

    folded = unicodedata.normalize("NFKC", current).lower()
    if folded != current:
        trace.append({"step": "unicode and case", "value": folded})

    return trace


def _feature_names(pipeline) -> np.ndarray:
    names = pipeline.named_steps["features"].get_feature_names_out()
    select = pipeline.named_steps.get("select")
    if select is not None:
        names = names[select.get_support()]
    return names


class Explainer:
    """Holds the feature names so they are resolved once, not per request."""

    def __init__(self, pipeline, scorer):
        self._names = _feature_names(pipeline)
        self._scorer = scorer
        self._booster = pipeline.named_steps["clf"].booster_

    def _class_contributions(self, contrib, class_index: int) -> np.ndarray:
        """Pull one class's per feature contributions out of LightGBM's output.

        The shape depends on the input. For a sparse row LightGBM returns a list
        of sparse matrices, one per class; for a dense row it returns a single
        array with the classes laid end to end. Each block carries one extra
        column, the bias term, which is dropped here because it is the same for
        every request and explains nothing about this one.
        """
        n = len(self._names)

        if isinstance(contrib, list):
            block = contrib[class_index]
            row = block.toarray()[0] if hasattr(block, "toarray") else np.asarray(block)[0]
            return np.asarray(row, dtype=np.float64)[:n]

        array = np.asarray(contrib)
        if array.ndim == 1:
            array = array.reshape(1, -1)
        start = class_index * (n + 1)
        return array[0, start:start + n].astype(np.float64)

    def contributions(self, text: str, url_text: str, body_text: str,
                      query: str, path: str, decode_depth: int,
                      attack_class_index: int) -> list[dict]:
        """Largest per feature contributions toward the predicted attack class."""
        matrix = self._scorer.matrix(text, url_text, body_text, query, path, decode_depth)
        with BOOSTER_LOCK:
            contrib = self._booster.predict(matrix, pred_contrib=True, num_threads=1)
        values = self._class_contributions(contrib, attack_class_index)

        order = np.argsort(-np.abs(values))[:TOP_FEATURES]
        return [
            {
                "feature": str(self._names[i]),
                "contribution": round(float(values[i]), 5),
                "direction": "toward attack" if values[i] > 0 else "toward benign",
            }
            for i in order
            if abs(values[i]) > 1e-9
        ]

    def explain(self, view, decision, attack_class_index: int) -> dict:
        url_text, body_text, depth = view.canonical()
        text = "\n".join(t for t in (url_text, body_text) if t)
        payload = view.query or view.body or view.path
        return {
            "decode_trace": decode_trace(payload),
            "decode_rounds": depth,
            "canonical": text,
            "contributions": self.contributions(
                text, url_text, body_text, view.query, view.path, depth,
                attack_class_index,
            ),
        }
