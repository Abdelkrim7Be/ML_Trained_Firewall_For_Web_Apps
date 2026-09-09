"""Model definitions.

Three models are trained so the comparison is honest:

1. RuleBaseline  -- the v0 heuristic: flag anything containing a quote, dash,
   paren, space or SQL keyword. It is here because a machine learning model that
   cannot beat a five-line rule has not earned its place.
2. Logistic regression on char n-grams -- fast, linear, interpretable.
3. LightGBM on char n-grams + numeric features -- the intended shipping model.
"""

from __future__ import annotations

import numpy as np
from lightgbm import LGBMClassifier
from sklearn.base import BaseEstimator, ClassifierMixin
from sklearn.compose import ColumnTransformer
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import MaxAbsScaler

from mlwaf.features import NUMERIC_COLS

CLASSES = ["benign", "sqli", "xss"]
BENIGN_IDX = 0


class RuleBaseline(BaseEstimator, ClassifierMixin):
    """Reproduces the original project's rule so it can be scored like a model.

    It only separates benign from attack -- it has no notion of attack type -- so
    for the multi-class comparison every flagged request is reported as `sqli`.
    That is deliberately generous to the baseline.
    """

    _MARKERS = ("'", '"', "--", "(", " ")
    _KEYWORDS = ("sleep", "drop", "uid", "select", "waitfor", "delay", "system",
                 "union", "order by", "group by")

    def fit(self, X, y=None):
        self.classes_ = np.array(CLASSES)
        return self

    def _flag(self, text: str) -> bool:
        # The original counted spaces in the decoded path, which fires on almost
        # any attack payload but also on ordinary text.
        return any(m in text for m in self._MARKERS) or any(k in text for k in self._KEYWORDS)

    def predict(self, X):
        return np.array(["sqli" if self._flag(t) else "benign" for t in X["text"]])

    def predict_proba(self, X):
        flags = np.array([self._flag(t) for t in X["text"]], dtype=float)
        proba = np.zeros((len(flags), 3))
        proba[:, 0] = 1.0 - flags
        proba[:, 1] = flags
        return proba


def _vectoriser() -> ColumnTransformer:
    return ColumnTransformer(
        [
            (
                "chars",
                TfidfVectorizer(
                    analyzer="char_wb",
                    ngram_range=(3, 5),
                    min_df=3,
                    sublinear_tf=True,
                    max_features=200_000,
                ),
                "text",
            ),
            ("nums", MaxAbsScaler(), NUMERIC_COLS),
        ]
    )


def logistic_model() -> Pipeline:
    return Pipeline(
        [
            ("features", _vectoriser()),
            (
                "clf",
                LogisticRegression(
                    class_weight="balanced",
                    max_iter=2000,
                    C=4.0,
                    n_jobs=-1,
                ),
            ),
        ]
    )


def lightgbm_model() -> Pipeline:
    return Pipeline(
        [
            ("features", _vectoriser()),
            (
                "clf",
                LGBMClassifier(
                    objective="multiclass",
                    num_class=3,
                    class_weight="balanced",
                    n_estimators=600,
                    learning_rate=0.08,
                    num_leaves=63,
                    min_child_samples=10,
                    colsample_bytree=0.6,
                    subsample=0.9,
                    subsample_freq=1,
                    verbose=-1,
                    n_jobs=-1,
                ),
            ),
        ]
    )


MODELS = {
    "rule_baseline": RuleBaseline,
    "logreg": logistic_model,
    "lightgbm": lightgbm_model,
}


def attack_score(proba: np.ndarray) -> np.ndarray:
    """Probability that a request is an attack of any type."""
    return 1.0 - proba[:, BENIGN_IDX]
