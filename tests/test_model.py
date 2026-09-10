import numpy as np
import pandas as pd

from mlwaf.decode import request_parts
from mlwaf.features import build_matrix
from mlwaf.model import CLASSES, RuleBaseline, attack_score


def _frame(rows):
    out = []
    for method, path, query, body in rows:
        url_text, body_text, depth = request_parts(method, path, query, body)
        out.append({
            "text": "\n".join(t for t in (url_text, body_text) if t),
            "text_url": url_text, "text_body": body_text,
            "query": query, "path": path, "decode_depth": depth,
        })
    return build_matrix(pd.DataFrame(out))


def test_attack_score_is_complement_of_benign():
    proba = np.array([[0.9, 0.07, 0.03], [0.1, 0.8, 0.1]])
    assert np.allclose(attack_score(proba), [0.1, 0.9])


def test_rule_baseline_flags_injection():
    X = _frame([("GET", "/item", "id=1%27+OR+1%3D1--", "")])
    assert RuleBaseline().fit(X).predict(X)[0] != "benign"


def test_rule_baseline_passes_clean_request():
    X = _frame([("GET", "/products/list", "page=2", "")])
    assert RuleBaseline().fit(X).predict(X)[0] == "benign"


def test_rule_baseline_proba_rows_sum_to_one():
    X = _frame([("GET", "/a", "b=1", ""), ("GET", "/c", "d=%27", "")])
    proba = RuleBaseline().fit(X).predict_proba(X)
    assert proba.shape == (2, len(CLASSES))
    assert np.allclose(proba.sum(axis=1), 1.0)
