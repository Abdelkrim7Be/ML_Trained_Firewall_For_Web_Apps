"""The serving path must be arithmetically identical to the training pipeline.

It bypasses pandas and sklearn validation for speed, which is only acceptable if
it computes exactly the same thing. If this file ever fails, the fast path is
lying about the model.
"""

import numpy as np
import pandas as pd
import pytest

from mlwaf.decode import request_parts
from mlwaf.features import build_matrix
from mlwaf.waf.scorer import FastScorer

CASES = [
    ("GET", "/item", "id=1%27+UNION+SELECT+password+FROM+users--", ""),
    ("GET", "/search", "q=%3Cimg+src%3Dx+onerror%3Dalert%281%29%3E", ""),
    ("GET", "/products/search", "q=running+shoes", ""),
    ("POST", "/account", "", "name=O'Brien&city=Cork"),
    ("POST", "/login", "", "user=admin%27--&pw=x"),
    ("GET", "/", "", ""),
    ("PUT", "/api/v1/items/9", "sort=name", '{"title":"a book"}'),
]


@pytest.fixture
def scorer(bundle):
    return FastScorer(bundle["pipeline"])


def _pipeline_proba(pipeline, method, path, query, body):
    url_text, body_text, depth = request_parts(method, path, query, body)
    frame = pd.DataFrame([{
        "text": "\n".join(t for t in (url_text, body_text) if t),
        "text_url": url_text, "text_body": body_text,
        "query": query, "path": path, "decode_depth": depth,
    }])
    return pipeline.predict_proba(build_matrix(frame))[0]


@pytest.mark.parametrize(("method", "path", "query", "body"), CASES)
def test_matches_the_pipeline_exactly(bundle, scorer, method, path, query, body):
    url_text, body_text, depth = request_parts(method, path, query, body)
    text = "\n".join(t for t in (url_text, body_text) if t)

    fast = scorer.score(text, url_text, body_text, query, path, depth)
    slow = _pipeline_proba(bundle["pipeline"], method, path, query, body)

    np.testing.assert_allclose(fast, slow, rtol=0, atol=1e-12)


def test_probabilities_are_a_distribution(scorer):
    url_text, body_text, depth = request_parts("GET", "/x", "id=1", "")
    text = "\n".join(t for t in (url_text, body_text) if t)
    proba = scorer.score(text, url_text, body_text, "id=1", "/x", depth)
    assert proba.shape == (3,)
    assert pytest.approx(proba.sum(), abs=1e-9) == 1.0
    assert (proba >= 0).all()


def test_faster_than_the_pipeline(bundle, scorer):
    """Not a benchmark, just a guard that the fast path has not quietly regressed."""
    import time

    method, path, query, body = CASES[0]
    url_text, body_text, depth = request_parts(method, path, query, body)
    text = "\n".join(t for t in (url_text, body_text) if t)

    scorer.score(text, url_text, body_text, query, path, depth)
    t0 = time.perf_counter()
    for _ in range(20):
        scorer.score(text, url_text, body_text, query, path, depth)
    fast = time.perf_counter() - t0

    _pipeline_proba(bundle["pipeline"], method, path, query, body)
    t0 = time.perf_counter()
    for _ in range(20):
        _pipeline_proba(bundle["pipeline"], method, path, query, body)
    slow = time.perf_counter() - t0

    assert fast < slow
