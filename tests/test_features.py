import pandas as pd

from mlwaf.features import NUMERIC_COLS, build_matrix, numeric_features


def _frame(text, query="", path="/"):
    return pd.DataFrame([{"text": text, "query": query, "path": path, "decode_depth": 0}])


def test_all_columns_present_and_finite():
    f = numeric_features(_frame("get /search q=' or 1=1--"))
    assert list(f.columns) == NUMERIC_COLS
    assert f.notna().all().all()


def test_sqli_signals_fire():
    f = numeric_features(_frame("get /x q=' union select * from users--")).iloc[0]
    assert f["single_q"] == 1
    assert f["dashes"] == 1
    assert f["sql_keywords"] >= 3


def test_xss_signals_fire():
    f = numeric_features(_frame('get /x q=<img src=x onerror=alert(1)>')).iloc[0]
    assert f["angle_open"] == 1
    assert f["tags"] == 1
    assert f["event_handlers"] == 1
    assert f["xss_keywords"] >= 2


def test_benign_request_is_quiet():
    f = numeric_features(_frame("get /products/search q=shoes")).iloc[0]
    assert f["single_q"] == 0
    assert f["tags"] == 0
    assert f["sql_keywords"] == 0
    assert f["event_handlers"] == 0


def test_entropy_higher_for_obfuscated():
    plain = numeric_features(_frame("get /a/b/c")).iloc[0]["entropy"]
    noisy = numeric_features(_frame("get /a q=%3c%73%63%72%69%70%74%3e9f2b")).iloc[0]["entropy"]
    assert noisy > plain


def test_empty_text_does_not_crash():
    f = numeric_features(_frame(""))
    assert f.notna().all().all()


def test_build_matrix_keeps_text_first():
    m = build_matrix(_frame("get /x"))
    assert m.columns[0] == "text"
    assert len(m.columns) == len(NUMERIC_COLS) + 1
