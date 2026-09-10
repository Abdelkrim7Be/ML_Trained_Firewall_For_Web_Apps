"""The transforms must actually obfuscate, and the normaliser must undo the ones
it claims to handle."""

import pandas as pd

from mlwaf.decode import decode, request_text
from mlwaf.evasion import HANDLED_BY_NORMALISER, TRANSFORMS
from mlwaf.robustness import mutate

PAYLOAD = "' UNION SELECT password FROM users--"
# hex_literal and concat_quotes rewrite quoted string literals, so they need a
# payload that actually contains a matched pair of quotes.
QUOTED_PAYLOAD = "id='admin' AND '1'='1'"
XSS_PAYLOAD = "<script>alert(1)</script>"


def test_every_transform_changes_the_payload():
    for name, fn in TRANSFORMS.items():
        if name == "none":
            continue
        assert any(
            fn(p) != p for p in (PAYLOAD, QUOTED_PAYLOAD, XSS_PAYLOAD)
        ), name


def test_normaliser_undoes_what_it_claims():
    """Anything in HANDLED_BY_NORMALISER must decode back to the original payload."""
    for name in HANDLED_BY_NORMALISER:
        obfuscated = TRANSFORMS[name](PAYLOAD)
        recovered, _ = decode(obfuscated)
        assert recovered.lower() == PAYLOAD.lower(), f"{name}: {recovered!r}"


def test_unhandled_transforms_survive_normalisation():
    """Transforms the normaliser makes no claim about. The suite measures the cost."""
    for name in ["concat_quotes"]:
        obfuscated = TRANSFORMS[name](QUOTED_PAYLOAD)
        recovered, _ = decode(obfuscated)
        assert recovered.lower() != QUOTED_PAYLOAD.lower(), name


def test_mysql_version_comment_wraps_keywords():
    assert TRANSFORMS["mysql_version_comment"]("UNION SELECT") == (
        "/*!50000UNION*/ /*!50000SELECT*/"
    )


def test_mutate_keeps_row_count_and_columns():
    df = pd.DataFrame([{
        "method": "GET", "path": "/item",
        "query": "id=1%27+OR+1%3D1--", "body": "",
    }])
    out = mutate(df, TRANSFORMS["case_flip"])
    assert len(out) == 1
    assert set(out.columns) == {"text", "query", "path", "decode_depth"}


def test_request_text_recovers_double_encoded_attack():
    raw = TRANSFORMS["double_url_encode"](PAYLOAD)
    text, depth = request_text("GET", "/item", raw, "")
    assert "union select" in text
    assert depth >= 2


def test_normaliser_resolves_sql_obfuscation():
    """These were measured bypasses before decode.py learned to undo them."""
    cases = {
        "space_to_comment": ("union/**/select", "union select"),
        "mysql_version_comment": ("/*!50000UNION*/ /*!50000SELECT*/", "union select"),
        # A hex literal is a *quoted* string literal, so it must normalise back to
        # the quoted form -- otherwise the evasion still strips the quote signal.
        "hex_literal": ("id=0x61646d696e", "id='admin'"),
        "char_function": ("id=CHAR(39)admin", "id='admin"),
        "space_to_tab": ("union\tselect", "union select"),
        "space_to_newline": ("union\nselect", "union select"),
    }
    for name, (payload, expected) in cases.items():
        text, _ = request_text("GET", "/x", payload, "")
        assert text == f"get\n/x\n{expected}", f"{name}: {text!r}"


def test_hex_literal_leaves_numeric_constants_alone():
    """0xdeadbeef is not printable text and must not be rewritten."""
    text, _ = request_text("GET", "/x", "id=0xdeadbeef", "")
    assert "0xdeadbeef" in text
