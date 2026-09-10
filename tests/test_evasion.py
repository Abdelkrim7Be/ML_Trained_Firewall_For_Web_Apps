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
    """These are genuine gaps, and the suite exists to measure them."""
    for name in ["char_function", "hex_literal", "concat_quotes"]:
        obfuscated = TRANSFORMS[name](QUOTED_PAYLOAD)
        recovered, _ = decode(obfuscated)
        assert recovered.lower() != QUOTED_PAYLOAD.lower(), name


def test_comment_split_is_semantically_equivalent():
    assert TRANSFORMS["comment_split"]("UNION SELECT") == "UN/**/ION SEL/**/ECT"


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
