from mlwaf.decode import decode, request_text, strip_sql_comments


def test_single_url_decode():
    assert decode("%27%20OR%201%3D1")[0] == "' OR 1=1"


def test_double_url_decode_is_peeled():
    text, rounds = decode("%2527%2520OR%25201%3D1")
    assert text == "' OR 1=1"
    assert rounds == 2


def test_html_entities():
    assert decode("&#60;script&#62;")[0] == "<script>"
    assert decode("&lt;script&gt;")[0] == "<script>"


def test_js_escapes():
    assert decode(r"\x3cscript\x3e")[0] == "<script>"
    assert decode(r"\u003cimg src=x\u003e")[0] == "<img src=x>"


def test_unicode_fullwidth_is_folded():
    assert decode("\uff1cscript\uff1e")[0] == "<script>"


def test_clean_text_needs_no_rounds():
    assert decode("/products/search")[1] == 0


def test_sql_comment_stripping():
    assert strip_sql_comments("un/**/ion sel/**/ect") == "union select"


def test_request_text_is_lowercased_and_joined():
    text, depth = request_text("GET", "/search", "q=%3Cscript%3E", "")
    assert text == "get /search q=<script>"
    assert depth == 1


def test_empty_input():
    assert decode("") == ("", 0)
