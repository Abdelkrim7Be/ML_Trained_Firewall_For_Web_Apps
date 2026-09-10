"""Obfuscation transforms, and how much recall they cost.

A detector is only as good as its behaviour against payloads that were written to
get past it. Reporting recall on clean corpus payloads answers a question no
attacker asks.

Each transform rewrites a payload so it still executes but no longer looks the
same. Some of them are answered by the normalisation chain in `decode.py` and
should cost nothing -- measuring that is how we know the chain works. Others are
not handled, and those are the honest gaps.
"""

from __future__ import annotations

import random
import re
from collections.abc import Callable
from urllib.parse import quote

Transform = Callable[[str], str]

SQL_KEYWORD_RE = re.compile(
    r"\b(select|union|from|where|and|or|insert|update|delete|drop|order|group|by)\b",
    re.IGNORECASE,
)


def identity(text: str) -> str:
    return text


def case_flip(text: str) -> str:
    """SeLeCt. Defeats any case-sensitive keyword list."""
    rng = random.Random(0)
    return "".join(c.upper() if rng.random() < 0.5 else c.lower() for c in text)


def url_encode(text: str) -> str:
    return quote(text, safe="")


def double_url_encode(text: str) -> str:
    return quote(quote(text, safe=""), safe="")


def html_entity_encode(text: str) -> str:
    """&#60;script&#62; -- classic XSS filter bypass."""
    return "".join(f"&#{ord(c)};" if not c.isalnum() else c for c in text)


def js_unicode_escape(text: str) -> str:
    r"""<script> -- executes inside a JS string context."""
    return "".join(f"\\u{ord(c):04x}" if not c.isalnum() else c for c in text)


def fullwidth(text: str) -> str:
    """Unicode compatibility forms that normalise back to ASCII."""
    out = []
    for c in text:
        code = ord(c)
        out.append(chr(code + 0xFEE0) if 0x21 <= code <= 0x7E else c)
    return "".join(out)


def mysql_version_comment(text: str) -> str:
    """UNION -> /*!50000UNION*/.

    MySQL executes the body of a version comment; every other parser, and any
    filter that merely strips comments, sees nothing. Note that splitting a
    keyword instead (`un/**/ion`) is *not* a working evasion: MySQL treats an
    inline comment as whitespace, so that payload is a syntax error and would
    never reach the database as `union`.
    """
    return SQL_KEYWORD_RE.sub(lambda m: f"/*!50000{m.group(0)}*/", text)


def space_to_comment(text: str) -> str:
    """union/**/select -- MySQL treats an inline comment as whitespace."""
    return text.replace(" ", "/**/")


def space_to_tab(text: str) -> str:
    """Tab, vertical tab and form feed are all whitespace to a SQL parser."""
    return text.replace(" ", "\t")


def space_to_newline(text: str) -> str:
    return text.replace(" ", "\n")


def char_function(text: str) -> str:
    """Replace quotes with CHAR(39) -- no literal quote survives in the payload."""
    return text.replace("'", "CHAR(39)").replace('"', "CHAR(34)")


def hex_literal(text: str) -> str:
    """Rewrite quoted strings as 0x hex literals, which MySQL accepts directly."""

    def sub(m: re.Match[str]) -> str:
        inner = m.group(1)
        return "0x" + inner.encode("utf-8", errors="replace").hex()

    return re.sub(r"'([^']*)'", sub, text)


def concat_quotes(text: str) -> str:
    """'ad'+'min' -- breaks up literals that a signature might match whole."""

    def sub(m: re.Match[str]) -> str:
        inner = m.group(1)
        if len(inner) < 2:
            return m.group(0)
        mid = len(inner) // 2
        return f"'{inner[:mid]}'+'{inner[mid:]}'"

    return re.sub(r"'([^']*)'", sub, text)


# Grouped so the report can say which family each result belongs to.
TRANSFORMS: dict[str, Transform] = {
    "none": identity,
    "case_flip": case_flip,
    "url_encode": url_encode,
    "double_url_encode": double_url_encode,
    "html_entity_encode": html_entity_encode,
    "js_unicode_escape": js_unicode_escape,
    "fullwidth": fullwidth,
    "mysql_version_comment": mysql_version_comment,
    "space_to_comment": space_to_comment,
    "space_to_tab": space_to_tab,
    "space_to_newline": space_to_newline,
    "char_function": char_function,
    "hex_literal": hex_literal,
    "concat_quotes": concat_quotes,
}

# Transforms the normalisation chain is designed to undo. If any of these costs
# recall, decode.py has a hole in it.
HANDLED_BY_NORMALISER = frozenset(
    {"case_flip", "url_encode", "double_url_encode", "html_entity_encode",
     "js_unicode_escape", "fullwidth"}
)
