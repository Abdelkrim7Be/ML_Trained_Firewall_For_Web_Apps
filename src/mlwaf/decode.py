"""Normalise request text before feature extraction.

Attackers do not send `' OR 1=1--` or `<script>` literally; they send them wrapped
in one or more encoding layers. Counting characters on the raw string therefore
misses most real payloads:

    %2527%20OR%201=1   -> no quote visible (double URL-encoded)
    &#60;script&#62;   -> no angle bracket visible (HTML entities)
    \\u003cscript\\u003e -> no angle bracket visible (JS escapes)

So we peel the layers first, and record how many rounds it took -- normal traffic
needs zero or one, and a high count is itself evidence.
"""

from __future__ import annotations

import base64
import binascii
import html
import re
import unicodedata
from urllib.parse import unquote_plus

MAX_ROUNDS = 5

# Widths are exact on purpose: \x takes two hex digits and \u takes four.
# A loose {2,6} would swallow following text -- "\\u0020FROM" would match six
# digits ("0020FR") and decode to a single wrong character instead of a space
# followed by "FROM". Only the braced form \u{...} has a variable width.
JS_ESCAPE_RE = re.compile(r"\\x([0-9a-fA-F]{2})|\\u\{([0-9a-fA-F]{1,6})\}|\\u([0-9a-fA-F]{4})")
SQL_COMMENT_RE = re.compile(r"/\*.*?\*/", re.DOTALL)
CHAR_CALL_RE = re.compile(r"\b(?:char|chr)\s*\(\s*([0-9a-fx,\s]+?)\s*\)", re.IGNORECASE)
# /*!50000UNION*/ executes on MySQL but reads as a comment to anything else,
# so the payload inside must be recovered before comments are flattened.
MYSQL_VERSION_COMMENT_RE = re.compile(r"/\*!(?:\d{5})?(.*?)\*/", re.DOTALL)
HEX_LITERAL_RE = re.compile(r"\b0x([0-9a-fA-F]{2,})\b")
WHITESPACE_RE = re.compile(r"[ \t\n\r\v\f\u00a0\u2028\u2029]+")
DATA_URI_B64_RE = re.compile(r"data:[^;,]*;base64,([A-Za-z0-9+/=]{8,})", re.IGNORECASE)


def _js_unescape(text: str) -> str:
    def sub(m: re.Match[str]) -> str:
        digits = m.group(1) or m.group(2) or m.group(3)
        try:
            return chr(int(digits, 16))
        except (ValueError, OverflowError):
            return m.group(0)

    return JS_ESCAPE_RE.sub(sub, text)


def _decode_data_uris(text: str) -> str:
    def sub(m: re.Match[str]) -> str:
        try:
            raw = base64.b64decode(m.group(1), validate=True)
            return m.group(0) + " " + raw.decode("utf-8", errors="replace")
        except (binascii.Error, ValueError):
            return m.group(0)

    return DATA_URI_B64_RE.sub(sub, text)


def decode(text: str) -> tuple[str, int]:
    """Peel encoding layers until the string stops changing.

    Returns the normalised text and the number of rounds that changed something.
    """
    if not text:
        return "", 0

    current, rounds = text, 0
    for _ in range(MAX_ROUNDS):
        step = unquote_plus(current)
        step = html.unescape(step)
        step = _js_unescape(step)
        if step == current:
            break
        current, rounds = step, rounds + 1

    current = _decode_data_uris(current)
    # NFKC folds fullwidth/compatibility forms (e.g. ＜ -> <) used to dodge filters.
    current = unicodedata.normalize("NFKC", current)
    return current, rounds


def unwrap_mysql_comments(text: str) -> str:
    """/*!50000UNION*/ -> UNION. MySQL executes the contents; other parsers skip it."""
    return MYSQL_VERSION_COMMENT_RE.sub(lambda m: m.group(1), text)


def strip_sql_comments(text: str) -> str:
    """Replace inline comments with a space, the way a SQL parser treats them.

    Deleting them instead is wrong in both directions. `un/**/ion` is meant to
    rejoin into `union`, but `union/**/select` is meant to stay two words -- and
    deleting the comment yields `unionselect`, which destroys the very n-gram the
    model relies on. A space is what the database sees, so a space is what we use;
    the doubled space in the first case is collapsed later.
    """
    return SQL_COMMENT_RE.sub(" ", text)


def decode_char_calls(text: str) -> str:
    """CHAR(39) -> ' and CHR(0x27) -> ', including comma-separated runs.

    Lets an attacker write a payload containing no literal quote at all.
    """

    def sub(m: re.Match[str]) -> str:
        parts = [p.strip() for p in m.group(1).split(",") if p.strip()]
        out = []
        for part in parts:
            try:
                code = int(part, 16) if part.lower().startswith("0x") else int(part)
            except ValueError:
                return m.group(0)
            if not 0 <= code <= 0x10FFFF:
                return m.group(0)
            out.append(chr(code))
        return "".join(out) if out else m.group(0)

    return CHAR_CALL_RE.sub(sub, text)


def decode_hex_literals(text: str) -> str:
    """0x61646d696e -> admin. MySQL accepts a hex literal wherever a string fits."""

    def sub(m: re.Match[str]) -> str:
        digits = m.group(1)
        if len(digits) % 2:
            return m.group(0)
        try:
            raw = bytes.fromhex(digits).decode("ascii")
        except (ValueError, UnicodeDecodeError):
            return m.group(0)
        if not raw.isprintable():
            # Not text -- a genuine numeric constant, leave it alone.
            return m.group(0)
        # Re-quote it. `0x61646d696e` *is* the string literal `'admin'` to MySQL,
        # so unwrapping to bare `admin` would drop the quote characters the model
        # legitimately treats as evidence, and the evasion would still work.
        return f"'{raw}'"

    return HEX_LITERAL_RE.sub(sub, text)


def collapse_whitespace(text: str) -> str:
    """Tabs, newlines and vertical tabs are all whitespace to a SQL parser."""
    return WHITESPACE_RE.sub(" ", text).strip()


def _canonicalise(part: str) -> str:
    """Resolve obfuscation, then flatten whitespace.

    Order matters: comments and encoded literals are resolved first, so that
    comment- and tab-separated keywords end up looking identical to the
    space-separated form the model was trained on.
    """
    part = unwrap_mysql_comments(part)
    part = strip_sql_comments(part)
    part = decode_char_calls(part)
    part = decode_hex_literals(part)
    return collapse_whitespace(part)


def request_parts(method: str, path: str, query: str, body: str) -> tuple[str, str, int]:
    """Normalised (url_text, body_text, decode_depth).

    URL and body are kept apart because they behave differently: bodies are longer
    and, measured on the held-out set, attacks carrying one were missed three times
    as often. A single bag of n-grams over the whole request lets a long body
    dilute a short payload, so each gets its own vectoriser.
    """
    decoded_path, d1 = decode(path)
    decoded_query, d2 = decode(query)
    decoded_body, d3 = decode(body)

    url_parts = [_canonicalise(p) for p in (method, decoded_path, decoded_query) if p]
    url_text = "\n".join(p for p in url_parts if p)
    body_text = _canonicalise(decoded_body) if decoded_body else ""

    return url_text.lower(), body_text.lower(), max(d1, d2, d3)


def request_text(method: str, path: str, query: str, body: str) -> tuple[str, int]:
    """Build the single normalised string the model sees, plus max decode depth.

    Host, cookies and user-agent are deliberately excluded: they are corpus
    fingerprints (CSIC is all localhost:8080, ECML is randomised), and training on
    them teaches the model which dataset a row came from rather than whether it is
    an attack.
    """
    # Joined on newlines rather than spaces: a space separator would inject a
    # space into every single request, which silently breaks any space-counting
    # feature -- and the v0 rule baseline, which flags a request the moment it
    # sees one space, would then flag 100% of traffic.
    url_text, body_text, depth = request_parts(method, path, query, body)
    joined = "\n".join(p for p in (url_text, body_text) if p)
    return joined, depth
