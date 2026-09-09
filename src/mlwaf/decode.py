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

JS_ESCAPE_RE = re.compile(r"\\[xu]\{?([0-9a-fA-F]{2,6})\}?")
SQL_COMMENT_RE = re.compile(r"/\*.*?\*/", re.DOTALL)
DATA_URI_B64_RE = re.compile(r"data:[^;,]*;base64,([A-Za-z0-9+/=]{8,})", re.IGNORECASE)


def _js_unescape(text: str) -> str:
    def sub(m: re.Match[str]) -> str:
        try:
            return chr(int(m.group(1), 16))
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


def strip_sql_comments(text: str) -> str:
    """Collapse inline comments used to break up keywords: un/**/ion -> union."""
    return SQL_COMMENT_RE.sub("", text)


def request_text(method: str, path: str, query: str, body: str) -> tuple[str, int]:
    """Build the single normalised string the model sees, plus max decode depth.

    Host, cookies and user-agent are deliberately excluded: they are corpus
    fingerprints (CSIC is all localhost:8080, ECML is randomised), and training on
    them teaches the model which dataset a row came from rather than whether it is
    an attack.
    """
    decoded_path, d1 = decode(path)
    decoded_query, d2 = decode(query)
    decoded_body, d3 = decode(body)

    joined = " ".join(part for part in (method, decoded_path, decoded_query, decoded_body) if part)
    joined = strip_sql_comments(joined)
    return joined.lower(), max(d1, d2, d3)
