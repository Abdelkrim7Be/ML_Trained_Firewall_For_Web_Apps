"""Feature extraction.

Two blocks are fused:

- Character n-grams (TF-IDF). These carry the real signal. A count of quotes
  cannot tell "O'Brien" from "admin' OR 1=1", but the n-grams "' or", "union sel",
  "<scr", "onerror=" can. This is the main upgrade over counting characters.
- Hand-built numeric features. Cheap, interpretable, and they give the feature
  importance plot something a human can read.
"""

from __future__ import annotations

import math
import re
from collections import Counter

import numpy as np
import pandas as pd

SQL_KEYWORDS = (
    "select", "union", "insert", "update", "delete", "drop", "from", "where",
    "order by", "group by", "having", "sleep", "waitfor", "delay", "benchmark",
    "information_schema", "or 1=1", "exec", "cast", "convert",
)
XSS_KEYWORDS = (
    "script", "javascript:", "alert", "onerror", "onload", "eval", "document.cookie",
    "iframe", "svg", "img src", "prompt", "confirm", "expression", "vbscript",
)

EVENT_HANDLER_RE = re.compile(r"on[a-z]{3,15}\s*=")
TAG_RE = re.compile(r"<\s*/?\s*[a-z][a-z0-9]*")
ENTITY_RE = re.compile(r"&(?:#x?[0-9a-f]+|[a-z]+);")

NUMERIC_COLS = [
    # SQL injection oriented
    "single_q", "double_q", "dashes", "parens", "semicolons", "equals",
    "sql_keywords", "sql_comment",
    # XSS oriented
    "angle_open", "angle_close", "tags", "event_handlers", "xss_keywords",
    "entities", "slashes",
    # generic
    "length", "entropy", "decode_depth", "spaces", "non_ascii_ratio",
    "digit_ratio", "punct_ratio", "param_count", "path_depth", "max_token_len",
    # Where the payload sits matters: attacks carrying a body were missed three
    # times as often as those that did not, so the split is given to the model.
    "body_length", "body_ratio", "has_body",
]


def _entropy(text: str) -> float:
    """Shannon entropy. Encoded or obfuscated payloads look more random than paths."""
    if not text:
        return 0.0
    counts = Counter(text)
    n = len(text)
    return -sum((c / n) * math.log2(c / n) for c in counts.values())


def _row_features(
    text: str, query: str, path: str, decode_depth: int, body: str = ""
) -> dict[str, float]:
    n = max(len(text), 1)
    non_ascii = sum(1 for ch in text if ord(ch) > 127)
    digits = sum(1 for ch in text if ch.isdigit())
    punct = sum(1 for ch in text if not ch.isalnum() and not ch.isspace())
    tokens = text.split()

    return {
        "single_q": text.count("'"),
        "double_q": text.count('"'),
        "dashes": text.count("--"),
        "parens": text.count("("),
        "semicolons": text.count(";"),
        "equals": text.count("="),
        "sql_keywords": sum(text.count(k) for k in SQL_KEYWORDS),
        "sql_comment": text.count("/*") + text.count("#"),
        "angle_open": text.count("<"),
        "angle_close": text.count(">"),
        "tags": len(TAG_RE.findall(text)),
        "event_handlers": len(EVENT_HANDLER_RE.findall(text)),
        "xss_keywords": sum(text.count(k) for k in XSS_KEYWORDS),
        "entities": len(ENTITY_RE.findall(text)),
        "slashes": text.count("/") + text.count("\\"),
        "length": len(text),
        "entropy": _entropy(text),
        "decode_depth": float(decode_depth),
        "spaces": text.count(" "),
        "non_ascii_ratio": non_ascii / n,
        "digit_ratio": digits / n,
        "punct_ratio": punct / n,
        "param_count": query.count("&") + 1 if query else 0,
        "path_depth": path.count("/"),
        "max_token_len": max((len(t) for t in tokens), default=0),
        "body_length": len(body),
        "body_ratio": len(body) / n,
        "has_body": float(bool(body)),
    }


def numeric_features(df: pd.DataFrame) -> pd.DataFrame:
    rows = [
        _row_features(r.text, r.query, r.path, r.decode_depth, getattr(r, "text_body", ""))
        for r in df.itertuples(index=False)
    ]
    return pd.DataFrame(rows, columns=NUMERIC_COLS, index=df.index).astype(np.float32)


def build_matrix(df: pd.DataFrame) -> pd.DataFrame:
    """Frame with both text columns plus every numeric column, ready for the pipeline."""
    out = numeric_features(df)
    out.insert(0, "text", df["text"].values)
    out.insert(1, "text_url", df["text_url"].values)
    out.insert(2, "text_body", df["text_body"].values)
    return out
