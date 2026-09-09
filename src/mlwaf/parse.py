"""Parse the raw corpora into request records.

Both ECML/PKDD and CSIC ship in the same block format::

    Start - Id: 1174
    class: Attack
    POST http://host/path HTTP/1.1
    Header: value
    ...
                        <- blank line
    body text           <- the literal string "null" when there is no body
                        <- blank line
    End - Id: 1174
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Iterator

START_RE = re.compile(r"^Start - Id:\s*(\S+)")
END_RE = re.compile(r"^End - Id:")
CLASS_RE = re.compile(r"^class:\s*(\S+)")
# The URL is matched greedily: attack payloads legitimately contain spaces
# (e.g. "GET /cgi-bin/../../WINNT/system32/ping.exe 127.0.0.1? HTTP/1.0"), so a
# \S+ URL would silently drop the most malicious requests in the corpus.
REQUEST_LINE_RE = re.compile(r"^([A-Z]+)\s+(.*?)\s+(HTTP/\d\.\d)\s*$")

# ECML pads records with these filler "headers"; they carry no signal.
FILLER_HEADER_RE = re.compile(r"^[-~]+$")


@dataclass
class Request:
    request_id: str
    label: str
    method: str = ""
    url: str = ""
    http_version: str = ""
    headers: dict[str, str] = field(default_factory=dict)
    body: str = ""

    @property
    def path(self) -> str:
        return self.url.split("?", 1)[0]

    @property
    def query(self) -> str:
        _, _, q = self.url.partition("?")
        return q


def _parse_block(block: list[str], request_id: str, label: str) -> Request:
    req = Request(request_id=request_id, label=label)

    # Split head from body on the first blank line.
    try:
        blank = block.index("")
        head, body_lines = block[:blank], block[blank + 1 :]
    except ValueError:
        head, body_lines = block, []

    if head:
        if m := REQUEST_LINE_RE.match(head[0]):
            req.method, req.url, req.http_version = m.groups()
        for line in head[1:]:
            name, sep, value = line.partition(":")
            if not sep or FILLER_HEADER_RE.match(name):
                continue
            req.headers[name.strip()] = value.strip()

    body = "\n".join(body_lines).strip()
    req.body = "" if body == "null" else body
    return req


def parse_file(path: Path) -> Iterator[Request]:
    """Yield one Request per block. Malformed blocks are skipped, not fatal."""
    request_id, label, block, in_block = "", "", [], False

    with path.open(encoding="utf-8", errors="replace") as fh:
        for raw in fh:
            line = raw.rstrip("\n").rstrip("\r")

            if m := START_RE.match(line):
                request_id, label, block, in_block = m.group(1), "", [], True
                continue
            if not in_block:
                continue
            if END_RE.match(line):
                if label:
                    # Trailing blank lines are block padding, not body content.
                    while block and block[-1] == "":
                        block.pop()
                    yield _parse_block(block, request_id, label)
                in_block = False
                continue
            if not label and (m := CLASS_RE.match(line)):
                label = m.group(1)
                continue
            block.append(line)
