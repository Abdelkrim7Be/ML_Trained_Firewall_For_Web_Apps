from pathlib import Path

import pytest

from mlwaf.parse import parse_file

BLOCK = """Start - Id: 42
class: SqlInjection
POST http://localhost:8080/login HTTP/1.1
Host: localhost:8080
Content-Type: application/x-www-form-urlencoded
Content-Length: 30

user=admin%27+OR+1%3D1--&pw=x

End - Id: 42
Start - Id: 43
class: Valid
GET /products.jsp?id=7 HTTP/1.1
Host: localhost:8080

null

End - Id: 43
"""


@pytest.fixture
def corpus(tmp_path: Path) -> Path:
    p = tmp_path / "corpus.txt"
    p.write_text(BLOCK)
    return p


def test_parses_every_block(corpus):
    assert len(list(parse_file(corpus))) == 2


def test_post_fields(corpus):
    req = list(parse_file(corpus))[0]
    assert req.request_id == "42"
    assert req.label == "SqlInjection"
    assert req.method == "POST"
    assert req.body == "user=admin%27+OR+1%3D1--&pw=x"
    assert req.headers["Content-Type"] == "application/x-www-form-urlencoded"


def test_null_body_becomes_empty(corpus):
    req = list(parse_file(corpus))[1]
    assert req.body == ""
    assert req.query == "id=7"
    assert req.path == "/products.jsp"


def test_url_with_spaces_is_kept(tmp_path):
    # Payloads legitimately contain spaces; a \S+ URL pattern would drop them.
    p = tmp_path / "c.txt"
    p.write_text(
        "Start - Id: 1\nclass: OsCommanding\n"
        "GET /cgi-bin/../../WINNT/system32/ping.exe 127.0.0.1? HTTP/1.0\n"
        "Host: x\n\nnull\n\nEnd - Id: 1\n"
    )
    req = next(iter(parse_file(p)))
    assert req.method == "GET"
    assert "ping.exe 127.0.0.1" in req.url
