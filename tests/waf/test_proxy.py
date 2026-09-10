"""The proxy end to end, against a real upstream.

The point of these is the thing v0 got wrong: an attack must not reach the origin.
Asserting on the 403 is not enough, so the fake upstream records every request it
receives and the tests check it stayed empty.
"""

import threading
from http.server import BaseHTTPRequestHandler, HTTPServer

import httpx
import pytest
from fastapi.testclient import TestClient

from mlwaf.waf.app import create_app
from mlwaf.waf.config import Settings

from .conftest import AUTH, TEST_TOKEN

RECEIVED: list[dict] = []


class _Upstream(BaseHTTPRequestHandler):
    def _handle(self):
        length = int(self.headers.get("Content-Length") or 0)
        body = self.rfile.read(length).decode() if length else ""
        RECEIVED.append({"path": self.path, "method": self.command, "body": body})
        payload = b'{"upstream":"ok"}'
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    do_GET = do_POST = do_PUT = _handle
    do_DELETE = do_HEAD = do_OPTIONS = _handle

    def log_message(self, *_args):
        pass


@pytest.fixture(scope="module")
def upstream():
    server = HTTPServer(("127.0.0.1", 0), _Upstream)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    yield f"http://127.0.0.1:{server.server_port}"
    server.shutdown()


def _client(upstream, bundle, **overrides) -> TestClient:
    overrides.setdefault("mode", "block")
    overrides.setdefault("scoring_budget_ms", 60_000.0)
    overrides.setdefault("admin_token", TEST_TOKEN)
    settings = Settings(upstream=upstream, db_path=":memory:", **overrides)
    return TestClient(create_app(settings, bundle=dict(bundle)))


@pytest.fixture
def client(upstream, bundle):
    RECEIVED.clear()
    with _client(upstream, bundle) as c:
        yield c


def test_benign_request_reaches_upstream(client):
    r = client.get("/products/search", params={"q": "running shoes"})
    assert r.status_code == 200
    assert r.json() == {"upstream": "ok"}
    assert len(RECEIVED) == 1


def test_sql_injection_is_refused(client):
    r = client.get("/item", params={"id": "1' UNION SELECT password FROM users--"})
    assert r.status_code == 403
    assert r.json()["error"] == "request_blocked"
    assert r.headers["X-MLWAF-Action"] == "block"
    # The attack never reached the application. This is what v0 failed to do.
    assert RECEIVED == []


def test_xss_is_refused(client):
    r = client.get("/search", params={"q": "<img src=x onerror=alert(1)>"})
    assert r.status_code == 403
    assert RECEIVED == []


def test_injection_in_a_post_body_is_refused(client):
    """v0 inspected GET paths only, so this class of attack walked straight past."""
    r = client.post("/login", content="username=admin' OR 1=1--&password=x",
                    headers={"Content-Type": "application/x-www-form-urlencoded"})
    assert r.status_code == 403
    assert RECEIVED == []


def test_a_weak_injection_gets_through_at_this_threshold(client):
    """A known gap, asserted rather than hidden.

    `admin'--` scores around 0.79, under the 0.96 operating point, so it is
    allowed. That is the 20% miss rate the training run reports, showing up where
    you would expect it: a short payload with little signal. Lowering the
    threshold catches it and costs false positives, which is the whole trade the
    threshold exists to express.
    """
    r = client.post("/login", content="username=admin'--&password=x",
                    headers={"Content-Type": "application/x-www-form-urlencoded"})
    assert r.status_code == 200
    row = client.get("/_waf/decisions", headers=AUTH).json()["decisions"][0]
    assert 0.5 < row["score"] < row["threshold"]


def test_apostrophe_in_a_name_is_allowed_through(client):
    r = client.post("/account", content="name=O'Brien&city=Cork",
                    headers={"Content-Type": "application/x-www-form-urlencoded"})
    assert r.status_code == 200
    assert RECEIVED[0]["body"] == "name=O'Brien&city=Cork"


def test_every_response_carries_a_request_id(client):
    assert client.get("/").headers["X-MLWAF-Request-Id"]
    blocked = client.get("/item", params={"id": "1' OR 1=1--"})
    assert blocked.headers["X-MLWAF-Request-Id"]


def test_detect_mode_forwards_but_marks(upstream, bundle):
    RECEIVED.clear()
    with _client(upstream, bundle, mode="detect") as c:
        r = c.get("/item", params={"id": "1' UNION SELECT password FROM users--"})
    assert r.status_code == 200
    assert r.headers["X-MLWAF-Action"] == "would-block"
    assert len(RECEIVED) == 1        # deliberately not blocked


def test_oversized_body_is_forwarded_unscored(upstream, bundle):
    RECEIVED.clear()
    with _client(upstream, bundle, max_body_bytes=64) as c:
        r = c.post("/upload", content="x" * 500)
        assert r.status_code == 200
        assert len(RECEIVED) == 1
        decisions = c.get("/_waf/decisions", headers=AUTH).json()["decisions"]
    assert decisions[0]["reason"] == "body_too_large"
    assert decisions[0]["degraded"] is True


def test_upstream_failure_becomes_502(bundle):
    with _client("http://127.0.0.1:1", bundle) as c:
        assert c.get("/anything").status_code == 502


def test_post_body_attack_is_explained(client):
    """The explanation must cover the body, not just the query string."""
    client.post("/login", content="username=admin' OR 1=1--&password=x",
                headers={"Content-Type": "application/x-www-form-urlencoded"})
    row = client.get("/_waf/decisions", headers=AUTH).json()["decisions"][0]
    trace = row["explanation"]["decode_trace"]
    assert trace, "a body borne attack must still produce a decode trace"
    assert any("or 1=1" in s["value"].lower() for s in trace)


def test_decision_is_recorded_with_an_explanation(client):
    client.get("/item", params={"id": "1' UNION SELECT password FROM users--"})
    row = client.get("/_waf/decisions", headers=AUTH).json()["decisions"][0]
    assert row["verdict"] == "block"
    assert row["attack_class"] == "sqli"
    trace = row["explanation"]["decode_trace"]
    assert trace[0]["step"] == "raw"
    assert any("union" in s["value"].lower() for s in trace)
    assert row["explanation"]["contributions"]


def test_headers_are_not_relayed_verbatim(client):
    client.get("/x", headers={"Connection": "keep-alive", "X-Custom": "kept"})
    assert "connection" not in {k.lower() for k in RECEIVED[0].get("headers", {})}


@pytest.mark.parametrize("method", ["GET", "POST", "PUT", "DELETE"])
def test_all_methods_are_proxied(client, method):
    r = client.request(method, "/api/thing")
    assert r.status_code == 200
    assert RECEIVED[-1]["method"] == method


def test_httpx_is_installed_for_the_proxy():
    assert httpx.__version__
