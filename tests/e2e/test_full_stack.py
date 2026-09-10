"""The whole platform, against a running server.

Grouped by what an operator would actually want to be true.
"""

from __future__ import annotations

import concurrent.futures
import json
import time
from urllib.parse import quote

import httpx
import pytest

# --- payloads ---------------------------------------------------------------
# Split by what the model actually does, not by what we would like it to do.
# Locking in the misses is deliberate: it makes a regression visible in either
# direction, and it stops the suite quietly implying a recall this model does not
# have. Scores are from the shipped model at threshold 0.963.

CAUGHT_SQLI = [
    "1' UNION SELECT username,password FROM users--",   # 1.000
    "1' OR '1'='1",                                     # 0.999
    "admin' OR 1=1#",                                   # 0.970
    "1' UNION ALL SELECT NULL,version()--",             # 0.988
]
MISSED_SQLI = [
    ("1'; DROP TABLE users--", 0.938),                  # just under the threshold
    ("1' AND SLEEP(5)--", 0.227),                       # blind injection, little signal
    ("1' OR 1=1--", 0.481),                             # the canonical payload, missed
    ("1' UNION SELECT password--", 0.867),              # same query minus "users"
]
CAUGHT_XSS = [
    "<script>alert(1)</script>",
    "<img src=x onerror=alert(1)>",
    "<svg/onload=alert(1)>",
    "<iframe src=javascript:alert(1)>",
    "<body onload=alert(document.cookie)>",
]
# Obfuscations of a payload the model catches when it is in the clear. These test
# the normalisation chain, so the payload has to be one that would otherwise be
# caught, or the test measures the model's recall instead of the decoder.
OBFUSCATED = [
    "1%27%20UNION%20SELECT%20password%20FROM%20users--",
    "1%2527%2520UNION%2520SELECT%2520password%2520FROM%2520users--",
    "1' UNION/**/SELECT/**/password/**/FROM/**/users--",
    "1' uNiOn SeLeCt password FrOm users--",
    "1' UNION SELECT password FROM users\t--",
]
BENIGN = [
    "/", "/index.html", "/assets/app.css", "/api/products?page=2&sort=name",
    "/rest/products/search?q=apple+juice",
    "/search?q=O'Brien", "/search?q=don't stop", "/blog/2024/01/a-post-about-sql",
    "/api/v1/orders?status=shipped&from=2026-01-01",
]
# Ordinary paths this model refuses. See docs/FINDINGS.md: it learned the literal
# token "users" as evidence of an attack, because ECML's benign URLs are
# randomised strings that never contain real English words.
KNOWN_FALSE_POSITIVES = ["/users/42/profile"]


def _flagged(client) -> list[dict]:
    return client.get("/_waf/decisions", params={"only_flagged": True, "limit": 200}) \
                 .json()["decisions"]


# --- 1. it protects the origin ----------------------------------------------
@pytest.mark.parametrize("payload", CAUGHT_SQLI)
def test_sql_injection_never_reaches_the_origin(client, origin, payload):
    r = client.get(f"/item?id={quote(payload)}")
    assert r.status_code == 403, payload
    assert origin.received == [], f"{payload} reached the application"


@pytest.mark.parametrize(("payload", "expected_score"), MISSED_SQLI)
def test_known_misses_are_still_missed(client, payload, expected_score):
    """Documented gaps, asserted rather than hidden.

    Each of these is a working SQL injection that this model scores below the
    operating point. If one starts being caught, that is good news and this test
    should be updated; if a caught one starts being missed, that is a regression
    and this file is where it shows up.
    """
    assert client.get(f"/item?id={quote(payload)}").status_code == 200
    row = client.get("/_waf/decisions").json()["decisions"][0]
    assert row["score"] == pytest.approx(expected_score, abs=0.05)
    assert row["score"] < row["threshold"]


@pytest.mark.parametrize("payload", CAUGHT_XSS)
def test_xss_never_reaches_the_origin(client, origin, payload):
    r = client.get(f"/search?q={quote(payload)}")
    assert r.status_code == 403, payload
    assert origin.received == []


@pytest.mark.parametrize("payload", OBFUSCATED)
def test_obfuscated_attacks_are_still_refused(client, origin, payload):
    """The normalisation chain is what these are really testing."""
    r = client.get(f"/item?id={quote(payload, safe='%')}")
    assert r.status_code == 403, payload
    assert origin.received == []


@pytest.mark.parametrize("path", KNOWN_FALSE_POSITIVES)
def test_known_false_positives_are_still_wrong(client, path):
    """An ordinary path this model refuses. Recorded, not papered over.

    `/users/42/profile` is about as common a URL as exists, and it scores 0.9996.
    The cause is in docs/FINDINGS.md: the training corpus never showed the model
    a benign URL containing a real English word, so it learned the token "users"
    as evidence. This is the single strongest argument for the detect mode default.
    """
    assert client.get(path).status_code == 403


def test_injection_in_a_post_body_is_refused(client, origin):
    r = client.post("/login", content="user=admin' OR 1=1--&pw=x",
                    headers={"Content-Type": "application/x-www-form-urlencoded"})
    assert r.status_code == 403
    assert origin.received == []


def test_injection_in_json_is_refused(client, origin):
    r = client.post("/api/search",
                    content=json.dumps({"q": "1' UNION SELECT password FROM users--"}),
                    headers={"Content-Type": "application/json"})
    assert r.status_code == 403
    assert origin.received == []


# --- 2. it does not break the application -----------------------------------
@pytest.mark.parametrize("path", BENIGN)
def test_ordinary_traffic_passes(client, origin, path):
    r = client.get(path)
    assert r.status_code == 200, path
    assert r.json() == {"origin": "reached"}
    assert len(origin.received) == 1


def test_apostrophes_in_real_data_pass(client, origin):
    for body in ["name=O'Brien&city=Cork",
                 "comment=don't stop believing",
                 "title=Marie's Guide to L'Hôpital"]:
        origin.clear()
        r = client.post("/account", content=body,
                        headers={"Content-Type": "application/x-www-form-urlencoded"})
        assert r.status_code == 200, body
        assert origin.received[0]["body"] == body


@pytest.mark.parametrize("method", ["GET", "POST", "PUT", "PATCH", "DELETE"])
def test_every_method_is_proxied(client, origin, method):
    r = client.request(method, "/api/resource")
    assert r.status_code == 200
    assert origin.received[0]["method"] == method


def test_response_body_is_relayed_intact(client, origin):
    r = client.get("/api/thing")
    assert r.json() == {"origin": "reached"}
    assert r.headers["content-type"].startswith("application/json")


def test_query_string_reaches_the_origin_unchanged(client, origin):
    client.get("/api/items?a=1&b=two&c=three%20four")
    assert origin.received[0]["path"] == "/api/items?a=1&b=two&c=three%20four"


# --- 3. observability --------------------------------------------------------
def test_every_response_carries_a_request_id(client):
    assert client.get("/x").headers["X-MLWAF-Request-Id"]
    assert client.get("/item?id=1%27+OR+1%3D1--").headers["X-MLWAF-Request-Id"]


def test_decisions_are_recorded_with_explanations(client):
    client.get("/item?id=" + quote("1' UNION SELECT password FROM users--"))
    row = _flagged(client)[0]
    assert row["verdict"] == "block"
    assert row["attack_class"] == "sqli"

    trace = row["explanation"]["decode_trace"]
    assert trace[0]["step"] == "raw"
    assert "union select" in trace[-1]["value"].lower()
    assert row["explanation"]["contributions"]


def test_double_encoding_shows_two_decode_rounds(client):
    client.get("/item?id=1%2527%2520UNION%2520SELECT%2520password%2520FROM%2520users--")
    row = client.get("/_waf/decisions").json()["decisions"][0]
    steps = [s["step"] for s in row["explanation"]["decode_trace"]]
    assert "decode round 2" in steps


def test_metrics_track_verdicts(client):
    before = client.get("/_waf/metrics").text
    client.get("/item?id=" + quote("1' OR '1'='1"))
    after = client.get("/_waf/metrics").text
    assert "mlwaf_requests_total" in after
    assert "mlwaf_flagged_total" in after
    assert after != before


def test_health_and_readiness_are_distinct(client):
    assert client.get("/_waf/healthz").json()["status"] == "ok"
    assert client.get("/_waf/readyz").json()["status"] == "ready"


def test_console_is_served(client):
    assert "mlwaf" in client.get("/_waf/").text
    for asset in ("style.css", "app.js"):
        assert client.get(f"/_waf/static/{asset}").status_code == 200


# --- 4. the live stream ------------------------------------------------------
def test_sse_delivers_decisions_as_they_happen(waf):
    """A real socket, not an in process queue."""
    received: list[dict] = []

    with (
        httpx.Client(base_url=waf.url, timeout=20.0) as c,
        c.stream("GET", "/_waf/stream") as stream,
    ):
        lines = stream.iter_lines()
        next(lines)  # the ": connected" preamble

        with httpx.Client(base_url=waf.url, timeout=10.0) as probe:
            probe.get("/item?id=" + quote("1' UNION SELECT password FROM users--"))

        deadline = time.time() + 15
        for line in lines:
            if line.startswith("data: "):
                received.append(json.loads(line[6:]))
                break
            if time.time() > deadline:
                break

    assert received, "no event arrived over the stream"
    assert received[0]["verdict"] == "block"
    assert received[0]["attack_class"] == "sqli"


# --- 5. runtime control ------------------------------------------------------
def test_threshold_change_takes_effect_on_live_traffic(client, origin):
    payload = "/search?q=" + quote("mildly odd 'input")
    assert client.get(payload).status_code == 200

    original = client.get("/_waf/status").json()["threshold"]
    try:
        client.post("/_waf/threshold", json={"value": 0.0})
        origin.clear()
        assert client.get(payload).status_code == 403
        assert origin.received == []
    finally:
        client.post("/_waf/threshold", json={"value": original})

    origin.clear()
    assert client.get(payload).status_code == 200


def test_mode_can_be_promoted_and_demoted_live(client, origin):
    attack = "/item?id=" + quote("1' UNION SELECT password FROM users--")
    assert client.get(attack).status_code == 403

    client.post("/_waf/mode", json={"mode": "detect"})
    try:
        origin.clear()
        r = client.get(attack)
        assert r.status_code == 200
        assert r.headers["X-MLWAF-Action"] == "would-block"
        assert len(origin.received) == 1     # deliberately allowed through
    finally:
        client.post("/_waf/mode", json={"mode": "block"})

    origin.clear()
    assert client.get(attack).status_code == 403


def test_threshold_impact_is_monotonic(client):
    for _ in range(5):
        client.get("/item?id=" + quote("1' OR '1'='1"))
        client.get("/products?q=shoes")

    low = client.get("/_waf/threshold/impact", params={"value": 0.05}).json()
    high = client.get("/_waf/threshold/impact", params={"value": 0.95}).json()
    assert low["blocked_at_this_threshold"] >= high["blocked_at_this_threshold"]


def test_feedback_round_trips_to_disk(client, waf):
    client.get("/item?id=" + quote("1' UNION SELECT password FROM users--"))
    decision_id = _flagged(client)[0]["id"]

    r = client.post(f"/_waf/decisions/{decision_id}/feedback",
                    json={"label": "false_positive"})
    assert r.status_code == 200
    assert client.get(f"/_waf/decisions/{decision_id}").json()["feedback"] == "false_positive"

    path = waf.db_path.parent / "feedback.jsonl"
    entries = [json.loads(line) for line in path.read_text().splitlines() if line]
    assert any(e["decision_id"] == decision_id for e in entries)


# --- 6. behaviour under stress ----------------------------------------------
def test_concurrent_traffic_is_handled_correctly(waf):
    """Mixed attack and benign traffic in parallel. Every verdict must be right."""
    attacks = [f"/item?id={quote(p)}" for p in CAUGHT_SQLI] * 8
    benign = [f"/api/items?id={i}&q=sample{i}" for i in range(40)]

    def fetch(path: str) -> tuple[str, int]:
        with httpx.Client(base_url=waf.url, timeout=30.0) as c:
            return path, c.get(path).status_code

    with concurrent.futures.ThreadPoolExecutor(max_workers=16) as pool:
        results = list(pool.map(fetch, attacks + benign))

    for path, status in results:
        expected = 403 if "/item?id=" in path else 200
        assert status == expected, f"{path} returned {status}"


def test_throughput_and_latency_are_sane(waf):
    paths = [f"/api/load?id={i}&q=value{i}" for i in range(150)]

    def fetch(path):
        with httpx.Client(base_url=waf.url, timeout=30.0) as c:
            return c.get(path).status_code

    started = time.perf_counter()
    with concurrent.futures.ThreadPoolExecutor(max_workers=12) as pool:
        codes = list(pool.map(fetch, paths))
    elapsed = time.perf_counter() - started

    assert all(c == 200 for c in codes)
    with httpx.Client(base_url=waf.url, timeout=20.0) as c:
        summary = c.get("/_waf/status").json()["summary"]

    print(f"\n  {len(paths)} requests in {elapsed:.2f}s "
          f"({len(paths) / elapsed:.0f} rps), "
          f"scoring avg {summary['avg_latency_ms']:.2f}ms "
          f"max {summary['max_latency_ms']:.2f}ms")
    assert summary["avg_latency_ms"] < 100


def test_repeat_requests_hit_the_cache(waf):
    path = "/api/cacheable?id=constant"
    with httpx.Client(base_url=waf.url, timeout=20.0) as c:
        before = c.get("/_waf/status").json()["engine"]["cached"]
        for _ in range(10):
            c.get(path)
        after = c.get("/_waf/status").json()["engine"]["cached"]
    assert after > before


def test_oversized_bodies_are_forwarded_unscored(origin, waf, tmp_path_factory):
    from .conftest import Waf

    db = tmp_path_factory.mktemp("waf-big") / "waf.db"
    small = Waf(origin.url, db, WAF_MAX_BODY_BYTES=128).start()
    try:
        origin.clear()
        with httpx.Client(base_url=small.url, timeout=20.0) as c:
            r = c.post("/upload", content="x" * 4096)
            assert r.status_code == 200
            row = c.get("/_waf/decisions").json()["decisions"][0]
        assert row["reason"] == "body_too_large"
        assert row["degraded"] is True
        assert len(origin.received) == 1
    finally:
        small.stop()


# --- 7. failure and recovery -------------------------------------------------
def test_dead_origin_becomes_502_not_a_crash(origin, tmp_path_factory):
    from .conftest import Waf, free_port

    db = tmp_path_factory.mktemp("waf-dead") / "waf.db"
    dead = Waf(f"http://127.0.0.1:{free_port()}", db).start()
    try:
        with httpx.Client(base_url=dead.url, timeout=20.0) as c:
            assert c.get("/anything").status_code == 502
            # The firewall itself is still healthy and still refuses attacks.
            assert c.get("/_waf/healthz").status_code == 200
            assert c.get("/item?id=" + quote("1' OR '1'='1")).status_code == 403
    finally:
        dead.stop()


def test_decisions_survive_a_restart(origin, tmp_path_factory):
    """SQLite is on disk for a reason."""
    from .conftest import Waf

    db = tmp_path_factory.mktemp("waf-restart") / "waf.db"

    first = Waf(origin.url, db).start()
    try:
        with httpx.Client(base_url=first.url, timeout=20.0) as c:
            c.get("/item?id=" + quote("1' UNION SELECT password FROM users--"))
            before = c.get("/_waf/decisions").json()["decisions"]
        assert before
    finally:
        first.stop()

    second = Waf(origin.url, db).start()
    try:
        with httpx.Client(base_url=second.url, timeout=20.0) as c:
            after = c.get("/_waf/decisions").json()["decisions"]
        assert len(after) >= len(before)
        assert after[0]["explanation"]["decode_trace"]
    finally:
        second.stop()


def test_graceful_shutdown_is_clean(origin, tmp_path_factory):
    from .conftest import Waf

    db = tmp_path_factory.mktemp("waf-shutdown") / "waf.db"
    w = Waf(origin.url, db).start()
    with httpx.Client(base_url=w.url, timeout=20.0) as c:
        c.get("/api/thing")

    w.proc.terminate()
    w.proc.wait(timeout=25)
    output = w.proc.stdout.read()
    w.proc = None

    assert w.proc is None
    assert "waf stopped" in output
    assert "Traceback" not in output


def test_logs_are_structured_json(origin, tmp_path_factory):
    from .conftest import Waf

    db = tmp_path_factory.mktemp("waf-logs") / "waf.db"
    w = Waf(origin.url, db).start()
    with httpx.Client(base_url=w.url, timeout=20.0) as c:
        c.get("/item?id=" + quote("1' UNION SELECT password FROM users--"))
    time.sleep(0.5)
    w.proc.terminate()
    w.proc.wait(timeout=25)
    output = w.proc.stdout.read()
    w.proc = None

    lines = [line for line in output.splitlines() if line.startswith("{")]
    assert lines, "no JSON log lines"
    for line in lines:
        json.loads(line)          # every one must parse

    events = [json.loads(line) for line in lines]
    assert any(e.get("message") == "blocked" for e in events)
    assert any(e.get("message") == "waf ready" for e in events)
