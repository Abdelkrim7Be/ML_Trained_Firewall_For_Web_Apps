"""Sustained load, protocol edge cases, and what happens over time.

The other suites answer whether the firewall is correct. This one asks whether it
stays correct: under concurrency, after a lot of traffic, with several consoles
attached, and when a client does something unusual.
"""

from __future__ import annotations

import concurrent.futures
import json
import statistics
import time
from urllib.parse import quote

import httpx
import pytest

from .conftest import AUTH, Waf

ATTACK = "1' UNION SELECT username,password FROM users--"


# --- protocol ----------------------------------------------------------------
def test_head_and_options_are_proxied(client, origin):
    assert client.head("/api/thing").status_code == 200
    assert client.request("OPTIONS", "/api/thing").status_code == 200
    assert len(origin.received) == 2


def test_empty_body_post_is_fine(client, origin):
    assert client.post("/api/thing", content=b"").status_code == 200
    assert origin.received[0]["body"] == ""


def test_binary_body_does_not_crash_scoring(client, origin):
    payload = bytes(range(256)) * 4
    r = client.post("/upload", content=payload,
                    headers={"Content-Type": "application/octet-stream"})
    assert r.status_code in (200, 403)
    assert "Traceback" not in r.text


def test_invalid_utf8_body_is_handled(client):
    r = client.post("/upload", content=b"\xff\xfe\x00bad bytes",
                    headers={"Content-Type": "application/octet-stream"})
    assert r.status_code in (200, 403)


def test_unicode_in_a_path_is_handled(client, origin):
    r = client.get("/café/menü?q=crème")
    assert r.status_code == 200
    assert len(origin.received) == 1


def test_duplicate_query_parameters(client, origin):
    assert client.get("/api?a=1&a=2&a=3").status_code == 200


def test_attack_in_a_duplicated_parameter_is_caught(client, origin):
    r = client.get(f"/api?id=1&id={quote(ATTACK)}")
    assert r.status_code == 403
    assert origin.received == []


def test_many_headers_are_handled(client, origin):
    headers = {f"X-Custom-{i}": f"value-{i}" for i in range(60)}
    assert client.get("/api/thing", headers=headers).status_code == 200


def test_large_but_allowed_body_is_scored(client, origin):
    body = "field=" + ("a" * 200_000)
    r = client.post("/api/thing", content=body,
                    headers={"Content-Type": "application/x-www-form-urlencoded"})
    assert r.status_code == 200
    assert len(origin.received) == 1


def test_attack_hidden_in_a_large_body_is_caught(client, origin):
    body = "pad=" + ("a" * 100_000) + "&id=" + ATTACK
    r = client.post("/api/thing", content=body,
                    headers={"Content-Type": "application/x-www-form-urlencoded"})
    assert r.status_code == 403
    assert origin.received == []


# --- sustained load ----------------------------------------------------------
@pytest.mark.parametrize("workers", [4, 16])
def test_sustained_mixed_load_stays_correct(pooled, workers):
    """Every verdict must be right, at every level of concurrency.

    Correctness under load is the assertion. Throughput is measured separately,
    because on a shared machine it says as much about the machine as the server.
    """
    attacks = [f"/item?id={quote(ATTACK)}&n={i}" for i in range(60)]
    benign = [f"/api/items?id={i}&q=sample{i}" for i in range(180)]
    jobs = attacks + benign

    started = time.perf_counter()
    with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as pool:
        results = list(pool.map(lambda p: (p, pooled.get(p).status_code), jobs))
    elapsed = time.perf_counter() - started

    wrong = [(p, s) for p, s in results if s != (403 if "/item?id=" in p else 200)]
    assert not wrong, f"{len(wrong)} wrong verdicts, first: {wrong[:3]}"
    print(f"\n  {workers:>2} workers: {len(jobs)} requests in {elapsed:.1f}s "
          f"({len(jobs) / elapsed:.0f} rps)")


def test_latency_stays_within_the_budget_under_load(pooled):
    """The budget exists so a slow model degrades protection rather than uptime.

    If scoring routinely exceeded it under load, requests would be allowed
    through unscored and the firewall would quietly stop working.
    """
    paths = [f"/api/load?id={i}&token=value{i}" for i in range(240)]

    with concurrent.futures.ThreadPoolExecutor(max_workers=8) as pool:
        assert all(code == 200 for code in
                   pool.map(lambda p: pooled.get(p).status_code, paths))

    rows = pooled.get("/_waf/decisions", params={"limit": 240}).json()["decisions"]
    status = pooled.get("/_waf/status").json()

    latencies = sorted(r["latency_ms"] for r in rows)
    p50 = statistics.median(latencies)
    p99 = latencies[int(len(latencies) * 0.99)]
    print(f"\n  scoring p50 {p50:.2f}ms  p99 {p99:.2f}ms  max {latencies[-1]:.2f}ms")

    assert status["engine"]["timeouts"] == 0, "requests were allowed through unscored"
    assert status["engine"]["errors"] == 0


def test_repeated_traffic_is_served_from_cache(pooled):
    before = pooled.get("/_waf/status").json()["engine"]
    for _ in range(50):
        pooled.get("/api/hot?id=constant")
    after = pooled.get("/_waf/status").json()["engine"]

    assert after["cached"] - before["cached"] >= 45
    # Almost none of those should have reached the model a second time.
    assert after["scored"] - before["scored"] <= 5


# --- several consoles --------------------------------------------------------
def test_multiple_consoles_all_receive_events(waf):
    """A second console must not starve the first, or the request path."""
    def listen(_):
        got = []
        with (
            httpx.Client(base_url=waf.url, timeout=30.0, headers=AUTH) as c,
            c.stream("GET", "/_waf/stream") as stream,
        ):
            lines = stream.iter_lines()
            next(lines)
            deadline = time.time() + 20
            for line in lines:
                if line.startswith("data: "):
                    got.append(json.loads(line[6:]))
                    break
                if time.time() > deadline:
                    break
        return got

    with concurrent.futures.ThreadPoolExecutor(max_workers=4) as pool:
        listeners = [pool.submit(listen, i) for i in range(3)]
        time.sleep(2.0)
        with httpx.Client(base_url=waf.url, timeout=30.0, headers=AUTH) as c:
            for i in range(3):
                c.get(f"/item?id={quote(ATTACK)}&n={i}")
        results = [f.result() for f in listeners]

    assert all(r for r in results), "a console received nothing"


def test_a_stalled_console_does_not_block_traffic(waf):
    """Open a stream and never read it. Requests must keep flowing."""
    with (
        httpx.Client(base_url=waf.url, timeout=30.0, headers=AUTH) as c,
        c.stream("GET", "/_waf/stream") as _stalled,
    ):
        with httpx.Client(base_url=waf.url, timeout=60.0, headers=AUTH) as probe:
            started = time.perf_counter()
            for i in range(40):
                assert probe.get(f"/api/flow?id={i}").status_code == 200
            elapsed = time.perf_counter() - started

    assert elapsed < 45, "traffic stalled while a console was not reading"


# --- over time ---------------------------------------------------------------
def test_the_decision_log_is_trimmed(origin, tmp_path_factory):
    """Retention has to actually bound the table, or the disk fills."""
    db = tmp_path_factory.mktemp("waf-retain") / "waf.db"
    w = Waf(origin.url, db, WAF_RETENTION_ROWS=200).start()
    try:
        limits = httpx.Limits(max_connections=16, max_keepalive_connections=16)
        with httpx.Client(base_url=w.url, timeout=120.0, headers=AUTH, limits=limits) as c:
            for i in range(1300):
                c.get(f"/api/churn?id={i}")
            rows = c.get("/_waf/decisions", params={"limit": 500}).json()["decisions"]
    finally:
        w.stop()

    assert len(rows) <= 400, f"retention did not bound the log: {len(rows)} rows"
    assert db.stat().st_size < 40_000_000


def test_memory_does_not_run_away(waf, pooled):
    """A crude guard. The cache is bounded, so RSS should settle."""
    import os

    import psutil  # noqa: PLC0415

    proc = psutil.Process(waf.proc.pid) if waf.proc else None
    if proc is None or not hasattr(os, "getpid"):
        pytest.skip("cannot inspect the process")

    for i in range(150):
        pooled.get(f"/api/warm?id={i}")
    baseline = proc.memory_info().rss
    for i in range(1200):
        pooled.get(f"/api/mem?id={i}&q=value{i}")
    after = proc.memory_info().rss

    growth = (after - baseline) / baseline
    print(f"\n  rss {baseline / 1e6:.0f}MB -> {after / 1e6:.0f}MB ({growth:+.1%})")
    assert growth < 1.0, "memory more than doubled over 1200 requests"
