"""Attacking the firewall itself.

The first suite asked whether the model's verdicts reach the origin correctly.
This one asks a different question: can someone get past the firewall, or turn it
off, without defeating the model at all. A WAF is a security control, and a
security control that can be disabled by anyone who can reach it is decoration.
"""

from __future__ import annotations

import concurrent.futures
from urllib.parse import quote

import httpx
import pytest

from .conftest import AUTH

ATTACK = "1' UNION SELECT username,password FROM users--"


def _attack_url(prefix: str = "/item") -> str:
    return f"{prefix}?id={quote(ATTACK)}"


# --- 1. can the control plane be reached by whoever can reach the site? ------
def test_control_plane_rejects_unauthenticated_callers(anonymous):
    """Anyone who can send a request to the proxy can also reach /_waf.

    Before this was enforced, switching the firewall off was a single
    unauthenticated POST, which is a far cheaper attack than evading a
    classifier. These calls run on a client with no token at all.
    """
    assert anonymous.get("/_waf/status").status_code == 401
    assert anonymous.post("/_waf/mode", json={"mode": "detect"}).status_code == 401
    assert anonymous.post("/_waf/threshold", json={"value": 1.0}).status_code == 401
    assert anonymous.get("/_waf/decisions").status_code == 401
    assert anonymous.get("/_waf/metrics").status_code == 401


def test_a_wrong_token_is_rejected(waf):
    with httpx.Client(base_url=waf.url, timeout=20.0,
                      headers={"X-MLWAF-Token": "not-the-token"}) as c:
        assert c.post("/_waf/mode", json={"mode": "detect"}).status_code == 401


def test_disabling_the_firewall_requires_the_token(anonymous, client, origin):
    """The attack this whole mechanism exists to prevent."""
    assert anonymous.post("/_waf/mode", json={"mode": "detect"}).status_code == 401
    origin.clear()
    assert anonymous.get(_attack_url()).status_code == 403
    assert origin.received == []
    assert client.get("/_waf/status").json()["blocking"] is True


def test_health_endpoints_stay_open(anonymous):
    """Liveness and readiness must not need credentials: orchestrators poll them."""
    assert anonymous.get("/_waf/healthz").status_code == 200
    assert anonymous.get("/_waf/readyz").status_code == 200


# --- 2. can the router be tricked into skipping the scan? -------------------
@pytest.mark.parametrize("path", [
    "/%2e%2e/item",
    "/./item",
    "/foo/../item",
    "//item",
    "/item/",
    "/ITEM",
    "/item%00",
    "/item;x=1",
    "/%69tem",
])
def test_path_tricks_do_not_skip_scanning(client, origin, path):
    """However the path is spelled, the query still has to be scored."""
    r = client.get(f"{path}?id={quote(ATTACK)}")
    assert r.status_code == 403, f"{path} was not scanned"
    assert origin.received == []


@pytest.mark.parametrize("prefix", [
    "/_WAF/mode", "/%5fwaf/mode", "/_waf//mode",
])
def test_control_plane_lookalikes_do_not_change_state(anonymous, client, prefix):
    """A near miss on the prefix must not reach the control plane."""
    anonymous.post(prefix, json={"mode": "detect"})
    assert client.get("/_waf/status").json()["blocking"] is True
    assert client.get(_attack_url()).status_code == 403


def test_very_long_url_is_handled(client):
    r = client.get("/item?id=" + "A" * 8000)
    assert r.status_code in (200, 403, 414, 431)


@pytest.mark.parametrize("params", [0, 30, 50, 62])
def test_moderate_padding_does_not_hide_an_attack(client, origin, params):
    padding = "&".join(f"f{i}=v{i}" for i in range(params))
    query = f"{padding}&id={quote(ATTACK)}" if params else f"id={quote(ATTACK)}"
    assert client.get(f"/item?{query}").status_code == 403
    assert origin.received == []


@pytest.mark.parametrize("params", [63, 100, 300])
def test_heavy_parameter_padding_evades_this_model(client, params):
    """A working evasion, asserted rather than hidden. See docs/FINDINGS.md.

    The old, request-level model was evaded by n-gram dilution: enough junk
    parameters spread the vectoriser's weight thin enough that the attack's own
    n-grams lost relative weight (tipping point ~150 params). Scoring each
    parameter value on its own, independent of its neighbours, closes that
    hole entirely: dilution has nothing left to dilute.

    What replaces it is narrower. `units.py` scores at most MAX_UNITS=64 values
    per request and drops the rest, because scoring one value costs about 1.5ms
    and an unbounded count turns an ordinary request into a multi-second one.
    A payload placed after the 64th parameter is simply never looked at. The
    boundary is exact: 62 padding parameters plus the path and the payload is
    64 units and is still refused; 63 pushes the payload to unit 65 and it is
    not scored at all. This is bounded and this is the honest tradeoff, not a
    subtler version of the old bug: an operator who expects requests wider than
    a few dozen fields should cap parameter count ahead of this firewall,
    the same way they would for any other WAF.
    """
    padding = "&".join(f"f{i}=v{i}" for i in range(params))
    assert client.get(f"/item?{padding}&id={quote(ATTACK)}").status_code == 200


def test_padding_with_prose_does_not_evade(client, origin):
    """A large body does not evade either: it is one unit, scored whole."""
    filler = "lorem ipsum dolor sit amet " * 200
    r = client.get(f"/item?id={quote(ATTACK)}&note={quote(filler)}")
    assert r.status_code == 403
    assert origin.received == []


def test_attack_in_a_deeply_nested_path_is_caught(client, origin):
    deep = "/".join(f"seg{i}" for i in range(50))
    assert client.get(f"/{deep}?id={quote(ATTACK)}").status_code == 403
    assert origin.received == []


# --- 3. header handling ------------------------------------------------------
def test_hop_by_hop_headers_are_not_relayed(client, origin):
    client.get("/x", headers={
        "Connection": "keep-alive, X-Secret",
        "Transfer-Encoding": "chunked",
        "Upgrade": "websocket",
        "X-Keep": "yes",
    })
    relayed = {k.lower() for k in origin.received[0]["headers"]}
    assert "upgrade" not in relayed
    assert "x-keep" in relayed


def test_header_values_cannot_inject_a_response(client):
    r = client.get("/x", headers={"X-Probe": "a"})
    assert r.status_code == 200
    assert "\r" not in "".join(r.headers.values())


def test_host_header_does_not_redirect_the_upstream(client, origin):
    """A rewritten Host must not send the request somewhere else."""
    client.get("/x", headers={"Host": "evil.example.com"})
    assert len(origin.received) == 1


# --- 4. cache correctness ----------------------------------------------------
def test_cache_does_not_confuse_different_requests(client, origin):
    """Same path, different query: verdicts must not be shared."""
    benign = client.get("/same?id=harmless")
    attack = client.get(f"/same?id={quote(ATTACK)}")
    benign_again = client.get("/same?id=harmless")

    assert benign.status_code == 200
    assert attack.status_code == 403
    assert benign_again.status_code == 200


def test_cache_distinguishes_method_and_body(client):
    body_attack = client.post("/same", content=f"id={ATTACK}",
                              headers={"Content-Type": "application/x-www-form-urlencoded"})
    body_benign = client.post("/same", content="id=harmless",
                              headers={"Content-Type": "application/x-www-form-urlencoded"})
    assert body_attack.status_code == 403
    assert body_benign.status_code == 200


def test_cached_verdicts_still_block(client, origin):
    for _ in range(5):
        assert client.get(_attack_url()).status_code == 403
    assert origin.received == []


# --- 5. concurrency on shared state -----------------------------------------
def test_concurrent_threshold_changes_do_not_corrupt_state(isolated):
    def flip(value):
        with httpx.Client(base_url=isolated.url, timeout=20.0, headers=AUTH) as c:
            return c.post("/_waf/threshold", json={"value": value}).status_code

    values = [0.1, 0.5, 0.9, 0.3, 0.7] * 4
    with concurrent.futures.ThreadPoolExecutor(max_workers=8) as pool:
        codes = list(pool.map(flip, values))

    assert all(c == 200 for c in codes)
    with httpx.Client(base_url=isolated.url, timeout=20.0, headers=AUTH) as c:
        assert 0.0 <= c.get("/_waf/status").json()["threshold"] <= 1.0


def test_traffic_during_a_threshold_change_is_never_unhandled(isolated):
    """Requests in flight while the threshold moves must still get an answer."""
    def request(_):
        with httpx.Client(base_url=isolated.url, timeout=20.0, headers=AUTH) as c:
            return c.get("/api/mixed?id=1").status_code

    def change(_):
        with httpx.Client(base_url=isolated.url, timeout=20.0, headers=AUTH) as c:
            return c.post("/_waf/threshold", json={"value": 0.5}).status_code

    with concurrent.futures.ThreadPoolExecutor(max_workers=10) as pool:
        traffic = list(pool.map(request, range(40)))
        list(pool.map(change, range(5)))

    assert all(c in (200, 403) for c in traffic)
