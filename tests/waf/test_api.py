"""The control plane the console depends on."""

import json

import pytest
from fastapi.testclient import TestClient

from mlwaf.waf.app import create_app
from mlwaf.waf.config import Settings

from .conftest import AUTH, TEST_TOKEN


@pytest.fixture
def client(bundle, tmp_path):
    settings = Settings(
        upstream="http://127.0.0.1:1",
        db_path=str(tmp_path / "waf.db"),
        feedback_path=str(tmp_path / "feedback.jsonl"),
        mode="block",
        scoring_budget_ms=60_000.0,
        admin_token=TEST_TOKEN,
    )
    with TestClient(create_app(settings, bundle=dict(bundle))) as c:
        yield c


def _attack(client):
    client.get("/item", params={"id": "1' UNION SELECT password FROM users--"})


def test_healthz_is_liveness_only(client):
    assert client.get("/_waf/healthz").json() == {"status": "ok"}


def test_readyz_reports_the_threshold(client):
    body = client.get("/_waf/readyz").json()
    assert body["status"] == "ready"
    assert 0 < body["threshold"] <= 1


def test_metrics_are_prometheus_text(client):
    _attack(client)
    text = client.get("/_waf/metrics", headers=AUTH).text
    assert "mlwaf_requests_total" in text
    assert "mlwaf_scoring_seconds" in text


def test_status_describes_the_deployment(client):
    body = client.get("/_waf/status", headers=AUTH).json()
    assert body["mode"] == "block"
    assert body["fail_mode"] == "open"
    assert "summary" in body and "engine" in body


def test_decisions_can_be_filtered(client):
    _attack(client)
    client.get("/products", params={"q": "shoes"})

    blocked = client.get("/_waf/decisions", params={"verdict": "block"}, headers=AUTH).json()["decisions"]
    assert blocked and all(d["verdict"] == "block" for d in blocked)

    flagged = client.get("/_waf/decisions", params={"only_flagged": True}, headers=AUTH).json()["decisions"]
    assert flagged and all(d["would_block"] for d in flagged)

    found = client.get("/_waf/decisions", params={"search": "products"}, headers=AUTH).json()["decisions"]
    assert found and all("products" in d["path"] for d in found)


def test_unknown_decision_is_404(client):
    assert client.get("/_waf/decisions/999999", headers=AUTH).status_code == 404


def test_threshold_impact_is_computed_from_stored_scores(client):
    _attack(client)
    low = client.get("/_waf/threshold/impact", params={"value": 0.01}, headers=AUTH).json()
    high = client.get("/_waf/threshold/impact", params={"value": 0.99}, headers=AUTH).json()
    # A lower threshold can only ever block at least as much as a higher one.
    assert low["blocked_at_this_threshold"] >= high["blocked_at_this_threshold"]


def test_threshold_can_be_changed_at_runtime(client):
    assert client.post("/_waf/threshold", json={"value": 0.5}, headers=AUTH).json()["threshold"] == 0.5
    assert client.get("/_waf/status", headers=AUTH).json()["threshold"] == 0.5


def test_threshold_is_validated(client):
    assert client.post("/_waf/threshold", json={"value": 1.5}, headers=AUTH).status_code == 422


def test_mode_can_be_promoted_and_demoted(client):
    assert client.post("/_waf/mode", json={"mode": "detect"}, headers=AUTH).json()["blocking"] is False
    assert client.post("/_waf/mode", json={"mode": "block"}, headers=AUTH).json()["blocking"] is True
    assert client.post("/_waf/mode", json={"mode": "sideways"}, headers=AUTH).status_code == 422


def test_feedback_is_stored_and_appended_for_training(client, tmp_path):
    _attack(client)
    decision_id = client.get("/_waf/decisions", headers=AUTH).json()["decisions"][0]["id"]

    r = client.post(f"/_waf/decisions/{decision_id}/feedback",
                    json={"label": "false_positive"}, headers=AUTH)
    assert r.status_code == 200
    assert client.get(f"/_waf/decisions/{decision_id}", headers=AUTH).json()["feedback"] == "false_positive"

    lines = (tmp_path / "feedback.jsonl").read_text().strip().splitlines()
    record = json.loads(lines[0])
    assert record["label"] == "false_positive"
    assert record["canonical"]


def test_feedback_label_is_validated(client):
    _attack(client)
    decision_id = client.get("/_waf/decisions", headers=AUTH).json()["decisions"][0]["id"]
    assert client.post(f"/_waf/decisions/{decision_id}/feedback",
                       json={"label": "maybe"}, headers=AUTH).status_code == 422


def test_traffic_series_has_one_entry_per_bucket(client):
    series = client.get("/_waf/traffic", params={"buckets": 20}, headers=AUTH).json()["series"]
    assert len(series) == 20


def test_console_is_served(client):
    assert client.get("/_waf/", headers=AUTH).status_code == 200
    assert "mlwaf" in client.get("/_waf/", headers=AUTH).text
    assert client.get("/_waf/static/app.js", headers=AUTH).status_code == 200


def test_control_plane_is_not_proxied_upstream(client):
    """The upstream here is a dead port, so a 200 proves the route never left."""
    assert client.get("/_waf/healthz").status_code == 200
