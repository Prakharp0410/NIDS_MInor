import pytest
from fastapi.testclient import TestClient

from dashboard import api
from dashboard.database import Database


@pytest.fixture
def db(tmp_path, monkeypatch):
    database = Database(tmp_path / "api.db")
    monkeypatch.setattr(api, "db", database)
    return database


@pytest.fixture
def client():
    return TestClient(api.app)


def kernel(monkeypatch, state):
    monkeypatch.setattr(api, "_read_firewall_state", lambda: state)


def test_blocked_threats_are_verified_against_the_kernel(db, client, monkeypatch):
    db.upsert_block("192.168.77.23", "PortScan", "RULE", 0.8, "192.168.77.40", latency_ms=4.2)
    db.upsert_block("192.168.77.24", "DoS", "ML", 0.95, "192.168.77.40")
    kernel(monkeypatch, {"192.168.77.23": {"packets": 1500, "bytes": 90000}})

    body = client.get("/blocked_threats").json()

    assert body["firewall_visible"] is True
    assert body["count"] == 2
    assert body["total_dropped_packets"] == 1500
    by_ip = {b["ip"]: b for b in body["blocked"]}
    assert by_ip["192.168.77.23"]["enforced"] is True
    assert by_ip["192.168.77.23"]["dropped_packets"] == 1500
    assert by_ip["192.168.77.23"]["block_latency_ms"] == pytest.approx(4.2)
    assert by_ip["192.168.77.24"]["enforced"] is False  # rule missing from the kernel


def test_blocked_threats_without_firewall_access(db, client, monkeypatch):
    db.upsert_block("192.168.77.23", "PortScan", "RULE", 0.8)
    kernel(monkeypatch, None)

    body = client.get("/blocked_threats").json()

    assert body["firewall_visible"] is False
    assert body["total_dropped_packets"] is None
    assert body["blocked"][0]["enforced"] is None
    assert body["blocked"][0]["dropped_packets"] is None


def test_lifted_blocks_only_appear_in_history(db, client, monkeypatch):
    db.upsert_block("192.168.77.23", "PortScan", "RULE", 0.8)
    db.reconcile_blocks([])
    kernel(monkeypatch, {})

    assert client.get("/blocked_threats").json()["blocked"] == []
    history = client.get("/blocked_threats?include_history=true").json()
    assert history["count"] == 0
    assert history["blocked"][0]["active"] is False
    assert history["blocked"][0]["enforced"] is False


def test_alerts_endpoint_exposes_prevention_status(db, client):
    db.insert_alert({"timestamp": "2026-10-07 10:00:00", "src_ip": "192.168.77.23",
                     "dst_ip": "192.168.77.40", "src_port": 4000, "dst_port": 22,
                     "attack_type": "SSH-BruteForce", "attack_class": 11,
                     "confidence": 0.85, "protocol": "TCP",
                     "status": "BLOCKED", "detector": "RULE"})
    alert = client.get("/alerts").json()["alerts"][0]
    assert (alert["status"], alert["detector"]) == ("BLOCKED", "RULE")


def test_dashboard_page_has_the_firewall_panel(db, client):
    page = client.get("/dashboard")
    assert page.status_code == 200
    assert "Active Firewall Blocks" in page.text
    assert 'id="blocked-tbody"' in page.text
