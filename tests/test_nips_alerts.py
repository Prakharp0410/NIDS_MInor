import sqlite3

from dashboard.database import Database
from raspberry_pi.alert_system import AlertSystem, DETECTOR_ML, DETECTOR_RULE
from nips_fakes import CHAIN, GATEWAY, FakeIptables, make_firewall

ATTACKER = "192.168.77.23"
VICTIM = "192.168.77.40"


def make_system(tmp_path, fake=None, **overrides):
    firewall, fake = make_firewall(fake)
    params = dict(log_file=tmp_path / "alerts.log", min_confidence=0.05,
                  db_path=tmp_path / "alerts.db", firewall=firewall,
                  rule_block_min_confidence=0.60, ml_block_min_confidence=0.90)
    params.update(overrides)
    return AlertSystem(**params), fake


def rule_alert(system, src=ATTACKER, confidence=0.85, attack="SSH-BruteForce"):
    return system.generate_alert(src, VICTIM, 51515, 22, 11, confidence, "TCP",
                                 attack_type=attack, detector=DETECTOR_RULE)


def ml_alert(system, confidence, src=ATTACKER):
    return system.generate_alert(src, VICTIM, 40000, 80, 10, confidence, "TCP",
                                 detector=DETECTOR_ML)


def test_rule_alert_blocks_attacker_and_is_recorded(tmp_path):
    system, fake = make_system(tmp_path)

    alert = system.log_alert(rule_alert(system))

    assert alert.status == "BLOCKED"
    assert system.is_blocked(ATTACKER)
    assert len(fake.drop_inserts()) == 1

    stored = system.db.get_recent_alerts(5)[0]
    assert (stored["status"], stored["detector"], stored["attack_type"]) == \
        ("BLOCKED", "RULE", "SSH-BruteForce")

    block = system.db.get_blocked_threats()[0]
    assert block["ip"] == ATTACKER and block["target_ip"] == VICTIM
    assert block["active"] is True and block["alert_count"] == 1
    assert block["block_latency_ms"] is not None

    assert "Action: BLOCKED" in (tmp_path / "alerts.log").read_text(encoding="utf-8")


def test_low_confidence_ml_alert_is_logged_but_not_blocked(tmp_path):
    system, fake = make_system(tmp_path)
    alert = system.log_alert(ml_alert(system, confidence=0.50))
    assert alert.status == "DETECTED"
    assert fake.drop_inserts() == []
    assert system.db.get_blocked_threats() == []


def test_high_confidence_ml_alert_blocks(tmp_path):
    system, _ = make_system(tmp_path)
    assert system.log_alert(ml_alert(system, confidence=0.95)).status == "BLOCKED"


def test_whitelisted_source_is_flagged_not_blocked(tmp_path):
    system, fake = make_system(tmp_path)
    assert system.log_alert(rule_alert(system, src=GATEWAY)).status == "WHITELISTED"
    assert fake.drop_inserts() == []


def test_repeat_alert_reuses_the_rule_and_counts(tmp_path):
    system, fake = make_system(tmp_path)
    system.log_alert(rule_alert(system))
    second = system.log_alert(rule_alert(system, attack="PortScan"))
    assert second.status == "BLOCKED"
    assert len(fake.drop_inserts()) == 1
    block = system.db.get_blocked_threats()[0]
    assert block["alert_count"] == 2
    assert block["attack_type"] == "SSH-BruteForce"  # first reason is kept


def test_iptables_failure_is_reported(tmp_path):
    system, _ = make_system(tmp_path, FakeIptables(fail_inserts=2))
    assert system.log_alert(rule_alert(system)).status == "BLOCK_FAILED"
    assert system.db.get_blocked_threats() == []


def test_prevention_disabled_behaves_like_the_original_nids(tmp_path):
    system = AlertSystem(log_file=tmp_path / "alerts.log", min_confidence=0.05,
                         db_path=tmp_path / "alerts.db", enable_prevention=False)
    assert system.firewall is None
    assert system.log_alert(rule_alert(system)).status == "DETECTED"
    assert not system.is_blocked(ATTACKER)
    assert system.get_alert_statistics()["blocked_ips"] == 0


def test_icmp_alert_without_ports_is_stored(tmp_path):
    system, _ = make_system(tmp_path)
    alert = system.generate_alert(ATTACKER, VICTIM, None, None, 2, 0.9, "ICMP",
                                  attack_type="ICMP-Flood", detector=DETECTOR_RULE)
    system.log_alert(alert)
    stored = system.db.get_recent_alerts(1)[0]
    assert (stored["src_port"], stored["dst_port"]) == (0, 0)


def test_restart_reconciles_dashboard_with_kernel(tmp_path):
    db = Database(tmp_path / "alerts.db")
    db.upsert_block(ATTACKER, "DoS", "RULE", 0.9, VICTIM)          # rule since flushed
    fake = FakeIptables(rules=[f"-A {CHAIN} -s 192.168.77.99/32 -j DROP"])  # added by hand

    system, _ = make_system(tmp_path, fake)

    active = {b["ip"]: b for b in system.db.get_blocked_threats()}
    assert set(active) == {"192.168.77.99"}
    assert active["192.168.77.99"]["attack_type"] == "Restored"
    lifted = {b["ip"]: b for b in system.db.get_blocked_threats(active_only=False)}
    assert lifted[ATTACKER]["active"] is False
    assert lifted[ATTACKER]["unblocked_at"] is not None


def test_block_after_reset_starts_a_fresh_record(tmp_path):
    db = Database(tmp_path / "alerts.db")
    db.upsert_block(ATTACKER, "DoS", "RULE", 0.9, VICTIM, timestamp="2026-01-01 10:00:00")
    db.upsert_block(ATTACKER, "DoS", "RULE", 0.9, VICTIM, timestamp="2026-01-01 10:00:05")
    db.reconcile_blocks([])
    db.upsert_block(ATTACKER, "PortScan", "ML", 0.95, VICTIM, timestamp="2026-01-01 11:00:00")
    block = db.get_blocked_threats()[0]
    assert (block["attack_type"], block["alert_count"], block["blocked_at"]) == \
        ("PortScan", 1, "2026-01-01 11:00:00")


def test_original_nids_database_is_upgraded_in_place(tmp_path):
    path = tmp_path / "old.db"
    conn = sqlite3.connect(path)
    conn.execute("""
        CREATE TABLE alerts (
            id INTEGER PRIMARY KEY AUTOINCREMENT, timestamp TEXT NOT NULL,
            src_ip TEXT NOT NULL, dst_ip TEXT NOT NULL, src_port INTEGER NOT NULL,
            dst_port INTEGER NOT NULL, attack_type TEXT NOT NULL, attack_class INTEGER,
            confidence REAL NOT NULL, protocol TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP)
    """)
    conn.execute("INSERT INTO alerts (timestamp, src_ip, dst_ip, src_port, dst_port, "
                 "attack_type, attack_class, confidence, protocol) VALUES "
                 "('2026-01-01 09:00:00', '10.0.0.5', '10.0.0.9', 1, 2, 'PortScan', 10, 0.8, 'TCP')")
    conn.commit()
    conn.close()

    db = Database(path)
    Database(path)  # opening twice must be harmless

    old = db.get_recent_alerts(5)[0]
    assert (old["status"], old["detector"]) == ("DETECTED", "UNKNOWN")
    assert db.insert_alert({"timestamp": "2026-01-01 09:01:00", "src_ip": "10.0.0.5",
                            "dst_ip": "10.0.0.9", "src_port": 1, "dst_port": 2,
                            "attack_type": "DoS", "confidence": 0.9,
                            "status": "BLOCKED", "detector": "RULE"}) > 0
    assert db.get_blocked_threats() == []
