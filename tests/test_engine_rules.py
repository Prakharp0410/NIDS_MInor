"""Engine behaviour: who gets blamed, what is a real attack, and what is not."""

import ipaddress
import sys
import time
from pathlib import Path

import numpy as np

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "raspberry_pi"))

import main as engine  # noqa: E402  (raspberry_pi/main.py)
from capture import HairpinFilter  # noqa: E402
from feature_extractor import FeatureExtractor  # noqa: E402
from flow_manager import FlowManager, NetworkFlow  # noqa: E402

ATTACKER = "192.168.77.23"
VICTIM = "192.168.77.40"
PHONE = "192.168.77.50"
LAN = ipaddress.ip_network("192.168.77.0/24")


class FakeAlertSystem:
    def __init__(self, blocked=()):
        self.blocked = set(blocked)
        self.logged = []

    def is_blocked(self, ip):
        return ip in self.blocked

    def generate_alert(self, **kwargs):
        return type("Alert", (), dict(kwargs, status="BLOCKED"))()

    def log_alert(self, alert):
        self.logged.append(alert)
        return alert

    def get_alert_statistics(self):
        return {"total_alerts": len(self.logged), "alert_types": {}, "blocked_ips": len(self.blocked)}


class FakeInference:
    """Stands in for the Random Forest: flows to port 666 are attacks."""
    is_ready = True

    def __init__(self):
        self.batches = []

    def predict_batch(self, X):
        self.batches.append(len(X))
        return [(1, "DoS Hulk", 0.95) if row[0] == 666 else (0, "Benign", 0.99) for row in X]

    def is_malicious_class(self, index):
        return index != 0

    def get_attack_family(self, index):
        return "DoS"


class PortFeatures:
    def extract_features(self, flow):
        return np.array([flow.dst_port], dtype=float)


def bare_runtime(blocked=()):
    """A runtime with real detection state and stubbed I/O, model and database."""
    rt = engine.NIIDSRuntime.__new__(engine.NIIDSRuntime)
    rt._init_state()
    rt.threshold = 0.6
    rt.lan_network = LAN
    rt.flow_manager = FlowManager(timeout_seconds=120, max_flows=10000)
    rt.feature_extractor = PortFeatures()
    rt.inference_engine = FakeInference()
    rt.alert_system = FakeAlertSystem(blocked)
    rt.hairpin_filter = HairpinFilter(None, None, None)
    rt.raised = []

    def record(attack, src, dst, sport, dport, proto, conf):
        rt.alerted_ips[src] = time.monotonic()
        rt.raised.append((attack, src, dst))

    rt._raise_alert = record
    return rt


def feed(rt, monkeypatch, packets):
    """Push packet_info dicts through process_packet."""
    queue = iter(packets)
    monkeypatch.setattr(engine, "extract_packet_info", lambda pkt: next(queue))
    for _ in packets:
        rt.process_packet(None)


def pkt(src, dst, sport, dport, proto="TCP", flags="S", payload=0, ts=None, icmp_type=None):
    return {"src_ip": src, "dst_ip": dst, "src_port": sport, "dst_port": dport,
            "protocol": proto, "flags": flags, "payload_len": payload, "length": payload + 54,
            "header_len": 20, "ts": ts if ts is not None else time.time(), "icmp_type": icmp_type}


def flow_with(fwd, bwd, seconds, fwd_payload=0, bwd_payload=0, proto="TCP"):
    """A flow with fwd/bwd packets evenly interleaved over `seconds`."""
    flow = NetworkFlow(ATTACKER, VICTIM, 40000, 80, proto, ts=1000.0)
    order = sorted([(i / fwd, "fwd") for i in range(fwd)] +
                   [((j + 0.5) / bwd, "bwd") for j in range(bwd)])
    for position, direction in order:
        flow.add_packet({"ts": 1000.0 + seconds * position,
                         "payload_len": fwd_payload if direction == "fwd" else bwd_payload},
                        direction=direction)
    return flow


# ── Who gets blamed ──────────────────────────────────────────────
def test_flood_is_blamed_on_the_initiator_even_when_a_reply_crosses_the_threshold():
    rt = bare_runtime()
    flow = flow_with(fwd=400, bwd=10, seconds=0.2)
    rt._detect_flood(flow, "TCP")  # called while processing the victim's reply
    assert rt.raised == [("DDoS", ATTACKER, VICTIM)]


def test_icmp_flood_ignores_the_victims_echo_replies():
    rt = bare_runtime()
    flow = NetworkFlow(ATTACKER, VICTIM, 0, 0, "ICMP")
    for _ in range(500):
        rt._detect_icmp_flood(flow, VICTIM, ATTACKER, "ICMP", icmp_type=0)
    assert rt.raised == []
    for _ in range(201):
        rt._detect_icmp_flood(flow, ATTACKER, VICTIM, "ICMP", icmp_type=8)
    assert rt.raised == [("ICMP-Flood", ATTACKER, VICTIM)]


def test_icmp_counter_is_a_sliding_window():
    rt = bare_runtime()
    flow = NetworkFlow(ATTACKER, VICTIM, 0, 0, "ICMP")
    stale = time.monotonic() - 30
    for _ in range(250):
        rt.icmp_times[ATTACKER].events.append((stale, None))  # slow pings long ago
    rt.icmp_times[ATTACKER].distinct[None] = 250
    rt._detect_icmp_flood(flow, ATTACKER, VICTIM, "ICMP", icmp_type=8)
    assert rt.raised == []
    assert len(rt.icmp_times[ATTACKER]) == 1


def test_traffic_from_or_to_blocked_hosts_skips_detection(monkeypatch):
    rt = bare_runtime(blocked={ATTACKER})
    feed(rt, monkeypatch, [pkt(ATTACKER, VICTIM, 1, 80),        # attacker's packet
                           pkt(VICTIM, ATTACKER, 80, 1, flags="RA")])  # victim's reply
    assert rt.blocked_packets_skipped == 2
    assert rt.flow_manager.get_flow_count() == 0


def test_victim_answering_a_blocked_scanner_is_never_flagged(monkeypatch):
    rt = bare_runtime(blocked={ATTACKER})
    # The scanner keeps probing after the block; the victim sends RSTs back.
    feed(rt, monkeypatch, [pkt(VICTIM, ATTACKER, port, 40000 + port, flags="RA")
                           for port in range(1, 200)])
    assert rt.raised == []


# ── Real attacks are detected ────────────────────────────────────
def test_vertical_port_scan_is_detected(monkeypatch):
    rt = bare_runtime()
    feed(rt, monkeypatch, [pkt(ATTACKER, VICTIM, 40000 + p, p) for p in range(1, 30)])
    assert rt.raised[0] == ("PortScan", ATTACKER, VICTIM)


def test_syn_flood_with_changing_source_ports_is_detected(monkeypatch):
    rt = bare_runtime()
    feed(rt, monkeypatch, [pkt(ATTACKER, VICTIM, 1024 + i, 80) for i in range(600)])
    assert ("DoS", ATTACKER, VICTIM) in rt.raised


def test_http_flood_is_detected(monkeypatch):
    rt = bare_runtime()
    packets = []
    for i in range(55):
        packets += [pkt(ATTACKER, VICTIM, 50000 + i, 80),
                    pkt(ATTACKER, VICTIM, 50000 + i, 80, flags="PA", payload=300)]
    feed(rt, monkeypatch, packets)
    assert rt.raised == [("WebAttack", ATTACKER, VICTIM)]


def test_ssh_brute_force_is_detected(monkeypatch):
    rt = bare_runtime()
    feed(rt, monkeypatch, [pkt(ATTACKER, VICTIM, 45000 + i, 22) for i in range(6)])
    assert rt.raised == [("SSH-BruteForce", ATTACKER, VICTIM)]


def test_udp_flood_without_replies_is_detected():
    rt = bare_runtime()
    rt._detect_flood(flow_with(fwd=400, bwd=0, seconds=0.5, fwd_payload=1400, proto="UDP"), "UDP")
    assert rt.raised and rt.raised[0][1] == ATTACKER


def test_slowloris_needs_many_slow_connections():
    rt = bare_runtime()
    now = time.monotonic()
    for i in range(12):
        flow = NetworkFlow(ATTACKER, VICTIM, 50000 + i, 80, "TCP", ts=1000.0)
        flow.add_packet({"ts": 1000.0, "payload_len": 0})
        flow.add_packet({"ts": 1040.0, "payload_len": 20})
        rt._detect_slowloris(flow, now)
        if i == 0:
            assert rt.raised == [], "one long-lived connection is normal"
    assert rt.raised == [("WebAttack", ATTACKER, VICTIM)]


# ── Normal traffic is not an attack ──────────────────────────────
def test_fast_download_is_not_a_flood():
    rt = bare_runtime()
    # Phone downloads at ~1700 pkt/s: data comes back, ACKs go out
    rt._detect_flood(flow_with(fwd=700, bwd=1400, seconds=1.0, fwd_payload=6, bwd_payload=1448), "TCP")
    assert rt.raised == []


def test_fast_upload_is_not_a_flood():
    rt = bare_runtime()
    rt._detect_flood(flow_with(fwd=1400, bwd=700, seconds=1.0, fwd_payload=1448, bwd_payload=6), "TCP")
    assert rt.raised == []


def test_app_startup_with_many_connections_is_not_a_port_scan(monkeypatch):
    rt = bare_runtime()
    # 40 HTTPS connections to 40 different internet servers, 40 DNS lookups
    packets = [pkt(PHONE, f"142.250.{i}.1", 50000 + i, 443) for i in range(40)]
    packets += [pkt(PHONE, "192.168.77.1", 30000 + i, 53, proto="UDP", flags="") for i in range(40)]
    feed(rt, monkeypatch, packets)
    assert rt.raised == []


# ── ML micro-batching ────────────────────────────────────────────
def test_ml_runs_in_batches_and_blames_the_initiator(monkeypatch):
    rt = bare_runtime()
    packets = []
    for i in range(40):
        dport = 666 if i == 7 else 443
        packets += [pkt(PHONE if dport == 443 else ATTACKER, VICTIM, 50000 + i, dport),
                    pkt(VICTIM, PHONE if dport == 443 else ATTACKER, dport, 50000 + i, flags="SA")]
    feed(rt, monkeypatch, packets)
    assert rt.inference_engine.batches[0] == engine.ML_BATCH_SIZE
    alerts = rt.alert_system.logged
    assert [(a.src_ip, a.attack_type, a.detector) for a in alerts] == [(ATTACKER, "DoS", "ML")]


def test_ticker_flushes_a_partial_batch_after_the_delay(monkeypatch):
    rt = bare_runtime()
    feed(rt, monkeypatch, [pkt(PHONE, VICTIM, 50000, 443), pkt(VICTIM, PHONE, 443, 50000, flags="SA")])
    assert rt.inference_engine.batches == []          # waiting for more flows
    rt.ml_pending_since -= engine.ML_MAX_DELAY_SECONDS
    rt.tick()
    assert rt.inference_engine.batches == [1]


def test_ml_skips_flows_from_hosts_blocked_while_queued(monkeypatch):
    rt = bare_runtime()
    feed(rt, monkeypatch, [pkt(ATTACKER, VICTIM, 1, 666), pkt(VICTIM, ATTACKER, 666, 1, flags="SA")])
    rt.alert_system.blocked.add(ATTACKER)
    rt._flush_ml()
    assert rt.inference_engine.batches == [] and rt.alert_system.logged == []


def test_housekeeping_forgets_idle_sources(monkeypatch):
    rt = bare_runtime()
    feed(rt, monkeypatch, [pkt(PHONE, VICTIM, 50000 + i, 443) for i in range(5)])
    rt._housekeeping(time.monotonic() + 3600)
    assert not rt.pair_ports and not rt.http_conns


def test_hairpin_filter_drops_only_the_routed_copy_of_client_traffic():
    pi_mac = "dc:a6:32:00:00:01"
    hairpin = HairpinFilter(pi_mac, LAN, "192.168.77.1")
    assert hairpin.is_duplicate({"eth_src": pi_mac.upper(), "src_ip": ATTACKER})
    assert not hairpin.is_duplicate({"eth_src": "aa:bb:cc:dd:ee:ff", "src_ip": ATTACKER})
    assert not hairpin.is_duplicate({"eth_src": pi_mac, "src_ip": "142.250.1.1"})
    assert not hairpin.is_duplicate({"eth_src": pi_mac, "src_ip": "192.168.77.1"})
    assert not HairpinFilter(None, LAN, "192.168.77.1").is_duplicate(
        {"eth_src": pi_mac, "src_ip": ATTACKER})


# ── Logging and shutdown ─────────────────────────────────────────
def test_info_messages_reach_the_console(capsys):
    import logging
    from utils.helpers import configure_logging, log_runtime
    root = logging.getLogger()
    saved = (root.handlers[:], root.level, getattr(root, "_edge_sentinel_configured", False))
    root._edge_sentinel_configured = False
    try:
        configure_logging()
        log_runtime("model ready marker")
        assert "model ready marker" in capsys.readouterr().out
    finally:
        root.handlers[:], root.level = saved[0], saved[1]
        root._edge_sentinel_configured = saved[2]


def test_ctrl_c_and_sigterm_stop_the_engine_once(monkeypatch):
    stops = []

    class Runtime:
        def __init__(self, **kwargs):
            pass

        def run_continuous(self):
            raise KeyboardInterrupt     # what Ctrl+C or SIGTERM delivers

        def stop(self):
            stops.append(1)

    monkeypatch.setattr(engine, "NIIDSRuntime", Runtime)
    monkeypatch.setattr(engine, "configure_logging", lambda **kw: None)
    monkeypatch.setattr(engine.signal, "signal", lambda *a: None)
    monkeypatch.setattr(sys, "argv", ["main.py", "--interface", "wlan0"])
    engine.main()
    assert stops == [1]


def test_stop_is_idempotent_and_flushes_pending_ml(monkeypatch):
    rt = bare_runtime()
    rt.packet_capture = type("Capture", (), {"stop_capture": lambda self: None})()
    feed(rt, monkeypatch, [pkt(ATTACKER, VICTIM, 1, 666), pkt(VICTIM, ATTACKER, 666, 1, flags="SA")])
    rt.stop()
    rt.stop()
    assert rt.inference_engine.batches == [1]
    assert rt._stop_event.is_set()


def test_sigterm_handler_raises_keyboard_interrupt():
    import pytest
    with pytest.raises(KeyboardInterrupt):
        engine._raise_keyboard_interrupt(15, None)
