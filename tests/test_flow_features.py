"""Flow statistics, CICIDS2017 feature conventions and the real model."""

import json
import sys
from pathlib import Path

import numpy as np
import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "raspberry_pi"))

from feature_extractor import FEATURE_NAMES, FeatureExtractor  # noqa: E402
from flow_manager import FlowManager, NetworkFlow  # noqa: E402

A, B = "192.168.77.23", "192.168.77.40"


def features_of(flow):
    return dict(zip(FEATURE_NAMES, FeatureExtractor().extract_features(flow)))


def add(flow, ts, payload=0, direction="fwd", flags="", window=None, header=20):
    flow.add_packet({"ts": ts, "payload_len": payload, "flags": flags,
                     "window": window, "header_len": header}, direction=direction)


def test_feature_order_matches_the_trained_model():
    cfg = json.loads((ROOT / "models" / "rf_features.json").read_text())
    names = cfg if isinstance(cfg, list) else cfg["features"]
    assert FEATURE_NAMES == names


def test_lengths_and_averages_follow_cicflowmeter():
    # Same shape as a real CICIDS2017 row: two forward packets of 37 and 0
    # bytes give Packet Length Mean 24.67 and Avg Packet Size 37.
    flow = NetworkFlow(A, B, 1, 80, "TCP", ts=10.0)
    add(flow, 10.0, payload=37)
    add(flow, 10.5, payload=0)
    f = features_of(flow)
    assert f["Packet Length Mean"] == pytest.approx(24.6667, rel=1e-3)
    assert f["Avg Packet Size"] == pytest.approx(37.0)
    assert (f["Packet Length Min"], f["Packet Length Max"]) == (0, 37)
    assert f["Fwd Packet Length Mean"] == pytest.approx(18.5)


def test_times_are_microseconds_and_rates_per_second():
    flow = NetworkFlow(A, B, 1, 80, "TCP", ts=0.0)
    add(flow, 0.0, payload=100)
    add(flow, 0.25, payload=300, direction="bwd")
    add(flow, 1.0, payload=100)
    f = features_of(flow)
    assert f["Flow Duration"] == pytest.approx(1_000_000)
    assert f["Flow IAT Mean"] == pytest.approx(500_000)
    assert f["Fwd IAT Total"] == pytest.approx(1_000_000)
    assert f["Flow Packets/s"] == pytest.approx(3.0)
    assert f["Flow Bytes/s"] == pytest.approx(500.0)
    assert f["Down/Up Ratio"] == 0          # integer 1 // 2


def test_direction_comes_from_the_flow_not_packet_order():
    flow = NetworkFlow(A, B, 1, 80, "TCP", ts=0.0)
    add(flow, 0.0, payload=10)
    for i in range(4):
        add(flow, 0.1 + i / 10, payload=1000, direction="bwd")
    f = features_of(flow)
    assert (f["Total Fwd Packets"], f["Total Backward Packets"]) == (1, 4)
    assert f["Bwd Packet Length Mean"] == 1000


def test_flags_windows_and_protocol_codes():
    flow = NetworkFlow(A, B, 1, 80, "TCP", ts=0.0)
    add(flow, 0.0, flags="S", window=64240, header=40)
    add(flow, 0.1, flags="SA", window=65160, direction="bwd")
    add(flow, 0.2, flags="PA", payload=50, header=32)
    f = features_of(flow)
    assert f["SYN Flag Count"] == f["ACK Flag Count"] == f["PSH Flag Count"] == 1  # 0/1 indicators
    assert f["Fwd PSH Flags"] == f["SYN Flag Count"]                               # CICFlowMeter quirk
    assert (f["Init Fwd Win Bytes"], f["Init Bwd Win Bytes"]) == (64240, 65160)
    assert f["Fwd Seg Size Min"] == 32 and f["Fwd Header Length"] == 72
    assert f["Fwd Act Data Packets"] == 1

    icmp = NetworkFlow(A, B, 0, 0, "ICMP", ts=0.0)
    add(icmp, 0.0)
    assert features_of(icmp)["Protocol"] == 0
    assert features_of(icmp)["Init Fwd Win Bytes"] == -1


def test_idle_gaps_over_five_seconds_split_activity():
    flow = NetworkFlow(A, B, 1, 80, "TCP", ts=0.0)
    add(flow, 0.0)
    add(flow, 1.0)
    add(flow, 9.0)          # 8 s idle
    f = features_of(flow)
    assert f["Idle Mean"] == pytest.approx(8_000_000)
    assert f["Active Mean"] == pytest.approx(1_000_000)


def test_ml_checkpoints_double_and_fire_at_flow_end():
    flow = NetworkFlow(A, B, 1, 80, "TCP", ts=0.0)
    fired = []
    for i in range(20):
        add(flow, i * 0.01)
        if flow.ml_due():
            fired.append(flow.packet_count)
            flow.mark_ml_queued()
    assert fired == [2, 4, 8, 16]
    add(flow, 1.0, flags="FA")
    assert flow.ml_due()


def test_flow_table_is_bounded_and_evicts_the_least_recent():
    import time
    now = time.time()
    fm = FlowManager(timeout_seconds=120, max_flows=3)
    for port in (1, 2, 3):
        fm.add_packet_to_flow({"src_ip": A, "dst_ip": B, "src_port": port, "dst_port": 80,
                               "protocol": "TCP", "ts": now})
    fm.add_packet_to_flow({"src_ip": A, "dst_ip": B, "src_port": 1, "dst_port": 80,
                           "protocol": "TCP", "ts": now + 1})      # flow 1 is active again
    fm.add_packet_to_flow({"src_ip": A, "dst_ip": B, "src_port": 4, "dst_port": 80,
                           "protocol": "TCP", "ts": now + 2})
    assert fm.get_flow_count() == 3
    assert {key[1] for key in fm.flows} == {1, 3, 4}     # flow 2 was evicted


def test_joining_mid_handshake_keeps_the_client_as_initiator():
    fm = FlowManager()
    flow = fm.add_packet_to_flow({"src_ip": B, "dst_ip": A, "src_port": 80, "dst_port": 5000,
                                  "protocol": "TCP", "flags": "SA"})
    assert (flow.src_ip, flow.dst_port) == (A, 80)
    assert flow.total_bwd_packets == 1


def test_expiry_removes_only_idle_flows():
    fm = FlowManager(timeout_seconds=60)
    fm.add_packet_to_flow({"src_ip": A, "dst_ip": B, "src_port": 1, "dst_port": 80,
                           "protocol": "TCP", "ts": 0.0})
    fm.add_packet_to_flow({"src_ip": A, "dst_ip": B, "src_port": 2, "dst_port": 80,
                           "protocol": "TCP", "ts": 100.0})
    assert fm.cleanup_expired_flows(now=120.0) == 1
    assert fm.get_flow_count() == 1


# ── The real model ───────────────────────────────────────────────
@pytest.fixture(scope="module")
def model():
    from inference import InferenceEngine
    engine = InferenceEngine()
    assert engine.is_ready
    return engine


def test_model_runs_single_threaded_with_readable_class_names(model):
    assert model.model.n_jobs == 1
    assert len(model.class_names) == 15
    assert not any("�" in name for name in model.class_names)
    assert [model.class_names[i] for i in model.benign_indices] == ["Benign"]
    families = {model.get_attack_family(i) for i in range(15)}
    assert {"DoS", "DDoS", "PortScan", "BruteForce", "Botnet", "WebAttack"} <= families


def test_batch_and_single_predictions_agree(model):
    X = np.random.default_rng(0).random((5, 77)) * 1000
    batch = model.predict_batch(X)
    assert len(batch) == 5
    single = model.is_attack(X[2], threshold=0.0)
    assert single[1:] == (batch[2][0], pytest.approx(batch[2][2]))


def test_model_still_recognises_cicids2017_rows(model):
    """Real training-set rows through the new scaling path stay accurate."""
    pd = pytest.importorskip("pandas")
    pytest.importorskip("pyarrow")
    frames = []
    for name, label in [("Portscan-Friday", "PortScan"), ("DDoS-Friday", "DDoS"),
                        ("Benign-Monday", "Benign")]:
        path = ROOT / "dataset" / f"{name}-no-metadata.parquet"
        if not path.exists():
            pytest.skip("dataset not available")
        df = pd.read_parquet(path)
        frames.append(df[df.Label == label].sample(150, random_state=1))
    rows = pd.concat(frames)
    predicted = [name for _, name, _ in model.predict_batch(rows[FEATURE_NAMES].to_numpy())]
    accuracy = np.mean([p == t for p, t in zip(predicted, rows.Label)])
    assert accuracy > 0.95
