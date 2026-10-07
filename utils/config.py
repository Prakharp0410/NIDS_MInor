"""
Configuration module for NIDS project.

Centralizes all configuration parameters for training and runtime systems.
"""

import os
from pathlib import Path

# ===========================
# PROJECT PATHS
# ===========================

PROJECT_ROOT = Path(__file__).parent.parent
DATA_DIR = PROJECT_ROOT / "data"
RAW_DATA_DIR = DATA_DIR / "raw"
PROCESSED_DATA_DIR = DATA_DIR / "processed"
MODELS_DIR = PROJECT_ROOT / "models"
TRAINING_DIR = PROJECT_ROOT / "training"
LOGS_DIR = PROJECT_ROOT / "logs"

LOGS_DIR.mkdir(exist_ok=True)

# ===========================
# DATASET CONFIGURATION
# ===========================

DATASET_FILES = [
    "Benign-Monday-WorkingHours.pcap_ISCX.csv",
    "Bruteforce-Tuesday-WorkingHours.pcap_ISCX.csv",
    "DoS-Wednesday-WorkingHours.pcap_ISCX.csv",
    "WebAttacks-Thursday-WorkingHours-Morning.pcap_ISCX.csv",
    "Infiltration-Thursday-WorkingHours-Afternoon.pcap_ISCX.csv",
    "Botnet-Friday-WorkingHours-Morning.pcap_ISCX.csv",
    "Portscan-Friday-WorkingHours-Afternoon.pcap_ISCX.csv",
    "DDoS-Friday-WorkingHours-Afternoon.pcap_ISCX.csv",
]

# Attack type mapping
# Keep the canonical values used by the project and support common dataset label variations.
ATTACK_TYPES = {
    "BENIGN": 0,
    "Benign": 0,
    "DoS": 1,
    "DoS Hulk": 1,
    "DoS GoldenEye": 1,
    "DoS Slowloris": 1,
    "DoS Slowhttptest": 1,
    "DDoS": 2,
    "DDOS": 2,
    "PortScan": 3,
    "Port Scan": 3,
    "Portscan": 3,
    "SSH-Patator": 4,
    "FTP-Patator": 4,
    "BruteForce": 4,
    "Bot": 5,
    "Botnet": 5,
    "WebAttack": 6,
    "Web Attack": 6,
    "Web Attack – Brute Force": 6,
    "Web Attack – SQL Injection": 6,
    "Web Attack – XSS": 6,
    "Web Attack Brute Force": 6,
    "Web Attack SQL Injection": 6,
    "Web Attack XSS": 6,
    "Infiltration": 7,
}

CLASS_LABELS = {
    0: "Benign",
    1: "DoS",
    2: "DDoS",
    3: "PortScan",
    4: "BruteForce",
    5: "Botnet",
    6: "WebAttack",
    7: "Infiltration",
    8: "DoS",
    9: "Infiltration",
    10: "PortScan",
    11: "BruteForce",
    12: "WebAttack",
    13: "WebAttack",
    14: "WebAttack",
}


def normalize_label(value) -> str:
    """Normalize label strings to a comparable, punctuation-insensitive form."""
    if value is None:
        return ""

    text = str(value).strip()
    text = text.replace("_", " ").replace("-", " ").replace("/", " ")
    text = text.replace("–", " ").replace("—", " ")
    text = " ".join(text.split())
    return text.casefold()

# ===========================
# TRAINING CONFIGURATION
# ===========================

TRAIN_TEST_SPLIT = 0.2
RANDOM_STATE = 42
RF_N_ESTIMATORS = 100
RF_MAX_DEPTH = 20
RF_MIN_SAMPLES_SPLIT = 5
RF_MIN_SAMPLES_LEAF = 2
RF_N_JOBS = -1

USE_SCALER = True
SCALER_TYPE = "StandardScaler"

# ===========================
# RUNTIME CONFIGURATION
# ===========================

NETWORK_INTERFACE = "eth0"
PACKET_CAPTURE_TIMEOUT = 20
PACKET_CAPTURE_PACKET_COUNT = 1000
PACKET_BUFFER_SIZE = 100
MIN_PACKETS_IN_FLOW = 2

INFERENCE_BATCH_SIZE = 1
INFERENCE_THRESHOLD = 0.5

# Engine tuning for the Raspberry Pi (environment variables override)
# Flows are classified at 2, 4, 8, 16, ... packets and when they end, in
# batches of up to ML_BATCH_SIZE, at most ML_MAX_DELAY_SECONDS after queueing.
ML_BATCH_SIZE = int(os.getenv("EDGE_ML_BATCH_SIZE", "32"))
ML_MAX_DELAY_SECONDS = float(os.getenv("EDGE_ML_MAX_DELAY", "0.25"))
# ML predictions below this confidence are not alerted at all. Blocking has
# its own, higher bar (NIPS_ML_BLOCK_MIN_CONFIDENCE).
ML_ALERT_MIN_CONFIDENCE = float(os.getenv("EDGE_ML_ALERT_MIN_CONF", "0.60"))
FLOW_TIMEOUT_SECONDS = int(os.getenv("EDGE_FLOW_TIMEOUT", "120"))
MAX_FLOWS = int(os.getenv("EDGE_MAX_FLOWS", "20000"))
STATS_INTERVAL_SECONDS = int(os.getenv("EDGE_STATS_INTERVAL", "30"))

# ===========================
# ALERT CONFIGURATION
# ===========================

ALERT_LOG_FILE = LOGS_DIR / "alerts.log"
RUNTIME_LOG_FILE = LOGS_DIR / "runtime.log"
ERROR_LOG_FILE = LOGS_DIR / "errors.log"
ALERT_MIN_CONFIDENCE = 0.7

# ===========================
# DASHBOARD CONFIGURATION
# ===========================

DASHBOARD_HOST = os.getenv("EDGE_DASHBOARD_HOST", "0.0.0.0")
DASHBOARD_PORT = int(os.getenv("EDGE_DASHBOARD_PORT", "8000"))
DATABASE_PATH = Path(os.getenv("EDGE_DB_PATH", str(PROJECT_ROOT / "alerts.db")))

# ===========================
# NIPS (ACTIVE PREVENTION) CONFIGURATION
# ===========================
# Every value can be overridden with an environment variable. On the Pi the
# systemd units load them from /etc/edge-sentinel/edge-sentinel.env, which
# deploy/scripts/install.sh writes.

# Gateway topology: IoT devices join the Wi-Fi AP on LAN_INTERFACE and reach
# the internet through WAN_INTERFACE.
LAN_INTERFACE = os.getenv("EDGE_LAN_IF", "wlan0")
WAN_INTERFACE = os.getenv("EDGE_WAN_IF", "eth0")
LAN_GATEWAY_IP = os.getenv("EDGE_LAN_IP", "192.168.77.1")
# Empty means "read it from LAN_INTERFACE at runtime" (e.g. 192.168.77.0/24).
LAN_SUBNET = os.getenv("EDGE_LAN_SUBNET", "")

# enforce = insert iptables DROP rules, dry-run = log only, off = pure NIDS.
NIPS_MODE = os.getenv("EDGE_NIPS_MODE", "enforce").strip().lower()
# Dedicated chain that holds every block. It is jumped to from the top of
# INPUT and FORWARD, so a demo reset only flushes this chain and NAT survives.
NIPS_CHAIN = os.getenv("EDGE_NIPS_CHAIN", "EDGE_SENTINEL")
# lan = only block addresses inside LAN_SUBNET (attackers on the Wi-Fi).
# any = also block outside addresses (risk: blocking a CDN breaks clients).
NIPS_BLOCK_SCOPE = os.getenv("EDGE_NIPS_BLOCK_SCOPE", "lan").strip().lower()
# Comma-separated IPs or CIDRs that are never blocked (e.g. the examiner laptop).
NIPS_WHITELIST = [
    item.strip()
    for item in os.getenv("EDGE_NIPS_WHITELIST", "").split(",")
    if item.strip()
]
# Rule-based detections are deterministic, so they block at a lower confidence
# than the Random Forest, whose live-traffic false positives must not cut off
# legitimate devices.
NIPS_RULE_BLOCK_MIN_CONFIDENCE = float(os.getenv("EDGE_RULE_BLOCK_MIN_CONF", "0.60"))
NIPS_ML_BLOCK_MIN_CONFIDENCE = float(os.getenv("EDGE_ML_BLOCK_MIN_CONF", "0.90"))
IPTABLES_TIMEOUT_SECONDS = 5

# ===========================
# LOGGING CONFIGURATION
# ===========================

LOG_FORMAT = "%(asctime)s - %(name)s - %(levelname)s - %(message)s"
LOG_LEVEL = "INFO"

# ===========================
# MODEL FILES
# ===========================

MODEL_FILE = MODELS_DIR / "model.joblib"
SCALER_FILE = MODELS_DIR / "scaler.joblib"
FEATURES_FILE = MODELS_DIR / "features.json"
