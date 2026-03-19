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
ATTACK_TYPES = {
    "BENIGN": 0,
    "DoS Hulk": 1, "DoS GoldenEye": 1, "DoS Slowloris": 1, "DoS Slowhttptest": 1,
    "DDoS": 2,
    "Port Scan": 3,
    "SSH-Patator": 4, "FTP-Patator": 4,
    "Bot": 5,
    "Web Attack – Brute Force": 6, "Web Attack – SQL Injection": 6, "Web Attack – XSS": 6,
    "Infiltration": 7,
}

CLASS_LABELS = {
    0: "Benign",
    1: "Bot",
    2: "DDoS",
    3: "DoS GoldenEye",
    4: "DoS Hulk",
    5: "DoS Slowhttptest",
    6: "DoS slowloris",
    7: "FTP-Patator",
    8: "Heartbleed",
    9: "Infiltration",
    10: "PortScan",
    11: "SSH-Patator",
    12: "Web Attack Brute Force",
    13: "Web Attack SQL Injection",
    14: "Web Attack XSS",
}

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

DASHBOARD_HOST = "0.0.0.0"
DASHBOARD_PORT = 8000
DATABASE_PATH = PROJECT_ROOT / "alerts.db"

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
