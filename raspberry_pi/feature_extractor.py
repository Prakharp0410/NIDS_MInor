"""
Feature Extractor for the Raspberry Pi NIDS/NIPS.

Builds the 77 CICIDS2017 features (in the model's column order) from the
running statistics kept by NetworkFlow. Extraction is O(1): it never looks at
individual packets.

Conventions match the training data (checked against dataset/*.parquet):
- lengths are payload bytes; durations and IATs are microseconds;
- rates are per second;
- protocol is 6 (TCP), 17 (UDP) or 0 (anything else, ICMP included);
- flag-count features are 0/1 indicators, as produced by CICFlowMeter.
  Its quirks are reproduced: 'Fwd PSH Flags' mirrors the SYN indicator and
  Bwd PSH, Fwd/Bwd URG and CWE are always 0;
- 'Packet Length *' stats count the first packet twice, and 'Avg Packet
  Size' divides that sum by the real packet count;
- Down/Up Ratio is the integer quotient of backward over forward packets;
- bulk features are always 0 and subflows equal the whole flow.
"""

import numpy as np
from typing import List
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))
from utils.helpers import log_runtime, log_error

PROTOCOL_NUMBERS = {'TCP': 6, 'UDP': 17}

FEATURE_NAMES = [
    'Protocol', 'Flow Duration', 'Total Fwd Packets',
    'Total Backward Packets', 'Fwd Packets Length Total',
    'Bwd Packets Length Total', 'Fwd Packet Length Max',
    'Fwd Packet Length Min', 'Fwd Packet Length Mean',
    'Fwd Packet Length Std', 'Bwd Packet Length Max',
    'Bwd Packet Length Min', 'Bwd Packet Length Mean',
    'Bwd Packet Length Std', 'Flow Bytes/s', 'Flow Packets/s',
    'Flow IAT Mean', 'Flow IAT Std', 'Flow IAT Max', 'Flow IAT Min',
    'Fwd IAT Total', 'Fwd IAT Mean', 'Fwd IAT Std',
    'Fwd IAT Max', 'Fwd IAT Min', 'Bwd IAT Total',
    'Bwd IAT Mean', 'Bwd IAT Std', 'Bwd IAT Max', 'Bwd IAT Min',
    'Fwd PSH Flags', 'Bwd PSH Flags', 'Fwd URG Flags', 'Bwd URG Flags',
    'Fwd Header Length', 'Bwd Header Length',
    'Fwd Packets/s', 'Bwd Packets/s',
    'Packet Length Min', 'Packet Length Max',
    'Packet Length Mean', 'Packet Length Std', 'Packet Length Variance',
    'FIN Flag Count', 'SYN Flag Count', 'RST Flag Count',
    'PSH Flag Count', 'ACK Flag Count', 'URG Flag Count',
    'CWE Flag Count', 'ECE Flag Count',
    'Down/Up Ratio', 'Avg Packet Size',
    'Avg Fwd Segment Size', 'Avg Bwd Segment Size',
    'Fwd Avg Bytes/Bulk', 'Fwd Avg Packets/Bulk',
    'Fwd Avg Bulk Rate', 'Bwd Avg Bytes/Bulk',
    'Bwd Avg Packets/Bulk', 'Bwd Avg Bulk Rate',
    'Subflow Fwd Packets', 'Subflow Fwd Bytes',
    'Subflow Bwd Packets', 'Subflow Bwd Bytes',
    'Init Fwd Win Bytes', 'Init Bwd Win Bytes',
    'Fwd Act Data Packets', 'Fwd Seg Size Min',
    'Active Mean', 'Active Std', 'Active Max', 'Active Min',
    'Idle Mean', 'Idle Std', 'Idle Max', 'Idle Min',
]


class FeatureExtractor:

    def __init__(self):
        self.feature_names = list(FEATURE_NAMES)
        log_runtime(f"Initialized FeatureExtractor with {len(self.feature_names)} features")

    def extract_features(self, flow) -> np.ndarray:
        try:
            duration_us = max(flow.get_duration() * 1e6, 1.0)
            duration_s = duration_us / 1e6
            fwd, bwd, all_ = flow.fwd_len, flow.bwd_len, flow.all_len
            n_fwd, n_bwd = flow.total_fwd_packets, flow.total_bwd_packets
            n_all = n_fwd + n_bwd
            flags = flow.flag_counts

            def flag(count):
                return 1.0 if count else 0.0

            features = [
                PROTOCOL_NUMBERS.get(flow.protocol, 0),   # Protocol
                duration_us,                              # Flow Duration
                n_fwd,                                    # Total Fwd Packets
                n_bwd,                                    # Total Backward Packets
                fwd.total,                                # Fwd Packets Length Total
                bwd.total,                                # Bwd Packets Length Total
                fwd.max, fwd.min, fwd.mean, fwd.std,      # Fwd Packet Length *
                bwd.max, bwd.min, bwd.mean, bwd.std,      # Bwd Packet Length *
                (fwd.total + bwd.total) / duration_s,     # Flow Bytes/s
                n_all / duration_s,                       # Flow Packets/s
                flow.flow_iat.mean, flow.flow_iat.std,    # Flow IAT Mean/Std
                flow.flow_iat.max, flow.flow_iat.min,     # Flow IAT Max/Min
                flow.fwd_iat.total, flow.fwd_iat.mean,    # Fwd IAT Total/Mean
                flow.fwd_iat.std, flow.fwd_iat.max,       # Fwd IAT Std/Max
                flow.fwd_iat.min,                         # Fwd IAT Min
                flow.bwd_iat.total, flow.bwd_iat.mean,    # Bwd IAT Total/Mean
                flow.bwd_iat.std, flow.bwd_iat.max,       # Bwd IAT Std/Max
                flow.bwd_iat.min,                         # Bwd IAT Min
                flag(flags['S']), 0.0,                    # Fwd/Bwd PSH Flags (quirk)
                0.0, 0.0,                                 # Fwd/Bwd URG Flags (quirk)
                flow.fwd_header_bytes,                    # Fwd Header Length
                flow.bwd_header_bytes,                    # Bwd Header Length
                n_fwd / duration_s,                       # Fwd Packets/s
                n_bwd / duration_s,                       # Bwd Packets/s
                all_.min, all_.max, all_.mean,            # Packet Length Min/Max/Mean
                all_.std, all_.variance,                  # Packet Length Std/Variance
                flag(flags['F']), flag(flags['S']),       # FIN, SYN
                flag(flags['R']), flag(flags['P']),       # RST, PSH
                flag(flags['A']), flag(flags['U']),       # ACK, URG
                0.0, flag(flags['E']),                    # CWE (always 0), ECE
                n_bwd // n_fwd if n_fwd else 0,           # Down/Up Ratio
                all_.total / n_all if n_all else 0.0,     # Avg Packet Size
                fwd.mean,                                 # Avg Fwd Segment Size
                bwd.mean,                                 # Avg Bwd Segment Size
                0, 0, 0, 0, 0, 0,                         # Bulk features
                n_fwd, fwd.total,                         # Subflow Fwd Packets/Bytes
                n_bwd, bwd.total,                         # Subflow Bwd Packets/Bytes
                flow.init_fwd_win,                        # Init Fwd Win Bytes
                flow.init_bwd_win,                        # Init Bwd Win Bytes
                flow.fwd_act_data_packets,                # Fwd Act Data Packets
                flow.fwd_seg_size_min,                    # Fwd Seg Size Min
                flow.active.mean, flow.active.std,        # Active Mean/Std
                flow.active.max, flow.active.min,         # Active Max/Min
                flow.idle.mean, flow.idle.std,            # Idle Mean/Std
                flow.idle.max, flow.idle.min,             # Idle Max/Min
            ]

            vector = np.asarray(features, dtype=np.float64)
            vector[~np.isfinite(vector)] = 0.0
            return vector

        except Exception as e:
            log_error("Failed to extract features", e)
            return np.zeros(len(FEATURE_NAMES), dtype=np.float64)

    def get_feature_names(self) -> List[str]:
        return self.feature_names.copy()
