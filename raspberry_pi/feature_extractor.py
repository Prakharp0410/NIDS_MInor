"""
Feature Extractor - FIXED VERSION
Extracts all 77 CICIDS2017-compatible features from live network flows.
"""

import numpy as np
from typing import List
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))
from utils.helpers import log_runtime, log_error, sanitize_data

class FeatureExtractor:

    def __init__(self):
        self.feature_names = self._get_feature_names()
        log_runtime(f"Initialized FeatureExtractor with {len(self.feature_names)} features")

    def _get_feature_names(self) -> List[str]:
        return [
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
            'Down/Up Ratio', 'Average Packet Size',
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

    def extract_features(self, flow) -> np.ndarray:
        try:
            duration = max(flow.get_duration(), 0.000001)
            packets   = flow.packets
            fwd_pkts  = [p for i, p in enumerate(packets) if i % 2 == 0]
            bwd_pkts  = [p for i, p in enumerate(packets) if i % 2 == 1]

            fwd_lens = [p.get('length', 0) for p in fwd_pkts]
            bwd_lens = [p.get('length', 0) for p in bwd_pkts]
            all_lens = [p.get('length', 0) for p in packets]

            total_fwd_pkts  = len(fwd_pkts)
            total_bwd_pkts  = len(bwd_pkts)
            total_fwd_bytes = sum(fwd_lens)
            total_bwd_bytes = sum(bwd_lens)
            total_bytes     = flow.total_bytes
            total_pkts      = total_fwd_pkts + total_bwd_pkts

            # IAT (inter-arrival times)
            def get_iats(pkt_list):
                times = [p.get('timestamp', 0) for p in pkt_list]
                if len(times) < 2:
                    return [0]
                try:
                    from datetime import datetime
                    diffs = []
                    for i in range(1, len(times)):
                        if isinstance(times[i], str) and isinstance(times[i-1], str):
                            fmt = "%Y-%m-%d %H:%M:%S"
                            diff = (datetime.strptime(times[i], fmt) -
                                    datetime.strptime(times[i-1], fmt)).total_seconds()
                        else:
                            diff = 0
                        diffs.append(abs(diff))
                    return diffs if diffs else [0]
                except:
                    return [0]

            all_iats = get_iats(packets)
            fwd_iats = get_iats(fwd_pkts)
            bwd_iats = get_iats(bwd_pkts)

            # TCP flags
            def flag_count(pkt_list, flag):
                return sum(1 for p in pkt_list
                           if p.get('flags') and flag in str(p.get('flags', '')))

            fin = flag_count(packets, 'F')
            syn = flag_count(packets, 'S')
            rst = flag_count(packets, 'R')
            psh = flag_count(packets, 'P')
            ack = flag_count(packets, 'A')
            urg = flag_count(packets, 'U')

            def safe_mean(lst): return float(np.mean(lst)) if lst else 0.0
            def safe_std(lst):  return float(np.std(lst))  if lst else 0.0
            def safe_max(lst):  return float(max(lst))     if lst else 0.0
            def safe_min(lst):  return float(min(lst))     if lst else 0.0

            # Protocol number (TCP=6, UDP=17, other=0)
            proto_map = {'TCP': 6, 'UDP': 17, 'ICMP': 1}
            protocol_num = proto_map.get(flow.protocol, 0)

            avg_pkt_size = safe_mean(all_lens)

            features = [
                protocol_num,                           # Protocol
                duration * 1e6,                         # Flow Duration (microseconds)
                total_fwd_pkts,                         # Total Fwd Packets
                total_bwd_pkts,                         # Total Backward Packets
                total_fwd_bytes,                        # Fwd Packets Length Total
                total_bwd_bytes,                        # Bwd Packets Length Total
                safe_max(fwd_lens),                     # Fwd Packet Length Max
                safe_min(fwd_lens),                     # Fwd Packet Length Min
                safe_mean(fwd_lens),                    # Fwd Packet Length Mean
                safe_std(fwd_lens),                     # Fwd Packet Length Std
                safe_max(bwd_lens),                     # Bwd Packet Length Max
                safe_min(bwd_lens),                     # Bwd Packet Length Min
                safe_mean(bwd_lens),                    # Bwd Packet Length Mean
                safe_std(bwd_lens),                     # Bwd Packet Length Std
                total_bytes / duration,                 # Flow Bytes/s
                total_pkts  / duration,                 # Flow Packets/s
                safe_mean(all_iats),                    # Flow IAT Mean
                safe_std(all_iats),                     # Flow IAT Std
                safe_max(all_iats),                     # Flow IAT Max
                safe_min(all_iats),                     # Flow IAT Min
                sum(fwd_iats),                          # Fwd IAT Total
                safe_mean(fwd_iats),                    # Fwd IAT Mean
                safe_std(fwd_iats),                     # Fwd IAT Std
                safe_max(fwd_iats),                     # Fwd IAT Max
                safe_min(fwd_iats),                     # Fwd IAT Min
                sum(bwd_iats),                          # Bwd IAT Total
                safe_mean(bwd_iats),                    # Bwd IAT Mean
                safe_std(bwd_iats),                     # Bwd IAT Std
                safe_max(bwd_iats),                     # Bwd IAT Max
                safe_min(bwd_iats),                     # Bwd IAT Min
                flag_count(fwd_pkts, 'P'),              # Fwd PSH Flags
                flag_count(bwd_pkts, 'P'),              # Bwd PSH Flags
                flag_count(fwd_pkts, 'U'),              # Fwd URG Flags
                flag_count(bwd_pkts, 'U'),              # Bwd URG Flags
                total_fwd_pkts * 20,                    # Fwd Header Length (approx)
                total_bwd_pkts * 20,                    # Bwd Header Length (approx)
                total_fwd_pkts / duration,              # Fwd Packets/s
                total_bwd_pkts / duration,              # Bwd Packets/s
                safe_min(all_lens),                     # Packet Length Min
                safe_max(all_lens),                     # Packet Length Max
                safe_mean(all_lens),                    # Packet Length Mean
                safe_std(all_lens),                     # Packet Length Std
                float(np.var(all_lens)) if all_lens else 0.0,  # Packet Length Variance
                fin, syn, rst, psh, ack, urg,           # Flag counts
                0, 0,                                   # CWE, ECE flags
                total_bwd_pkts / max(total_fwd_pkts, 1),  # Down/Up Ratio
                avg_pkt_size,                           # Average Packet Size
                safe_mean(fwd_lens),                    # Avg Fwd Segment Size
                safe_mean(bwd_lens),                    # Avg Bwd Segment Size
                0, 0, 0, 0, 0, 0,                      # Bulk features (not available live)
                total_fwd_pkts,                         # Subflow Fwd Packets
                total_fwd_bytes,                        # Subflow Fwd Bytes
                total_bwd_pkts,                         # Subflow Bwd Packets
                total_bwd_bytes,                        # Subflow Bwd Bytes
                -1,                                     # Init Fwd Win Bytes
                -1,                                     # Init Bwd Win Bytes
                total_fwd_pkts,                         # Fwd Act Data Packets
                safe_min(fwd_lens),                     # Fwd Seg Size Min
                duration * 1e6,                         # Active Mean
                0,                                      # Active Std
                duration * 1e6,                         # Active Max
                0,                                      # Active Min
                0, 0, 0, 0,                             # Idle features
            ]

            feature_vector = np.array(features, dtype=np.float32)
            feature_vector = sanitize_data(feature_vector)
            return feature_vector

        except Exception as e:
            log_error("Failed to extract features", e)
            return np.zeros(77, dtype=np.float32)

    def get_feature_names(self) -> List[str]:
        return self.feature_names.copy()
