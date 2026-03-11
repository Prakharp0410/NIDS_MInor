"""
Feature Extractor module for Raspberry Pi NIDS.

Extracts CICIDS2017-like statistical features from network flows.
"""

import numpy as np
from typing import Dict, List, Optional
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from utils.helpers import log_runtime, log_error, sanitize_data

class FeatureExtractor:
    """Extracts statistical features from network flows."""
    
    def __init__(self):
        """Initialize feature extractor."""
        self.feature_names = self._get_feature_names()
        log_runtime(f"Initialized FeatureExtractor with {len(self.feature_names)} features")
    
    def _get_feature_names(self) -> List[str]:
        """Get list of extracted feature names."""
        return [
            'flow_duration',
            'total_fwd_packets',
            'total_bwd_packets',
            'total_bytes',
            'total_fwd_bytes',
            'total_bwd_bytes',
            'fwd_packet_length_max',
            'fwd_packet_length_min',
            'fwd_packet_length_mean',
            'fwd_packet_length_std',
            'bwd_packet_length_max',
            'bwd_packet_length_min',
            'bwd_packet_length_mean',
            'bwd_packet_length_std',
            'flow_bytes_per_sec',
            'flow_packets_per_sec',
            'syn_flag_count',
            'ack_flag_count',
            'fin_flag_count',
            'rst_flag_count',
            'avg_packet_length',
            'std_packet_length',
            'min_packet_length',
            'max_packet_length',
        ]
    
    def extract_features(self, flow) -> np.ndarray:
        """
        Extract features from a network flow.
        
        Args:
            flow: NetworkFlow object
            
        Returns:
            Feature vector as numpy array
        """
        try:
            features = []
            
            # Flow duration
            duration = max(flow.get_duration(), 0.001)
            features.append(duration)
            
            # Packet counts
            fwd_packets = flow.total_fwd_packets
            bwd_packets = flow.total_bwd_packets
            total_packets = fwd_packets + bwd_packets
            
            features.append(fwd_packets)
            features.append(bwd_packets)
            features.append(flow.total_bytes)
            
            # Bytes per direction
            fwd_bytes = sum(p.get('length', 0) for p in flow.packets 
                           if p == flow.packets[0] or flow.packets.index(p) % 2 == 0)
            bwd_bytes = flow.total_bytes - fwd_bytes
            
            features.append(fwd_bytes)
            features.append(bwd_bytes)
            
            # Forward packet lengths
            fwd_lengths = [p.get('length', 0) for i, p in enumerate(flow.packets) 
                          if i % 2 == 0 and p.get('length', 0) > 0]
            
            if fwd_lengths:
                features.append(max(fwd_lengths))
                features.append(min(fwd_lengths))
                features.append(np.mean(fwd_lengths))
                features.append(np.std(fwd_lengths))
            else:
                features.extend([0, 0, 0, 0])
            
            # Backward packet lengths
            bwd_lengths = [p.get('length', 0) for i, p in enumerate(flow.packets) 
                          if i % 2 == 1 and p.get('length', 0) > 0]
            
            if bwd_lengths:
                features.append(max(bwd_lengths))
                features.append(min(bwd_lengths))
                features.append(np.mean(bwd_lengths))
                features.append(np.std(bwd_lengths))
            else:
                features.extend([0, 0, 0, 0])
            
            # Flow bytes per second
            features.append(flow.total_bytes / duration if duration > 0 else 0)
            
            # Flow packets per second
            features.append(total_packets / duration if duration > 0 else 0)
            
            # TCP flags
            syn_count = sum(1 for p in flow.packets if p.get('flags') and 'S' in str(p.get('flags', '')))
            ack_count = sum(1 for p in flow.packets if p.get('flags') and 'A' in str(p.get('flags', '')))
            fin_count = sum(1 for p in flow.packets if p.get('flags') and 'F' in str(p.get('flags', '')))
            rst_count = sum(1 for p in flow.packets if p.get('flags') and 'R' in str(p.get('flags', '')))
            
            features.append(syn_count)
            features.append(ack_count)
            features.append(fin_count)
            features.append(rst_count)
            
            # Average packet length
            avg_length = np.mean([p.get('length', 0) for p in flow.packets]) if flow.packets else 0
            features.append(avg_length)
            
            # Std packet length
            std_length = np.std([p.get('length', 0) for p in flow.packets]) if flow.packets else 0
            features.append(std_length)
            
            # Min/Max packet length
            all_lengths = [p.get('length', 0) for p in flow.packets]
            features.append(min(all_lengths) if all_lengths else 0)
            features.append(max(all_lengths) if all_lengths else 0)
            
            # Convert to numpy array and sanitize
            feature_vector = np.array(features, dtype=np.float32)
            feature_vector = sanitize_data(feature_vector)
            
            return feature_vector
            
        except Exception as e:
            log_error("Failed to extract features", e)
            return np.zeros(len(self.feature_names), dtype=np.float32)
    
    def extract_batch_features(self, flows: List) -> np.ndarray:
        """
        Extract features from multiple flows.
        
        Args:
            flows: List of NetworkFlow objects
            
        Returns:
            Feature matrix (n_samples, n_features)
        """
        feature_vectors = []
        
        for flow in flows:
            features = self.extract_features(flow)
            feature_vectors.append(features)
        
        if feature_vectors:
            return np.array(feature_vectors)
        else:
            return np.array([]).reshape(0, len(self.feature_names))
    
    def get_feature_names(self) -> List[str]:
        """Get feature names."""
        return self.feature_names.copy()
