"""
Alert System module for Raspberry Pi NIDS.

Generates and logs security alerts when attacks are detected.
"""

from pathlib import Path
from typing import Dict, Optional
from datetime import datetime
import sys
import json

sys.path.insert(0, str(Path(__file__).parent.parent))

from utils.config import CLASS_LABELS, ALERT_LOG_FILE, ALERT_MIN_CONFIDENCE
from utils.helpers import log_alert, log_runtime, log_error, format_timestamp, get_class_label

class Alert:
    """Represents a security alert."""
    
    def __init__(self, timestamp: str, src_ip: str, dst_ip: str, src_port: int,
                 dst_port: int, attack_type: str, attack_class: int, 
                 confidence: float, protocol: str = 'TCP'):
        """Initialize alert."""
        self.timestamp = timestamp
        self.src_ip = src_ip
        self.dst_ip = dst_ip
        self.src_port = src_port
        self.dst_port = dst_port
        self.attack_type = attack_type
        self.attack_class = attack_class
        self.confidence = confidence
        self.protocol = protocol
    
    def to_dict(self) -> Dict:
        """Convert alert to dictionary."""
        return {
            'timestamp': self.timestamp,
            'src_ip': self.src_ip,
            'dst_ip': self.dst_ip,
            'src_port': self.src_port,
            'dst_port': self.dst_port,
            'attack_type': self.attack_type,
            'attack_class': self.attack_class,
            'confidence': self.confidence,
            'protocol': self.protocol,
        }
    
    def to_json(self) -> str:
        """Convert alert to JSON string."""
        return json.dumps(self.to_dict())
    
    def to_log_string(self) -> str:
        """Convert alert to log string."""
        return (
            f"[ALERT] {self.timestamp} | "
            f"{self.src_ip}:{self.src_port} -> {self.dst_ip}:{self.dst_port} | "
            f"Type: {self.attack_type} | Confidence: {self.confidence:.4f} | "
            f"Protocol: {self.protocol}"
        )

class AlertSystem:
    """Manages security alerts."""
    
    def __init__(self, log_file: Path = ALERT_LOG_FILE, 
                 min_confidence: float = ALERT_MIN_CONFIDENCE):
        """
        Initialize alert system.
        
        Args:
            log_file: Path to alert log file
            min_confidence: Minimum confidence for logging alerts
        """
        self.log_file = log_file
        self.min_confidence = min_confidence
        self.alerts = []
        
        # Ensure log file directory exists
        self.log_file.parent.mkdir(parents=True, exist_ok=True)
        
        log_runtime(f"Initialized AlertSystem with confidence threshold {min_confidence}")
    
    def generate_alert(self, src_ip: str, dst_ip: str, src_port: int, dst_port: int,
                      predicted_class: int, confidence: float, protocol: str = 'TCP') -> Alert:
        """
        Generate security alert.
        
        Args:
            src_ip: Source IP address
            dst_ip: Destination IP address
            src_port: Source port
            dst_port: Destination port
            predicted_class: Predicted attack class
            confidence: Detection confidence
            protocol: Network protocol
            
        Returns:
            Alert object
        """
        timestamp = format_timestamp()
        attack_type = get_class_label(predicted_class)
        
        alert = Alert(
            timestamp=timestamp,
            src_ip=src_ip,
            dst_ip=dst_ip,
            src_port=src_port,
            dst_port=dst_port,
            attack_type=attack_type,
            attack_class=predicted_class,
            confidence=confidence,
            protocol=protocol
        )
        
        return alert
    
    def log_alert(self, alert: Alert) -> None:
        """Log alert to file and memory."""
        if alert.confidence < self.min_confidence:
            return
        
        try:
            self.alerts.append(alert)
            
            # Log to file
            with open(self.log_file, 'a') as f:
                f.write(alert.to_log_string() + '\n')
            
            # Log to runtime logger
            log_alert(
                alert.timestamp,
                alert.src_ip,
                alert.dst_ip,
                alert.src_port,
                alert.dst_port,
                alert.attack_type,
                alert.confidence
            )
            
        except Exception as e:
            log_error("Failed to log alert", e)
    
    def get_recent_alerts(self, count: int = 10) -> list:
        """Get recent alerts."""
        return self.alerts[-count:]
    
    def get_alerts_by_type(self, attack_type: str) -> list:
        """Get alerts by attack type."""
        return [a for a in self.alerts if a.attack_type == attack_type]
    
    def get_alert_count(self) -> int:
        """Get total alert count."""
        return len(self.alerts)
    
    def clear_alerts(self) -> None:
        """Clear in-memory alerts."""
        self.alerts.clear()
        log_runtime("Alerts cleared")
    
    def get_alert_statistics(self) -> Dict:
        """Get alert statistics."""
        if not self.alerts:
            return {
                'total_alerts': 0,
                'alert_types': {}
            }
        
        type_counts = {}
        for alert in self.alerts:
            attack_type = alert.attack_type
            type_counts[attack_type] = type_counts.get(attack_type, 0) + 1
        
        return {
            'total_alerts': len(self.alerts),
            'alert_types': type_counts,
            'avg_confidence': sum(a.confidence for a in self.alerts) / len(self.alerts)
        }
