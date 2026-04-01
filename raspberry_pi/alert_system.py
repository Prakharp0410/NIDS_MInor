"""
Alert System module for Raspberry Pi NIDS.
Generates and logs security alerts when attacks are detected.
"""

from pathlib import Path
from typing import Dict, Optional
from datetime import datetime
import sys
import json
import sqlite3

sys.path.insert(0, str(Path(__file__).parent.parent))

from utils.config import CLASS_LABELS, ALERT_LOG_FILE, ALERT_MIN_CONFIDENCE, DATABASE_PATH
from utils.helpers import log_alert, log_runtime, log_error, format_timestamp, get_class_label

class Alert:
    def __init__(self, timestamp, src_ip, dst_ip, src_port,
                 dst_port, attack_type, attack_class, confidence, protocol='TCP'):
        self.timestamp = timestamp
        self.src_ip = src_ip
        self.dst_ip = dst_ip
        self.src_port = src_port
        self.dst_port = dst_port
        self.attack_type = attack_type
        self.attack_class = attack_class
        self.confidence = confidence
        self.protocol = protocol

    def to_dict(self):
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

    def to_json(self):
        return json.dumps(self.to_dict())

    def to_log_string(self):
        return (
            f"[ALERT] {self.timestamp} | "
            f"{self.src_ip}:{self.src_port} -> {self.dst_ip}:{self.dst_port} | "
            f"Type: {self.attack_type} | Confidence: {self.confidence:.4f} | "
            f"Protocol: {self.protocol}"
        )


class AlertSystem:
    def __init__(self, log_file=ALERT_LOG_FILE, min_confidence=ALERT_MIN_CONFIDENCE):
        self.log_file = log_file
        self.min_confidence = min_confidence
        self.alerts = []
        self.db_path = DATABASE_PATH
        self.log_file.parent.mkdir(parents=True, exist_ok=True)
        self._init_db()
        log_runtime(f"Initialized AlertSystem with confidence threshold {min_confidence}")

    def _init_db(self):
        """Create alerts table if it doesn't exist."""
        try:
            conn = sqlite3.connect(str(self.db_path))
            cursor = conn.cursor()
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS alerts (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp TEXT NOT NULL,
                    src_ip TEXT NOT NULL,
                    dst_ip TEXT NOT NULL,
                    src_port INTEGER NOT NULL,
                    dst_port INTEGER NOT NULL,
                    attack_type TEXT NOT NULL,
                    attack_class INTEGER,
                    confidence REAL NOT NULL,
                    protocol TEXT,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            """)
            conn.commit()
            conn.close()
        except Exception as e:
            log_error("Failed to initialize alert database", e)

    def generate_alert(self, src_ip, dst_ip, src_port, dst_port,
                       predicted_class, confidence, protocol='TCP'):
        timestamp = format_timestamp()
        attack_type = get_class_label(predicted_class)
        return Alert(
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

    def log_alert(self, alert):
        """Log alert to file, memory AND database."""
        if alert.confidence < self.min_confidence:
            return
        try:
            self.alerts.append(alert)

            # 1. Write to log file
            with open(self.log_file, 'a') as f:
                f.write(alert.to_log_string() + '\n')

            # 2. Write to SQLite database (so dashboard can read it)
            conn = sqlite3.connect(str(self.db_path))
            cursor = conn.cursor()
            cursor.execute("""
                INSERT INTO alerts
                (timestamp, src_ip, dst_ip, src_port, dst_port,
                 attack_type, attack_class, confidence, protocol)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                alert.timestamp, alert.src_ip, alert.dst_ip,
                alert.src_port, alert.dst_port, alert.attack_type,
                alert.attack_class, alert.confidence, alert.protocol
            ))
            conn.commit()
            conn.close()

            # 3. Print to terminal
            log_alert(
                alert.timestamp, alert.src_ip, alert.dst_ip,
                alert.src_port, alert.dst_port,
                alert.attack_type, alert.confidence
            )

        except Exception as e:
            log_error("Failed to log alert", e)

    def get_recent_alerts(self, count=10):
        return self.alerts[-count:]

    def get_alerts_by_type(self, attack_type):
        return [a for a in self.alerts if a.attack_type == attack_type]

    def get_alert_count(self):
        return len(self.alerts)

    def clear_alerts(self):
        self.alerts.clear()
        log_runtime("Alerts cleared")

    def get_alert_statistics(self):
        if not self.alerts:
            return {'total_alerts': 0, 'alert_types': {}}
        type_counts = {}
        for alert in self.alerts:
            type_counts[alert.attack_type] = type_counts.get(alert.attack_type, 0) + 1
        return {
            'total_alerts': len(self.alerts),
            'alert_types': type_counts,
            'avg_confidence': sum(a.confidence for a in self.alerts) / len(self.alerts)
        }
