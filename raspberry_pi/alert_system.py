"""
Alert System module for the Raspberry Pi NIPS.

Generates and logs security alerts and, in NIPS mode, fires the kill-switch:
the attacker's IP is dropped by iptables before the alert is even written,
so mitigation is never delayed by disk I/O.
"""

from pathlib import Path
from typing import Optional
import sys
import json

sys.path.insert(0, str(Path(__file__).parent.parent))

from utils.config import (
    ALERT_LOG_FILE,
    ALERT_MIN_CONFIDENCE,
    DATABASE_PATH,
    LAN_INTERFACE,
    NIPS_ML_BLOCK_MIN_CONFIDENCE,
    NIPS_RULE_BLOCK_MIN_CONFIDENCE,
)
from utils.helpers import log_alert, log_runtime, log_error, format_timestamp, get_class_label
from dashboard.database import (
    Database,
    STATUS_BLOCKED,
    STATUS_BLOCK_FAILED,
    STATUS_DETECTED,
    STATUS_DRY_RUN,
    STATUS_WHITELISTED,
)
from raspberry_pi import firewall as fw

DETECTOR_RULE = "RULE"
DETECTOR_ML = "ML"

# Kill-switch outcome -> status stored with the alert
_OUTCOME_STATUS = {
    fw.BLOCKED: STATUS_BLOCKED,
    fw.ALREADY_BLOCKED: STATUS_BLOCKED,
    fw.WHITELISTED: STATUS_WHITELISTED,
    fw.DRY_RUN: STATUS_DRY_RUN,
    fw.FAILED: STATUS_BLOCK_FAILED,
}


class Alert:
    def __init__(self, timestamp, src_ip, dst_ip, src_port,
                 dst_port, attack_type, attack_class, confidence, protocol='TCP',
                 detector=DETECTOR_ML, status=STATUS_DETECTED):
        self.timestamp = timestamp
        self.src_ip = src_ip
        self.dst_ip = dst_ip
        self.src_port = src_port
        self.dst_port = dst_port
        self.attack_type = attack_type
        self.attack_class = attack_class
        self.confidence = confidence
        self.protocol = protocol
        self.detector = detector
        self.status = status

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
            'detector': self.detector,
            'status': self.status,
        }

    def to_json(self):
        return json.dumps(self.to_dict())

    def to_log_string(self):
        return (
            f"[ALERT] {self.timestamp} | "
            f"{self.src_ip}:{self.src_port} -> {self.dst_ip}:{self.dst_port} | "
            f"Type: {self.attack_type} | Confidence: {self.confidence:.4f} | "
            f"Protocol: {self.protocol} | Detector: {self.detector} | "
            f"Action: {self.status}"
        )


class AlertSystem:
    def __init__(self, log_file=ALERT_LOG_FILE, min_confidence=ALERT_MIN_CONFIDENCE,
                 db_path=DATABASE_PATH, firewall: Optional["fw.FirewallManager"] = None,
                 enable_prevention=True, lan_interface=LAN_INTERFACE,
                 rule_block_min_confidence=NIPS_RULE_BLOCK_MIN_CONFIDENCE,
                 ml_block_min_confidence=NIPS_ML_BLOCK_MIN_CONFIDENCE):
        self.log_file = Path(log_file)
        self.min_confidence = min_confidence
        self.rule_block_min_confidence = rule_block_min_confidence
        self.ml_block_min_confidence = ml_block_min_confidence
        self.alerts = []
        self.db_path = Path(db_path)
        self.log_file.parent.mkdir(parents=True, exist_ok=True)
        self.db = self._open_db()

        # The kill-switch. Without it the system behaves as the original NIDS.
        if firewall is None and enable_prevention:
            firewall = fw.FirewallManager(lan_interface=lan_interface)
        self.firewall = firewall
        self._reconcile_blocks()

        log_runtime(f"Initialized AlertSystem with confidence threshold {min_confidence}")

    def _open_db(self) -> Optional[Database]:
        # Blocking must keep working even if the database is unavailable.
        try:
            return Database(self.db_path)
        except Exception as e:
            log_error("Alert database unavailable; alerts will only be logged to file", e)
            return None

    def _reconcile_blocks(self):
        """Align the dashboard's block list with the kernel after a (re)start."""
        if self.db and self.firewall is not None and self.firewall.is_enforcing and self.firewall.synced:
            self.db.reconcile_blocks(self.firewall.blocked_ips)

    # ── Alert creation ─────────────────────────────────────────
    def generate_alert(self, src_ip, dst_ip, src_port, dst_port,
                       predicted_class, confidence, protocol='TCP',
                       attack_type=None, detector=DETECTOR_ML):
        timestamp = format_timestamp()
        if attack_type is None:
            attack_type = get_class_label(predicted_class)
        return Alert(
            timestamp=timestamp,
            src_ip=src_ip,
            dst_ip=dst_ip,
            src_port=src_port or 0,   # ICMP flows have no ports
            dst_port=dst_port or 0,
            attack_type=attack_type,
            attack_class=predicted_class,
            confidence=confidence,
            protocol=protocol,
            detector=detector,
        )

    # ── NIPS kill-switch ───────────────────────────────────────
    def is_blocked(self, ip) -> bool:
        """True when the kernel is already dropping this source."""
        return (self.firewall is not None and self.firewall.is_enforcing
                and self.firewall.is_blocked(ip))

    def _apply_prevention(self, alert) -> str:
        """Block the attacker if policy allows; return the alert's status."""
        if self.firewall is None:
            return STATUS_DETECTED
        threshold = (self.ml_block_min_confidence if alert.detector == DETECTOR_ML
                     else self.rule_block_min_confidence)
        if alert.confidence < threshold:
            return STATUS_DETECTED
        try:
            outcome = self.firewall.block(alert.src_ip, reason=alert.attack_type)
        except Exception as e:
            log_error(f"Kill-switch error for {alert.src_ip}", e)
            return STATUS_BLOCK_FAILED

        if self.db and outcome in (fw.BLOCKED, fw.ALREADY_BLOCKED):
            self.db.upsert_block(
                ip=alert.src_ip,
                attack_type=alert.attack_type,
                detector=alert.detector,
                confidence=alert.confidence,
                target_ip=alert.dst_ip,
                timestamp=alert.timestamp,
                latency_ms=self.firewall.last_latency_ms if outcome == fw.BLOCKED else None,
            )
        return _OUTCOME_STATUS.get(outcome, STATUS_DETECTED)

    # ── Logging ────────────────────────────────────────────────
    def log_alert(self, alert):
        """Block (NIPS), then log the alert to memory, file and database."""
        if alert.confidence < self.min_confidence:
            return alert

        # 1. Kill-switch first: mitigation must not wait for disk writes
        alert.status = self._apply_prevention(alert)
        self.alerts.append(alert)

        # 2. Write to log file
        try:
            with open(self.log_file, 'a', encoding='utf-8') as f:
                f.write(alert.to_log_string() + '\n')
        except Exception as e:
            log_error("Failed to write alert log file", e)

        # 3. Write to SQLite database (so dashboard can read it)
        if self.db:
            self.db.insert_alert(alert.to_dict())

        # 4. Print to terminal
        try:
            log_alert(
                alert.timestamp, alert.src_ip, alert.dst_ip,
                alert.src_port, alert.dst_port,
                alert.attack_type, alert.confidence
            )
        except Exception as e:
            log_error("Failed to log alert", e)

        return alert

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
        blocked = len(self.firewall.blocked_ips) if self.firewall is not None else 0
        if not self.alerts:
            return {'total_alerts': 0, 'alert_types': {}, 'blocked_ips': blocked}
        type_counts = {}
        for alert in self.alerts:
            type_counts[alert.attack_type] = type_counts.get(alert.attack_type, 0) + 1
        return {
            'total_alerts': len(self.alerts),
            'alert_types': type_counts,
            'avg_confidence': sum(a.confidence for a in self.alerts) / len(self.alerts),
            'blocked_ips': blocked,
        }
