"""
Database module for NIDS / NIPS.

Manages the SQLite database shared by the detection engine (writer) and the
dashboard (reader): alerts, their prevention status, and firewall blocks.
"""

import sqlite3
from pathlib import Path
import sys
from typing import Iterable, Optional

sys.path.insert(0, str(Path(__file__).parent.parent))

from utils.config import DATABASE_PATH
from utils.helpers import log_runtime, log_error, format_timestamp

# Values of alerts.status
STATUS_DETECTED = "DETECTED"         # logged only (NIDS behaviour)
STATUS_BLOCKED = "BLOCKED"           # source IP is dropped by iptables
STATUS_WHITELISTED = "WHITELISTED"   # protected address, deliberately not blocked
STATUS_DRY_RUN = "DRY_RUN"           # would have been blocked (dry-run mode)
STATUS_BLOCK_FAILED = "BLOCK_FAILED" # iptables call failed

# Columns added after the original NIDS schema, with their SQL definitions.
# Older databases are upgraded in place when the Database is opened.
_ALERT_MIGRATIONS = {
    "status": f"TEXT NOT NULL DEFAULT '{STATUS_DETECTED}'",
    "detector": "TEXT NOT NULL DEFAULT 'UNKNOWN'",
}

_ALERT_COLUMNS = ("id", "timestamp", "src_ip", "dst_ip", "src_port", "dst_port",
                  "attack_type", "attack_class", "confidence", "protocol",
                  "status", "detector")

_BLOCK_COLUMNS = ("ip", "attack_type", "detector", "confidence", "target_ip",
                  "blocked_at", "last_seen", "alert_count", "block_latency_ms",
                  "active", "unblocked_at")


class Database:
    """Manages SQLite database for alerts and firewall blocks."""

    def __init__(self, db_path: Path = DATABASE_PATH):
        """Initialize database."""
        self.db_path = Path(db_path)
        self.db_path.parent.mkdir(parents=True, exist_ok=True)

        self.initialize_database()
        log_runtime(f"Initialized database at {self.db_path}")

    def _connect(self) -> sqlite3.Connection:
        # The engine writes while the dashboard reads: wait for locks briefly
        # instead of failing with "database is locked".
        return sqlite3.connect(str(self.db_path), timeout=10)

    def initialize_database(self) -> None:
        """Create tables if they don't exist and upgrade older schemas."""
        try:
            conn = self._connect()
            cursor = conn.cursor()

            # Create alerts table
            cursor.execute(f"""
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
                    status {_ALERT_MIGRATIONS['status']},
                    detector {_ALERT_MIGRATIONS['detector']},
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            """)
            self._migrate_alerts(cursor)

            # Create indices
            cursor.execute("""
                CREATE INDEX IF NOT EXISTS idx_timestamp ON alerts(timestamp)
            """)
            cursor.execute("""
                CREATE INDEX IF NOT EXISTS idx_attack_type ON alerts(attack_type)
            """)
            cursor.execute("""
                CREATE INDEX IF NOT EXISTS idx_src_ip ON alerts(src_ip)
            """)

            # Firewall blocks: one row per attacker IP, `active` mirrors iptables
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS blocked_ips (
                    ip TEXT PRIMARY KEY,
                    attack_type TEXT NOT NULL,
                    detector TEXT,
                    confidence REAL,
                    target_ip TEXT,
                    blocked_at TEXT NOT NULL,
                    last_seen TEXT NOT NULL,
                    alert_count INTEGER NOT NULL DEFAULT 1,
                    block_latency_ms REAL,
                    active INTEGER NOT NULL DEFAULT 1,
                    unblocked_at TEXT
                )
            """)
            cursor.execute("""
                CREATE INDEX IF NOT EXISTS idx_blocked_active ON blocked_ips(active)
            """)

            # Create statistics table
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS statistics (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp TEXT NOT NULL,
                    packets_processed INTEGER,
                    active_flows INTEGER,
                    total_alerts INTEGER,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            """)

            conn.commit()
            conn.close()

            log_runtime("Database tables initialized")

        except Exception as e:
            log_error("Failed to initialize database", e)
            raise

    @staticmethod
    def _migrate_alerts(cursor: sqlite3.Cursor) -> None:
        """Add NIPS columns to an alerts table created by the original NIDS."""
        existing = {row[1] for row in cursor.execute("PRAGMA table_info(alerts)")}
        for column, definition in _ALERT_MIGRATIONS.items():
            if column in existing:
                continue
            try:
                cursor.execute(f"ALTER TABLE alerts ADD COLUMN {column} {definition}")
                log_runtime(f"Database upgraded: added alerts.{column}")
            except sqlite3.OperationalError as e:
                # The engine and dashboard may start together and race here.
                if "duplicate column" not in str(e).lower():
                    raise

    # ── Alerts ─────────────────────────────────────────────────
    def insert_alert(self, alert_dict: dict) -> int:
        """Insert alert into database."""
        try:
            conn = self._connect()
            cursor = conn.cursor()

            cursor.execute("""
                INSERT INTO alerts
                (timestamp, src_ip, dst_ip, src_port, dst_port, attack_type,
                 attack_class, confidence, protocol, status, detector)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                alert_dict.get('timestamp'),
                alert_dict.get('src_ip'),
                alert_dict.get('dst_ip'),
                alert_dict.get('src_port') or 0,
                alert_dict.get('dst_port') or 0,
                alert_dict.get('attack_type'),
                alert_dict.get('attack_class'),
                alert_dict.get('confidence'),
                alert_dict.get('protocol', 'TCP'),
                alert_dict.get('status') or STATUS_DETECTED,
                alert_dict.get('detector') or 'UNKNOWN',
            ))

            conn.commit()
            alert_id = cursor.lastrowid
            conn.close()

            return alert_id

        except Exception as e:
            log_error("Failed to insert alert", e)
            return -1

    def get_recent_alerts(self, limit: int = 100) -> list:
        """Get recent alerts."""
        try:
            conn = self._connect()
            cursor = conn.cursor()

            cursor.execute(f"""
                SELECT {', '.join(_ALERT_COLUMNS)}
                FROM alerts
                ORDER BY timestamp DESC, id DESC
                LIMIT ?
            """, (limit,))

            rows = cursor.fetchall()
            conn.close()

            return [dict(zip(_ALERT_COLUMNS, row)) for row in rows]

        except Exception as e:
            log_error("Failed to get recent alerts", e)
            return []

    # ── Firewall blocks ────────────────────────────────────────
    def upsert_block(self, ip: str, attack_type: str, detector: str,
                     confidence: float, target_ip: Optional[str] = None,
                     timestamp: Optional[str] = None,
                     latency_ms: Optional[float] = None) -> None:
        """
        Record that `ip` is blocked. A repeat for an active block bumps its
        counters; a block after a reset starts a fresh record.
        """
        ts = timestamp or format_timestamp()
        try:
            conn = self._connect()
            conn.execute("""
                INSERT INTO blocked_ips
                    (ip, attack_type, detector, confidence, target_ip,
                     blocked_at, last_seen, alert_count, block_latency_ms, active)
                VALUES (?, ?, ?, ?, ?, ?, ?, 1, ?, 1)
                ON CONFLICT(ip) DO UPDATE SET
                    attack_type = CASE WHEN blocked_ips.active = 1
                                       THEN blocked_ips.attack_type ELSE excluded.attack_type END,
                    detector = CASE WHEN blocked_ips.active = 1
                                    THEN blocked_ips.detector ELSE excluded.detector END,
                    confidence = CASE WHEN blocked_ips.active = 1
                                      THEN MAX(COALESCE(blocked_ips.confidence, 0), excluded.confidence)
                                      ELSE excluded.confidence END,
                    target_ip = CASE WHEN blocked_ips.active = 1
                                     THEN blocked_ips.target_ip ELSE excluded.target_ip END,
                    blocked_at = CASE WHEN blocked_ips.active = 1
                                      THEN blocked_ips.blocked_at ELSE excluded.blocked_at END,
                    block_latency_ms = CASE WHEN blocked_ips.active = 1
                                            THEN blocked_ips.block_latency_ms
                                            ELSE excluded.block_latency_ms END,
                    alert_count = CASE WHEN blocked_ips.active = 1
                                       THEN blocked_ips.alert_count + 1 ELSE 1 END,
                    last_seen = excluded.last_seen,
                    active = 1,
                    unblocked_at = NULL
            """, (ip, attack_type, detector, confidence, target_ip, ts, ts, latency_ms))
            conn.commit()
            conn.close()
        except Exception as e:
            log_error(f"Failed to record block for {ip}", e)

    def reconcile_blocks(self, active_ips: Iterable[str], timestamp: Optional[str] = None) -> None:
        """
        Make `blocked_ips.active` match the kernel: rows whose rule is gone are
        marked lifted, and rules with no row (e.g. added by hand) get one.
        """
        ts = timestamp or format_timestamp()
        active = sorted(set(active_ips))
        try:
            conn = self._connect()
            if active:
                placeholders = ",".join("?" * len(active))
                conn.execute(f"""
                    UPDATE blocked_ips SET active = 0, unblocked_at = ?
                    WHERE active = 1 AND ip NOT IN ({placeholders})
                """, (ts, *active))
            else:
                conn.execute("""
                    UPDATE blocked_ips SET active = 0, unblocked_at = ?
                    WHERE active = 1
                """, (ts,))
            for ip in active:
                conn.execute("""
                    INSERT INTO blocked_ips
                        (ip, attack_type, detector, blocked_at, last_seen, alert_count, active)
                    VALUES (?, 'Restored', 'FIREWALL', ?, ?, 0, 1)
                    ON CONFLICT(ip) DO UPDATE SET active = 1, unblocked_at = NULL
                """, (ip, ts, ts))
            conn.commit()
            conn.close()
        except Exception as e:
            log_error("Failed to reconcile firewall blocks", e)

    def get_blocked_threats(self, active_only: bool = True, limit: int = 100) -> list:
        """Get firewall blocks, newest first."""
        try:
            conn = self._connect()
            where = "WHERE active = 1" if active_only else ""
            rows = conn.execute(f"""
                SELECT {', '.join(_BLOCK_COLUMNS)}
                FROM blocked_ips
                {where}
                ORDER BY active DESC, blocked_at DESC
                LIMIT ?
            """, (limit,)).fetchall()
            conn.close()
            blocks = [dict(zip(_BLOCK_COLUMNS, row)) for row in rows]
            for block in blocks:
                block["active"] = bool(block["active"])
            return blocks
        except Exception as e:
            log_error("Failed to get blocked threats", e)
            return []

    # ── Summaries ──────────────────────────────────────────────
    def get_alert_summary(self) -> dict:
        """Get alert summary statistics."""
        try:
            conn = self._connect()
            cursor = conn.cursor()

            # Total alerts
            cursor.execute("SELECT COUNT(*) FROM alerts")
            total = cursor.fetchone()[0]

            # Alerts by type
            cursor.execute("""
                SELECT attack_type, COUNT(*) FROM alerts
                GROUP BY attack_type
            """)

            type_counts = {row[0]: row[1] for row in cursor.fetchall()}

            conn.close()

            return {
                'total_alerts': total,
                'alerts_by_type': type_counts
            }

        except Exception as e:
            log_error("Failed to get alert summary", e)
            return {'total_alerts': 0, 'alerts_by_type': {}}

    def get_attack_statistics(self) -> dict:
        """Get detailed attack statistics for charts."""
        try:
            conn = self._connect()
            cursor = conn.cursor()

            # Only attack alerts (exclude Benign)
            cursor.execute("""
                SELECT COUNT(*) FROM alerts
                WHERE LOWER(attack_type) != 'benign'
            """)
            total_attacks = cursor.fetchone()[0]

            # Attack counts by type
            cursor.execute("""
                SELECT attack_type, COUNT(*) FROM alerts
                WHERE LOWER(attack_type) != 'benign'
                GROUP BY attack_type
            """)
            attack_type_counts = {row[0]: row[1] for row in cursor.fetchall()}

            # Severity distribution
            cursor.execute("""
                SELECT
                    SUM(CASE WHEN confidence >= 0.8 THEN 1 ELSE 0 END) as high,
                    SUM(CASE WHEN confidence >= 0.5 AND confidence < 0.8 THEN 1 ELSE 0 END) as medium,
                    SUM(CASE WHEN confidence < 0.5 THEN 1 ELSE 0 END) as low
                FROM alerts
                WHERE LOWER(attack_type) != 'benign'
            """)
            row = cursor.fetchone()
            severity = {
                'high': row[0] or 0,
                'medium': row[1] or 0,
                'low': row[2] or 0
            }

            # Protocol distribution
            cursor.execute("""
                SELECT protocol, COUNT(*) FROM alerts
                WHERE LOWER(attack_type) != 'benign'
                GROUP BY protocol
            """)
            protocol_counts = {row[0]: row[1] for row in cursor.fetchall()}

            # Prevention outcome distribution (BLOCKED, DETECTED, ...)
            cursor.execute("""
                SELECT status, COUNT(*) FROM alerts
                WHERE LOWER(attack_type) != 'benign'
                GROUP BY status
            """)
            status_counts = {row[0]: row[1] for row in cursor.fetchall()}

            conn.close()

            return {
                'total_attack_alerts': total_attacks,
                'attack_type_distribution': attack_type_counts,
                'severity_distribution': severity,
                'protocol_distribution': protocol_counts,
                'status_distribution': status_counts,
            }

        except Exception as e:
            log_error("Failed to get attack statistics", e)
            return {
                'total_attack_alerts': 0,
                'attack_type_distribution': {},
                'severity_distribution': {'high': 0, 'medium': 0, 'low': 0},
                'protocol_distribution': {},
                'status_distribution': {},
            }
