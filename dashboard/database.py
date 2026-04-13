"""
Database module for NIDS.

Manages SQLite database for storing alerts and metadata.
"""

import sqlite3
from pathlib import Path
import sys
from datetime import datetime

sys.path.insert(0, str(Path(__file__).parent.parent))

from utils.config import DATABASE_PATH
from utils.helpers import log_runtime, log_error

class Database:
    """Manages SQLite database for alerts."""
    
    def __init__(self, db_path: Path = DATABASE_PATH):
        """Initialize database."""
        self.db_path = db_path
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        
        self.initialize_database()
        log_runtime(f"Initialized database at {db_path}")
    
    def initialize_database(self) -> None:
        """Create database tables if they don't exist."""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            # Create alerts table
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
    
    def insert_alert(self, alert_dict: dict) -> int:
        """Insert alert into database."""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            cursor.execute("""
                INSERT INTO alerts 
                (timestamp, src_ip, dst_ip, src_port, dst_port, attack_type, attack_class, confidence, protocol)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                alert_dict.get('timestamp'),
                alert_dict.get('src_ip'),
                alert_dict.get('dst_ip'),
                alert_dict.get('src_port'),
                alert_dict.get('dst_port'),
                alert_dict.get('attack_type'),
                alert_dict.get('attack_class'),
                alert_dict.get('confidence'),
                alert_dict.get('protocol', 'TCP')
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
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            cursor.execute("""
                SELECT id, timestamp, src_ip, dst_ip, src_port, dst_port,
                       attack_type, attack_class, confidence, protocol
                FROM alerts
                ORDER BY timestamp DESC
                LIMIT ?
            """, (limit,))
            
            rows = cursor.fetchall()
            conn.close()
            
            alerts = [
                {
                    'id': row[0],
                    'timestamp': row[1],
                    'src_ip': row[2],
                    'dst_ip': row[3],
                    'src_port': row[4],
                    'dst_port': row[5],
                    'attack_type': row[6],
                    'attack_class': row[7],
                    'confidence': row[8],
                    'protocol': row[9]
                }
                for row in rows
            ]
            
            return alerts
            
        except Exception as e:
            log_error("Failed to get recent alerts", e)
            return []
    
    def get_alert_summary(self) -> dict:
        """Get alert summary statistics."""
        try:
            conn = sqlite3.connect(self.db_path)
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
            conn = sqlite3.connect(self.db_path)
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
            
            conn.close()
            
            return {
                'total_attack_alerts': total_attacks,
                'attack_type_distribution': attack_type_counts,
                'severity_distribution': severity,
                'protocol_distribution': protocol_counts
            }
            
        except Exception as e:
            log_error("Failed to get attack statistics", e)
            return {
                'total_attack_alerts': 0,
                'attack_type_distribution': {},
                'severity_distribution': {'high': 0, 'medium': 0, 'low': 0},
                'protocol_distribution': {}
            }
