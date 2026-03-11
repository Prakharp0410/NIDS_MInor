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
    
    def get_alert_count(self) -> int:
        """Get total alert count."""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            cursor.execute("SELECT COUNT(*) FROM alerts")
            count = cursor.fetchone()[0]
            conn.close()
            
            return count
            
        except Exception as e:
            log_error("Failed to get alert count", e)
            return 0
    
    def get_alerts_by_type(self, attack_type: str, limit: int = 100) -> list:
        """Get alerts by attack type."""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            cursor.execute("""
                SELECT * FROM alerts
                WHERE attack_type = ?
                ORDER BY timestamp DESC
                LIMIT ?
            """, (attack_type, limit))
            
            rows = cursor.fetchall()
            conn.close()
            
            return rows
            
        except Exception as e:
            log_error("Failed to get alerts by type", e)
            return []
    
    def get_top_sources(self, limit: int = 10) -> list:
        """Get top source IPs by alert count."""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            cursor.execute("""
                SELECT src_ip, COUNT(*) as count
                FROM alerts
                GROUP BY src_ip
                ORDER BY count DESC
                LIMIT ?
            """, (limit,))
            
            rows = cursor.fetchall()
            conn.close()
            
            return [(row[0], row[1]) for row in rows]
            
        except Exception as e:
            log_error("Failed to get top sources", e)
            return []
    
    def insert_statistics(self, stats_dict: dict) -> None:
        """Insert statistics record."""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            cursor.execute("""
                INSERT INTO statistics
                (timestamp, packets_processed, active_flows, total_alerts)
                VALUES (?, ?, ?, ?)
            """, (
                stats_dict.get('timestamp', datetime.now().isoformat()),
                stats_dict.get('packets_processed', 0),
                stats_dict.get('active_flows', 0),
                stats_dict.get('total_alerts', 0)
            ))
            
            conn.commit()
            conn.close()
            
        except Exception as e:
            log_error("Failed to insert statistics", e)
    
    def get_statistics(self, limit: int = 100) -> list:
        """Get statistics history."""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            cursor.execute("""
                SELECT id, timestamp, packets_processed, active_flows, total_alerts
                FROM statistics
                ORDER BY timestamp DESC
                LIMIT ?
            """, (limit,))
            
            rows = cursor.fetchall()
            conn.close()
            
            return rows
            
        except Exception as e:
            log_error("Failed to get statistics", e)
            return []
    
    def clear_old_alerts(self, days: int = 30) -> int:
        """Delete alerts older than specified days."""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            cursor.execute("""
                DELETE FROM alerts
                WHERE datetime(timestamp) < datetime('now', ? || ' days')
            """, (f"-{days}",))
            
            conn.commit()
            deleted = cursor.rowcount
            conn.close()
            
            log_runtime(f"Deleted {deleted} old alerts")
            return deleted
            
        except Exception as e:
            log_error("Failed to clear old alerts", e)
            return 0
    
    def export_alerts(self, output_file: Path, format: str = 'csv') -> None:
        """Export alerts to file."""
        try:
            alerts = self.get_recent_alerts(limit=10000)
            
            if format == 'csv':
                import csv
                
                with open(output_file, 'w', newline='') as f:
                    if alerts:
                        writer = csv.DictWriter(f, fieldnames=alerts[0].keys())
                        writer.writeheader()
                        writer.writerows(alerts)
            
            elif format == 'json':
                import json
                
                with open(output_file, 'w') as f:
                    json.dump(alerts, f, indent=4)
            
            log_runtime(f"Exported {len(alerts)} alerts to {output_file}")
            
        except Exception as e:
            log_error(f"Failed to export alerts", e)
