"""
FastAPI Dashboard for NIDS.

Provides REST API endpoints to monitor alerts and system status.
"""

from fastapi import FastAPI, HTTPException
from fastapi.responses import JSONResponse
from pathlib import Path
import sys
import sqlite3
from datetime import datetime, timedelta

sys.path.insert(0, str(Path(__file__).parent.parent))

from utils.config import DASHBOARD_HOST, DASHBOARD_PORT, DATABASE_PATH
from utils.helpers import log_runtime, load_json

# Initialize FastAPI app
app = FastAPI(
    title="NIDS Dashboard API",
    description="Network Intrusion Detection System Dashboard",
    version="1.0.0"
)

# Global state
class SystemState:
    """Holds system state."""
    alerts = []
    stats = {}
    is_running = False

state = SystemState()

@app.get("/")
async def root():
    """Root endpoint."""
    return {
        "title": "NIDS Dashboard API",
        "endpoints": {
            "/alerts": "Get recent alerts",
            "/alerts/summary": "Get alert summary",
            "/stats": "Get system statistics",
            "/flows": "Get active flows",
            "/health": "System health check"
        }
    }

@app.get("/health")
async def health_check():
    """Health check endpoint."""
    return {
        "status": "healthy",
        "timestamp": datetime.now().isoformat(),
        "is_running": state.is_running
    }

@app.get("/alerts")
async def get_alerts(limit: int = 20):
    """Get recent alerts."""
    try:
        # Load alerts from database
        conn = sqlite3.connect(DATABASE_PATH)
        cursor = conn.cursor()
        
        cursor.execute("""
            SELECT timestamp, src_ip, dst_ip, src_port, dst_port, 
                   attack_type, confidence, protocol
            FROM alerts
            ORDER BY timestamp DESC
            LIMIT ?
        """, (limit,))
        
        rows = cursor.fetchall()
        conn.close()
        
        alerts = [
            {
                "timestamp": row[0],
                "src_ip": row[1],
                "dst_ip": row[2],
                "src_port": row[3],
                "dst_port": row[4],
                "attack_type": row[5],
                "confidence": row[6],
                "protocol": row[7]
            }
            for row in rows
        ]
        
        return {
            "count": len(alerts),
            "alerts": alerts
        }
        
    except Exception as e:
        log_runtime(f"Error fetching alerts: {e}", "ERROR")
        return {"count": 0, "alerts": []}

@app.get("/alerts/summary")
async def get_alerts_summary():
    """Get alert summary statistics."""
    try:
        conn = sqlite3.connect(DATABASE_PATH)
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
        
        # Alerts last hour
        one_hour_ago = (datetime.now() - timedelta(hours=1)).isoformat()
        cursor.execute("SELECT COUNT(*) FROM alerts WHERE timestamp > ?", (one_hour_ago,))
        last_hour = cursor.fetchone()[0]
        
        conn.close()
        
        return {
            "total_alerts": total,
            "alerts_last_hour": last_hour,
            "alerts_by_type": type_counts
        }
        
    except Exception as e:
        log_runtime(f"Error fetching summary: {e}", "ERROR")
        return {"error": str(e)}

@app.get("/stats")
async def get_statistics():
    """Get system statistics."""
    return {
        "timestamp": datetime.now().isoformat(),
        "is_running": state.is_running,
        "packets_processed": state.stats.get("packets_processed", 0),
        "active_flows": state.stats.get("active_flows", 0),
        "total_alerts": state.stats.get("total_alerts", 0),
        "inference_ready": state.stats.get("inference_ready", False)
    }

@app.get("/flows")
async def get_active_flows():
    """Get active network flows."""
    try:
        # This would be implemented with actual flow data
        return {
            "active_flows": state.stats.get("active_flows", 0),
            "flows": []
        }
    except Exception as e:
        return {"error": str(e)}

@app.post("/alerts")
async def create_alert(alert_data: dict):
    """Create a new alert."""
    try:
        conn = sqlite3.connect(DATABASE_PATH)
        cursor = conn.cursor()
        
        cursor.execute("""
            INSERT INTO alerts 
            (timestamp, src_ip, dst_ip, src_port, dst_port, attack_type, confidence, protocol)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            alert_data["timestamp"],
            alert_data["src_ip"],
            alert_data["dst_ip"],
            alert_data["src_port"],
            alert_data["dst_port"],
            alert_data["attack_type"],
            alert_data["confidence"],
            alert_data.get("protocol", "TCP")
        ))
        
        conn.commit()
        conn.close()
        
        return {"success": True}
        
    except Exception as e:
        log_runtime(f"Error creating alert: {e}", "ERROR")
        raise HTTPException(status_code=400, detail=str(e))

@app.get("/config")
async def get_configuration():
    """Get system configuration."""
    return {
        "dashboard_host": DASHBOARD_HOST,
        "dashboard_port": DASHBOARD_PORT,
        "database_path": str(DATABASE_PATH)
    }

def setup_api(alerts_list: list = None, stats: dict = None):
    """Setup API with external state."""
    global state
    if alerts_list:
        state.alerts = alerts_list
    if stats:
        state.stats = stats

def run_dashboard(host: str = DASHBOARD_HOST, port: int = DASHBOARD_PORT):
    """Run FastAPI dashboard."""
    import uvicorn
    
    log_runtime(f"Starting NIDS Dashboard on {host}:{port}")
    
    uvicorn.run(
        app,
        host=host,
        port=port,
        log_level="info"
    )

if __name__ == "__main__":
    run_dashboard()
