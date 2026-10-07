"""
FastAPI Dashboard for the Edge-AI Sentinel NIDS/NIPS.

Provides REST API endpoints to monitor alerts, system status and the
firewall blocks enforced by the NIPS kill-switch.
Database-backed persistent storage (integrates with Raspberry Pi NIDS).
"""

from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from pathlib import Path
import sys
import sqlite3
import time
from datetime import datetime, timedelta
from typing import Dict, Optional

sys.path.insert(0, str(Path(__file__).parent.parent))

from utils.config import (DASHBOARD_HOST, DASHBOARD_PORT, DATABASE_PATH,
                          NIPS_CHAIN, NIPS_MODE)
from utils.helpers import log_runtime
from dashboard.database import Database
from raspberry_pi.firewall import read_chain_state

BASE_DIR = Path(__file__).parent
TEMPLATES_DIR = BASE_DIR / "templates"
STATIC_DIR = BASE_DIR / "static"

# Initialize FastAPI app
app = FastAPI(
    title="Edge-AI Sentinel NIPS Dashboard API",
    description="Network Intrusion Prevention System Dashboard",
    version="3.0.0"
)

app.mount("/static", StaticFiles(directory=str(STATIC_DIR)), name="static")
templates = Jinja2Templates(directory=str(TEMPLATES_DIR))

# Initialize database
db = Database(DATABASE_PATH)

# Global state
class SystemState:
    """Holds system state."""
    is_running = False
    stats = {}

state = SystemState()

# Live kernel firewall state, cached so several open dashboards polling every
# few seconds do not each spawn an iptables process.
FIREWALL_CACHE_SECONDS = 2.0
_firewall_cache = {"at": float("-inf"), "state": None}


def _read_firewall_state() -> Optional[Dict[str, Dict[str, int]]]:
    """{ip: {"packets", "bytes"}} from the NIPS chain, or None if unreadable."""
    now = time.monotonic()
    if now - _firewall_cache["at"] >= FIREWALL_CACHE_SECONDS:
        try:
            _firewall_cache["state"] = read_chain_state()
        except Exception as e:
            log_runtime(f"Error reading firewall state: {e}", "ERROR")
            _firewall_cache["state"] = None
        _firewall_cache["at"] = now
    return _firewall_cache["state"]

@app.get("/")
async def root():
    """Root endpoint."""
    return {
        "title": "NIDS Dashboard API",
        "endpoints": {
            "/dashboard": "Visual monitoring dashboard",
            "/alerts": "Get recent alerts",
            "/alerts/summary": "Get alert summary",
            "/blocked_threats": "Attacker IPs currently blocked by the NIPS firewall",
            "/stats": "Get system statistics",
            "/flows": "Get active flows",
            "/health": "System health check"
        }
    }

@app.get("/dashboard", response_class=HTMLResponse)
async def dashboard(request: Request):
    """Render the visual dashboard."""
    return templates.TemplateResponse(
        request,
        "index.html",
        {
            "request": request,
            "title": "NIDS Command Center"
        }
    )

@app.get("/health")
async def health_check():
    """Health check endpoint."""
    return {
        "status": "healthy",
        "timestamp": datetime.now().isoformat(),
        "is_running": state.is_running,
        "nips_mode": NIPS_MODE
    }

@app.get("/alerts")
async def get_alerts(limit: int = 50):
    """Get recent ATTACK alerts from database (filters out Benign traffic)."""
    try:
        # Get all recent alerts from database
        all_alerts = db.get_recent_alerts(limit * 2)  # Get more to filter
        
        # Filter only attack alerts (exclude Benign)
        attack_alerts = [
            alert for alert in all_alerts 
            if alert.get("attack_type", "").lower() != "benign"
        ][:limit]
        
        return {
            "count": len(attack_alerts),
            "alerts": attack_alerts
        }
        
    except Exception as e:
        log_runtime(f"Error fetching alerts: {e}", "ERROR")
        return {"count": 0, "alerts": []}

@app.get("/alerts/summary")
async def get_alerts_summary():
    """Get alert summary statistics from database."""
    try:
        # Get summary from database
        summary = db.get_alert_summary()
        
        # Only count attacks (exclude Benign)
        attack_counts = {
            k: v for k, v in summary['alerts_by_type'].items()
            if k.lower() != 'benign'
        }
        
        # Alerts last hour
        one_hour_ago = (datetime.now() - timedelta(hours=1))
        recent_alerts = db.get_recent_alerts(1000)
        last_hour = 0
        for alert in recent_alerts:
            try:
                alert_time = datetime.fromisoformat(alert.get("timestamp", ""))
                if alert_time > one_hour_ago and alert.get("attack_type", "").lower() != "benign":
                    last_hour += 1
            except:
                pass
        
        return {
            "total_alerts": sum(attack_counts.values()),
            "alerts_last_hour": last_hour,
            "alerts_by_type": attack_counts
        }
        
    except Exception as e:
        log_runtime(f"Error fetching summary: {e}", "ERROR")
        return {"total_alerts": 0, "alerts_last_hour": 0, "alerts_by_type": {}}

@app.get("/stats")
async def get_statistics():
    """Get system statistics with attack data for charts from database."""
    try:
        # Get attack statistics from database
        stats_data = db.get_attack_statistics()
        
        # Alerts last hour
        one_hour_ago = (datetime.now() - timedelta(hours=1))
        recent_alerts = db.get_recent_alerts(1000)
        last_hour = 0
        for alert in recent_alerts:
            try:
                alert_time = datetime.fromisoformat(alert.get("timestamp", ""))
                if alert_time > one_hour_ago and alert.get("attack_type", "").lower() != "benign":
                    last_hour += 1
            except:
                pass
        
        return {
            "timestamp": datetime.now().isoformat(),
            "total_attack_alerts": stats_data['total_attack_alerts'],
            "alerts_last_hour": last_hour,
            "attack_type_distribution": stats_data['attack_type_distribution'],
            "severity_distribution": stats_data['severity_distribution'],
            "protocol_distribution": stats_data['protocol_distribution'],
            "status_distribution": stats_data.get('status_distribution', {}),
            "active_flows": state.stats.get("active_flows", 0),
            "packets_processed": state.stats.get("packets_processed", 0)
        }
    except Exception as e:
        log_runtime(f"Error fetching statistics: {e}", "ERROR")
        return {"error": str(e)}

@app.get("/blocked_threats")
def get_blocked_threats(include_history: bool = False, limit: int = 100):
    """
    Attacker IPs blocked by the NIPS kill-switch.

    Each entry is cross-checked against the live iptables chain: `enforced`
    says whether the DROP rule is really in the kernel and `dropped_packets`
    counts the attack traffic it has discarded. Both are null when the
    dashboard cannot read the firewall (not root, not Linux, or not enforcing).
    Declared without `async` so the iptables call runs in a worker thread.
    """
    try:
        blocks = db.get_blocked_threats(active_only=not include_history, limit=limit)
        kernel = _read_firewall_state()

        for block in blocks:
            counters = kernel.get(block["ip"]) if kernel is not None else None
            if kernel is None or not block["active"]:
                block["enforced"] = None if block["active"] else False
            else:
                block["enforced"] = counters is not None
            block["dropped_packets"] = counters["packets"] if counters else None
            block["dropped_bytes"] = counters["bytes"] if counters else None

        active = [b for b in blocks if b["active"]]
        return {
            "mode": NIPS_MODE,
            "chain": NIPS_CHAIN,
            "firewall_visible": kernel is not None,
            "count": len(active),
            "total_dropped_packets": (sum(v["packets"] for v in kernel.values())
                                      if kernel is not None else None),
            "blocked": blocks,
        }

    except Exception as e:
        log_runtime(f"Error fetching blocked threats: {e}", "ERROR")
        return {"mode": NIPS_MODE, "chain": NIPS_CHAIN, "firewall_visible": False,
                "count": 0, "total_dropped_packets": None, "blocked": []}

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
    """Create a new alert and store in database (from Raspberry Pi NIDS)."""
    try:
        # Insert alert into database
        alert_id = db.insert_alert(alert_data)
        
        if alert_id > 0:
            log_runtime(f"Alert recorded: {alert_data.get('attack_type')} from {alert_data.get('src_ip')}")
            return {"success": True, "alert_id": alert_id}
        else:
            raise Exception("Failed to insert alert")
        
    except Exception as e:
        log_runtime(f"Error creating alert: {e}", "ERROR")
        raise HTTPException(status_code=400, detail=str(e))

@app.get("/config")
async def get_configuration():
    """Get system configuration."""
    return {
        "dashboard_host": DASHBOARD_HOST,
        "dashboard_port": DASHBOARD_PORT,
        "storage_type": "SQLite Database (Persistent)",
        "database_path": str(DATABASE_PATH),
        "nips_mode": NIPS_MODE,
        "nips_chain": NIPS_CHAIN
    }

def setup_api(stats: dict = None):
    """Setup API with external state."""
    global state
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
