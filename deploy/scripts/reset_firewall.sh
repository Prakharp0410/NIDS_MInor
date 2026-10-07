#!/usr/bin/env bash
# Edge-AI Sentinel: reset the NIPS between live demonstration runs.
#
#   sudo edge-sentinel-reset                                   # same, once installed
#   sudo bash deploy/scripts/reset_firewall.sh                 # unblock every attacker
#   sudo bash deploy/scripts/reset_firewall.sh --clear-alerts  # ...and wipe alert history
#   sudo bash deploy/scripts/reset_firewall.sh --full          # flush ALL iptables rules,
#                                                              # then rebuild NAT + chain
#
# The default only flushes the NIPS block chain, so Wi-Fi clients keep their
# internet access (NAT) throughout the demo.
set -euo pipefail

# Resolve symlinks: the installer links this script as edge-sentinel-reset.
SCRIPT_DIR="$(cd "$(dirname "$(readlink -f "${BASH_SOURCE[0]}")")" && pwd)"
APP_DIR="$(cd "$SCRIPT_DIR/../.." && pwd)"
ENV_FILE=/etc/edge-sentinel/edge-sentinel.env
ENGINE_UNIT=edge-sentinel-engine.service
GATEWAY_UNIT=edge-sentinel-gateway.service

FULL=0
CLEAR_ALERTS=0

usage() { sed -n '2,11p' "$SCRIPT_DIR/reset_firewall.sh" | sed 's/^# \{0,1\}//'; }
log()  { echo "[reset] $*"; }
warn() { echo "[reset] WARNING: $*" >&2; }
die()  { echo "[reset] ERROR: $*" >&2; exit 1; }

for arg in "$@"; do
    case "$arg" in
        --full) FULL=1 ;;
        --clear-alerts) CLEAR_ALERTS=1 ;;
        -h|--help) usage; exit 0 ;;
        *) usage; die "unknown option: $arg" ;;
    esac
done

[[ $EUID -eq 0 ]] || die "run as root: sudo bash $0 $*"
command -v iptables >/dev/null || die "iptables is not installed"

if [[ -f $ENV_FILE ]]; then
    set -a; source "$ENV_FILE"; set +a
fi
CHAIN=${EDGE_NIPS_CHAIN:-EDGE_SENTINEL}
DB_PATH=${EDGE_DB_PATH:-$APP_DIR/alerts.db}
ipt() { iptables -w 5 "$@"; }
has_systemd_unit() { command -v systemctl >/dev/null && systemctl cat "$1" >/dev/null 2>&1; }

# ── 1. Kernel firewall ───────────────────────────────────────
if (( FULL )); then
    log "Flushing every iptables rule in the filter and nat tables"
    ipt -P INPUT ACCEPT
    ipt -P FORWARD ACCEPT
    ipt -P OUTPUT ACCEPT
    ipt -F
    ipt -X
    ipt -t nat -F
    ipt -t nat -X
    if has_systemd_unit "$GATEWAY_UNIT"; then
        log "Rebuilding the gateway baseline (NAT + $CHAIN)"
        systemctl restart "$GATEWAY_UNIT"
    else
        warn "$GATEWAY_UNIT is not installed: NAT is now off until you re-run gateway_up.sh"
    fi
elif ipt -S "$CHAIN" >/dev/null 2>&1; then
    count=$(ipt -S "$CHAIN" | grep -c -- '-j DROP' || true)
    ipt -F "$CHAIN"
    log "Removed $count block rule(s) from chain $CHAIN"
else
    log "Chain $CHAIN does not exist yet; nothing to unblock"
fi

# ── 2. Dashboard database ────────────────────────────────────
if [[ -f $DB_PATH ]] && command -v python3 >/dev/null; then
    python3 - "$DB_PATH" "$CLEAR_ALERTS" <<'PY'
import datetime
import sqlite3
import sys

db_path, clear = sys.argv[1], sys.argv[2] == "1"
now = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
con = sqlite3.connect(db_path, timeout=10)
tables = {row[0] for row in con.execute("SELECT name FROM sqlite_master WHERE type='table'")}
if clear:
    for table in ("alerts", "blocked_ips"):
        if table in tables:
            con.execute(f"DELETE FROM {table}")
    print("[reset] Cleared alert and block history")
elif "blocked_ips" in tables:
    lifted = con.execute(
        "UPDATE blocked_ips SET active = 0, unblocked_at = ? WHERE active = 1", (now,)
    ).rowcount
    print(f"[reset] Marked {lifted} block(s) as lifted in the dashboard")
con.commit()
con.close()
PY
else
    log "No dashboard database at $DB_PATH; skipping"
fi

# ── 3. Engine memory ─────────────────────────────────────────
# The engine keeps an in-memory set of blocked IPs; restarting it re-reads
# the (now empty) chain so former attackers can be detected and blocked again.
if command -v systemctl >/dev/null && systemctl is-active --quiet "$ENGINE_UNIT"; then
    systemctl restart "$ENGINE_UNIT"
    log "Restarted $ENGINE_UNIT"
else
    warn "If the engine runs by hand (not as $ENGINE_UNIT), restart it now."
fi

log "Current NIPS chain:"
ipt -L "$CHAIN" -n -v --line-numbers 2>/dev/null || log "(chain $CHAIN not present)"
