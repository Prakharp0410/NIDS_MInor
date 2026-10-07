#!/usr/bin/env bash
# Edge-AI Sentinel gateway bring-up. Runs at boot (edge-sentinel-gateway
# service) before hostapd and dnsmasq. Idempotent: safe to run again.
#
#   1. Static address for the Wi-Fi access point interface
#   2. Kernel routing (IPv4 forwarding, client-to-client via the Pi)
#   3. Firewall baseline: NIPS block chain first, then forwarding + NAT
set -euo pipefail

ENV_FILE=/etc/edge-sentinel/edge-sentinel.env
if [[ -f $ENV_FILE ]]; then
    set -a; source "$ENV_FILE"; set +a
fi

LAN_IF=${EDGE_LAN_IF:-wlan0}
WAN_IF=${EDGE_WAN_IF:-eth0}
LAN_IP=${EDGE_LAN_IP:-192.168.77.1}
LAN_PREFIX=${EDGE_LAN_PREFIX:-24}
CHAIN=${EDGE_NIPS_CHAIN:-EDGE_SENTINEL}

log() { echo "[edge-sentinel-gateway] $*"; }
ipt() { iptables -w 5 "$@"; }
# Append a rule only if an identical one is not already present
ensure_rule() {
    local table=$1 chain=$2
    shift 2
    ipt -t "$table" -C "$chain" "$@" 2>/dev/null || ipt -t "$table" -A "$chain" "$@"
}

# ── 1. Access point address ──────────────────────────────────
# Raspberry Pi OS soft-blocks Wi-Fi until a country is set; hostapd sets it.
rfkill unblock wlan 2>/dev/null || true
ip addr replace "$LAN_IP/$LAN_PREFIX" dev "$LAN_IF"
log "$LAN_IF address $LAN_IP/$LAN_PREFIX"

# ── 2. Kernel routing (also persisted in /etc/sysctl.d) ─────
sysctl -q -w net.ipv4.ip_forward=1
sysctl -q -w "net.ipv4.conf.$LAN_IF.proxy_arp_pvlan=1"
sysctl -q -w "net.ipv4.neigh.$LAN_IF.proxy_delay=0"
sysctl -q -w net.ipv4.conf.all.send_redirects=0
sysctl -q -w "net.ipv4.conf.$LAN_IF.send_redirects=0"
log "IPv4 forwarding on, client-to-client traffic routed via the Pi"

# ── 3. Firewall baseline ─────────────────────────────────────
# NIPS block chain, evaluated first for traffic to the Pi (INPUT) and
# through it (FORWARD). The engine inserts one DROP rule per attacker here.
ipt -N "$CHAIN" 2>/dev/null || true
for parent in INPUT FORWARD; do
    ipt -C "$parent" -j "$CHAIN" 2>/dev/null || ipt -I "$parent" 1 -j "$CHAIN"
done

# Router policy: Wi-Fi may go out, only replies come back in
ensure_rule filter FORWARD -i "$LAN_IF" -o "$WAN_IF" -j ACCEPT
ensure_rule filter FORWARD -i "$WAN_IF" -o "$LAN_IF" -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT
# Client-to-client traffic hairpins through the Pi so the NIPS can inspect it
ensure_rule filter FORWARD -i "$LAN_IF" -o "$LAN_IF" -j ACCEPT
ipt -P FORWARD DROP

# NAT: Wi-Fi clients share the Pi's uplink address
ensure_rule nat POSTROUTING -o "$WAN_IF" -j MASQUERADE
log "firewall ready: chain $CHAIN, NAT $LAN_IF -> $WAN_IF"
