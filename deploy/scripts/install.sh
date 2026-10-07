#!/usr/bin/env bash
# Edge-AI Sentinel installer: turns a Raspberry Pi 5 into a plug-and-play
# NIPS gateway. Run it once, as root, from anywhere inside the project:
#
#   sudo bash deploy/scripts/install.sh
#
# Settings are environment variables. Put them after `sudo` so they survive
# sudo's environment reset, for example:
#
#   sudo EDGE_SSID=Lab_IoT AP_PASSPHRASE='a-long-secret' \
#        EDGE_NIPS_WHITELIST=192.168.77.20 bash deploy/scripts/install.sh
#
#   EDGE_SSID            Wi-Fi name                    [Edge_Sentinel_Net]
#   AP_PASSPHRASE        WPA2 passphrase, 8-63 chars   [generated once, then reused]
#   EDGE_COUNTRY         Wi-Fi regulatory country      [IN]
#   EDGE_CHANNEL         2.4 GHz channel 1-13          [6]
#   EDGE_LAN_IF          access point interface        [wlan0]
#   EDGE_WAN_IF          internet uplink interface     [eth0]
#   EDGE_LAN_IP          gateway address on the Wi-Fi  [192.168.77.1]
#   EDGE_LAN_PREFIX      Wi-Fi subnet prefix length    [24]
#   EDGE_DHCP_START/END  DHCP pool                     [.10 to .200 of the subnet]
#   EDGE_NIPS_MODE       enforce | dry-run | off       [enforce]
#   EDGE_NIPS_BLOCK_SCOPE lan | any                    [lan]
#   EDGE_NIPS_WHITELIST  never-blocked IPs/CIDRs, comma-separated  []
#   EDGE_RULE_BLOCK_MIN_CONF / EDGE_ML_BLOCK_MIN_CONF  [0.60 / 0.90]
#   EDGE_ML_ALERT_MIN_CONF  lowest ML confidence that raises an alert [0.60]
#   EDGE_ML_BATCH_SIZE / EDGE_ML_MAX_DELAY  ML batching [32 flows / 0.25 s]
#   EDGE_FLOW_TIMEOUT / EDGE_MAX_FLOWS      flow table  [120 s / 20000]
#   EDGE_STATS_INTERVAL  seconds between [stats] log lines [30]
#   EDGE_DASHBOARD_PORT  dashboard port                [8000]
#   EDGE_PYTHON          interpreter with the project's packages
#                        [venv inside the project, else python3]
#
# A re-run keeps earlier settings unless you override them.
# Options: --skip-apt   do not install packages (offline re-run)
#
# Nothing changes on the radio until you reboot. After the reboot the Pi's
# Wi-Fi becomes the access point and stops joining other networks, so run
# this over Ethernet or with a keyboard and screen.
set -euo pipefail
# Bash 5.2+: keep "&" in substituted values literal
shopt -u patsub_replacement 2>/dev/null || true

SCRIPT_DIR="$(cd "$(dirname "$(readlink -f "${BASH_SOURCE[0]}")")" && pwd)"
APP_DIR="$(cd "$SCRIPT_DIR/../.." && pwd)"
DEPLOY_DIR="$APP_DIR/deploy"
APP_LINK=/opt/edge-sentinel
ETC_DIR=/etc/edge-sentinel
ENV_FILE=$ETC_DIR/edge-sentinel.env
PASS_FILE=$ETC_DIR/ap_passphrase
UNITS=(edge-sentinel-gateway edge-sentinel-engine edge-sentinel-dashboard)

log()  { echo "[install] $*"; }
warn() { echo "[install] WARNING: $*" >&2; }
die()  { echo "[install] ERROR: $*" >&2; exit 1; }
usage() { sed -n '2,39p' "$SCRIPT_DIR/install.sh" | sed 's/^# \{0,1\}//'; }

SKIP_APT=0
for arg in "$@"; do
    case "$arg" in
        --skip-apt) SKIP_APT=1 ;;
        -h|--help) usage; exit 0 ;;
        *) usage; die "unknown option: $arg" ;;
    esac
done

[[ $EUID -eq 0 ]] || die "run as root: sudo bash $0"
[[ "$(uname -s)" == Linux ]] || die "this installer targets Raspberry Pi OS (Linux)"
command -v python3 >/dev/null || die "python3 is required"

# ── 1. Settings: explicit environment > previous install > defaults ──
SETTINGS=(EDGE_LAN_IF EDGE_WAN_IF EDGE_LAN_IP EDGE_LAN_PREFIX EDGE_DHCP_START
          EDGE_DHCP_END EDGE_SSID EDGE_COUNTRY EDGE_CHANNEL EDGE_NIPS_MODE
          EDGE_NIPS_CHAIN EDGE_NIPS_BLOCK_SCOPE EDGE_NIPS_WHITELIST
          EDGE_RULE_BLOCK_MIN_CONF EDGE_ML_BLOCK_MIN_CONF EDGE_DASHBOARD_PORT
          EDGE_PYTHON EDGE_ML_ALERT_MIN_CONF EDGE_ML_BATCH_SIZE EDGE_ML_MAX_DELAY
          EDGE_FLOW_TIMEOUT EDGE_MAX_FLOWS EDGE_STATS_INTERVAL)
declare -A EXPLICIT=()
for name in "${SETTINGS[@]}"; do
    if [[ -n "${!name+x}" ]]; then EXPLICIT[$name]="${!name}"; fi
done
if [[ -f $ENV_FILE ]]; then
    log "Keeping settings from $ENV_FILE (override with environment variables)"
    set -a; source "$ENV_FILE"; set +a
fi
for name in "${!EXPLICIT[@]}"; do printf -v "$name" '%s' "${EXPLICIT[$name]}"; done
# A moved subnet invalidates a DHCP pool carried over from a previous install
if [[ -n ${EXPLICIT[EDGE_LAN_IP]+x}${EXPLICIT[EDGE_LAN_PREFIX]+x} ]]; then
    [[ -n ${EXPLICIT[EDGE_DHCP_START]+x} ]] || unset EDGE_DHCP_START
    [[ -n ${EXPLICIT[EDGE_DHCP_END]+x} ]] || unset EDGE_DHCP_END
fi

: "${EDGE_LAN_IF:=wlan0}"
: "${EDGE_WAN_IF:=eth0}"
: "${EDGE_LAN_IP:=192.168.77.1}"
: "${EDGE_LAN_PREFIX:=24}"
: "${EDGE_SSID:=Edge_Sentinel_Net}"
: "${EDGE_COUNTRY:=IN}"
: "${EDGE_CHANNEL:=6}"
: "${EDGE_NIPS_MODE:=enforce}"
: "${EDGE_NIPS_CHAIN:=EDGE_SENTINEL}"
: "${EDGE_NIPS_BLOCK_SCOPE:=lan}"
: "${EDGE_NIPS_WHITELIST:=}"
: "${EDGE_RULE_BLOCK_MIN_CONF:=0.60}"
: "${EDGE_ML_BLOCK_MIN_CONF:=0.90}"
: "${EDGE_DASHBOARD_PORT:=8000}"
: "${EDGE_PYTHON:=}"
: "${EDGE_ML_ALERT_MIN_CONF:=0.60}"
: "${EDGE_ML_BATCH_SIZE:=32}"
: "${EDGE_ML_MAX_DELAY:=0.25}"
: "${EDGE_FLOW_TIMEOUT:=120}"
: "${EDGE_MAX_FLOWS:=20000}"
: "${EDGE_STATS_INTERVAL:=30}"

ssid_re='^[A-Za-z0-9 _.-]{1,32}$'
[[ $EDGE_SSID =~ $ssid_re ]] || die "EDGE_SSID must be 1-32 letters, digits, spaces, _ . -"
[[ $EDGE_COUNTRY =~ ^[A-Z]{2}$ ]] || die "EDGE_COUNTRY must be a two-letter code such as IN"
[[ $EDGE_CHANNEL =~ ^([1-9]|1[0-3])$ ]] || die "EDGE_CHANNEL must be 1-13"
[[ $EDGE_LAN_IF =~ ^[A-Za-z0-9_.-]+$ && $EDGE_WAN_IF =~ ^[A-Za-z0-9_.-]+$ ]] || die "invalid interface name"
[[ $EDGE_NIPS_MODE =~ ^(enforce|dry-run|off)$ ]] || die "EDGE_NIPS_MODE must be enforce, dry-run or off"
[[ $EDGE_NIPS_BLOCK_SCOPE =~ ^(lan|any)$ ]] || die "EDGE_NIPS_BLOCK_SCOPE must be lan or any"
[[ $EDGE_NIPS_CHAIN =~ ^[A-Za-z0-9_-]{1,28}$ ]] || die "invalid EDGE_NIPS_CHAIN"
[[ $EDGE_NIPS_WHITELIST =~ ^[0-9./,]*$ ]] || die "EDGE_NIPS_WHITELIST must be comma-separated IPs or CIDRs"
[[ $EDGE_DASHBOARD_PORT =~ ^[0-9]{2,5}$ ]] || die "invalid EDGE_DASHBOARD_PORT"
number_re='^[0-9]+(\.[0-9]+)?$'
for name in EDGE_RULE_BLOCK_MIN_CONF EDGE_ML_BLOCK_MIN_CONF EDGE_ML_ALERT_MIN_CONF \
            EDGE_ML_BATCH_SIZE EDGE_ML_MAX_DELAY EDGE_FLOW_TIMEOUT EDGE_MAX_FLOWS \
            EDGE_STATS_INTERVAL; do
    [[ ${!name} =~ $number_re ]] || die "$name must be a number"
done

# Subnet maths and validation, done once in Python
net_info=$(python3 - "$EDGE_LAN_IP" "$EDGE_LAN_PREFIX" "${EDGE_DHCP_START:-}" "${EDGE_DHCP_END:-}" <<'PY'
import ipaddress
import sys

ip, prefix, start, end = sys.argv[1:5]
try:
    iface = ipaddress.IPv4Interface(f"{ip}/{prefix}")
except ValueError as exc:
    sys.exit(f"invalid EDGE_LAN_IP/EDGE_LAN_PREFIX: {exc}")
net = iface.network
if not 16 <= net.prefixlen <= 29:
    sys.exit("EDGE_LAN_PREFIX must be between 16 and 29")
first, last = net.network_address + 1, net.broadcast_address - 1
start = ipaddress.IPv4Address(start) if start else min(net.network_address + 10, last)
end = ipaddress.IPv4Address(end) if end else min(net.network_address + 200, last)
if not (first <= start <= end <= last):
    sys.exit(f"DHCP range {start}-{end} must lie inside {net}")
if start <= iface.ip <= end:
    sys.exit(f"DHCP range {start}-{end} must not contain the gateway {iface.ip}")
print(net, net.netmask, start, end)
PY
) || die "network settings rejected"
read -r EDGE_LAN_SUBNET LAN_NETMASK EDGE_DHCP_START EDGE_DHCP_END <<<"$net_info"

# WPA2 passphrase: explicit > stored from a previous run > newly generated
if [[ -n ${AP_PASSPHRASE:-} ]]; then
    PASSPHRASE=$AP_PASSPHRASE
elif [[ -s $PASS_FILE ]]; then
    PASSPHRASE=$(<"$PASS_FILE")
else
    PASSPHRASE=$(python3 -c 'import secrets, string; a = string.ascii_letters + string.digits; print("".join(secrets.choice(a) for _ in range(12)))')
    log "Generated a new Wi-Fi passphrase (stored in $PASS_FILE)"
fi
pass_re='^[ -~]{8,63}$'
LC_ALL=C
[[ $PASSPHRASE =~ $pass_re ]] || die "AP_PASSPHRASE must be 8-63 printable ASCII characters"

[[ -e /sys/class/net/$EDGE_LAN_IF ]] || warn "interface $EDGE_LAN_IF not found (is Wi-Fi present?)"
[[ -e /sys/class/net/$EDGE_WAN_IF ]] || warn "interface $EDGE_WAN_IF not found (uplink cable/adapter?)"

# ── 2. Python interpreter with the project's packages ─────────────
if [[ -z $EDGE_PYTHON ]]; then
    for candidate in venv .venv nids_env env; do
        if [[ -x "$APP_DIR/$candidate/bin/python" ]]; then
            EDGE_PYTHON="$APP_DIR/$candidate/bin/python"
            break
        fi
    done
    : "${EDGE_PYTHON:=$(command -v python3)}"
fi
# Reach a project venv through the space-free /opt/edge-sentinel link
if [[ $EDGE_PYTHON == "$APP_DIR"/* ]]; then
    EDGE_PYTHON="$APP_LINK/${EDGE_PYTHON#"$APP_DIR"/}"
fi
missing=()
for module in scapy sklearn joblib numpy fastapi uvicorn jinja2; do
    "${EDGE_PYTHON/#$APP_LINK/$APP_DIR}" -c "import $module" 2>/dev/null || missing+=("$module")
done
if (( ${#missing[@]} )); then
    warn "Python at $EDGE_PYTHON lacks: ${missing[*]}"
    warn "Install them before rebooting, e.g.: $EDGE_PYTHON -m pip install -r $APP_DIR/requirements-pi.txt"
fi
# The saved model only loads correctly with the scikit-learn it was built with
sk_version=$("${EDGE_PYTHON/#$APP_LINK/$APP_DIR}" -c 'import sklearn; print(sklearn.__version__)' 2>/dev/null || true)
if [[ -n $sk_version && $sk_version != 1.6.1 ]]; then
    warn "scikit-learn $sk_version found; the model needs 1.6.1 (pip install -r requirements-pi.txt)"
fi

# ── 3. Packages ──────────────────────────────────────────────────
if (( ! SKIP_APT )); then
    log "Installing hostapd, dnsmasq, iptables, rfkill, tcpdump"
    apt-get update
    # tcpdump lets Scapy compile the engine's "ip" capture filter in the kernel
    DEBIAN_FRONTEND=noninteractive apt-get install -y hostapd dnsmasq iptables rfkill tcpdump
fi
for tool in hostapd dnsmasq iptables; do
    command -v "$tool" >/dev/null || [[ -x /usr/sbin/$tool ]] || die "$tool is not installed (drop --skip-apt)"
done

# ── 4. Render configuration files ────────────────────────────────
declare -A TPL=(
    [LAN_IF]=$EDGE_LAN_IF [SSID]=$EDGE_SSID [COUNTRY]=$EDGE_COUNTRY
    [CHANNEL]=$EDGE_CHANNEL [PASSPHRASE]=$PASSPHRASE [LAN_IP]=$EDGE_LAN_IP
    [NETMASK]=$LAN_NETMASK [DHCP_START]=$EDGE_DHCP_START [DHCP_END]=$EDGE_DHCP_END
    [DASHBOARD_PORT]=$EDGE_DASHBOARD_PORT [APP_DIR]=$APP_LINK [PYTHON]=$EDGE_PYTHON
)
# Fixed order; the passphrase goes last so its text is never re-substituted
TPL_ORDER=(LAN_IF SSID COUNTRY CHANNEL LAN_IP NETMASK DHCP_START DHCP_END
           DASHBOARD_PORT APP_DIR PYTHON PASSPHRASE)
render() {  # render <template> <destination> <mode>
    local src=$1 dest=$2 mode=$3 content key token
    for token in $(grep -o '@[A-Z_]*@' "$src" | sort -u); do
        key=${token//@/}
        [[ -n ${TPL[$key]+x} ]] || die "no value for placeholder $token in $src"
    done
    content="$(<"$src")"
    for key in "${TPL_ORDER[@]}"; do
        content="${content//"@${key}@"/"${TPL[$key]}"}"
    done
    install -d -m 755 "$(dirname "$dest")"
    printf '%s\n' "$content" > "$dest.tmp"
    chmod "$mode" "$dest.tmp"
    mv -f "$dest.tmp" "$dest"
    log "wrote $dest"
}
backup_once() {  # keep the original of a file we take over
    local file=$1
    if [[ -f $file && ! -f $file.pre-edge-sentinel ]] && ! grep -q "Edge-AI Sentinel" "$file"; then
        cp -p "$file" "$file.pre-edge-sentinel"
        log "backed up $file"
    fi
}

install -d -m 755 "$ETC_DIR"
umask 077
printf '%s\n' "$PASSPHRASE" > "$PASS_FILE"
umask 022

cat > "$ENV_FILE" <<EOF
# Edge-AI Sentinel settings, written by deploy/scripts/install.sh.
# Read by the edge-sentinel-* services and scripts. Re-run the installer
# to change them (it keeps values you do not override).
EDGE_LAN_IF=$EDGE_LAN_IF
EDGE_WAN_IF=$EDGE_WAN_IF
EDGE_LAN_IP=$EDGE_LAN_IP
EDGE_LAN_PREFIX=$EDGE_LAN_PREFIX
EDGE_LAN_SUBNET=$EDGE_LAN_SUBNET
EDGE_DHCP_START=$EDGE_DHCP_START
EDGE_DHCP_END=$EDGE_DHCP_END
EDGE_SSID="$EDGE_SSID"
EDGE_COUNTRY=$EDGE_COUNTRY
EDGE_CHANNEL=$EDGE_CHANNEL
EDGE_NIPS_MODE=$EDGE_NIPS_MODE
EDGE_NIPS_CHAIN=$EDGE_NIPS_CHAIN
EDGE_NIPS_BLOCK_SCOPE=$EDGE_NIPS_BLOCK_SCOPE
EDGE_NIPS_WHITELIST=$EDGE_NIPS_WHITELIST
EDGE_RULE_BLOCK_MIN_CONF=$EDGE_RULE_BLOCK_MIN_CONF
EDGE_ML_BLOCK_MIN_CONF=$EDGE_ML_BLOCK_MIN_CONF
EDGE_ML_ALERT_MIN_CONF=$EDGE_ML_ALERT_MIN_CONF
EDGE_ML_BATCH_SIZE=$EDGE_ML_BATCH_SIZE
EDGE_ML_MAX_DELAY=$EDGE_ML_MAX_DELAY
EDGE_FLOW_TIMEOUT=$EDGE_FLOW_TIMEOUT
EDGE_MAX_FLOWS=$EDGE_MAX_FLOWS
EDGE_STATS_INTERVAL=$EDGE_STATS_INTERVAL
EDGE_DASHBOARD_HOST=0.0.0.0
EDGE_DASHBOARD_PORT=$EDGE_DASHBOARD_PORT
EDGE_PYTHON="$EDGE_PYTHON"
EOF
chmod 644 "$ENV_FILE"
log "wrote $ENV_FILE"

backup_once /etc/hostapd/hostapd.conf
render "$DEPLOY_DIR/config/hostapd.conf.template" /etc/hostapd/hostapd.conf 600
render "$DEPLOY_DIR/config/dnsmasq-edge-sentinel.conf.template" /etc/dnsmasq.d/edge-sentinel.conf 644
render "$DEPLOY_DIR/config/sysctl-edge-sentinel.conf.template" /etc/sysctl.d/90-edge-sentinel.conf 644

# Keep other network managers away from the access point interface
if [[ -d /etc/NetworkManager ]]; then
    render "$DEPLOY_DIR/config/networkmanager-unmanaged.conf.template" \
        /etc/NetworkManager/conf.d/90-edge-sentinel.conf 644
fi
if [[ -f /etc/dhcpcd.conf ]] && ! grep -q "^denyinterfaces $EDGE_LAN_IF\$" /etc/dhcpcd.conf; then
    printf '\n# Edge-AI Sentinel: %s is the access point\ndenyinterfaces %s\n' \
        "$EDGE_LAN_IF" "$EDGE_LAN_IF" >> /etc/dhcpcd.conf
    log "excluded $EDGE_LAN_IF from dhcpcd"
fi

# Regulatory country for the radio (also unblocks Wi-Fi on Raspberry Pi OS)
if command -v raspi-config >/dev/null; then
    raspi-config nonint do_wifi_country "$EDGE_COUNTRY" >/dev/null 2>&1 \
        || warn "raspi-config could not set the Wi-Fi country; hostapd sets it at start-up"
fi

# ── 5. Services ──────────────────────────────────────────────────
if [[ -e $APP_LINK && ! -L $APP_LINK ]]; then
    die "$APP_LINK exists and is not a symlink; move it away and re-run"
fi
ln -sfn "$APP_DIR" "$APP_LINK"
log "linked $APP_LINK -> $APP_DIR"
chmod +x "$DEPLOY_DIR"/scripts/*.sh
ln -sfn "$APP_LINK/deploy/scripts/reset_firewall.sh" /usr/local/sbin/edge-sentinel-reset

for unit in "${UNITS[@]}"; do
    render "$DEPLOY_DIR/systemd/$unit.service.template" "/etc/systemd/system/$unit.service" 644
done
systemctl daemon-reload
systemctl unmask hostapd >/dev/null 2>&1 || true
systemctl enable hostapd dnsmasq "${UNITS[@]}"

cat <<EOF

============================================================
 Edge-AI Sentinel installed. Reboot to go live:  sudo reboot
============================================================
 Wi-Fi network : $EDGE_SSID
 Passphrase    : $PASSPHRASE
 Gateway       : $EDGE_LAN_IP ($EDGE_LAN_SUBNET, DHCP $EDGE_DHCP_START-$EDGE_DHCP_END)
 Uplink        : $EDGE_WAN_IF (plug Ethernet with internet in here)
 Prevention    : $EDGE_NIPS_MODE (scope $EDGE_NIPS_BLOCK_SCOPE, chain $EDGE_NIPS_CHAIN)
 Whitelist     : ${EDGE_NIPS_WHITELIST:-none (gateway is always protected)}
 Dashboard     : http://$EDGE_LAN_IP:$EDGE_DASHBOARD_PORT/dashboard
                 http://sentinel.lan:$EDGE_DASHBOARD_PORT/dashboard
 Demo reset    : sudo edge-sentinel-reset
 Engine logs   : journalctl -u edge-sentinel-engine -f
============================================================
EOF
