# Edge-AI Sentinel: NIPS Gateway Deployment

This folder turns a Raspberry Pi 5 into a plug-and-play Network Intrusion
Prevention System. The Pi becomes a Wi-Fi router for IoT devices. Every packet
on that Wi-Fi passes through the detection engine, and attackers are dropped by
the Linux kernel firewall the moment they are classified.

```
 Internet ──(Ethernet)── eth0 ┌───────────────────────────┐ wlan0 ))) Wi-Fi "Edge_Sentinel_Net"
                              │ Raspberry Pi 5            │           ├─ IoT victim   192.168.77.x
                              │  NAT + routing            │           ├─ attacker     192.168.77.y
                              │  Scapy capture on wlan0   │           └─ examiner PC  192.168.77.z
                              │  Rules + Random Forest    │
                              │  iptables kill-switch     │
                              │  Dashboard :8000          │
                              └───────────────────────────┘
```

## What gets installed

| Piece | File on the Pi | Source in this repo |
|---|---|---|
| Wi-Fi access point (hostapd) | `/etc/hostapd/hostapd.conf` | `config/hostapd.conf.template` |
| DHCP + DNS (dnsmasq) | `/etc/dnsmasq.d/edge-sentinel.conf` | `config/dnsmasq-edge-sentinel.conf.template` |
| IPv4 forwarding | `/etc/sysctl.d/90-edge-sentinel.conf` | `config/sysctl-edge-sentinel.conf.template` |
| Keep NetworkManager off wlan0 | `/etc/NetworkManager/conf.d/90-edge-sentinel.conf` | `config/networkmanager-unmanaged.conf.template` |
| Boot-time address, NAT, NIPS chain | `edge-sentinel-gateway.service` | `scripts/gateway_up.sh` |
| Detection engine + kill-switch | `edge-sentinel-engine.service` | `raspberry_pi/main.py` |
| Dashboard (uvicorn) | `edge-sentinel-dashboard.service` | `dashboard/api.py` |
| Settings | `/etc/edge-sentinel/edge-sentinel.env` | written by `scripts/install.sh` |
| Demo reset command | `/usr/local/sbin/edge-sentinel-reset` | `scripts/reset_firewall.sh` |

The roadmap asked for forwarding in `/etc/sysctl.conf`. A drop-in under
`/etc/sysctl.d/` is used instead because recent Debian releases no longer read
`/etc/sysctl.conf` at boot. The drop-in works on both Bookworm and Trixie.

## 1. Before you start

- Raspberry Pi 5 running Raspberry Pi OS (Bookworm or Trixie), with an Ethernet
  cable that has internet access plugged into `eth0`.
- The project's Python packages installed on the Pi. A virtual environment
  inside the project folder is picked up automatically. Use the slim
  `requirements-pi.txt`: it pins scikit-learn 1.6.1, the version the model was
  saved with, and skips the training-only packages.

  ```bash
  git clone https://github.com/Prakharp0410/NIDS_MInor.git ~/edge-sentinel
  cd ~/edge-sentinel
  python3 -m venv venv
  venv/bin/pip install -r requirements-pi.txt
  venv/bin/python -m pytest -q
  ```

- Work over Ethernet SSH or with a keyboard and screen. After the reboot the
  Pi's Wi-Fi becomes the access point and stops joining other networks. Once it
  is up you can also SSH in from any device on the new Wi-Fi at `192.168.77.1`.

## 2. Install (one time)

```bash
sudo bash deploy/scripts/install.sh
sudo reboot
```

The installer prints the Wi-Fi name, the generated passphrase and the dashboard
address. To choose your own values, put them after `sudo`:

```bash
sudo EDGE_SSID=Edge_Sentinel_Net AP_PASSPHRASE='choose-a-long-one' \
     EDGE_NIPS_WHITELIST=192.168.77.20 bash deploy/scripts/install.sh
```

Re-running the installer is safe. It keeps earlier settings and the passphrase
unless you override them. Run `bash deploy/scripts/install.sh --help` for every
option.

## 3. Check it after the reboot

```bash
systemctl status edge-sentinel-gateway hostapd dnsmasq edge-sentinel-engine edge-sentinel-dashboard
iw dev wlan0 info                    # "type AP" and the SSID
sudo iptables -S EDGE_SENTINEL       # the NIPS chain (empty until an attack)
sudo iptables -S FORWARD             # -j EDGE_SENTINEL must be the first rule
sudo iptables -t nat -S POSTROUTING  # MASQUERADE on eth0
journalctl -u edge-sentinel-engine -f   # a [stats] line every 30 s shows it is alive
```

The `[stats]` line reports packets per second, active flows, model batches
and their timing, alerts and blocked IPs. If packets per second stays at zero
while devices are using the Wi-Fi, the engine is not seeing traffic.

Join the Wi-Fi from a phone and confirm it gets a `192.168.77.x` address and
internet access. Then open the dashboard:
`http://192.168.77.1:8000/dashboard` or `http://sentinel.lan:8000/dashboard`.

## 4. Live demonstration

1. Find the examiner laptop's IP after it joins the Wi-Fi and whitelist it so a
   false positive can never cut off the screen you are presenting on:
   `sudo EDGE_NIPS_WHITELIST=192.168.77.20 bash deploy/scripts/install.sh --skip-apt`,
   then `sudo systemctl restart edge-sentinel-engine`.
2. Connect the victim device and the attacker device to the Wi-Fi.
3. Open the dashboard on the examiner laptop. The "Active Firewall Blocks" panel
   refreshes every 2 seconds.
4. Launch an attack from the attacker at the victim, for example:

   ```bash
   nmap -sS -T4 192.168.77.40                 # PortScan rule
   sudo hping3 -S -p 80 --flood 192.168.77.40              # DoS rule
   sudo ping -f 192.168.77.40                 # ICMP-Flood rule
   hydra -l root -P words.txt ssh://192.168.77.40          # SSH-BruteForce rule
   ```

5. Within seconds the attacker appears in the panel with status `BLOCKED`.
   "Block Time" shows how long the kernel rule took to install, "Dropped
   Packets" climbs as the kernel discards the ongoing attack, and "Kernel Rule:
   ACTIVE" proves the rule really is in iptables. The attacker loses all
   connectivity, including internet access and the dashboard.
6. Reset before the next run:

   ```bash
   sudo edge-sentinel-reset                 # unblock everyone, keep history
   sudo edge-sentinel-reset --clear-alerts  # also wipe alerts for a clean slate
   ```

`--full` flushes every iptables rule and then rebuilds NAT and the NIPS chain.
Use it only if the firewall was changed by hand.

## 5. How the kill-switch decides

- **Where blocks live.** Every block is one rule in the `EDGE_SENTINEL` chain,
  which is jumped to from the top of `INPUT` (attacks on the Pi) and `FORWARD`
  (attacks through the Pi). A reset only flushes this chain, so NAT survives.
- **Who gets blocked.** Alerts are attributed to the flow's initiator, never to
  a victim that is answering. ICMP floods count only the initiator's echo
  requests within a 5-second window.
- **Confidence gates.** Rule-based detections block at confidence 0.60 or above.
  Random Forest detections raise an alert from 0.60 and block only at 0.90 or
  above. Alerts between the two are shown with status `DETECTED`.
- **Fewer false alarms.** Large downloads and uploads are not treated as
  floods, a port scan means many distinct ports on one host (or one port
  across many hosts), and Slowloris needs many slow connections at once.
- **Never blocked.** The gateway itself, whitelisted addresses, broadcast,
  multicast and loopback. With the default `lan` scope only addresses on the
  Wi-Fi subnet are blocked, so a busy internet server can never be cut off.
- **No repeated system calls.** An in-memory set mirrors the chain, so an
  attacker triggers at most one `iptables` call. Packets from a blocked source
  skip flow tracking and ML entirely, which keeps the Pi responsive during a
  flood.
- **Restarts and reboots.** If the engine crashes, systemd restarts it and it
  re-reads the chain, so blocks stay in force. A reboot starts with an empty
  chain because iptables rules are not saved.
- **Client-to-client visibility.** Wi-Fi devices normally talk to each other
  directly through the radio, invisible to the Pi's firewall. `ap_isolate=1`
  plus `proxy_arp_pvlan` force that traffic to be routed through the Pi.
  Routed traffic leaves `wlan0` a second time, so the engine ignores that copy
  and counts each packet once.

Alert statuses shown on the dashboard:

| Status | Meaning |
|---|---|
| `BLOCKED` | The source IP is dropped by iptables |
| `DETECTED` | Logged only: below the blocking threshold, outside the scope, or prevention off |
| `WHITELISTED` | The source is protected and deliberately not blocked |
| `DRY_RUN` | Would have been blocked; `EDGE_NIPS_MODE=dry-run` |
| `BLOCK_FAILED` | iptables refused the rule; see `journalctl -u edge-sentinel-engine` |

## 6. Settings

All settings live in `/etc/edge-sentinel/edge-sentinel.env`. Change them by
re-running the installer with new values, then reboot.

| Variable | Default | Purpose |
|---|---|---|
| `EDGE_SSID` | `Edge_Sentinel_Net` | Wi-Fi name |
| `AP_PASSPHRASE` | generated | WPA2 passphrase, stored in `/etc/edge-sentinel/ap_passphrase` |
| `EDGE_COUNTRY` / `EDGE_CHANNEL` | `IN` / `6` | Regulatory country and 2.4 GHz channel |
| `EDGE_LAN_IF` / `EDGE_WAN_IF` | `wlan0` / `eth0` | Access point and uplink interfaces |
| `EDGE_LAN_IP` / `EDGE_LAN_PREFIX` | `192.168.77.1` / `24` | Gateway address on the Wi-Fi |
| `EDGE_NIPS_MODE` | `enforce` | `enforce`, `dry-run` or `off` (pure NIDS) |
| `EDGE_NIPS_BLOCK_SCOPE` | `lan` | `lan` blocks Wi-Fi clients only; `any` also blocks outside IPs |
| `EDGE_NIPS_WHITELIST` | empty | Comma-separated IPs or CIDRs that are never blocked |
| `EDGE_RULE_BLOCK_MIN_CONF` | `0.60` | Minimum confidence for rule-based blocks |
| `EDGE_ML_BLOCK_MIN_CONF` | `0.90` | Minimum confidence for Random Forest blocks |
| `EDGE_ML_ALERT_MIN_CONF` | `0.60` | Minimum confidence for a Random Forest alert |
| `EDGE_ML_BATCH_SIZE` / `EDGE_ML_MAX_DELAY` | `32` / `0.25` | Flows per model batch, and the longest a flow waits for one (seconds) |
| `EDGE_FLOW_TIMEOUT` / `EDGE_MAX_FLOWS` | `120` / `20000` | Idle seconds before a flow is dropped, and the flow table size |
| `EDGE_STATS_INTERVAL` | `30` | Seconds between `[stats]` log lines |
| `EDGE_DASHBOARD_PORT` | `8000` | Dashboard port |

## 7. Troubleshooting

- **Wi-Fi network not visible.** Run `journalctl -u hostapd -b`. Check
  `rfkill list` shows no soft block and that `EDGE_COUNTRY` is correct.
- **Devices join but get no address.** Run `journalctl -u dnsmasq -b` and check
  `ip addr show wlan0` shows `192.168.77.1/24`.
- **No internet on the Wi-Fi.** Check `ip addr show eth0` has an address,
  `sysctl net.ipv4.ip_forward` is 1, and the MASQUERADE rule exists.
- **Attacks between Wi-Fi devices are not detected.** Confirm isolation is
  active: `sudo tcpdump -eni wlan0 host <victim-ip>` must show the attacker's
  frames addressed to the Pi's MAC address, not straight to the victim.
- **"Kernel Rule: UNVERIFIED".** The dashboard cannot read iptables. It must run
  as root on the Pi, which the installed service does, and the mode must be
  `enforce`.
- **"Unknown key name 'RestartSteps'" in the journal.** This is harmless on
  Bookworm's older systemd. The services still restart every 3 seconds.
- **Charts are blank but the tables work.** Chart.js loads from a CDN, so the
  viewing device needs internet access. The firewall panel does not need it.

## 8. Undo

```bash
sudo systemctl disable --now edge-sentinel-engine edge-sentinel-dashboard edge-sentinel-gateway hostapd
sudo rm /etc/systemd/system/edge-sentinel-*.service /etc/dnsmasq.d/edge-sentinel.conf \
        /etc/sysctl.d/90-edge-sentinel.conf /etc/NetworkManager/conf.d/90-edge-sentinel.conf \
        /usr/local/sbin/edge-sentinel-reset /opt/edge-sentinel
sudo rm -r /etc/edge-sentinel
# restore the original access point config if there was one
[ -f /etc/hostapd/hostapd.conf.pre-edge-sentinel ] && sudo mv /etc/hostapd/hostapd.conf.pre-edge-sentinel /etc/hostapd/hostapd.conf
sudo reboot
```

On Raspberry Pi OS Bullseye the installer also appends `denyinterfaces wlan0`
to `/etc/dhcpcd.conf`. Remove those two lines too.
