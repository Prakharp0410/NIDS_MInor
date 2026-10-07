"""
NIPS kill-switch for Edge-AI Sentinel.

Drives the Linux kernel firewall (iptables) so the detection engine can drop
every packet from an attacker the moment an alert is raised.

Design:
- All blocks live in one dedicated chain (EDGE_SENTINEL by default). It is
  jumped to from the top of INPUT, for attacks on the gateway itself, and of
  FORWARD, for attacks routed through it, including Wi-Fi client to client.
  A demo reset therefore only flushes this chain and never touches NAT.
- An in-memory set mirrors the chain, so repeated alerts for an attacker that
  is already blocked never spawn another iptables process.
- Safety rails: IPv4 validation, a whitelist that always contains the gateway
  itself, LAN-only scope by default, and no shell is ever involved.
"""

import ipaddress
import os
import platform
import re
import shutil
import subprocess
import sys
import time
from pathlib import Path
from typing import Callable, Dict, Iterable, List, Optional, Set, Tuple

sys.path.insert(0, str(Path(__file__).parent.parent))

from utils.config import (
    IPTABLES_TIMEOUT_SECONDS,
    LAN_GATEWAY_IP,
    LAN_INTERFACE,
    LAN_SUBNET,
    NIPS_BLOCK_SCOPE,
    NIPS_CHAIN,
    NIPS_MODE,
    NIPS_WHITELIST,
)
from utils.helpers import log_error, log_runtime

# Outcomes of FirewallManager.block()
BLOCKED = "BLOCKED"                  # a new DROP rule is now in the kernel
ALREADY_BLOCKED = "ALREADY_BLOCKED"  # rule already present, no system call made
WHITELISTED = "WHITELISTED"          # protected address, never blocked
OUT_OF_SCOPE = "OUT_OF_SCOPE"        # outside the LAN while scope is "lan"
INVALID = "INVALID"                  # not a blockable unicast IPv4 address
DRY_RUN = "DRY_RUN"                  # dry-run mode: logged, not enforced
DISABLED = "DISABLED"                # prevention is switched off
FAILED = "FAILED"                    # iptables refused or is unavailable

MODES = ("enforce", "dry-run", "off")

Runner = Callable[[List[str], float], subprocess.CompletedProcess]

_RULE_SOURCE_RE = re.compile(r"-s (\d{1,3}(?:\.\d{1,3}){3})(?:/32)?(?=\s|$)")
_RULE_COUNTERS_RE = re.compile(r"-c (\d+) (\d+)")
_COMMENT_SAFE_RE = re.compile(r"[^A-Za-z0-9_.:-]")


def _default_runner(cmd: List[str], timeout: float) -> subprocess.CompletedProcess:
    return subprocess.run(cmd, capture_output=True, text=True, timeout=timeout, check=False)


def _find_iptables() -> str:
    """Locate iptables even when /usr/sbin is missing from a non-root PATH."""
    search = os.pathsep.join(
        [os.environ.get("PATH", ""), "/usr/sbin", "/sbin", "/usr/bin", "/bin"]
    )
    return shutil.which("iptables", path=search) or "iptables"


def _running_as_root() -> bool:
    return hasattr(os, "geteuid") and os.geteuid() == 0


class IptablesCLI:
    """Runs iptables without a shell; adds `sudo -n` when not root."""

    def __init__(self, runner: Optional[Runner] = None,
                 timeout: float = IPTABLES_TIMEOUT_SECONDS,
                 use_sudo: Optional[bool] = None,
                 binary: Optional[str] = None):
        self._runner = runner or _default_runner
        self.timeout = timeout
        self.binary = binary or _find_iptables()
        # sudo -n never prompts, so a missing sudo rule fails fast instead of hanging.
        self.use_sudo = (not _running_as_root()) if use_sudo is None else use_sudo

    def run(self, args: List[str]) -> Tuple[bool, str, str]:
        cmd = [self.binary, "-w", "3", *args]
        if self.use_sudo:
            cmd = ["sudo", "-n", *cmd]
        try:
            result = self._runner(cmd, self.timeout)
        except (OSError, subprocess.SubprocessError) as exc:
            return False, "", str(exc)
        return result.returncode == 0, result.stdout or "", result.stderr or ""


def parse_chain_rules(rules_text: str) -> Dict[str, Dict[str, int]]:
    """
    Parse `iptables -S <chain> [-v]` output.

    Returns {ip: {"packets": n, "bytes": n}} for every single-host DROP rule.
    Counters are 0 when the listing was taken without -v.
    """
    blocked: Dict[str, Dict[str, int]] = {}
    for line in rules_text.splitlines():
        line = line.strip()
        if not line.startswith("-A ") or "-j DROP" not in line:
            continue
        match = _RULE_SOURCE_RE.search(line)
        if not match:
            continue
        try:
            ip = str(ipaddress.IPv4Address(match.group(1)))
        except ValueError:
            continue
        counters = _RULE_COUNTERS_RE.search(line)
        entry = blocked.setdefault(ip, {"packets": 0, "bytes": 0})
        if counters:
            entry["packets"] += int(counters.group(1))
            entry["bytes"] += int(counters.group(2))
    return blocked


def read_chain_state(chain: str = NIPS_CHAIN, mode: str = NIPS_MODE,
                     cli: Optional[IptablesCLI] = None) -> Optional[Dict[str, Dict[str, int]]]:
    """
    Read the live block list with per-rule drop counters from the kernel.

    Returns None when the kernel state cannot be read: prevention is not
    enforcing, the host is not Linux, or the caller lacks privileges.
    """
    if mode != "enforce" or (cli is None and platform.system() != "Linux"):
        return None
    ok, out, _ = (cli or IptablesCLI()).run(["-S", chain, "-v"])
    return parse_chain_rules(out) if ok else None


def detect_interface_ipv4(interface: str) -> Optional[ipaddress.IPv4Interface]:
    """Return the first IPv4 address/prefix of an interface (Linux only)."""
    if platform.system() != "Linux":
        return None
    ip_bin = shutil.which("ip", path="/usr/sbin:/sbin:/usr/bin:/bin") or "ip"
    try:
        out = subprocess.run([ip_bin, "-4", "-o", "addr", "show", "dev", interface],
                             capture_output=True, text=True, timeout=3, check=False).stdout
    except (OSError, subprocess.SubprocessError):
        return None
    match = re.search(r"inet (\d{1,3}(?:\.\d{1,3}){3}/\d{1,2})", out)
    if not match:
        return None
    try:
        return ipaddress.IPv4Interface(match.group(1))
    except ValueError:
        return None


class FirewallManager:
    """The NIPS kill-switch: turns alerts into kernel DROP rules."""

    def __init__(self,
                 mode: str = NIPS_MODE,
                 chain: str = NIPS_CHAIN,
                 lan_interface: str = LAN_INTERFACE,
                 lan_subnet: str = LAN_SUBNET,
                 gateway_ip: str = LAN_GATEWAY_IP,
                 block_scope: str = NIPS_BLOCK_SCOPE,
                 whitelist: Iterable[str] = NIPS_WHITELIST,
                 runner: Optional[Runner] = None,
                 use_sudo: Optional[bool] = None,
                 manage_chain: bool = True):
        mode = (mode or "enforce").strip().lower()
        if mode not in MODES:
            log_runtime(f"Unknown NIPS mode '{mode}', falling back to dry-run", "WARNING")
            mode = "dry-run"
        if mode == "enforce" and runner is None and platform.system() != "Linux":
            log_runtime("iptables needs Linux; NIPS runs in dry-run mode on this host", "WARNING")
            mode = "dry-run"

        self.mode = mode
        self.chain = chain
        self.block_scope = "any" if str(block_scope).lower() == "any" else "lan"
        self.cli = IptablesCLI(runner=runner, use_sudo=use_sudo)
        self.blocked_ips: Set[str] = set()
        self.synced = False
        self.last_latency_ms: Optional[float] = None

        detected = detect_interface_ipv4(lan_interface) if lan_interface else None
        self.own_ip: Optional[str] = str(detected.ip) if detected else None
        self.lan_network: Optional[ipaddress.IPv4Network] = self._parse_network(
            lan_subnet or (str(detected.network) if detected else ""))
        self._protected = self._build_protected(whitelist, gateway_ip)

        log_runtime(
            f"NIPS kill-switch: mode={self.mode} chain={self.chain} "
            f"scope={self.block_scope} lan={self.lan_network or 'unknown'}"
        )
        if self.block_scope == "lan" and self.lan_network is None and self.mode != "off":
            log_runtime("LAN subnet unknown: set EDGE_LAN_SUBNET, otherwise nothing can be "
                        "blocked while EDGE_NIPS_BLOCK_SCOPE=lan", "WARNING")

        if self.mode == "enforce" and manage_chain:
            self.ensure_chain()
            self.sync()

    # ── Properties ─────────────────────────────────────────────
    @property
    def is_enforcing(self) -> bool:
        return self.mode == "enforce"

    # ── Setup ──────────────────────────────────────────────────
    @staticmethod
    def _parse_network(value: str) -> Optional[ipaddress.IPv4Network]:
        if not value:
            return None
        try:
            return ipaddress.IPv4Network(value, strict=False)
        except ValueError:
            log_error(f"Invalid LAN subnet '{value}'")
            return None

    def _build_protected(self, whitelist: Iterable[str], gateway_ip: str) -> List[ipaddress.IPv4Network]:
        entries = ["127.0.0.0/8", "0.0.0.0/32", "255.255.255.255/32", *whitelist]
        if gateway_ip:
            entries.append(gateway_ip)
        if self.own_ip:
            entries.append(self.own_ip)
        if self.lan_network is not None and self.lan_network.prefixlen < 31:
            entries.append(str(self.lan_network.network_address))
            entries.append(str(self.lan_network.broadcast_address))
        protected = []
        for entry in entries:
            try:
                protected.append(ipaddress.IPv4Network(entry, strict=False))
            except ValueError:
                log_error(f"Ignoring invalid whitelist entry '{entry}'")
        return protected

    def ensure_chain(self) -> bool:
        """Create the block chain and hook it first into INPUT and FORWARD."""
        ok, _, _ = self.cli.run(["-S", self.chain])
        if not ok:
            ok, _, err = self.cli.run(["-N", self.chain])
            if not ok:
                log_error(f"NIPS: cannot create iptables chain {self.chain}: {err.strip()}")
                return False
        hooked = True
        for parent in ("INPUT", "FORWARD"):
            present, _, _ = self.cli.run(["-C", parent, "-j", self.chain])
            if not present:
                ok, _, err = self.cli.run(["-I", parent, "1", "-j", self.chain])
                if not ok:
                    hooked = False
                    log_error(f"NIPS: cannot hook {self.chain} into {parent}: {err.strip()}")
        return hooked

    def sync(self) -> Set[str]:
        """Rebuild the in-memory set from the kernel (survives engine restarts)."""
        ok, out, err = self.cli.run(["-S", self.chain])
        if ok:
            self.blocked_ips = set(parse_chain_rules(out))
            self.synced = True
            if self.blocked_ips:
                log_runtime(f"NIPS: restored {len(self.blocked_ips)} active block(s) from {self.chain}")
        else:
            log_error(f"NIPS: cannot read chain {self.chain}: {err.strip()}")
        return set(self.blocked_ips)

    # ── Policy ─────────────────────────────────────────────────
    def evaluate(self, ip: str) -> Optional[str]:
        """Return why `ip` must not be blocked, or None if blocking is allowed."""
        if self.mode == "off":
            return DISABLED
        try:
            addr = ipaddress.IPv4Address(str(ip).strip())
        except ValueError:
            return INVALID
        if addr.is_multicast or addr.is_unspecified or addr.is_loopback:
            return INVALID
        if any(addr in net for net in self._protected):
            return WHITELISTED
        if self.block_scope == "lan" and (self.lan_network is None or addr not in self.lan_network):
            return OUT_OF_SCOPE
        return None

    # ── Actions ────────────────────────────────────────────────
    def is_blocked(self, ip: str) -> bool:
        return ip in self.blocked_ips

    def block(self, ip: str, reason: str = "") -> str:
        """Drop all traffic from `ip`. Idempotent and safe to call per alert."""
        verdict = self.evaluate(ip)
        if verdict is not None:
            return verdict
        ip = str(ipaddress.IPv4Address(str(ip).strip()))

        if ip in self.blocked_ips:
            return DRY_RUN if self.mode == "dry-run" else ALREADY_BLOCKED

        if self.mode == "dry-run":
            self.blocked_ips.add(ip)
            log_runtime(f"[NIPS dry-run] would block {ip} ({reason})", "WARNING")
            return DRY_RUN

        started = time.perf_counter()
        comment = "edge-sentinel:" + _COMMENT_SAFE_RE.sub("-", reason or "alert")[:48]
        ok, _, err = self.cli.run(["-I", self.chain, "-s", ip,
                                   "-m", "comment", "--comment", comment, "-j", "DROP"])
        if not ok:
            # Some minimal kernels lack the comment match; the rule matters more.
            ok, _, err = self.cli.run(["-I", self.chain, "-s", ip, "-j", "DROP"])
        if not ok:
            log_error(f"NIPS: failed to block {ip}: {err.strip() or 'iptables unavailable'}")
            return FAILED

        self.last_latency_ms = (time.perf_counter() - started) * 1000
        self.blocked_ips.add(ip)
        log_runtime(f"🛑 NIPS: blocked {ip} ({reason}) in {self.last_latency_ms:.1f} ms "
                    f"via iptables chain {self.chain}", "WARNING")
        return BLOCKED

    def flush(self) -> bool:
        """Remove every block (the reset script does the same from the shell)."""
        if self.mode == "enforce":
            ok, _, err = self.cli.run(["-F", self.chain])
            if not ok:
                log_error(f"NIPS: failed to flush {self.chain}: {err.strip()}")
                return False
        self.blocked_ips.clear()
        return True

    def read_state(self) -> Optional[Dict[str, Dict[str, int]]]:
        return read_chain_state(self.chain, self.mode, self.cli)
