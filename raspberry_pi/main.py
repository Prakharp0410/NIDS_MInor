"""
Main NIDS/NIPS Runtime System for Raspberry Pi (Edge-AI Sentinel).
Detects: PortScan, DoS, DDoS, SSH/FTP BruteForce, Web Attack, ICMP flood
Prevents: drops the attacker's traffic with iptables (see firewall.py)

Pipeline per packet (all O(1)):
  capture -> skip duplicates / blocked hosts -> flow statistics
  -> deterministic rules -> queue the flow for ML at checkpoints
ML runs in micro-batches (up to ML_BATCH_SIZE flows, at most
ML_MAX_DELAY_SECONDS after queueing), flushed by the packet path or by a
background ticker when traffic is quiet.
"""

import sys
from pathlib import Path
import argparse
import signal
import threading
import time
import warnings
from collections import Counter, OrderedDict, defaultdict, deque
from typing import Deque, Dict, Optional, Tuple

import numpy as np

warnings.filterwarnings("ignore")

sys.path.insert(0, str(Path(__file__).parent))
sys.path.insert(0, str(Path(__file__).parent.parent))

from utils.config import (
    FLOW_TIMEOUT_SECONDS,
    LAN_INTERFACE,
    MAX_FLOWS,
    ML_ALERT_MIN_CONFIDENCE,
    ML_BATCH_SIZE,
    ML_MAX_DELAY_SECONDS,
    RUNTIME_LOG_FILE,
    STATS_INTERVAL_SECONDS,
)
from utils.helpers import configure_logging, log_runtime, log_error

from capture import PacketCapture, HairpinFilter, extract_packet_info
from flow_manager import FlowManager
from feature_extractor import FeatureExtractor
from inference import InferenceEngine
from alert_system import AlertSystem, DETECTOR_ML, DETECTOR_RULE

WEB_PORTS = (80, 443, 8000, 8080)
AUTH_PORTS = {22: "SSH-BruteForce", 21: "FTP-BruteForce"}


class WindowCounter:
    """Events in a sliding time window, with a count of distinct values."""

    __slots__ = ("window", "events", "distinct")

    def __init__(self, window: float):
        self.window = window
        self.events: Deque[Tuple[float, object]] = deque()
        self.distinct: Counter = Counter()

    def add(self, now: float, value=None) -> None:
        self.events.append((now, value))
        self.distinct[value] += 1
        self.prune(now)

    def prune(self, now: float) -> None:
        events, distinct = self.events, self.distinct
        while events and now - events[0][0] > self.window:
            _, value = events.popleft()
            distinct[value] -= 1
            if not distinct[value]:
                del distinct[value]

    def __len__(self) -> int:
        return len(self.events)

    @property
    def n_distinct(self) -> int:
        return len(self.distinct)


class NIIDSRuntime:

    def __init__(self, interface=LAN_INTERFACE, threshold=ML_ALERT_MIN_CONFIDENCE):
        self.interface = interface
        self.threshold = threshold

        self.packet_capture    = PacketCapture(interface=interface)
        self.flow_manager      = FlowManager(timeout_seconds=FLOW_TIMEOUT_SECONDS,
                                             max_flows=MAX_FLOWS)
        self.feature_extractor = FeatureExtractor()
        self.inference_engine  = InferenceEngine()
        self.alert_system      = AlertSystem(min_confidence=0.05,
                                             lan_interface=interface)

        firewall = self.alert_system.firewall
        self.lan_network = firewall.lan_network if firewall else None
        self.hairpin_filter = HairpinFilter.for_interface(
            interface,
            lan_network=self.lan_network,
            own_ip=firewall.own_ip if firewall else None,
        )

        self._init_state()

        nips = (f"{firewall.mode} (chain {firewall.chain}, scope {firewall.block_scope})"
                if firewall else "off")
        log_runtime("=" * 55)
        log_runtime("  Edge-AI Sentinel NIPS Runtime Started")
        log_runtime(f"  Interface : {interface}")
        log_runtime(f"  ML alerts : confidence >= {threshold}")
        log_runtime("  Rules     : PortScan | DoS | DDoS | BruteForce | WebAttack | ICMP")
        log_runtime(f"  Prevention: {nips}")
        log_runtime("=" * 55)

    def _init_state(self):
        """Counters, rule trackers and thresholds (also used by tests)."""
        self._lock = threading.RLock()
        self._stop_event = threading.Event()
        self._ticker: Optional[threading.Thread] = None
        self._stopped = False
        self.is_running = False

        self.packet_count = 0
        self.blocked_packets_skipped = 0
        self.ml_predictions = 0
        self.ml_batches = 0
        self.ml_seconds = 0.0
        self._stats_mark = (time.monotonic(), 0)
        self._last_housekeeping = time.monotonic()
        self._last_stats = time.monotonic()

        # ML micro-batch: id(flow) -> flow, oldest first
        self.ml_pending: "OrderedDict[int, object]" = OrderedDict()
        self.ml_pending_since: Optional[float] = None

        # ── Thresholds ─────────────────────────────────────────
        self.PORTSCAN_WINDOW   = 5     # seconds
        self.PORTSCAN_THRESH   = 20    # distinct ports on one host / LAN hosts on one port
        self.CONN_FLOOD_WINDOW = 5     # seconds
        self.CONN_FLOOD_THRESH = 500   # new flows from one host to one host
        self.FLOOD_PKT_THRESH  = 300   # initiator packets in one flow
        self.FLOOD_PPS_THRESH  = 500   # initiator packets per second
        self.BRUTE_WINDOW      = 10    # seconds
        self.BRUTE_THRESH      = 5     # login attempts (new connections)
        self.HTTP_WINDOW       = 5     # seconds
        self.HTTP_THRESH       = 50    # new web connections to one server
        self.SLOW_WINDOW       = 60    # seconds
        self.SLOW_FLOW_SECONDS = 30    # a connection this old ...
        self.SLOW_FLOW_PACKETS = 20    # ... with this few packets is "slow"
        self.SLOW_THRESH       = 10    # slow connections to one server
        self.ICMP_WINDOW       = 5     # seconds
        self.ICMP_THRESH       = 200   # echo requests from one host
        self.ALERT_COOLDOWN    = 10    # seconds between rule alerts per IP
        self.ML_COOLDOWN       = 5     # seconds between ML alerts per IP

        # ── Rule trackers (monotonic timestamps) ───────────────
        self.alerted_ips: Dict[str, float] = {}
        self.pair_ports = defaultdict(lambda: WindowCounter(self.PORTSCAN_WINDOW))   # (src,dst) -> dst ports
        self.sweep_hosts = defaultdict(lambda: WindowCounter(self.PORTSCAN_WINDOW))  # (src,port) -> LAN dsts
        self.auth_attempts = defaultdict(lambda: WindowCounter(self.BRUTE_WINDOW))   # (src,dst,port)
        self.http_conns = defaultdict(lambda: WindowCounter(self.HTTP_WINDOW))       # (src,dst)
        self.slow_flows = defaultdict(dict)                                          # (src,dst) -> {(sport,dport): t}
        self.icmp_times = defaultdict(lambda: WindowCounter(self.ICMP_WINDOW))       # src

    # ── Helpers ────────────────────────────────────────────────
    def _cooldown_ok(self, src_ip: str, cooldown: Optional[float] = None) -> bool:
        last = self.alerted_ips.get(src_ip)
        if last is None:
            return True
        return (time.monotonic() - last) > (cooldown or self.ALERT_COOLDOWN)

    def _in_lan(self, ip: str) -> bool:
        if self.lan_network is None:
            return False
        try:
            import ipaddress
            return ipaddress.IPv4Address(ip) in self.lan_network
        except ValueError:
            return False

    # ── Alert generator ────────────────────────────────────────
    def _raise_alert(self, attack_type: str, src_ip: str, dst_ip: str,
                     src_port: int, dst_port: int,
                     protocol: str, confidence: float):

        self.alerted_ips[src_ip] = time.monotonic()

        alert = self.alert_system.generate_alert(
            src_ip=src_ip, dst_ip=dst_ip,
            src_port=src_port, dst_port=dst_port,
            predicted_class=None,
            confidence=confidence,
            protocol=protocol,
            attack_type=attack_type,
            detector=DETECTOR_RULE,
        )
        self.alert_system.log_alert(alert)

        log_runtime(
            f"\n{'='*60}\n"
            f"  🚨  ATTACK DETECTED  🚨\n"
            f"  Type       : {attack_type}\n"
            f"  Source IP  : {src_ip}:{src_port}\n"
            f"  Target     : {dst_ip}:{dst_port}\n"
            f"  Protocol   : {protocol}\n"
            f"  Confidence : {confidence:.2%}\n"
            f"  Action     : {alert.status}\n"
            f"{'='*60}"
        )

    # ── Rules on a new connection (first packet from the initiator) ──
    def _on_new_flow(self, flow, now: float):
        src, dst, dport, proto = flow.src_ip, flow.dst_ip, flow.dst_port, flow.protocol

        # Rule 1a: vertical port scan - many ports on one host
        ports = self.pair_ports[(src, dst)]
        ports.add(now, (proto, dport))
        if ports.n_distinct >= self.PORTSCAN_THRESH and self._cooldown_ok(src):
            conf = min(0.99, 0.5 + ports.n_distinct / 100)
            self._raise_alert("PortScan", src, dst, flow.src_port, dport, proto, conf)
            return

        # Rule 1b: horizontal sweep - one port across many LAN hosts
        if dport and self._in_lan(dst):
            hosts = self.sweep_hosts[(src, dport)]
            hosts.add(now, dst)
            if hosts.n_distinct >= self.PORTSCAN_THRESH and self._cooldown_ok(src):
                conf = min(0.99, 0.5 + hosts.n_distinct / 100)
                self._raise_alert("PortScan", src, dst, flow.src_port, dport, proto, conf)
                return

        # Rule 2b: connection flood - new flows to one host (SYN/UDP floods
        # with changing source ports never grow a single flow)
        if len(ports) >= self.CONN_FLOOD_THRESH and self._cooldown_ok(src):
            rate = len(ports) / self.CONN_FLOOD_WINDOW
            attack = "DDoS" if rate > 2000 else "DoS"
            # 100+ new connections per second to one host is unambiguous
            self._raise_alert(attack, src, dst, flow.src_port, dport, proto,
                              min(0.99, 0.75 + rate / 10000))
            return

        # Rule 4: SSH / FTP brute force - repeated logins to one service
        if dport in AUTH_PORTS:
            attempts = self.auth_attempts[(src, dst, dport)]
            attempts.add(now)
            if len(attempts) >= self.BRUTE_THRESH and self._cooldown_ok(src):
                conf = min(0.99, 0.6 + len(attempts) / 20)
                self._raise_alert(AUTH_PORTS[dport], src, dst, flow.src_port, dport, proto, conf)
                return

    # ── Rule 5a: HTTP flood - many requests to one web server ──
    def _detect_http_flood(self, flow, now: float):
        """Called once per connection, when it carries its first request
        data. Counting at the SYN would label SYN floods on port 80 as web
        attacks; those are caught by the connection-flood rule instead."""
        if flow.dst_port not in WEB_PORTS:
            return
        conns = self.http_conns[(flow.src_ip, flow.dst_ip)]
        conns.add(now)
        if len(conns) >= self.HTTP_THRESH and self._cooldown_ok(flow.src_ip):
            self._raise_alert("WebAttack", flow.src_ip, flow.dst_ip,
                              flow.src_port, flow.dst_port, flow.protocol, 0.85)

    # ── Rule 2a: single-flow flood ─────────────────────────────
    def _detect_flood(self, flow, protocol):
        n_fwd = flow.total_fwd_packets
        if n_fwd <= self.FLOOD_PKT_THRESH:
            return
        pps = n_fwd / max(flow.get_duration(), 0.001)
        if pps <= self.FLOOD_PPS_THRESH:
            return
        # A flood is one-sided or carries no data. Downloads (data flows
        # back) and uploads (large payloads, ACKs flow back) are neither.
        one_sided = flow.total_bwd_packets < 0.1 * n_fwd
        no_data = flow.fwd_len.mean < 32 and flow.bwd_len.mean < 32
        if not (one_sided or no_data):
            return
        # Flows are bidirectional, so blame the initiator, never the victim.
        attacker = flow.src_ip
        if self._cooldown_ok(attacker):
            attack = "DDoS" if pps > 2000 else "DoS"
            conf   = min(0.99, 0.6 + pps / 10000)
            self._raise_alert(attack, attacker, flow.dst_ip,
                              flow.src_port, flow.dst_port, protocol, conf)

    # ── Rule 3: ICMP flood ─────────────────────────────────────
    def _detect_icmp_flood(self, flow, src_ip, dst_ip, protocol, icmp_type=8):
        if protocol != "ICMP":
            return
        # Count only the initiator's echo requests: the victim's echo
        # replies must not get the victim flagged and blocked.
        if src_ip != flow.src_ip or icmp_type not in (8, None):
            return
        times = self.icmp_times[src_ip]
        times.add(time.monotonic())
        if len(times) > self.ICMP_THRESH and self._cooldown_ok(src_ip):
            self._raise_alert("ICMP-Flood", src_ip, dst_ip, 0, 0, "ICMP", 0.90)
            times.events.clear()
            times.distinct.clear()

    # ── Rule 5b: Slowloris - many slow connections to one server ──
    def _detect_slowloris(self, flow, now: float):
        if flow.dst_port not in WEB_PORTS:
            return
        if (flow.get_duration() < self.SLOW_FLOW_SECONDS
                or flow.packet_count >= self.SLOW_FLOW_PACKETS):
            return
        slow = self.slow_flows[(flow.src_ip, flow.dst_ip)]
        slow[(flow.src_port, flow.dst_port)] = now
        for key in [k for k, t in slow.items() if now - t > self.SLOW_WINDOW]:
            del slow[key]
        if len(slow) >= self.SLOW_THRESH and self._cooldown_ok(flow.src_ip):
            self._raise_alert("WebAttack", flow.src_ip, flow.dst_ip,
                              flow.src_port, flow.dst_port, flow.protocol, 0.82)

    # ── ML micro-batching ──────────────────────────────────────
    def _queue_for_ml(self, flow, now: float):
        flow.mark_ml_queued()
        if not self.ml_pending:
            self.ml_pending_since = now
        self.ml_pending[id(flow)] = flow
        self.ml_pending.move_to_end(id(flow))

    def _ml_flush_due(self, now: float) -> bool:
        return bool(self.ml_pending) and (
            len(self.ml_pending) >= ML_BATCH_SIZE
            or now - (self.ml_pending_since or now) >= ML_MAX_DELAY_SECONDS)

    def _flush_ml(self):
        """Classify every queued flow in one model call."""
        if not self.ml_pending:
            return
        flows = [f for f in self.ml_pending.values()
                 if not self.alert_system.is_blocked(f.src_ip)]
        self.ml_pending.clear()
        self.ml_pending_since = None
        if not flows or not self.inference_engine.is_ready:
            return
        try:
            X = np.vstack([self.feature_extractor.extract_features(f) for f in flows])
            started = time.perf_counter()
            results = self.inference_engine.predict_batch(X)
            self.ml_seconds += time.perf_counter() - started
            self.ml_batches += 1
            self.ml_predictions += len(flows)
        except Exception as e:
            log_error("ML batch failed", e)
            return

        for flow, (index, class_name, confidence) in zip(flows, results):
            if not self.inference_engine.is_malicious_class(index):
                continue
            if confidence < self.threshold:
                continue
            # The model classifies the whole bidirectional flow, so the
            # initiator is the party to blame (and block).
            attacker = flow.src_ip
            if not self._cooldown_ok(attacker, cooldown=self.ML_COOLDOWN):
                continue
            self.alerted_ips[attacker] = time.monotonic()
            family = self.inference_engine.get_attack_family(index)
            alert = self.alert_system.generate_alert(
                src_ip=attacker, dst_ip=flow.dst_ip,
                src_port=flow.src_port, dst_port=flow.dst_port,
                predicted_class=index,
                confidence=confidence, protocol=flow.protocol,
                attack_type=family,
                detector=DETECTOR_ML,
            )
            self.alert_system.log_alert(alert)
            log_runtime(
                f"🤖 ML ALERT: {family} ({class_name}) from {attacker} "
                f"-> {flow.dst_ip}:{flow.dst_port} conf={confidence:.3f} "
                f"action={alert.status}", "WARNING")

    # ── Main packet processor ──────────────────────────────────
    def process_packet(self, packet):
        with self._lock:
            try:
                self.packet_count += 1
                packet_info = extract_packet_info(packet)

                if not packet_info.get('src_ip'):
                    return

                # Second copy of a Wi-Fi client-to-client packet routed back
                # out of wlan0 by the gateway: already counted on the way in.
                if self.hairpin_filter.is_duplicate(packet_info):
                    return

                src_ip   = packet_info['src_ip']
                dst_ip   = packet_info['dst_ip']
                protocol = packet_info.get('protocol', 'TCP')

                # NIPS fast path. Traffic from a blocked host is dropped by
                # the kernel; traffic to it is the victim's replies, which
                # must not be mistaken for the victim starting connections.
                if self.alert_system.is_blocked(src_ip) or self.alert_system.is_blocked(dst_ip):
                    self.blocked_packets_skipped += 1
                    return

                flow = self.flow_manager.add_packet_to_flow(packet_info)
                if flow is None:
                    return
                now = time.monotonic()

                # Connection-level rules run once, on the initiator's first packet
                if flow.packet_count == 1 and src_ip == flow.src_ip:
                    self._on_new_flow(flow, now)

                self._detect_flood(flow, protocol)
                self._detect_icmp_flood(flow, src_ip, dst_ip, protocol,
                                        packet_info.get('icmp_type'))
                if src_ip == flow.src_ip:
                    self._detect_slowloris(flow, now)
                    data = packet_info.get('data_len', packet_info.get('payload_len', 0))
                    if data and not flow.request_seen:
                        flow.request_seen = True
                        self._detect_http_flood(flow, now)

                # ML at checkpoints (2, 4, 8, ... packets and at flow end)
                if flow.ml_due():
                    self._queue_for_ml(flow, now)
                if self._ml_flush_due(now):
                    self._flush_ml()

            except Exception as e:
                log_error("Error processing packet", e)

    # ── Background ticker ──────────────────────────────────────
    def tick(self):
        """Flush late ML batches, expire state and report statistics."""
        with self._lock:
            now = time.monotonic()
            if self._ml_flush_due(now):
                self._flush_ml()
            if now - self._last_housekeeping >= 5:
                self._last_housekeeping = now
                self._housekeeping(now)
            if STATS_INTERVAL_SECONDS and now - self._last_stats >= STATS_INTERVAL_SECONDS:
                self._last_stats = now
                self._log_stats(now)

    def _housekeeping(self, now: float):
        self.flow_manager.cleanup_expired_flows()
        for table in (self.pair_ports, self.sweep_hosts, self.auth_attempts,
                      self.http_conns, self.icmp_times):
            for key in list(table):
                table[key].prune(now)
                if not table[key]:
                    del table[key]
        for key in list(self.slow_flows):
            slow = self.slow_flows[key]
            for fid in [k for k, t in slow.items() if now - t > self.SLOW_WINDOW]:
                del slow[fid]
            if not slow:
                del self.slow_flows[key]
        stale = max(self.ALERT_COOLDOWN, self.ML_COOLDOWN) * 6
        for ip in [ip for ip, t in self.alerted_ips.items() if now - t > stale]:
            del self.alerted_ips[ip]

    def _log_stats(self, now: float):
        last_time, last_count = self._stats_mark
        pps = (self.packet_count - last_count) / max(now - last_time, 1e-6)
        self._stats_mark = (now, self.packet_count)
        avg_ms = self.ml_seconds / self.ml_batches * 1000 if self.ml_batches else 0.0
        stats = self.alert_system.get_alert_statistics()
        log_runtime(
            f"[stats] {pps:.0f} pkt/s | {self.packet_count} pkts | "
            f"{self.flow_manager.get_flow_count()} flows | "
            f"ML {self.ml_predictions} flows in {self.ml_batches} batches "
            f"({avg_ms:.1f} ms/batch) | alerts {stats['total_alerts']} | "
            f"blocked {stats['blocked_ips']} | skipped {self.blocked_packets_skipped}")

    def _start_ticker(self):
        def loop():
            while not self._stop_event.wait(0.1):
                try:
                    self.tick()
                except Exception as e:
                    log_error("Ticker error", e)
        self._ticker = threading.Thread(target=loop, name="edge-sentinel-ticker", daemon=True)
        self._ticker.start()

    # ── Run modes ──────────────────────────────────────────────
    def run_continuous(self):
        try:
            self.is_running = True
            self._start_ticker()
            log_runtime(f"Monitoring started on {self.interface}...")
            from capture import LivePacketCapture
            capture = LivePacketCapture(interface=self.interface)
            capture.stream_packets(callback=self.process_packet, packet_count=0)
        except Exception as e:
            log_error("Error in continuous run", e)
        finally:
            self.stop()

    def run_batch(self, packet_count=1000):
        try:
            self.is_running = True
            self._start_ticker()
            self.packet_capture.packet_count = packet_count
            self.packet_capture.start_capture(callback=self.process_packet)
        except Exception as e:
            log_error("Error in batch run", e)
        finally:
            self.stop()

    def stop(self):
        """Idempotent: safe from the capture loop, signals and main()."""
        if self._stopped:
            return
        self._stopped = True
        self.is_running = False
        self._stop_event.set()
        with self._lock:
            self._flush_ml()
            self.packet_capture.stop_capture()
            self.flow_manager.cleanup_expired_flows()
            self.print_statistics()
        log_runtime("Edge-AI Sentinel engine stopped.")

    def print_statistics(self):
        stats = self.alert_system.get_alert_statistics()
        log_runtime("=" * 40)
        log_runtime("  FINAL STATISTICS")
        log_runtime(f"  Packets processed : {self.packet_count}")
        log_runtime(f"  Active flows      : {self.flow_manager.get_flow_count()}")
        log_runtime(f"  ML classified     : {self.ml_predictions} flows in {self.ml_batches} batches")
        log_runtime(f"  Total alerts      : {stats['total_alerts']}")
        log_runtime(f"  By type           : {stats['alert_types']}")
        log_runtime(f"  Blocked IPs       : {stats['blocked_ips']}")
        log_runtime(f"  Pkts from blocked : {self.blocked_packets_skipped}")
        log_runtime("=" * 40)

    def get_status(self):
        stats = self.alert_system.get_alert_statistics()
        return {
            'is_running'       : self.is_running,
            'interface'        : self.interface,
            'packets_processed': self.packet_count,
            'active_flows'     : self.flow_manager.get_flow_count(),
            'total_alerts'     : stats['total_alerts'],
            'alert_types'      : stats['alert_types'],
            'inference_ready'  : self.inference_engine.is_ready,
            'ml_predictions'   : self.ml_predictions,
            'blocked_ips'      : stats['blocked_ips'],
            'nips_mode'        : (self.alert_system.firewall.mode
                                  if self.alert_system.firewall else 'off'),
        }


def _raise_keyboard_interrupt(signum, frame):
    # systemd stops the service with SIGTERM. Turning it into
    # KeyboardInterrupt lets Scapy's capture loop exit cleanly, exactly
    # like Ctrl+C, so final statistics are logged and the ML queue flushed.
    raise KeyboardInterrupt


def main():
    parser = argparse.ArgumentParser(description='Edge-AI Sentinel NIPS for Raspberry Pi')
    parser.add_argument('--interface', type=str, default=LAN_INTERFACE)
    parser.add_argument('--threshold', type=float, default=ML_ALERT_MIN_CONFIDENCE,
                        help='minimum ML confidence for an alert')
    parser.add_argument('--mode', type=str,
                        choices=['continuous', 'batch'], default='continuous')
    parser.add_argument('--packets', type=int, default=1000)
    args = parser.parse_args()

    configure_logging(log_file=RUNTIME_LOG_FILE)
    signal.signal(signal.SIGTERM, _raise_keyboard_interrupt)

    nids = None
    try:
        nids = NIIDSRuntime(interface=args.interface, threshold=args.threshold)
        if args.mode == 'continuous':
            nids.run_continuous()
        else:
            nids.run_batch(packet_count=args.packets)
    except KeyboardInterrupt:
        log_runtime("Shutdown requested")
    except Exception as e:
        log_error("Fatal error", e)
        if nids is not None:
            nids.stop()
        sys.exit(1)
    finally:
        if nids is not None:
            nids.stop()


if __name__ == "__main__":
    main()
