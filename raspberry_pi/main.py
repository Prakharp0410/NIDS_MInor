"""
Main NIDS Runtime System for Raspberry Pi.
Detects: PortScan, DoS, DDoS, SSH BruteForce, FTP BruteForce, Web Attack
"""

import sys
from pathlib import Path
import argparse
import signal
import warnings
from collections import defaultdict
from datetime import datetime

warnings.filterwarnings("ignore")

sys.path.insert(0, str(Path(__file__).parent.parent))

from utils.config import NETWORK_INTERFACE, MIN_PACKETS_IN_FLOW, INFERENCE_THRESHOLD
from utils.helpers import log_runtime, log_error, format_timestamp

from capture import PacketCapture, extract_packet_info
from flow_manager import FlowManager
from feature_extractor import FeatureExtractor
from inference import InferenceEngine
from alert_system import AlertSystem


class NIIDSRuntime:

    def __init__(self, interface=NETWORK_INTERFACE, threshold=INFERENCE_THRESHOLD):
        self.interface = interface
        self.threshold = threshold

        self.packet_capture    = PacketCapture(interface=interface)
        self.flow_manager      = FlowManager(timeout_seconds=120, max_flows=5000)
        self.feature_extractor = FeatureExtractor()
        self.inference_engine  = InferenceEngine()
        self.alert_system      = AlertSystem(min_confidence=0.05)

        self.is_running   = False
        self.packet_count = 0

        # ── Tracker dictionaries ───────────────────────────────
        self.new_flow_times    = defaultdict(list)  # src_ip → [datetime, ...]
        self.failed_auth_times = defaultdict(list)  # src_ip → [datetime, ...]
        self.http_req_times    = defaultdict(list)  # src_ip → [datetime, ...]
        self.alerted_ips       = {}                 # src_ip → last alert datetime
        self.icmp_counts       = defaultdict(int)   # src_ip → packet count

        # ── Thresholds ─────────────────────────────────────────
        self.PORTSCAN_WINDOW   = 5    # seconds
        self.PORTSCAN_THRESH   = 20   # new flows in window
        self.FLOOD_PKT_THRESH  = 300  # packets in one flow
        self.FLOOD_PPS_THRESH  = 500  # packets per second
        self.BRUTE_WINDOW      = 10   # seconds
        self.BRUTE_THRESH      = 5    # failed auth attempts in window
        self.HTTP_WINDOW       = 5    # seconds
        self.HTTP_THRESH       = 50   # HTTP requests in window
        self.ICMP_THRESH       = 200  # ICMP packets from one IP
        self.ALERT_COOLDOWN    = 10   # seconds between alerts for same IP

        log_runtime("=" * 55)
        log_runtime("  NIDS Runtime Started")
        log_runtime(f"  Interface : {interface}")
        log_runtime(f"  Threshold : {threshold}")
        log_runtime("  Rules     : PortScan | DoS | DDoS | BruteForce | WebAttack")
        log_runtime("=" * 55)

        signal.signal(signal.SIGINT, self._signal_handler)

    def _signal_handler(self, sig, frame):
        log_runtime("Shutting down NIDS...")
        self.stop()

    # ── Helper: cooldown check ─────────────────────────────────
    def _cooldown_ok(self, src_ip: str, cooldown: int = None) -> bool:
        cd = cooldown or self.ALERT_COOLDOWN
        last = self.alerted_ips.get(src_ip)
        if last is None:
            return True
        return (datetime.now() - last).total_seconds() > cd

    # ── Helper: prune old timestamps ───────────────────────────
    def _prune(self, times_list: list, window: int) -> list:
        now = datetime.now()
        return [t for t in times_list if (now - t).total_seconds() < window]

    # ── Alert generator ────────────────────────────────────────
    def _raise_alert(self, attack_type: str, src_ip: str, dst_ip: str,
                     src_port: int, dst_port: int,
                     protocol: str, confidence: float):

        self.alerted_ips[src_ip] = datetime.now()

        class_map = {
            "PortScan"      : 10,
            "DDoS"          : 2,
            "DoS"           : 4,
            "SSH-BruteForce": 11,
            "FTP-BruteForce": 7,
            "WebAttack"     : 12,
            "ICMP-Flood"    : 2,
        }
        class_id = class_map.get(attack_type, 10)

        alert = self.alert_system.generate_alert(
            src_ip=src_ip, dst_ip=dst_ip,
            src_port=src_port, dst_port=dst_port,
            predicted_class=class_id,
            confidence=confidence,
            protocol=protocol
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
            f"{'='*60}"
        )

    # ── Rule 1: Port Scan ──────────────────────────────────────
    def _detect_portscan(self, src_ip, dst_ip, src_port, dst_port, protocol):
        times = self._prune(self.new_flow_times[src_ip], self.PORTSCAN_WINDOW)
        self.new_flow_times[src_ip] = times
        if len(times) >= self.PORTSCAN_THRESH and self._cooldown_ok(src_ip):
            conf = min(0.99, 0.5 + len(times) / 100)
            self._raise_alert("PortScan", src_ip, dst_ip,
                              src_port, dst_port, protocol, conf)

    # ── Rule 2: SYN/UDP/ICMP Flood ────────────────────────────
    def _detect_flood(self, flow, src_ip, dst_ip,
                      src_port, dst_port, protocol):
        pkt_count = flow.get_packet_count()
        duration  = max(flow.get_duration(), 0.001)
        pps = pkt_count / duration

        if pkt_count > self.FLOOD_PKT_THRESH and pps > self.FLOOD_PPS_THRESH:
            if self._cooldown_ok(src_ip):
                attack = "DDoS" if pps > 2000 else "DoS"
                conf   = min(0.99, 0.6 + pps / 10000)
                self._raise_alert(attack, src_ip, dst_ip,
                                  src_port, dst_port, protocol, conf)

    # ── Rule 3: ICMP Flood ─────────────────────────────────────
    def _detect_icmp_flood(self, src_ip, dst_ip, protocol):
        if protocol == "ICMP":
            self.icmp_counts[src_ip] += 1
            if (self.icmp_counts[src_ip] > self.ICMP_THRESH
                    and self._cooldown_ok(src_ip)):
                self._raise_alert("ICMP-Flood", src_ip, dst_ip,
                                  0, 0, "ICMP", 0.90)
                self.icmp_counts[src_ip] = 0

    # ── Rule 4: SSH / FTP Brute Force ─────────────────────────
    def _detect_bruteforce(self, src_ip, dst_ip, src_port,
                           dst_port, protocol, flow):
        # SSH = port 22, FTP = port 21
        if dst_port not in (22, 21):
            return

        pkt_count = flow.get_packet_count()
        duration  = max(flow.get_duration(), 0.001)

        # Brute force signature:
        # Many small flows to port 22/21 from same IP
        times = self._prune(
            self.failed_auth_times[src_ip], self.BRUTE_WINDOW
        )
        self.failed_auth_times[src_ip] = times

        # Each new flow to SSH/FTP = one auth attempt
        if pkt_count == 1:
            self.failed_auth_times[src_ip].append(datetime.now())

        if (len(self.failed_auth_times[src_ip]) >= self.BRUTE_THRESH
                and self._cooldown_ok(src_ip)):
            attack = "SSH-BruteForce" if dst_port == 22 else "FTP-BruteForce"
            conf   = min(0.99, 0.6 + len(self.failed_auth_times[src_ip]) / 20)
            self._raise_alert(attack, src_ip, dst_ip,
                              src_port, dst_port, protocol, conf)

    # ── Rule 5: HTTP Web Attack / Slowloris ───────────────────
    def _detect_webattack(self, src_ip, dst_ip, src_port,
                          dst_port, protocol, flow):
        # HTTP ports
        if dst_port not in (80, 8000, 8080, 443):
            return

        pkt_count = flow.get_packet_count()
        duration  = max(flow.get_duration(), 0.001)

        # Slowloris: one flow stays open very long with few packets
        if duration > 30 and pkt_count < 20:
            if self._cooldown_ok(src_ip):
                self._raise_alert("WebAttack", src_ip, dst_ip,
                                  src_port, dst_port, protocol, 0.82)
            return

        # HTTP flood: many requests per second to web port
        times = self._prune(self.http_req_times[src_ip], self.HTTP_WINDOW)
        self.http_req_times[src_ip] = times

        if pkt_count == 1:
            self.http_req_times[src_ip].append(datetime.now())

        if (len(self.http_req_times[src_ip]) >= self.HTTP_THRESH
                and self._cooldown_ok(src_ip)):
            self._raise_alert("WebAttack", src_ip, dst_ip,
                              src_port, dst_port, protocol, 0.85)

    # ── Main packet processor ──────────────────────────────────
    def process_packet(self, packet):
        try:
            self.packet_count += 1
            packet_info = extract_packet_info(packet)

            if not packet_info.get('src_ip'):
                return

            src_ip   = packet_info['src_ip']
            dst_ip   = packet_info['dst_ip']
            src_port = packet_info.get('src_port', 0)
            dst_port = packet_info.get('dst_port', 0)
            protocol = packet_info.get('protocol', 'TCP')

            flow = self.flow_manager.add_packet_to_flow(packet_info)

            if flow:
                pkt_count = flow.get_packet_count()

                # Track new flows for port scan detection
                if pkt_count == 1:
                    self.new_flow_times[src_ip].append(datetime.now())

                # ── Apply all rules ────────────────────────────
                self._detect_portscan(src_ip, dst_ip,
                                      src_port, dst_port, protocol)
                self._detect_flood(flow, src_ip, dst_ip,
                                   src_port, dst_port, protocol)
                self._detect_icmp_flood(src_ip, dst_ip, protocol)
                self._detect_bruteforce(src_ip, dst_ip,
                                        src_port, dst_port, protocol, flow)
                self._detect_webattack(src_ip, dst_ip,
                                       src_port, dst_port, protocol, flow)

                # ── ML detection ───────────────────────────────
                if pkt_count >= MIN_PACKETS_IN_FLOW:
                    features = self.feature_extractor.extract_features(flow)
                    is_attack, pred_class, confidence = \
                        self.inference_engine.is_attack(
                            features, threshold=self.threshold
                        )

                    if self.packet_count % 150 == 0:
                        class_name = self.inference_engine.get_class_name(pred_class)
                        log_runtime(
                            f"[ML] pkts={self.packet_count} | "
                            f"{src_ip}->{dst_ip}:{dst_port} | "
                            f"class={class_name} | conf={confidence:.3f}"
                        )

                    if is_attack and self._cooldown_ok(src_ip, cooldown=5):
                        alert = self.alert_system.generate_alert(
                            src_ip=src_ip, dst_ip=dst_ip,
                            src_port=src_port, dst_port=dst_port,
                            predicted_class=pred_class,
                            confidence=confidence, protocol=protocol
                        )
                        self.alert_system.log_alert(alert)
                        class_name = self.inference_engine.get_class_name(pred_class)
                        log_runtime(
                            f"\n🤖 ML ALERT: {class_name} from "
                            f"{src_ip} conf={confidence:.3f}"
                        )

        except Exception as e:
            log_error("Error processing packet", e)

    def run_continuous(self):
        try:
            self.is_running = True
            log_runtime(f"Monitoring started on {self.interface}...")
            from capture import LivePacketCapture
            capture = LivePacketCapture(interface=self.interface)
            capture.stream_packets(
                callback=self.process_packet, packet_count=0
            )
        except Exception as e:
            log_error("Error in continuous run", e)
        finally:
            self.stop()

    def run_batch(self, packet_count=1000):
        try:
            self.is_running = True
            self.packet_capture.start_capture(
                callback=self.process_packet
            )
        except Exception as e:
            log_error("Error in batch run", e)
        finally:
            self.stop()

    def stop(self):
        self.is_running = False
        self.packet_capture.stop_capture()
        self.flow_manager.cleanup_expired_flows()
        self.print_statistics()
        log_runtime("NIDS stopped.")

    def print_statistics(self):
        stats = self.alert_system.get_alert_statistics()
        log_runtime("=" * 40)
        log_runtime("  FINAL STATISTICS")
        log_runtime(f"  Packets processed : {self.packet_count}")
        log_runtime(f"  Active flows      : {self.flow_manager.get_flow_count()}")
        log_runtime(f"  Total alerts      : {stats['total_alerts']}")
        log_runtime(f"  By type           : {stats['alert_types']}")
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
        }


def main():
    parser = argparse.ArgumentParser(description='NIDS for Raspberry Pi')
    parser.add_argument('--interface', type=str, default=NETWORK_INTERFACE)
    parser.add_argument('--threshold', type=float, default=0.1)
    parser.add_argument('--mode', type=str,
                        choices=['continuous', 'batch'], default='continuous')
    parser.add_argument('--packets', type=int, default=1000)
    args = parser.parse_args()

    nids = NIIDSRuntime(
        interface=args.interface,
        threshold=args.threshold
    )

    try:
        if args.mode == 'continuous':
            nids.run_continuous()
        else:
            nids.run_batch(packet_count=args.packets)
    except KeyboardInterrupt:
        nids.stop()
    except Exception as e:
        log_error("Fatal error", e)
        nids.stop()


if __name__ == "__main__":
    main()
