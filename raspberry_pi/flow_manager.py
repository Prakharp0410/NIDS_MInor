"""
Flow Manager module for the Raspberry Pi NIDS/NIPS.

Groups packets into bidirectional flows and keeps *running* statistics per
flow instead of storing every packet. Each packet costs O(1) time and memory
no matter how long the flow gets, which keeps the Pi responsive during a
flood. The statistics follow CICFlowMeter, the tool that produced the
CICIDS2017 training data:

- packet lengths are transport payload bytes, with Ethernet padding to a
  60-byte frame counted as payload (a pure ACK has length 6),
- the overall Packet Length statistics count the first packet twice,
- header lengths are TCP header bytes (IP header for other protocols),
- times are measured in microseconds,
- standard deviations are sample (n - 1) deviations,
- active/idle periods use a 5-second activity timeout.
"""

import math
import time
from collections import OrderedDict
from typing import Dict, Optional, Tuple
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from utils.helpers import log_runtime, log_error

ACTIVITY_TIMEOUT_US = 5_000_000  # CICFlowMeter default
FIRST_ML_CHECKPOINT = 2          # packets before the first ML classification


class RunningStats:
    """Count, sum, min, max, mean and sample variance in O(1) memory."""

    __slots__ = ("n", "total", "mean", "_m2", "min", "max")

    def __init__(self):
        self.n = 0
        self.total = 0.0
        self.mean = 0.0
        self._m2 = 0.0
        self.min = 0.0
        self.max = 0.0

    def add(self, value: float) -> None:
        self.n += 1
        self.total += value
        if self.n == 1:
            self.min = self.max = value
        else:
            if value < self.min:
                self.min = value
            if value > self.max:
                self.max = value
        delta = value - self.mean
        self.mean += delta / self.n
        self._m2 += delta * (value - self.mean)

    @property
    def variance(self) -> float:
        return self._m2 / (self.n - 1) if self.n > 1 else 0.0

    @property
    def std(self) -> float:
        return math.sqrt(self.variance)


class NetworkFlow:
    """A bidirectional flow; 'fwd' is the direction of the initiator."""

    def __init__(self, src_ip: str, dst_ip: str, src_port: int,
                 dst_port: int, protocol: str, ts: Optional[float] = None):
        self.src_ip = src_ip
        self.dst_ip = dst_ip
        self.src_port = src_port
        self.dst_port = dst_port
        self.protocol = protocol

        now = time.time() if ts is None else ts
        self.first_ts = now
        self.last_ts = now

        self.packet_count = 0
        self.total_fwd_packets = 0
        self.total_bwd_packets = 0
        self.total_bytes = 0            # frame bytes, for statistics only

        # Payload length statistics
        self.fwd_len = RunningStats()
        self.bwd_len = RunningStats()
        self.all_len = RunningStats()

        # Inter-arrival times (microseconds)
        self.flow_iat = RunningStats()
        self.fwd_iat = RunningStats()
        self.bwd_iat = RunningStats()
        self._last_fwd_ts: Optional[float] = None
        self._last_bwd_ts: Optional[float] = None

        # Headers and TCP details
        self.fwd_header_bytes = 0
        self.bwd_header_bytes = 0
        self.fwd_seg_size_min = 0
        self.init_fwd_win = -1
        self.init_bwd_win = -1
        self.fwd_act_data_packets = 0
        self.fwd_psh = self.bwd_psh = 0
        self.fwd_urg = self.bwd_urg = 0
        self.flag_counts = {flag: 0 for flag in "FSRPAUCE"}

        # Active / idle periods (microseconds)
        self.active = RunningStats()
        self.idle = RunningStats()
        self._start_active = now
        self._end_active = now

        # Engine bookkeeping
        self.finished = False           # FIN or RST seen
        self.next_ml_at = FIRST_ML_CHECKPOINT
        self.ml_final_done = False
        self.request_seen = False       # first real data from the initiator

    # ── Packet intake ──────────────────────────────────────────
    def add_packet(self, packet_info: dict, direction: str = 'fwd') -> None:
        ts = packet_info.get('ts')
        if ts is None:
            ts = time.time()
        payload = packet_info.get('payload_len', packet_info.get('length', 0)) or 0
        header = packet_info.get('header_len', 0) or 0
        flags = packet_info.get('flags') or ''
        forward = direction == 'fwd'

        if self.packet_count:
            gap_us = max(ts - self.last_ts, 0.0) * 1e6
            self.flow_iat.add(gap_us)
            # Active/idle bookkeeping (CICFlowMeter updateActiveIdleTime)
            if gap_us > ACTIVITY_TIMEOUT_US:
                active_us = (self._end_active - self._start_active) * 1e6
                if active_us > 0:
                    self.active.add(active_us)
                self.idle.add(gap_us)
                self._start_active = ts
            self._end_active = ts
        self.packet_count += 1
        self.last_ts = max(self.last_ts, ts)
        self.total_bytes += packet_info.get('length', 0) or 0
        if self.packet_count == 1:
            self.all_len.add(payload)   # CICFlowMeter counts the first packet twice
        self.all_len.add(payload)

        if forward:
            if self._last_fwd_ts is not None:
                self.fwd_iat.add(max(ts - self._last_fwd_ts, 0.0) * 1e6)
            self._last_fwd_ts = ts
            self.total_fwd_packets += 1
            self.fwd_len.add(payload)
            self.fwd_header_bytes += header
            if header and (self.fwd_seg_size_min == 0 or header < self.fwd_seg_size_min):
                self.fwd_seg_size_min = header
            if payload > 0:
                self.fwd_act_data_packets += 1
            if 'P' in flags:
                self.fwd_psh += 1
            if 'U' in flags:
                self.fwd_urg += 1
        else:
            if self._last_bwd_ts is not None:
                self.bwd_iat.add(max(ts - self._last_bwd_ts, 0.0) * 1e6)
            self._last_bwd_ts = ts
            self.total_bwd_packets += 1
            self.bwd_len.add(payload)
            self.bwd_header_bytes += header
            if 'P' in flags:
                self.bwd_psh += 1
            if 'U' in flags:
                self.bwd_urg += 1

        window = packet_info.get('window')
        if window is not None:
            if forward and self.init_fwd_win == -1:
                self.init_fwd_win = window
            elif not forward and self.init_bwd_win == -1:
                self.init_bwd_win = window

        if flags:
            for flag in flags:
                if flag in self.flag_counts:
                    self.flag_counts[flag] += 1
            if 'F' in flags or 'R' in flags:
                self.finished = True

    # ── Queries ────────────────────────────────────────────────
    def get_flow_key(self) -> str:
        return f"{self.src_ip}:{self.src_port}-{self.dst_ip}:{self.dst_port}-{self.protocol}"

    def get_duration(self) -> float:
        """Flow duration in seconds."""
        return self.last_ts - self.first_ts

    def get_packet_count(self) -> int:
        return self.packet_count

    def is_expired(self, timeout_seconds: int = 120, now: Optional[float] = None) -> bool:
        now = time.time() if now is None else now
        return (now - self.last_ts) > timeout_seconds

    def ml_due(self) -> bool:
        """True when the flow reached its next ML checkpoint (2, 4, 8, ... packets)
        or just ended. Bounds ML work to O(log n) classifications per flow."""
        if self.packet_count >= self.next_ml_at:
            return True
        return (self.finished and not self.ml_final_done
                and self.packet_count >= FIRST_ML_CHECKPOINT)

    def mark_ml_queued(self) -> None:
        while self.next_ml_at <= self.packet_count:
            self.next_ml_at *= 2
        if self.finished:
            self.ml_final_done = True


FlowKey = Tuple[str, int, str, int, str]


class FlowManager:
    """Tracks active flows with a bounded, least-recently-used table."""

    def __init__(self, timeout_seconds: int = 120, max_flows: int = 1000):
        self.flows: "OrderedDict[FlowKey, NetworkFlow]" = OrderedDict()
        self.timeout_seconds = timeout_seconds
        self.max_flows = max_flows
        self.expired_count = 0
        self.evicted_count = 0

        log_runtime(f"Initialized FlowManager (timeout={timeout_seconds}s, max_flows={max_flows})")

    def add_packet_to_flow(self, packet_info: dict) -> Optional[NetworkFlow]:
        """Add a packet to its flow (either direction); create the flow if new."""
        try:
            src_ip = packet_info.get('src_ip')
            dst_ip = packet_info.get('dst_ip')
            if not src_ip or not dst_ip:
                return None
            src_port = packet_info.get('src_port') or 0
            dst_port = packet_info.get('dst_port') or 0
            protocol = packet_info.get('protocol') or 'OTHER'

            key_fwd = (src_ip, src_port, dst_ip, dst_port, protocol)
            flow = self.flows.get(key_fwd)
            if flow is not None:
                self.flows.move_to_end(key_fwd)
                flow.add_packet(packet_info, direction='fwd')
                return flow

            key_bwd = (dst_ip, dst_port, src_ip, src_port, protocol)
            flow = self.flows.get(key_bwd)
            if flow is not None:
                self.flows.move_to_end(key_bwd)
                flow.add_packet(packet_info, direction='bwd')
                return flow

            if len(self.flows) >= self.max_flows:
                self.cleanup_expired_flows()
                while len(self.flows) >= self.max_flows:
                    self.flows.popitem(last=False)   # least recently active
                    self.evicted_count += 1

            # A SYN-ACK as the first packet means we joined mid-handshake:
            # the sender is the server, so orient the flow the other way.
            flags = packet_info.get('flags') or ''
            if protocol == 'TCP' and 'S' in flags and 'A' in flags:
                flow = NetworkFlow(dst_ip, src_ip, dst_port, src_port, protocol,
                                   ts=packet_info.get('ts'))
                flow.add_packet(packet_info, direction='bwd')
                self.flows[key_bwd] = flow
            else:
                flow = NetworkFlow(src_ip, dst_ip, src_port, dst_port, protocol,
                                   ts=packet_info.get('ts'))
                flow.add_packet(packet_info, direction='fwd')
                self.flows[key_fwd] = flow
            return flow

        except Exception as e:
            log_error("Failed to add packet to flow", e)
            return None

    def cleanup_expired_flows(self, now: Optional[float] = None) -> int:
        """Drop flows idle longer than the timeout. The table is ordered by
        last activity, so this stops at the first flow that is still live."""
        now = time.time() if now is None else now
        removed = 0
        while self.flows:
            key, flow = next(iter(self.flows.items()))
            if not flow.is_expired(self.timeout_seconds, now):
                break
            self.flows.popitem(last=False)
            removed += 1
        self.expired_count += removed
        return removed

    def get_active_flows(self) -> Dict[FlowKey, NetworkFlow]:
        return dict(self.flows)

    def get_flow_count(self) -> int:
        return len(self.flows)

    def reset(self) -> None:
        self.flows.clear()
        log_runtime("FlowManager reset")
