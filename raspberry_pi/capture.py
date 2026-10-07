"""
Packet Capture module for Raspberry Pi NIDS.

Captures network packets using scapy and pyshark.
"""

from typing import Optional, Callable, List
import ipaddress
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from utils.helpers import log_runtime, log_error, format_timestamp

class PacketCapture:
    """Captures network packets from specified interface."""
    
    def __init__(self, interface: str = "eth0", packet_count: int = 0, timeout: int = 20):
        """
        Initialize packet capture.
        
        Args:
            interface: Network interface to monitor
            packet_count: Number of packets to capture (0 = infinite)
            timeout: Capture timeout in seconds
        """
        self.interface = interface
        self.packet_count = packet_count
        self.timeout = timeout
        self.packet_buffer = []
        self.is_capturing = False
        
        log_runtime(f"Initialized PacketCapture on {interface}")
    
    def start_capture(self, callback: Optional[Callable] = None) -> List:
        """
        Start packet capture using scapy.
        
        Args:
            callback: Optional callback function to process each packet
            
        Returns:
            List of captured packets
        """
        try:
            from scapy.all import sniff
            
            log_runtime(f"Starting packet capture on {self.interface}...")
            self.is_capturing = True
            
            def packet_handler(packet):
                """Process each captured packet."""
                self.packet_buffer.append(packet)
                if callback:
                    callback(packet)
            
            packets = sniff(
                iface=self.interface,
                prn=packet_handler,
                count=self.packet_count,
                timeout=self.timeout,
                store=True
            )
            
            log_runtime(f"Capture complete. Captured {len(packets)} packets")
            self.is_capturing = False
            
            return packets
            
        except Exception as e:
            log_error("Failed to capture packets", e)
            self.is_capturing = False
            raise
    
    def stop_capture(self) -> None:
        """Stop packet capture."""
        self.is_capturing = False
        log_runtime("Packet capture stopped")
    
    def get_buffer(self) -> List:
        """Get packet buffer."""
        return self.packet_buffer
    
    def clear_buffer(self) -> None:
        """Clear packet buffer."""
        self.packet_buffer = []
        log_runtime("Packet buffer cleared")

class LivePacketCapture:
    """Live streaming packet capture."""
    
    def __init__(self, interface: str = "eth0"):
        """Initialize live capture."""
        self.interface = interface
        log_runtime(f"Initialized LivePacketCapture on {interface}")
    
    def stream_packets(self, callback: Callable, packet_count: int = 0) -> None:
        """
        Stream packets in real-time.
        
        Args:
            callback: Function to process each packet
            packet_count: Number of packets to capture (0 = infinite)
        """
        try:
            from scapy.all import sniff, conf, Ether, IP, TCP, UDP, ICMP

            # Dissect only the layers the engine reads. Payloads stay raw
            # bytes instead of being parsed as DNS, TLS, HTTP, ... which is
            # most of Scapy's per-packet CPU cost on a Pi.
            conf.layers.filter([Ether, IP, TCP, UDP, ICMP])

            log_runtime("Starting live packet stream...")

            def packet_handler(packet):
                """Process packet."""
                try:
                    callback(packet)
                except Exception as e:
                    log_error("Error processing packet", e)

            try:
                # Kernel-side BPF filter: IPv4 only, so ARP and IPv6 never
                # reach Python. Compiling it needs tcpdump or libpcap.
                sniff(iface=self.interface, prn=packet_handler,
                      count=packet_count, store=False, filter="ip")
            except Exception as e:
                if "filter" not in str(e).lower() and "tcpdump" not in str(e).lower():
                    raise
                log_runtime(f"BPF filter unavailable ({e}); capturing without it. "
                            "Install tcpdump for lower CPU use.", "WARNING")
                sniff(iface=self.interface, prn=packet_handler,
                      count=packet_count, store=False)

        except Exception as e:
            log_error("Failed to stream packets", e)
            raise

_LAYERS = None
ETHER_HEADER = 14
MIN_ETHER_FRAME = 60   # CICFlowMeter counted Ethernet padding as payload


def _layers():
    global _LAYERS
    if _LAYERS is None:
        from scapy.all import Ether, IP, TCP, UDP, ICMP
        _LAYERS = (Ether, IP, TCP, UDP, ICMP)
    return _LAYERS


def extract_packet_info(packet) -> dict:
    """
    Extract the fields the engine needs from a Scapy packet.

    Lengths come from header fields rather than len(packet), which would
    re-serialise the whole packet. 'payload_len' follows CICFlowMeter: the
    frame (padded to 60 bytes) minus Ethernet, IP and transport headers.
    """
    try:
        Ether, IP, TCP, UDP, ICMP = _layers()
        info = {
            'ts': float(getattr(packet, 'time', 0) or 0) or None,
            'src_ip': None,
            'dst_ip': None,
            'src_port': None,
            'dst_port': None,
            'protocol': None,
            'length': 0,
            'payload_len': 0,
            'data_len': 0,
            'header_len': 0,
            'flags': '',
            'window': None,
            'icmp_type': None,
            'eth_src': None,
        }

        ether = packet.getlayer(Ether)
        if ether is not None:
            info['eth_src'] = ether.src

        ip = packet.getlayer(IP)
        if ip is None:
            return info

        info['src_ip'] = ip.src
        info['dst_ip'] = ip.dst
        ip_header = (ip.ihl or 5) * 4
        ip_total = ip.len if ip.len is not None else len(ip.original or b'') or ip_header
        frame = max(ip_total + ETHER_HEADER, MIN_ETHER_FRAME)
        info['length'] = ip_total + ETHER_HEADER

        tcp = packet.getlayer(TCP)
        if tcp is not None:
            info['protocol'] = 'TCP'
            info['src_port'] = tcp.sport
            info['dst_port'] = tcp.dport
            info['flags'] = str(tcp.flags)
            info['window'] = tcp.window
            transport_header = (tcp.dataofs or 5) * 4
            info['header_len'] = transport_header
        else:
            udp = packet.getlayer(UDP)
            if udp is not None:
                info['protocol'] = 'UDP'
                info['src_port'] = udp.sport
                info['dst_port'] = udp.dport
                transport_header = 8
            else:
                icmp = packet.getlayer(ICMP)
                info['protocol'] = 'ICMP' if icmp is not None else 'OTHER'
                if icmp is not None:
                    info['icmp_type'] = icmp.type
                transport_header = 8 if icmp is not None else 0
            # The training data records the IP header length here
            info['header_len'] = ip_header

        info['payload_len'] = max(frame - ETHER_HEADER - ip_header - transport_header, 0)
        # True application data, without Ethernet padding (used by the rules)
        info['data_len'] = max(ip_total - ip_header - transport_header, 0)
        return info

    except Exception as e:
        log_error("Failed to extract packet info", e)
        return {}


class HairpinFilter:
    """
    Drops the second copy of Wi-Fi client-to-client packets.

    In gateway mode the access point isolates clients, so a packet from one
    Wi-Fi device to another enters wlan0 and is routed back out of wlan0.
    Sniffing wlan0 therefore sees it twice: inbound from the client, then
    outbound with the gateway's own MAC. Counting both would double packet
    rates and distort flow features, so the outbound copy is skipped.
    Traffic from the internet to clients is only seen once (outbound), and
    the gateway's own traffic is kept, so neither is affected.
    """

    def __init__(self, own_mac: Optional[str], lan_network, own_ip: Optional[str]):
        self.own_mac = own_mac.lower() if own_mac else None
        self.lan_network = lan_network
        self.own_ip = own_ip
        self.enabled = bool(self.own_mac and self.lan_network is not None and self.own_ip)

    @classmethod
    def for_interface(cls, interface: str, lan_network, own_ip: Optional[str]) -> "HairpinFilter":
        mac = None
        try:
            mac = Path(f"/sys/class/net/{interface}/address").read_text().strip()
        except OSError:
            pass
        return cls(mac, lan_network, own_ip)

    def is_duplicate(self, packet_info: dict) -> bool:
        if not self.enabled:
            return False
        eth_src = (packet_info.get('eth_src') or '').lower()
        src_ip = packet_info.get('src_ip')
        if eth_src != self.own_mac or not src_ip or src_ip == self.own_ip:
            return False
        try:
            return ipaddress.IPv4Address(src_ip) in self.lan_network
        except ValueError:
            return False
