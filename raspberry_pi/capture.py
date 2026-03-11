"""
Packet Capture module for Raspberry Pi NIDS.

Captures network packets using scapy and pyshark.
"""

from typing import Optional, Callable, List
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
            from scapy.all import sniff
            
            log_runtime("Starting live packet stream...")
            
            def packet_handler(packet):
                """Process packet."""
                try:
                    callback(packet)
                except Exception as e:
                    log_error("Error processing packet", e)
            
            sniff(
                iface=self.interface,
                prn=packet_handler,
                count=packet_count,
                store=False
            )
            
        except Exception as e:
            log_error("Failed to stream packets", e)
            raise

def extract_packet_info(packet) -> dict:
    """Extract relevant information from packet."""
    try:
        from scapy.all import IP, TCP, UDP, ICMP
        
        info = {
            'timestamp': format_timestamp(),
            'src_ip': None,
            'dst_ip': None,
            'src_port': None,
            'dst_port': None,
            'protocol': None,
            'length': len(packet),
            'flags': None,
        }
        
        if IP in packet:
            info['src_ip'] = packet[IP].src
            info['dst_ip'] = packet[IP].dst
            
            if TCP in packet:
                info['src_port'] = packet[TCP].sport
                info['dst_port'] = packet[TCP].dport
                info['protocol'] = 'TCP'
                info['flags'] = packet[TCP].flags
            
            elif UDP in packet:
                info['src_port'] = packet[UDP].sport
                info['dst_port'] = packet[UDP].dport
                info['protocol'] = 'UDP'
            
            elif ICMP in packet:
                info['protocol'] = 'ICMP'
        
        return info
        
    except Exception as e:
        log_error("Failed to extract packet info", e)
        return {}
