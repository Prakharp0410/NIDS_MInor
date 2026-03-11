"""
Flow Manager module for Raspberry Pi NIDS.

Groups packets into network flows and manages flow state.
"""

from typing import Dict, List, Optional, Tuple
from datetime import datetime, timedelta
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from utils.helpers import log_runtime, log_error

class NetworkFlow:
    """Represents a network flow."""
    
    def __init__(self, src_ip: str, dst_ip: str, src_port: int, 
                 dst_port: int, protocol: str):
        """Initialize network flow."""
        self.src_ip = src_ip
        self.dst_ip = dst_ip
        self.src_port = src_port
        self.dst_port = dst_port
        self.protocol = protocol
        
        # Flow statistics
        self.packets = []
        self.start_time = datetime.now()
        self.last_packet_time = self.start_time
        self.total_fwd_packets = 0
        self.total_bwd_packets = 0
        self.total_bytes = 0
        
    def add_packet(self, packet_info: dict, direction: str = 'fwd') -> None:
        """
        Add packet to flow.
        
        Args:
            packet_info: Packet information dictionary
            direction: 'fwd' for forward, 'bwd' for backward
        """
        self.packets.append(packet_info)
        self.last_packet_time = datetime.now()
        self.total_bytes += packet_info.get('length', 0)
        
        if direction == 'fwd':
            self.total_fwd_packets += 1
        else:
            self.total_bwd_packets += 1
    
    def get_flow_key(self) -> str:
        """Get unique flow key."""
        return f"{self.src_ip}:{self.src_port}-{self.dst_ip}:{self.dst_port}-{self.protocol}"
    
    def get_duration(self) -> float:
        """Get flow duration in seconds."""
        return (self.last_packet_time - self.start_time).total_seconds()
    
    def get_packet_count(self) -> int:
        """Get total packet count."""
        return len(self.packets)
    
    def is_expired(self, timeout_seconds: int = 120) -> bool:
        """Check if flow has expired."""
        duration = (datetime.now() - self.last_packet_time).total_seconds()
        return duration > timeout_seconds

class FlowManager:
    """Manages network flows."""
    
    def __init__(self, timeout_seconds: int = 120, max_flows: int = 1000):
        """
        Initialize flow manager.
        
        Args:
            timeout_seconds: Flow timeout in seconds
            max_flows: Maximum number of flows to track
        """
        self.flows: Dict[str, NetworkFlow] = {}
        self.timeout_seconds = timeout_seconds
        self.max_flows = max_flows
        self.completed_flows = []
        
        log_runtime(f"Initialized FlowManager (timeout={timeout_seconds}s, max_flows={max_flows})")
    
    def add_packet_to_flow(self, packet_info: dict) -> Optional[NetworkFlow]:
        """
        Add packet to appropriate flow.
        
        Args:
            packet_info: Packet information dictionary
            
        Returns:
            The flow that packet was added to
        """
        try:
            src_ip = packet_info.get('src_ip')
            dst_ip = packet_info.get('dst_ip')
            src_port = packet_info.get('src_port', 0)
            dst_port = packet_info.get('dst_port', 0)
            protocol = packet_info.get('protocol', 'OTHER')
            
            if not src_ip or not dst_ip:
                return None
            
            # Create flow key (both directions)
            flow_key_fwd = f"{src_ip}:{src_port}-{dst_ip}:{dst_port}-{protocol}"
            flow_key_bwd = f"{dst_ip}:{dst_port}-{src_ip}:{src_port}-{protocol}"
            
            # Check if flow exists (either direction)
            if flow_key_fwd in self.flows:
                flow = self.flows[flow_key_fwd]
                flow.add_packet(packet_info, direction='fwd')
                return flow
            
            elif flow_key_bwd in self.flows:
                flow = self.flows[flow_key_bwd]
                flow.add_packet(packet_info, direction='bwd')
                return flow
            
            else:
                # Create new flow
                if len(self.flows) >= self.max_flows:
                    self.cleanup_expired_flows()
                
                new_flow = NetworkFlow(src_ip, dst_ip, src_port, dst_port, protocol)
                new_flow.add_packet(packet_info, direction='fwd')
                self.flows[flow_key_fwd] = new_flow
                
                return new_flow
            
        except Exception as e:
            log_error("Failed to add packet to flow", e)
            return None
    
    def cleanup_expired_flows(self) -> int:
        """Clean up expired flows."""
        try:
            expired_keys = [
                key for key, flow in self.flows.items()
                if flow.is_expired(self.timeout_seconds)
            ]
            
            for key in expired_keys:
                flow = self.flows.pop(key)
                self.completed_flows.append(flow)
            
            if expired_keys:
                log_runtime(f"Cleaned up {len(expired_keys)} expired flows. Active: {len(self.flows)}")
            
            return len(expired_keys)
            
        except Exception as e:
            log_error("Failed to cleanup flows", e)
            return 0
    
    def get_active_flows(self) -> Dict[str, NetworkFlow]:
        """Get all active flows."""
        return self.flows.copy()
    
    def get_flow_by_key(self, flow_key: str) -> Optional[NetworkFlow]:
        """Get specific flow by key."""
        return self.flows.get(flow_key)
    
    def get_completed_flows(self) -> List[NetworkFlow]:
        """Get completed flows."""
        return self.completed_flows.copy()
    
    def get_flow_count(self) -> int:
        """Get count of active flows."""
        return len(self.flows)
    
    def reset(self) -> None:
        """Reset flow manager."""
        self.flows.clear()
        self.completed_flows.clear()
        log_runtime("FlowManager reset")
