"""
Main NIDS Runtime System for Raspberry Pi.

Orchestrates packet capture, flow management, feature extraction, and inference.
"""

import sys
from pathlib import Path
import argparse
import signal

sys.path.insert(0, str(Path(__file__).parent.parent))

from utils.config import NETWORK_INTERFACE, MIN_PACKETS_IN_FLOW, INFERENCE_THRESHOLD
from utils.helpers import log_runtime, log_error, format_timestamp

from capture import PacketCapture, extract_packet_info
from flow_manager import FlowManager
from feature_extractor import FeatureExtractor
from inference import InferenceEngine
from alert_system import AlertSystem
from logger import get_runtime_logger

class NIIDSRuntime:
    """Main NIDS runtime system."""
    
    def __init__(self, interface: str = NETWORK_INTERFACE, 
                 threshold: float = INFERENCE_THRESHOLD):
        """Initialize NIDS runtime."""
        self.interface = interface
        self.threshold = threshold
        
        self.packet_capture = PacketCapture(interface=interface)
        self.flow_manager = FlowManager(timeout_seconds=120, max_flows=5000)
        self.feature_extractor = FeatureExtractor()
        self.inference_engine = InferenceEngine()
        self.alert_system = AlertSystem(min_confidence=threshold)
        
        self.is_running = False
        self.packet_count = 0
        self.flow_count = 0
        
        log_runtime("Initialized NIDS Runtime System")
        
        # Register signal handler
        signal.signal(signal.SIGINT, self._signal_handler)
    
    def _signal_handler(self, sig, frame):
        """Handle interrupt signal."""
        log_runtime("Received interrupt signal")
        self.stop()
    
    def process_packet(self, packet) -> None:
        """Process captured packet."""
        try:
            self.packet_count += 1
            
            # Extract packet info
            packet_info = extract_packet_info(packet)
            
            if not packet_info.get('src_ip'):
                return
            
            # Add to flow
            flow = self.flow_manager.add_packet_to_flow(packet_info)
            
            if flow:
                # Check if flow has enough packets
                if flow.get_packet_count() >= MIN_PACKETS_IN_FLOW:
                    # Extract features
                    features = self.feature_extractor.extract_features(flow)
                    
                    # Make inference
                    is_attack, predicted_class, confidence = self.inference_engine.is_attack(
                        features, threshold=self.threshold
                    )
                    
                    # Log alert if attack detected
                    if is_attack:
                        alert = self.alert_system.generate_alert(
                            src_ip=flow.src_ip,
                            dst_ip=flow.dst_ip,
                            src_port=flow.src_port,
                            dst_port=flow.dst_port,
                            predicted_class=predicted_class,
                            confidence=confidence,
                            protocol=flow.protocol
                        )
                        
                        self.alert_system.log_alert(alert)
        
        except Exception as e:
            log_error("Error processing packet", e)
    
    def run_continuous(self, timeout: int = None) -> None:
        """Run continuous packet capture and analysis."""
        try:
            self.is_running = True
            log_runtime(f"Starting continuous monitoring on {self.interface}...")
            
            from capture import LivePacketCapture
            
            capture = LivePacketCapture(interface=self.interface)
            capture.stream_packets(
                callback=self.process_packet,
                packet_count=0  # Infinite
            )
            
        except Exception as e:
            log_error("Error in continuous run", e)
        finally:
            self.stop()
    
    def run_batch(self, packet_count: int = 1000, timeout: int = 20) -> None:
        """Run batch packet capture and analysis."""
        try:
            self.is_running = True
            log_runtime(f"Starting batch capture ({packet_count} packets)...")
            
            packets = self.packet_capture.start_capture(callback=self.process_packet)
            
            log_runtime(f"Batch processing complete. Captured {len(packets)} packets")
            
        except Exception as e:
            log_error("Error in batch run", e)
        finally:
            self.stop()
    
    def stop(self) -> None:
        """Stop NIDS runtime."""
        self.is_running = False
        
        # Cleanup
        self.packet_capture.stop_capture()
        self.flow_manager.cleanup_expired_flows()
        
        # Print statistics
        self.print_statistics()
        
        log_runtime("NIDS Runtime stopped")
    
    def print_statistics(self) -> None:
        """Print system statistics."""
        stats = self.alert_system.get_alert_statistics()
        active_flows = self.flow_manager.get_flow_count()
        
        log_runtime("=== NIDS Statistics ===")
        log_runtime(f"Total packets processed: {self.packet_count}")
        log_runtime(f"Active flows: {active_flows}")
        log_runtime(f"Total alerts: {stats['total_alerts']}")
        log_runtime(f"Alert types: {stats['alert_types']}")
        if stats['total_alerts'] > 0:
            log_runtime(f"Average confidence: {stats['avg_confidence']:.4f}")
    
    def get_status(self) -> dict:
        """Get current system status."""
        stats = self.alert_system.get_alert_statistics()
        
        return {
            'is_running': self.is_running,
            'interface': self.interface,
            'packets_processed': self.packet_count,
            'active_flows': self.flow_manager.get_flow_count(),
            'total_alerts': stats['total_alerts'],
            'alert_types': stats['alert_types'],
            'inference_ready': self.inference_engine.is_ready,
        }

def main():
    """Main entry point."""
    parser = argparse.ArgumentParser(description='Network Intrusion Detection System for Raspberry Pi')
    parser.add_argument('--interface', type=str, default=NETWORK_INTERFACE,
                       help=f'Network interface to monitor (default: {NETWORK_INTERFACE})')
    parser.add_argument('--threshold', type=float, default=INFERENCE_THRESHOLD,
                       help=f'Confidence threshold for attacks (default: {INFERENCE_THRESHOLD})')
    parser.add_argument('--mode', type=str, choices=['continuous', 'batch'], default='continuous',
                       help='Run mode: continuous or batch')
    parser.add_argument('--packets', type=int, default=1000,
                       help='Number of packets to capture in batch mode')
    
    args = parser.parse_args()
    
    # Initialize NIDS
    nids = NIIDSRuntime(interface=args.interface, threshold=args.threshold)
    
    # Check if inference engine is ready
    if not nids.inference_engine.is_ready:
        log_runtime("WARNING: Inference engine not ready. Ensure model files exist.", "WARNING")
    
    # Run
    try:
        if args.mode == 'continuous':
            nids.run_continuous()
        else:
            nids.run_batch(packet_count=args.packets)
    
    except KeyboardInterrupt:
        log_runtime("Interrupted by user")
        nids.stop()
    except Exception as e:
        log_error("Fatal error in main", e)
        nids.stop()

if __name__ == "__main__":
    main()
