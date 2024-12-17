# packet_handler.py

from scapy.all import *
from scapy.layers.inet import IP, TCP, UDP, ICMP
import threading
from typing import Dict, Optional, List
from dataclasses import dataclass
from datetime import datetime

from firewall_rules import RuleManager, Rule, Action, Protocol
from logger import FirewallLogger

@dataclass
class PacketStats:
    """Statistics for packet processing"""
    total_packets: int = 0
    allowed_packets: int = 0
    denied_packets: int = 0
    last_packet_time: Optional[datetime] = None

class PacketHandler:
    """
    Handles packet capture and processing with rule-based filtering.
    Supports multiple network interfaces and maintains per-interface statistics.
    """
    
    def __init__(self, interfaces: List[str]):
        self.interfaces = interfaces
        self.logger = FirewallLogger()
        self.rule_manager = RuleManager()
        
        # Per-interface statistics
        self.stats: Dict[str, PacketStats] = {
            interface: PacketStats() for interface in interfaces
        }
        
        # Thread management
        self.running = False
        self.capture_threads: Dict[str, threading.Thread] = {}
        self.lock = threading.Lock()

    def start(self):
        """Start packet capture on all interfaces"""
        self.running = True
        
        for interface in self.interfaces:
            thread = threading.Thread(
                target=self._capture_packets,
                args=(interface,)
            )
            thread.daemon = True
            thread.start()
            self.capture_threads[interface] = thread
            
        self.logger.log_info(f"Started packet capture on interfaces: {', '.join(self.interfaces)}")

    def stop(self):
        """Stop packet capture on all interfaces"""
        self.running = False
        
        for thread in self.capture_threads.values():
            if thread.is_alive():
                thread.join()
                
        self.logger.log_info("Packet capture stopped")

    def _capture_packets(self, interface: str):
        """Capture and process packets on specified interface"""
        try:
            sniff(
                iface=interface,
                prn=lambda pkt: self._process_packet(pkt, interface),
                store=0,
                stop_filter=lambda _: not self.running
            )
        except Exception as e:
            self.logger.log_error(f"Error capturing packets on {interface}: {e}")

    def _process_packet(self, packet: Packet, interface: str) -> bool:
        """Process a captured packet and apply firewall rules"""
        try:
            with self.lock:
                self.stats[interface].total_packets += 1
                self.stats[interface].last_packet_time = datetime.now()
            
            if not packet.haslayer(IP):
                return True
            
            packet_info = self._extract_packet_info(packet)
            if not packet_info:
                return True
            
            # Evaluate against rules
            action = self.rule_manager.evaluate_packet(packet_info)
            
            with self.lock:
                if action == Action.ALLOW:
                    self.stats[interface].allowed_packets += 1
                else:
                    self.stats[interface].denied_packets += 1
            
            self._log_packet(packet_info, action, interface)
            return action == Action.ALLOW
            
        except Exception as e:
            self.logger.log_error(f"Error processing packet: {e}")
            return False

    def _extract_packet_info(self, packet: Packet) -> Optional[Dict]:
        """Extract relevant information from packet"""
        if not packet.haslayer(IP):
            return None
            
        info = {
            'src_ip': packet[IP].src,
            'dst_ip': packet[IP].dst,
            'protocol': 'unknown',
            'timestamp': datetime.now()
        }
        
        if packet.haslayer(TCP):
            info.update({
                'protocol': 'tcp',
                'src_port': packet[TCP].sport,
                'dst_port': packet[TCP].dport,
                'flags': packet[TCP].flags
            })
        elif packet.haslayer(UDP):
            info.update({
                'protocol': 'udp',
                'src_port': packet[UDP].sport,
                'dst_port': packet[UDP].dport
            })
        elif packet.haslayer(ICMP):
            info.update({
                'protocol': 'icmp',
                'type': packet[ICMP].type,
                'code': packet[ICMP].code
            })
            
        return info

    def _log_packet(self, packet_info: Dict, action: Action, interface: str):
        """Log packet processing results"""
        self.logger.log_info(
            f"[{interface}] {packet_info['src_ip']}:{packet_info.get('src_port', '')} -> "
            f"{packet_info['dst_ip']}:{packet_info.get('dst_port', '')} "
            f"[{packet_info['protocol']}] - {action.value.upper()}"
        )

    def get_stats(self, interface: Optional[str] = None) -> Dict:
        """Get packet processing statistics"""
        if interface:
            return self._get_interface_stats(interface)
        return {
            iface: self._get_interface_stats(iface)
            for iface in self.interfaces
        }

    def _get_interface_stats(self, interface: str) -> Dict:
        """Get statistics for specific interface"""
        stats = self.stats[interface]
        return {
            'total_packets': stats.total_packets,
            'allowed_packets': stats.allowed_packets,
            'denied_packets': stats.denied_packets,
            'last_packet_time': stats.last_packet_time
        }

    def get_interfaces(self) -> List[str]:
        """Get list of monitored interfaces"""
        return self.interfaces.copy()

    def add_rule(self, rule: Rule):
        """Add a new firewall rule"""
        self.rule_manager.add_rule(rule)

    def remove_rule(self, rule_id: str) -> bool:
        """Remove a firewall rule"""
        return self.rule_manager.remove_rule(rule_id)

    def get_rules(self) -> List[Rule]:
        """Get all current firewall rules"""
        return self.rule_manager.get_rules()