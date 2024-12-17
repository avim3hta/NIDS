# Import all Scapy components and specific layers needed for packet analysis
from scapy.all import *
from scapy.layers.inet import IP, TCP, UDP, ICMP
from scapy.layers.http import HTTP, HTTPRequest, HTTPResponse
from scapy.layers.dns import DNS
from scapy.packet import Packet
from scapy.data import TCP_SERVICES, UDP_SERVICES

from dataclasses import dataclass
from typing import List, Dict, Optional
from datetime import datetime, timedelta
import threading
import collections
import re
from firewall_rules import Rule, Action, Protocol
from logger import FirewallLogger

@dataclass
class SecurityAlert:
    """Represents a security alert generated by NIDS"""
    timestamp: datetime
    alert_type: str
    severity: str  # 'low', 'medium', 'high', 'critical'
    source_ip: str
    destination_ip: str
    description: str
    packet_data: dict

class NIDSAnalyzer:
    """
    Network Intrusion Detection System that integrates with the firewall.
    Analyzes network traffic for potential security threats using Scapy.
    """
    
    def __init__(self, packet_handler):
        """Initialize NIDS with firewall's packet handler"""
        self.packet_handler = packet_handler
        self.logger = FirewallLogger()
        
        # Initialize detection components with type hints for clarity
        self.packet_history: Dict[str, List[datetime]] = collections.defaultdict(list)
        self.connection_tracking: Dict[str, str] = {}
        self.scan_detection: Dict[str, int] = collections.defaultdict(int)
        self.alerts: List[SecurityAlert] = []
        
        # Detection thresholds
        self.RATE_LIMIT_THRESHOLD = 100  # packets per second
        self.PORT_SCAN_THRESHOLD = 15    # unique ports in 5 seconds
        
        # Suspicious patterns for payload analysis
        self.SUSPICIOUS_PATTERNS = [
            # SQL injection patterns
            re.compile(rb'(?i)(?:union\s+select|drop\s+table|exec\s+sp_|exec\s+xp_)'),
            # Cross-site scripting (XSS) patterns
            re.compile(rb'(?i)(?:<script>|alert\(|onclick=|onerror=)'),
            # Path traversal patterns
            re.compile(rb'(?i)(?:/etc/passwd|/etc/shadow|/proc/self)'),
            # Command injection patterns
            re.compile(rb'(?i)(?:;\s*(?:bash|sh|ksh)|\/bin\/(?:bash|sh|ksh))'),
            # File inclusion patterns
            re.compile(rb'(?i)(?:\.\.\/|\.\.\\|~\/|~\\)')
        ]
        
        # Start background analysis thread
        self.running = True
        self.analysis_thread = threading.Thread(target=self._background_analysis)
        self.analysis_thread.daemon = True
        self.analysis_thread.start()
        
        # Register with packet handler
        self._register_with_packet_handler()

    def _register_with_packet_handler(self):
        """
        Extends packet handler's process_packet method to include NIDS analysis.
        Preserves original firewall functionality while adding NIDS capabilities.
        """
        original_process = self.packet_handler.process_packet
        
        def enhanced_process(packet: Packet) -> bool:
            # First, let the firewall process the packet
            allow = original_process(packet)
            
            # If packet is allowed, perform NIDS analysis
            if allow and isinstance(packet, Packet):
                if IP in packet:  # Check if packet has IP layer
                    packet_info = self._extract_packet_info(packet)
                    if packet_info:
                        alert = self.analyze_packet(packet, packet_info)
                        if alert:
                            self._handle_alert(alert)
            
            return allow
        
        # Replace packet handler's process_packet with enhanced version
        self.packet_handler.process_packet = enhanced_process

    def _extract_packet_info(self, packet: Packet) -> Optional[Dict]:
        """
        Extracts relevant information from a packet for analysis.
        Handles different protocol layers (IP, TCP, UDP, ICMP).
        """
        if not packet.haslayer(IP):
            return None
            
        info = {
            'src_ip': packet[IP].src,
            'dst_ip': packet[IP].dst,
            'protocol': 'unknown',
            'length': len(packet),
            'time': datetime.now()
        }
        
        # TCP layer analysis
        if packet.haslayer(TCP):
            info.update({
                'protocol': 'tcp',
                'src_port': packet[TCP].sport,
                'dst_port': packet[TCP].dport,
                'flags': packet[TCP].flags,
                'seq': packet[TCP].seq,
                'ack': packet[TCP].ack
            })
            
            # HTTP analysis if present
            if packet.haslayer(HTTPRequest):
                info['http_method'] = packet[HTTPRequest].Method.decode()
                info['http_path'] = packet[HTTPRequest].Path.decode()
                
        # UDP layer analysis
        elif packet.haslayer(UDP):
            info.update({
                'protocol': 'udp',
                'src_port': packet[UDP].sport,
                'dst_port': packet[UDP].dport
            })
            
            # DNS analysis if present
            if packet.haslayer(DNS):
                info['dns_query'] = True
                
        # ICMP layer analysis
        elif packet.haslayer(ICMP):
            info.update({
                'protocol': 'icmp',
                'type': packet[ICMP].type,
                'code': packet[ICMP].code
            })
            
        return info

    # ... [rest of the methods remain the same as in previous version] ...

    def analyze_packet(self, packet: Packet, packet_info: dict) -> Optional[SecurityAlert]:
        """
        Analyzes a packet for potential security threats using various detection methods.
        Now properly handles Scapy packet layers.
        """
        try:
            # Check for rate limiting violations
            if self._check_rate_limiting(packet_info):
                return self._create_alert("Rate Limit Exceeded", "medium", packet_info)

            # Detect port scanning
            if self._detect_port_scan(packet_info):
                return self._create_alert("Port Scan Detected", "high", packet_info)

            # Analyze packet payload for suspicious patterns
            if packet.haslayer(IP) and packet.haslayer(Raw):
                payload = packet[Raw].load
                for pattern in self.SUSPICIOUS_PATTERNS:
                    if pattern.search(payload):
                        return self._create_alert("Malicious Payload Detected", "critical", packet_info)

            # TCP SYN flood detection
            if packet.haslayer(TCP) and packet[TCP].flags & 0x02:
                if self._detect_syn_flood(packet_info):
                    return self._create_alert("SYN Flood Detected", "high", packet_info)

            # Analyze TCP connection states
            if packet.haslayer(TCP):
                if self._analyze_tcp_state(packet, packet_info):
                    return self._create_alert("TCP State Violation", "medium", packet_info)

            return None

        except Exception as e:
            self.logger.log_error(f"Error in NIDS analysis: {str(e)}")
            return None