from scapy.all import *
from scapy.layers.inet import IP, TCP, UDP, ICMP
import threading
from logger import FirewallLogger
from firewall_rules import RuleManager, Action, Protocol, Rule

class PacketHandler:
    #Handles packet capture and processing with rule-based filtering.
 
    def __init__(self, interfaces=None):
        if interfaces is None:
            interfaces = ['wlo1', 'eth0']
        self.interfaces = interfaces
        self.logger = FirewallLogger()
        self.rule_manager = RuleManager()
        self.running = False
        self.packet_count = 0
        self.lock = threading.Lock()
        
        # Set up default rules
        self._setup_default_rules()

    def _setup_default_rules(self):
        """Set up default firewall rules"""
        # Allow web traffic
        self.rule_manager.add_rule(Rule(
            action=Action.ALLOW,
            protocol=Protocol.TCP,
            destination_port=80,
            description="Allow HTTP traffic",
            priority=100
        ))
        
        self.rule_manager.add_rule(Rule(
            action=Action.ALLOW,
            protocol=Protocol.TCP,
            destination_port=443,
            description="Allow HTTPS traffic",
            priority=100
        ))

        # Allow DNS
        self.rule_manager.add_rule(Rule(
            action=Action.ALLOW,
            protocol=Protocol.UDP,
            destination_port=53,
            description="Allow DNS queries",
            priority=90
        ))

        # Allow local network
        self.rule_manager.add_rule(Rule(
            action=Action.ALLOW,
            protocol=Protocol.ANY,
            source_ip="192.168.1.0/24",
            description="Allow local network traffic",
            priority=80
        ))

    def start_capture(self):
        self.running = True
        self.logger.log_info(f"Starting packet capture on interfaces: {', '.join(self.interfaces)}")
        
        try:
            sniff(
                iface=self.interfaces,
                prn=self.process_packet,
                store=0,
                stop_filter=lambda _: not self.running
            )
            
        except Exception as e:
            self.logger.log_error(f"Error in packet capture: {str(e)}")
            self.running = False
            raise

    def stop_capture(self):
        #top packet capture
        self.logger.log_info("Stopping packet capture")
        self.running = False

    def process_packet(self, packet):
        #Process and filter captured packets
        try:
            with self.lock:
                self.packet_count += 1
            
            packet_info = self._extract_packet_info(packet)
            if not packet_info:
                return
            
            # Evaluate packet against rules
            action = self.rule_manager.evaluate_packet(packet_info)
            
            # Log the action
            self.logger.log_info(
                f"Packet {self.packet_count}: "
                f"{packet_info['src_ip']}:{packet_info.get('src_port', '')} -> "
                f"{packet_info['dst_ip']}:{packet_info.get('dst_port', '')} "
                f"[{packet_info['protocol']}] - {action.value.upper()}"
            )
            
            # Return true to allow packet,false to block
            return action == Action.ALLOW
            
        except Exception as e:
            self.logger.log_error(f"Error processing packet: {str(e)}")
            return False

    def _extract_packet_info(self, packet):
        #extract relevant information from a packet
        if IP not in packet:
            return None
            
        info = {
            'src_ip': packet[IP].src,
            'dst_ip': packet[IP].dst,
            'protocol': 'unknown'
        }
        
        if TCP in packet:
            info.update({
                'protocol': 'tcp',
                'src_port': packet[TCP].sport,
                'dst_port': packet[TCP].dport,
                'flags': packet[TCP].flags
            })
        elif UDP in packet:
            info.update({
                'protocol': 'udp',
                'src_port': packet[UDP].sport,
                'dst_port': packet[UDP].dport
            })
        elif ICMP in packet:
            info.update({
                'protocol': 'icmp',
                'type': packet[ICMP].type,
                'code': packet[ICMP].code
            })
            
        return info

    def add_rule(self, rule: Rule):
        #Add a new firewall rul
        self.rule_manager.add_rule(rule)

    def remove_rule(self, rule_id: str):
        #Remove a firewall rule
        return self.rule_manager.remove_rule(rule_id)

    def get_rules(self):
        #Get all current firewall rules
        return self.rule_manager.get_rules()