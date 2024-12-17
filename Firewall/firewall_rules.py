from dataclasses import dataclass
from typing import Optional, Union
from ipaddress import IPv4Network, IPv4Address
from enum import Enum
import uuid
import logging

class Action(Enum):
    #Defines possible actions for firewall rules
    ALLOW = "allow"
    DENY = "deny"
    LOG = "log"

class Protocol(Enum):
    #Supported network protocols
    TCP = "tcp"
    UDP = "udp"
    ICMP = "icmp"
    ANY = "any"

@dataclass
class Rule:
    """
    Represents a single firewall rule.
    Each rule defines criteria for matching packets and an action to take."""
    id: str = str(uuid.uuid4())
    action: Action = Action.DENY
    protocol: Protocol = Protocol.ANY
    source_ip: Optional[Union[str, IPv4Network, IPv4Address]] = None
    destination_ip: Optional[Union[str, IPv4Network, IPv4Address]] = None
    source_port: Optional[int] = None
    destination_port: Optional[int] = None
    priority: int = 0
    description: str = ""
    enabled: bool = True

    def __post_init__(self):
       #Validate and convert IP addresses after initialization
        if isinstance(self.source_ip, str):
            try:
                self.source_ip = IPv4Network(self.source_ip)
            except ValueError:
                self.source_ip = IPv4Address(self.source_ip)
        
        if isinstance(self.destination_ip, str):
            try:
                self.destination_ip = IPv4Network(self.destination_ip)
            except ValueError:
                self.destination_ip = IPv4Address(self.destination_ip)

class RuleManager:
    #manages firewall rules and handles packet evaluation against rules.
 
    def __init__(self):
        self.rules = []
        self.default_action = Action.DENY
        self.logger = logging.getLogger(__name__)

    def add_rule(self, rule: Rule) -> None:
        #add a new rule and sort by priority
        self.rules.append(rule)
        self._sort_rules()
        self.logger.info(f"Added rule {rule.id}: {rule.description}")

    def remove_rule(self, rule_id: str) -> bool:
        #Remove a rule by its id
        for i, rule in enumerate(self.rules):
            if rule.id == rule_id:
                self.rules.pop(i)
                self.logger.info(f"Removed rule {rule_id}")
                return True
        return False

    def _sort_rules(self) -> None:
        #Sort rules by priority (highest first)
        self.rules.sort(key=lambda x: x.priority, reverse=True)

    def evaluate_packet(self, packet_info: dict) -> Action:
        # Evaluate a packet against all rules and return the appropriate action.
        for rule in self.rules:
            if not rule.enabled:
                continue

            if self._packet_matches_rule(packet_info, rule):
                self.logger.debug(
                    f"Packet matched rule {rule.id}: {rule.description}"
                )
                return rule.action

        return self.default_action

    def _packet_matches_rule(self, packet_info: dict, rule: Rule) -> bool:
        #Check if a packet matches all criteria of a rule
        try:
            # Check protocol
            if (rule.protocol != Protocol.ANY and 
                packet_info['protocol'] != rule.protocol.value):
                return False

            # Check source IP
            if rule.source_ip:
                packet_src_ip = IPv4Address(packet_info['src_ip'])
                if isinstance(rule.source_ip, IPv4Network):
                    if packet_src_ip not in rule.source_ip:
                        return False
                elif packet_src_ip != rule.source_ip:
                    return False

            # Check destination IP
            if rule.destination_ip:
                packet_dst_ip = IPv4Address(packet_info['dst_ip'])
                if isinstance(rule.destination_ip, IPv4Network):
                    if packet_dst_ip not in rule.destination_ip:
                        return False
                elif packet_dst_ip != rule.destination_ip:
                    return False

            # Check ports for TCP/UDP
            if packet_info['protocol'] in ('tcp', 'udp'):
                if (rule.source_port and 
                    packet_info.get('src_port') != rule.source_port):
                    return False
                
                if (rule.destination_port and 
                    packet_info.get('dst_port') != rule.destination_port):
                    return False

            return True

        except Exception as e:
            self.logger.error(f"Error matching rule: {str(e)}")
            return False

    def get_rules(self) -> list:
        #Return all current rules
        return self.rules.copy()