# firewall_rules.py

from dataclasses import dataclass, field
from typing import Optional, Union, List, Dict
from ipaddress import IPv4Network, IPv4Address, ip_address, ip_network
from enum import Enum
import uuid
import logging
from datetime import datetime

class Action(Enum):
    """Defines possible actions for firewall rules"""
    ALLOW = "allow"
    DENY = "deny"
    LOG = "log"

class Protocol(Enum):
    """Supported network protocols"""
    TCP = "tcp"
    UDP = "udp"
    ICMP = "icmp"
    ANY = "any"

class RuleValidationError(Exception):
    """Custom exception for rule validation errors"""
    pass

@dataclass
class Rule:
    """
    Represents a single firewall rule.
    Each rule defines criteria for matching packets and an action to take.
    
    Attributes:
        id: Unique identifier for the rule
        action: Action to take when rule matches (ALLOW/DENY/LOG)
        protocol: Network protocol this rule applies to
        source_ip: Source IP address/network to match
        destination_ip: Destination IP address/network to match
        source_port: Source port to match (for TCP/UDP)
        destination_port: Destination port to match (for TCP/UDP)
        priority: Rule priority (higher numbers = higher priority)
        description: Human-readable description of the rule
        enabled: Whether the rule is currently active
        created_at: When the rule was created
        modified_at: When the rule was last modified
    """
    id: str = field(default_factory=lambda: str(uuid.uuid4()))
    action: Action = Action.DENY
    protocol: Protocol = Protocol.ANY
    source_ip: Optional[Union[str, IPv4Network, IPv4Address]] = None
    destination_ip: Optional[Union[str, IPv4Network, IPv4Address]] = None
    source_port: Optional[int] = None
    destination_port: Optional[int] = None
    priority: int = 0
    description: str = ""
    enabled: bool = True
    created_at: datetime = field(default_factory=datetime.now)
    modified_at: datetime = field(default_factory=datetime.now)

    def __post_init__(self):
        """Validate and convert rule attributes after initialization"""
        try:
            self._validate_ports()
            self._validate_and_convert_ips()
            self._validate_protocol_port_combination()
        except ValueError as e:
            raise RuleValidationError(f"Rule validation failed: {str(e)}")

    def _validate_ports(self):
        """Validate port numbers are within valid range"""
        for port_name, port in [("Source", self.source_port), 
                              ("Destination", self.destination_port)]:
            if port is not None:
                if not isinstance(port, int):
                    raise ValueError(f"{port_name} port must be an integer")
                if not 0 <= port <= 65535:
                    raise ValueError(
                        f"{port_name} port must be between 0 and 65535"
                    )

    def _validate_and_convert_ips(self):
        """Validate and convert IP addresses/networks"""
        for ip_attr in ['source_ip', 'destination_ip']:
            ip_value = getattr(self, ip_attr)
            if ip_value is not None:
                if isinstance(ip_value, str):
                    try:
                        # Try to convert to network first
                        setattr(self, ip_attr, ip_network(ip_value, strict=False))
                    except ValueError:
                        # If that fails, try as an individual address
                        try:
                            setattr(self, ip_attr, ip_address(ip_value))
                        except ValueError as e:
                            raise ValueError(
                                f"Invalid IP address/network for {ip_attr}: {str(e)}"
                            )

    def _validate_protocol_port_combination(self):
        """Validate protocol and port combinations make sense"""
        has_ports = self.source_port is not None or self.destination_port is not None
        
        if has_ports and self.protocol not in (Protocol.TCP, Protocol.UDP, Protocol.ANY):
            raise ValueError(
                "Ports can only be specified for TCP, UDP, or ANY protocols"
            )

    def update(self, **kwargs):
        """
        Update rule attributes while maintaining validation
        
        Args:
            **kwargs: Attributes to update
        """
        for key, value in kwargs.items():
            if hasattr(self, key):
                setattr(self, key, value)
            else:
                raise AttributeError(f"Invalid rule attribute: {key}")
        
        self.modified_at = datetime.now()
        self.__post_init__()  # Revalidate after updates

class RuleManager:
    """
    Manages firewall rules and handles packet evaluation against rules.
    
    Features:
    - Rule addition, removal, and updates
    - Priority-based rule ordering
    - Packet evaluation against rule set
    - Rule persistence and retrieval
    """

    def __init__(self):
        self.rules: List[Rule] = []
        self.default_action = Action.DENY
        self.logger = logging.getLogger(__name__)
        self.rules_by_id: Dict[str, Rule] = {}

    def add_rule(self, rule: Rule) -> None:
        """
        Add a new rule and sort by priority
        
        Args:
            rule: Rule to add
            
        Raises:
            RuleValidationError: If rule validation fails
        """
        if rule.id in self.rules_by_id:
            raise ValueError(f"Rule with ID {rule.id} already exists")
            
        self.rules.append(rule)
        self.rules_by_id[rule.id] = rule
        self._sort_rules()
        
        self.logger.info(
            f"Added rule {rule.id}: {rule.description} "
            f"(Priority: {rule.priority})"
        )

    def remove_rule(self, rule_id: str) -> bool:
        """
        Remove a rule by its ID
        
        Args:
            rule_id: ID of rule to remove
            
        Returns:
            bool: True if rule was removed, False if not found
        """
        if rule_id in self.rules_by_id:
            rule = self.rules_by_id[rule_id]
            self.rules.remove(rule)
            del self.rules_by_id[rule_id]
            self.logger.info(f"Removed rule {rule_id}")
            return True
        return False

    def update_rule(self, rule_id: str, **kwargs) -> bool:
        """
        Update an existing rule
        
        Args:
            rule_id: ID of rule to update
            **kwargs: Attributes to update
            
        Returns:
            bool: True if rule was updated, False if not found
        """
        if rule_id in self.rules_by_id:
            rule = self.rules_by_id[rule_id]
            try:
                rule.update(**kwargs)
                self._sort_rules()
                self.logger.info(f"Updated rule {rule_id}")
                return True
            except Exception as e:
                self.logger.error(f"Error updating rule {rule_id}: {str(e)}")
                raise
        return False

    def _sort_rules(self) -> None:
        """Sort rules by priority (highest first)"""
        self.rules.sort(key=lambda x: (-x.priority, x.created_at))

    def evaluate_packet(self, packet_info: dict) -> Action:
        """
        Evaluate a packet against all rules and return the appropriate action.
        
        Args:
            packet_info: Dictionary containing packet information
            
        Returns:
            Action: Action to take for this packet
        """
        for rule in self.rules:
            if not rule.enabled:
                continue

            try:
                if self._packet_matches_rule(packet_info, rule):
                    self.logger.debug(
                        f"Packet matched rule {rule.id}: {rule.description}"
                    )
                    return rule.action
            except Exception as e:
                self.logger.error(
                    f"Error evaluating packet against rule {rule.id}: {str(e)}"
                )
                continue

        return self.default_action

    def _packet_matches_rule(self, packet_info: dict, rule: Rule) -> bool:
        """
        Check if a packet matches all criteria of a rule
        
        Args:
            packet_info: Dictionary containing packet information
            rule: Rule to check against
            
        Returns:
            bool: True if packet matches rule, False otherwise
        """
        try:
            # Protocol check
            if (rule.protocol != Protocol.ANY and 
                packet_info['protocol'] != rule.protocol.value):
                return False

            # IP checks
            if rule.source_ip:
                packet_src_ip = ip_address(packet_info['src_ip'])
                if isinstance(rule.source_ip, IPv4Network):
                    if packet_src_ip not in rule.source_ip:
                        return False
                elif packet_src_ip != rule.source_ip:
                    return False

            if rule.destination_ip:
                packet_dst_ip = ip_address(packet_info['dst_ip'])
                if isinstance(rule.destination_ip, IPv4Network):
                    if packet_dst_ip not in rule.destination_ip:
                        return False
                elif packet_dst_ip != rule.destination_ip:
                    return False

            # Port checks for TCP/UDP
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

    def get_rule(self, rule_id: str) -> Optional[Rule]:
        """Get a specific rule by ID"""
        return self.rules_by_id.get(rule_id)

    def get_rules(self) -> List[Rule]:
        """Get all current rules"""
        return self.rules.copy()

    def get_rules_by_priority(self, min_priority: int = None, 
                            max_priority: int = None) -> List[Rule]:
        """Get rules filtered by priority range"""
        rules = self.rules.copy()
        if min_priority is not None:
            rules = [r for r in rules if r.priority >= min_priority]
        if max_priority is not None:
            rules = [r for r in rules if r.priority <= max_priority]
        return rules

# Example usage
if __name__ == "__main__":
    # Configure logging
    logging.basicConfig(level=logging.INFO)
    
    # Create rule manager
    manager = RuleManager()
    
    # Add some example rules
    try:
        # Allow HTTP traffic
        http_rule = Rule(
            action=Action.ALLOW,
            protocol=Protocol.TCP,
            destination_port=80,
            description="Allow incoming HTTP",
            priority=100
        )
        manager.add_rule(http_rule)
        
        # Allow HTTPS traffic
        https_rule = Rule(
            action=Action.ALLOW,
            protocol=Protocol.TCP,
            destination_port=443,
            description="Allow incoming HTTPS",
            priority=100
        )
        manager.add_rule(https_rule)
        
        # Block a specific IP
        block_rule = Rule(
            action=Action.DENY,
            source_ip="192.168.1.100",
            description="Block suspicious IP",
            priority=200
        )
        manager.add_rule(block_rule)
        
    except RuleValidationError as e:
        print(f"Error creating rules: {e}")