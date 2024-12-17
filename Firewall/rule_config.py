import yaml
import logging
from firewall_rules import Rule, Action, Protocol

class RuleConfiguration:
    #Handles loading and saving firewall rules from configuration files
    
    def __init__(self, config_file: str):
        self.config_file = config_file
        self.logger = logging.getLogger(__name__)

    def load_rules(self) -> list:
        #Returns a list of Rule objects
        try:
            with open(self.config_file, 'r') as f:
                config = yaml.safe_load(f)

            rules = []
            for rule_config in config.get('rules', []):
                try:
                    rule = self._create_rule_from_config(rule_config)
                    rules.append(rule)
                except Exception as e:
                    self.logger.error(f"Error creating rule: {str(e)}")
                    continue

            return rules

        except Exception as e:
            self.logger.error(f"Error loading rules: {str(e)}")
            return []

    def save_rules(self, rules: list) -> bool:
        #Returns true if successful,false otherwise

        try:
            config = {'rules': [self._rule_to_dict(rule) for rule in rules]}
            
            with open(self.config_file, 'w') as f:
                yaml.dump(config, f, default_flow_style=False)
            
            return True

        except Exception as e:
            self.logger.error(f"Error saving rules: {str(e)}")
            return False

    def _create_rule_from_config(self, config: dict) -> Rule:
        #Create a rule object from config dict
        return Rule(
            action=Action[config['action'].upper()],
            protocol=Protocol[config['protocol'].upper()],
            source_ip=config.get('source_ip'),
            destination_ip=config.get('destination_ip'),
            source_port=config.get('source_port'),
            destination_port=config.get('destination_port'),
            priority=config.get('priority', 0),
            description=config.get('description', ''),
            enabled=config.get('enabled', True)
        )

    def _rule_to_dict(self, rule: Rule) -> dict:
        #Convert a Rule object to a dictionary for YAML storage#
        return {
            'action': rule.action.value,
            'protocol': rule.protocol.value,
            'source_ip': str(rule.source_ip) if rule.source_ip else None,
            'destination_ip': str(rule.destination_ip) if rule.destination_ip else None,
            'source_port': rule.source_port,
            'destination_port': rule.destination_port,
            'priority': rule.priority,
            'description': rule.description,
            'enabled': rule.enabled
        }