# main.py

import os
import sys
import signal
import threading
from pathlib import Path
from typing import Dict, Any
import time
from packethandler import PacketHandler
from nids_analyzer import NIDSAnalyzer
from rule_config import RuleConfiguration
from logger import FirewallLogger

class FirewallNIDS:
    """
    Main application class that integrates firewall and NIDS functionality.
    Coordinates all components and manages system lifecycle.
    """
    
    def __init__(self, config_file: str = "config/rules.yaml"):
        # Initialize base paths
        self.base_dir = Path(__file__).parent.parent
        self.config_path = self.base_dir / config_file
        
        # Set up logging first
        self.logger = FirewallLogger(log_directory=self.base_dir / 'logs')
        
        # Initialize components
        self.config = RuleConfiguration(self.config_path)
        self.packet_handler = PacketHandler(self._get_network_interfaces())
        self.analyzers: Dict[str, NIDSAnalyzer] = {}
        
        # Create NIDS analyzer for each interface
        for interface in self.packet_handler.get_interfaces():
            self.analyzers[interface] = NIDSAnalyzer(interface)
        
        # State management
        self.running = False
        self.start_time = None
    
    def start(self):
        """Start the firewall and NIDS components"""
        try:
            self.running = True
            self.start_time = time.time()
            self.logger.log_info("Starting FirewallNIDS")
            
            # Set up signal handlers
            signal.signal(signal.SIGINT, lambda s, f: self.shutdown())
            signal.signal(signal.SIGTERM, lambda s, f: self.shutdown())
            
            # Load and apply firewall rules
            self._load_rules()
            
            # Start packet handler
            self.packet_handler.start()
            
            # Start NIDS analyzers
            for analyzer in self.analyzers.values():
                analyzer.start()
            
            self.logger.log_info("FirewallNIDS started successfully")
            
            # Keep main thread alive
            while self.running:
                self._monitor_system()
                time.sleep(1)
                
        except Exception as e:
            self.logger.log_error(f"Error starting FirewallNIDS: {str(e)}")
            self.shutdown()
            raise

    def shutdown(self):
        """Perform graceful shutdown of all components"""
        print("\nInitiating shutdown...")
        self.running = False
        
        # Stop analyzers
        for analyzer in self.analyzers.values():
            analyzer.stop()
        
        # Stop packet handler
        self.packet_handler.stop()
        
        # Save current rules
        self._save_rules()
        
        self.logger.log_info("FirewallNIDS shutdown complete")
        sys.exit(0)

    def _get_network_interfaces(self) -> list:
        """Get list of available network interfaces"""
        interfaces = []
        try:
            # Try to get all network interfaces
            for iface in os.listdir('/sys/class/net/'):
                if iface not in ['lo']:  # Exclude loopback
                    interfaces.append(iface)
            return interfaces or ['eth0']  # Default to eth0 if no interfaces found
        except Exception as e:
            self.logger.log_error(f"Error getting network interfaces: {e}")
            return ['eth0']

    def _load_rules(self):
        """Load firewall rules from configuration"""
        try:
            rules = self.config.load_rules()
            for rule in rules:
                self.packet_handler.add_rule(rule)
        except Exception as e:
            self.logger.log_error(f"Error loading rules: {e}")
            self._setup_default_rules()

    def _save_rules(self):
        """Save current firewall rules to configuration"""
        try:
            rules = self.packet_handler.get_rules()
            self.config.save_rules(rules)
        except Exception as e:
            self.logger.log_error(f"Error saving rules: {e}")

    def _monitor_system(self):
        """Monitor system status and log statistics"""
        try:
            stats = {
                'uptime': time.time() - self.start_time,
                'interfaces': {}
            }
            
            for interface, analyzer in self.analyzers.items():
                stats['interfaces'][interface] = {
                    'packets_processed': self.packet_handler.get_stats(interface),
                    'alerts': analyzer.get_stats()
                }
            
            self.logger.log_info("System Status", extra=stats)
            
        except Exception as e:
            self.logger.log_error(f"Error monitoring system: {e}")

def main():
    """Main entry point for the application"""
    # Check for root privileges
    if os.geteuid() != 0:
        print("Error: This program must be run with root privileges!")
        sys.exit(1)
    
    try:
        firewall = FirewallNIDS()
        firewall.start()
    except KeyboardInterrupt:
        print("\nShutdown requested by user")
    except Exception as e:
        print(f"Error: {str(e)}")
        sys.exit(1)

if __name__ == "__main__":
    main()