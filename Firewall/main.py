import os
import sys
import signal
import threading
from datetime import datetime
from scapy.all import *
from scapy.layers.inet import IP, TCP, UDP, ICMP

# Import our custom components
from packethandler import PacketHandler
from firewall_rules import Rule, Action, Protocol
from rule_config import RuleConfiguration
from logger import FirewallLogger
from nids_analyzer import NIDSAnalyzer

class FirewallNIDS:
    """
    Main application class that integrates firewall and NIDS functionality.
    Manages packet capture, rule enforcement, and intrusion detection.
    """
    def __init__(self, interface="wlo1", config_file="config/rules.yaml"):
        # Initialize base directory and paths
        self.base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        self.config_file = os.path.join(self.base_dir, config_file)
        
        # Initialize core components
        self.logger = FirewallLogger(log_directory=os.path.join(self.base_dir, 'logs'))
        self.packet_handler = PacketHandler(interface=interface)
        self.config = RuleConfiguration(self.config_file)
        
        # Initialize NIDS after packet handler
        self.nids = NIDSAnalyzer(self.packet_handler)
        
        # Set initial state
        self.running = False
        
        # Log initialization
        self.logger.log_info("FirewallNIDS initialization complete")
        self.logger.log_info(f"Using interface: {interface}")
        self.logger.log_info(f"Config file: {self.config_file}")

    def start(self):
        """
        Starts the firewall and NIDS components.
        Sets up signal handling and begins packet processing.
        """
        try:
            self.running = True
            self.logger.log_info("Starting FirewallNIDS")
            
            # Set up signal handlers for graceful shutdown
            def signal_handler(signum, frame):
                self.shutdown()
            
            signal.signal(signal.SIGINT, signal_handler)
            signal.signal(signal.SIGTERM, signal_handler)
            
            # Load firewall rules
            self.load_config()
            
            # Start packet capture in a separate thread
            capture_thread = threading.Thread(target=self.packet_handler.start_capture)
            capture_thread.daemon = True
            capture_thread.start()
            
            print("FirewallNIDS is running. Press Ctrl+C to stop.")
            
            # Keep the main thread alive and monitor system
            while self.running:
                # Monitor system status and performance
                self._monitor_system()
                # Sleep to prevent high CPU usage
                time.sleep(1)
                
        except Exception as e:
            self.logger.log_error(f"Error in FirewallNIDS operation: {str(e)}")
            self.shutdown()
            raise

    def shutdown(self):
        """
        Performs graceful shutdown of all components.
        Ensures all resources are properly cleaned up.
        """
        print("\nShutting down FirewallNIDS...")
        self.running = False
        
        # Stop NIDS analysis
        if hasattr(self, 'nids'):
            self.nids.stop()
            
        # Stop packet capture
        if hasattr(self, 'packet_handler'):
            self.packet_handler.stop_capture()
            
        # Save current rules configuration
        if hasattr(self, 'config'):
            self.save_config()
            
        self.logger.log_info("FirewallNIDS shutdown complete")
        sys.exit(0)

    def load_config(self):
        """
        Loads firewall rules from configuration file.
        Creates default rules if config file is missing.
        """
        try:
            rules = self.config.load_rules()
            for rule in rules:
                self.packet_handler.add_rule(rule)
            self.logger.log_info(f"Loaded {len(rules)} rules from configuration")
        except FileNotFoundError:
            self.logger.log_warning("Configuration file not found, using default rules")
            self._setup_default_rules()
        except Exception as e:
            self.logger.log_error(f"Error loading configuration: {str(e)}")
            self._setup_default_rules()

    def save_config(self):
        """
        Saves current firewall rules to configuration file.
        """
        try:
            rules = self.packet_handler.get_rules()
            if self.config.save_rules(rules):
                self.logger.log_info("Rules configuration saved successfully")
            else:
                self.logger.log_error("Failed to save rules configuration")
        except Exception as e:
            self.logger.log_error(f"Error saving configuration: {str(e)}")

    def _setup_default_rules(self):
        """
        Creates basic default rules for essential services.
        """
        default_rules = [
            Rule(
                action=Action.ALLOW,
                protocol=Protocol.TCP,
                destination_port=80,
                description="Allow HTTP traffic",
                priority=100
            ),
            Rule(
                action=Action.ALLOW,
                protocol=Protocol.TCP,
                destination_port=443,
                description="Allow HTTPS traffic",
                priority=100
            ),
            Rule(
                action=Action.ALLOW,
                protocol=Protocol.UDP,
                destination_port=53,
                description="Allow DNS queries",
                priority=90
            )
        ]
        
        for rule in default_rules:
            self.packet_handler.add_rule(rule)
            
        self.logger.log_info("Default rules configured")

    def _monitor_system(self):
        """
        Monitors system status and logs performance metrics.
        """
        if hasattr(self.packet_handler, 'packet_count'):
            self.logger.log_info(
                f"Processed packets: {self.packet_handler.packet_count}, "
                f"Active rules: {len(self.packet_handler.get_rules())}, "
                f"Alerts: {len(self.nids.alerts)}"
            )

def check_privileges():
    """
    Verifies the application has necessary privileges.
    """
    if os.geteuid() != 0:
        print("Error: This program must be run with root privileges!")
        print("Please try again using 'sudo python3 main.py'")
        sys.exit(1)

def main():
    """
    Main entry point for the FirewallNIDS application.
    """
    try:
        # Check for root privileges
        check_privileges()
        
        # Get the default network interface
        interfaces = os.listdir('/sys/class/net/')
        interface = 'wlo1' if 'wlo1' in interfaces else interfaces[0]
        
        # Create and start the firewall NIDS
        firewall_nids = FirewallNIDS(interface=interface)
        firewall_nids.start()
        
    except KeyboardInterrupt:
        print("\nFirewallNIDS stopped by user")
    except Exception as e:
        print(f"Error: {str(e)}")
        sys.exit(1)

if __name__ == "__main__":
    main()