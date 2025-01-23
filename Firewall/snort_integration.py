import subprocess
import threading
import os
import re
from datetime import datetime
from typing import Optional, List, Dict
from dataclasses import dataclass
import sqlite3

@dataclass
class SnortAlert:
    timestamp: datetime
    priority: int
    classification: str
    msg: str
    src_ip: str
    dst_ip: str
    protocol: str
    rule_id: Optional[int] = None

class SnortIntegration:
    def __init__(self, config_path="/etc/snort/snort.conf", 
                 rules_path="/etc/snort/rules",
                 alert_file="/var/log/snort/alert"):
        self.config_path = config_path
        self.rules_path = rules_path
        self.alert_file = alert_file
        self.snort_process = None
        self.alert_thread = None
        self.running = False
        self.db_conn = sqlite3.connect('/var/log/snort/alerts.db')
        self._setup_database()

    def _setup_database(self):
        cursor = self.db_conn.cursor()
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS snort_alerts (
                id INTEGER PRIMARY KEY,
                timestamp DATETIME,
                priority INTEGER,
                classification TEXT,
                message TEXT,
                src_ip TEXT,
                dst_ip TEXT,
                protocol TEXT,
                rule_id INTEGER
            )
        ''')
        self.db_conn.commit()

    def start_snort(self):
        """Start Snort in IDS mode"""
        try:
            cmd = [
                'snort',
                '-c', self.config_path,
                '-i', 'eth0',  # Interface to monitor
                '-A', 'fast',  # Alert output mode
                '-l', '/var/log/snort',  # Log directory
                '-D'  # Daemon mode
            ]
            
            self.snort_process = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE
            )
            
            # Start alert monitoring thread
            self.running = True
            self.alert_thread = threading.Thread(target=self._monitor_alerts)
            self.alert_thread.daemon = True
            self.alert_thread.start()
            
            return True
            
        except Exception as e:
            print(f"Error starting Snort: {e}")
            return False

    def stop_snort(self):
        """Stop Snort and clean up"""
        self.running = False
        if self.snort_process:
            self.snort_process.terminate()
            self.snort_process.wait()
        
        if self.alert_thread and self.alert_thread.is_alive():
            self.alert_thread.join()

    def _parse_alert(self, alert_line: str) -> Optional[SnortAlert]:
        """Parse a Snort fast alert format line"""
        try:
            pattern = r'''
                (\d{2}/\d{2}-\d{2}:\d{2}:\d{2}\.\d{6})\s+
                \[(\d+):\d+:\d+\]\s+
                ([^[]+)\s+
                \[Classification:\s+([^\]]+)\]\s+
                \[Priority:\s+(\d+)\]\s+
                {(\w+)}\s+
                (\d+\.\d+\.\d+\.\d+):?\d*\s+->\s+
                (\d+\.\d+\.\d+\.\d+):?\d*
            '''
            
            match = re.match(pattern, alert_line, re.VERBOSE)
            if not match:
                return None
                
            timestamp_str, rule_id, msg, classification, priority, \
            protocol, src_ip, dst_ip = match.groups()
            
            timestamp = datetime.strptime(
                timestamp_str, 
                "%m/%d-%H:%M:%S.%f"
            )
            
            return SnortAlert(
                timestamp=timestamp,
                priority=int(priority),
                classification=classification,
                msg=msg.strip(),
                src_ip=src_ip,
                dst_ip=dst_ip,
                protocol=protocol,
                rule_id=int(rule_id)
            )
            
        except Exception as e:
            print(f"Error parsing alert: {e}")
            return None

    def _monitor_alerts(self):
        """Monitor Snort alert file for new alerts"""
        with open(self.alert_file, 'r') as f:
            while self.running:
                line = f.readline()
                if not line:
                    continue
                    
                alert = self._parse_alert(line)
                if alert:
                    self._handle_alert(alert)

    def _handle_alert(self, alert: SnortAlert):
        """Process and store Snort alerts"""
        # Store in database
        cursor = self.db_conn.cursor()
        cursor.execute('''
            INSERT INTO snort_alerts 
            (timestamp, priority, classification, message,
             src_ip, dst_ip, protocol, rule_id)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        ''', (
            alert.timestamp, alert.priority, alert.classification,
            alert.msg, alert.src_ip, alert.dst_ip, 
            alert.protocol, alert.rule_id
        ))
        self.db_conn.commit()
        
        # Create firewall rule for high priority alerts
        if alert.priority <= 2:  # High or medium priority
            self._create_block_rule(alert)

    def _create_block_rule(self, alert: SnortAlert):
        """Create firewall rule based on Snort alert"""
        rule = {
            'action': 'DENY',
            'protocol': alert.protocol,
            'source_ip': alert.src_ip,
            'description': f"Snort Alert: {alert.msg}",
            'priority': 1000 + alert.priority  # High priority
        }
        
        # Send to firewall component
        if hasattr(self, 'firewall_handler'):
            self.firewall_handler.add_rule(rule)

    def add_rule(self, rule_content: str, rule_file: str = "local.rules"):
        """Add a new Snort rule"""
        rule_path = os.path.join(self.rules_path, rule_file)
        try:
            with open(rule_path, 'a') as f:
                f.write(f"\n{rule_content}")
            
            # Reload Snort rules
            subprocess.run(['snort', '-c', self.config_path, '-T'])
            
            # Signal Snort to reload rules
            if self.snort_process:
                self.snort_process.send_signal(subprocess.signal.SIGHUP)
                
            return True
            
        except Exception as e:
            print(f"Error adding rule: {e}")
            return False

    def get_alerts(self, 
                  limit: int = 100, 
                  min_priority: int = None, 
                  src_ip: str = None) -> List[Dict]:
        """Retrieve alerts with optional filtering"""
        query = "SELECT * FROM snort_alerts"
        params = []
        
        conditions = []
        if min_priority:
            conditions.append("priority <= ?")
            params.append(min_priority)
        if src_ip:
            conditions.append("src_ip = ?")
            params.append(src_ip)
            
        if conditions:
            query += " WHERE " + " AND ".join(conditions)
            
        query += " ORDER BY timestamp DESC LIMIT ?"
        params.append(limit)
        
        cursor = self.db_conn.cursor()
        cursor.execute(query, params)
        
        columns = [desc[0] for desc in cursor.description]
        return [dict(zip(columns, row)) for row in cursor.fetchall()]