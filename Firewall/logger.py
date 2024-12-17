# logger.py

import os
import logging
import logging.handlers
from datetime import datetime
import json
from pathlib import Path
from typing import Any, Dict, Optional, List
import threading
from dataclasses import dataclass, asdict
import time

@dataclass
class LogEntry:
    """Represents a structured log entry"""
    timestamp: str
    level: str
    message: str
    source: str
    event_type: str
    details: Dict[str, Any]

class FirewallLogger:
    """
    Advanced logging system for firewall and NIDS components.
    
    Features:
    - Multiple log levels (INFO, WARNING, ERROR, CRITICAL)
    - Automatic log rotation
    - JSON structured logging
    - Thread-safe logging operations
    - Separate security event logging
    - Log compression for archived logs
    """
    
    def __init__(self, log_directory: str = 'logs', max_size_mb: int = 10, backup_count: int = 5):
        """
        Initialize the logging system.
        
        Args:
            log_directory: Directory to store log files
            max_size_mb: Maximum size of each log file in MB
            backup_count: Number of backup files to keep
        """
        self.log_directory = Path(log_directory)
        self.max_size_bytes = max_size_mb * 1024 * 1024
        self.backup_count = backup_count
        self.log_lock = threading.Lock()
        
        # Create separate loggers for different types of logs
        self._setup_logging()
        
    def _setup_logging(self):
        """Configure the logging system with different handlers"""
        try:
            # Create log directories
            self.log_directory.mkdir(parents=True, exist_ok=True)
            (self.log_directory / 'security').mkdir(exist_ok=True)
            (self.log_directory / 'system').mkdir(exist_ok=True)
            
            # Set up main system logger
            self.system_logger = self._create_logger(
                'system',
                self.log_directory / 'system' / 'firewall.log',
                '%(asctime)s - %(levelname)s - %(message)s'
            )
            
            # Set up security event logger
            self.security_logger = self._create_logger(
                'security',
                self.log_directory / 'security' / 'security_events.log',
                '%(asctime)s - [SECURITY] - %(levelname)s - %(message)s'
            )
            
            self.system_logger.info("Logging system initialized successfully")
            
        except Exception as e:
            print(f"Critical error setting up logging: {str(e)}")
            raise

    def _create_logger(self, name: str, log_file: Path, format_string: str) -> logging.Logger:
        """Create a configured logger instance"""
        logger = logging.getLogger(name)
        logger.setLevel(logging.INFO)
        
        # Create rotating file handler
        file_handler = logging.handlers.RotatingFileHandler(
            log_file,
            maxBytes=self.max_size_bytes,
            backupCount=self.backup_count,
            encoding='utf-8'
        )
        
        # Create console handler
        console_handler = logging.StreamHandler()
        
        # Create formatter
        formatter = logging.Formatter(format_string)
        
        # Set formatter for handlers
        file_handler.setFormatter(formatter)
        console_handler.setFormatter(formatter)
        
        # Add handlers to logger
        logger.addHandler(file_handler)
        logger.addHandler(console_handler)
        
        return logger

    def _format_log_entry(self, message: str, level: str, event_type: str = "SYSTEM",
                         source: str = "FIREWALL", details: Dict[str, Any] = None) -> str:
        """Format a log entry as JSON"""
        entry = LogEntry(
            timestamp=datetime.now().isoformat(),
            level=level,
            message=message,
            source=source,
            event_type=event_type,
            details=details or {}
        )
        return json.dumps(asdict(entry))

    def log_security_event(self, message: str, level: str = "INFO", 
                          details: Optional[Dict[str, Any]] = None):
        """Log security-specific events"""
        with self.log_lock:
            formatted_message = self._format_log_entry(
                message, level, "SECURITY", "FIREWALL", details
            )
            if level == "ERROR":
                self.security_logger.error(formatted_message)
            elif level == "WARNING":
                self.security_logger.warning(formatted_message)
            else:
                self.security_logger.info(formatted_message)

    def log_packet(self, packet_info: Dict[str, Any], action: str):
        """Log packet processing information"""
        with self.log_lock:
            formatted_message = self._format_log_entry(
                f"Packet {action}",
                "INFO",
                "PACKET",
                "FIREWALL",
                packet_info
            )
            self.system_logger.info(formatted_message)

    def log_rule_change(self, rule_id: str, action: str, details: Dict[str, Any]):
        """Log firewall rule changes"""
        with self.log_lock:
            formatted_message = self._format_log_entry(
                f"Rule {action}: {rule_id}",
                "INFO",
                "RULE_CHANGE",
                "FIREWALL",
                details
            )
            self.system_logger.info(formatted_message)

    def log_info(self, message: str, extra: Optional[Dict[str, Any]] = None):
        """Log informational message"""
        with self.log_lock:
            formatted_message = self._format_log_entry(
                message, "INFO", details=extra
            )
            self.system_logger.info(formatted_message)

    def log_warning(self, message: str, extra: Optional[Dict[str, Any]] = None):
        """Log warning message"""
        with self.log_lock:
            formatted_message = self._format_log_entry(
                message, "WARNING", details=extra
            )
            self.system_logger.warning(formatted_message)

    def log_error(self, message: str, extra: Optional[Dict[str, Any]] = None):
        """Log error message"""
        with self.log_lock:
            formatted_message = self._format_log_entry(
                message, "ERROR", details=extra
            )
            self.system_logger.error(formatted_message)

    def log_critical(self, message: str, extra: Optional[Dict[str, Any]] = None):
        """Log critical message"""
        with self.log_lock:
            formatted_message = self._format_log_entry(
                message, "CRITICAL", details=extra
            )
            self.system_logger.critical(formatted_message)

    def archive_old_logs(self, days_to_keep: int = 30):
        """Archive logs older than specified days"""
        try:
            current_time = time.time()
            archives_dir = self.log_directory / 'archives'
            archives_dir.mkdir(exist_ok=True)

            for log_file in self.log_directory.glob('**/*.log.*'):
                if (current_time - log_file.stat().st_mtime) > (days_to_keep * 86400):
                    archive_name = archives_dir / f"{log_file.stem}_{int(time.time())}.gz"
                    self._compress_log(log_file, archive_name)
                    log_file.unlink()

        except Exception as e:
            self.log_error(f"Error archiving logs: {str(e)}")

    def _compress_log(self, source_path: Path, dest_path: Path):
        """Compress a log file using gzip"""
        import gzip
        with open(source_path, 'rb') as f_in:
            with gzip.open(dest_path, 'wb') as f_out:
                f_out.writelines(f_in)

    def get_recent_security_events(self, count: int = 100) -> List[Dict]:
        """Retrieve recent security events"""
        events = []
        security_log = self.log_directory / 'security' / 'security_events.log'
        
        if security_log.exists():
            with open(security_log, 'r') as f:
                for line in f.readlines()[-count:]:
                    try:
                        events.append(json.loads(line))
                    except json.JSONDecodeError:
                        continue
                        
        return events

# Example usage
if __name__ == "__main__":
    logger = FirewallLogger()
    
    # Log some example events
    logger.log_info("Firewall started")
    logger.log_security_event(
        "Potential port scan detected",
        "WARNING",
        {"source_ip": "192.168.1.100", "ports_scanned": 15}
    )
    logger.log_packet(
        {"src": "192.168.1.100", "dst": "10.0.0.1", "protocol": "TCP"},
        "BLOCKED"
    )