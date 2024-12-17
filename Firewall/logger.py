import os
import logging
from datetime import datetime
import pathlib

class FirewallLogger:
    #Handles log file creation, rotation, and different logging levels.
  
    def __init__(self, log_directory='logs'):
        #Initialize logging system with specified directory
        self.log_directory = self._ensure_absolute_path(log_directory)
        self._setup_logging()
    
    def _ensure_absolute_path(self, directory):

        project_root = pathlib.Path(__file__).parent.parent
        return os.path.join(project_root, directory)
    
    def _setup_logging(self):
        #Configure the logging system with proper dir
        try:
            # Create logs directory if it doesn't exist
            os.makedirs(self.log_directory, exist_ok=True)
            
            # Create log filename with timestamp
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            log_filename = os.path.join(
                self.log_directory,
                f'firewall_{timestamp}.log'
            )
            
            # Configure logging with both file and console output
            logging.basicConfig(
                level=logging.INFO,
                format='%(asctime)s - %(levelname)s - [%(filename)s:%(lineno)d] - %(message)s',
                handlers=[
                    logging.FileHandler(log_filename),
                    logging.StreamHandler()  # Also print to console
                ]
            )
            
            self.logger = logging.getLogger(__name__)
            self.logger.info(f"Logging initialized. Writing to: {log_filename}")
            
        except Exception as e:
            print(f"Error setting up logging: {str(e)}")
            print(f"Attempted to create log directory at: {self.log_directory}")
            raise
    
    def log_info(self, message):
        #Log an informational message
        self.logger.info(message)
    
    def log_warning(self, message):
        #Log a warning message\
        self.logger.warning(message)
    
    def log_error(self, message):
        #Log an error message
        self.logger.error(message)
    
    def log_packet(self, packet_info):
        #Log packet information with appropriate detail level
        self.logger.info(
            f"Packet captured - "
            f"Source: {packet_info.get('src_ip', 'Unknown')}, "
            f"Destination: {packet_info.get('dst_ip', 'Unknown')}, "
            f"Protocol: {packet_info.get('protocol', 'Unknown')}"
        )