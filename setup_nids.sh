#!/bin/bash

# Create main project directory and subdirectories
mkdir -p NIDS/{firewall,ids,integration,logging,ui,utils,config,output}/

# Create __init__.py files in each module directory
touch NIDS/firewall/__init__.py
touch NIDS/ids/__init__.py
touch NIDS/integration/__init__.py
touch NIDS/logging/__init__.py
touch NIDS/ui/__init__.py
touch NIDS/utils/__init__.py

# Copy existing firewall files
cp firewall_rules.py NIDS/firewall/
cp rule_config.py NIDS/firewall/

# Create empty files for the IDS module
touch NIDS/ids/snort_config.py
touch NIDS/ids/snort_rules.py
touch NIDS/ids/packet_analyzer.py

# Create empty files for the integration module
touch NIDS/integration/alert_handler.py
touch NIDS/integration/response_system.py
touch NIDS/integration/connector.py

# Create empty files for logging and utils
touch NIDS/logging/log_manager.py
touch NIDS/utils/helpers.py

# Create empty UI module file
touch NIDS/ui/dashboard.py

# Create main application file
touch NIDS/main.py

# Create empty config files
touch NIDS/config/snort.conf
touch NIDS/config/firewall.yaml

# Create requirements.txt
echo "pyyaml
pypcap
python-snort
logging
typing
ipaddress
" > NIDS/requirements.txt

echo "Directory structure created successfully!"