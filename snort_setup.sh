#!/bin/bash

SNORT_CONF="/etc/snort/snort.conf"
RULES_DIR="/etc/snort/rules"
LOG_DIR="/var/log/snort"
INTERFACE="eth0"  # Change this to your network interface


setup_directories() {
    echo "Creating necessary directories..."
    mkdir -p $LOG_DIR
    mkdir -p $RULES_DIR
    chmod -R 750 $LOG_DIR
    chmod -R 750 $RULES_DIR
}


setup_interface() {
    echo "Setting up network interface..."
    ip link set $INTERFACE promisc on
    # Verify promiscuous mode
    ip link show $INTERFACE | grep PROMISC
}


update_rules() {
    echo "Downloading and updating Snort rules..."
    if [ -f "/usr/local/bin/pulledpork.pl" ]; then
        pulledpork.pl -c /etc/snort/pulledpork.conf -l
    else
        echo "Please install PulledPork for automated rule updates"
        wget https://www.snort.org/downloads/community/community-rules.tar.gz -O /tmp/community-rules.tar.gz
        tar -xvf /tmp/community-rules.tar.gz -C $RULES_DIR
    fi
}


configure_snort() {
    echo "Configuring Snort..."
    cp $SNORT_CONF "${SNORT_CONF}.backup"

    cat > $SNORT_CONF << EOF
# Snort Configuration
# Network settings
ipvar HOME_NET [192.168.0.0/24]  # Modify this to match your network


ipvar EXTERNAL_NET !\$HOME_NET
var RULE_PATH $RULES_DIR

# Set up decoder
config checksum_mode: all
config policy_mode: inline

# Configure logging
config logdir: $LOG_DIR
output unified2: filename snort.log, limit 128

# Include rules
include \$RULE_PATH/local.rules
include \$RULE_PATH/community-rules/community.rules

# Performance settings
config detection: search-method ac-bnfa
config detection: max-pattern-len 20000
config detection: split-any-any on

# Preprocessor settings
preprocessor frag3_global: max_frags 65536
preprocessor frag3_engine: policy windows detect_anomalies
preprocessor stream5_global: max_tcp 8192, track_tcp yes, track_udp yes
preprocessor stream5_tcp: policy windows, detect_anomalies, require_3whs 180
preprocessor stream5_udp: timeout 180

# Basic rules
include classification.config
include reference.config
EOF
}


create_local_rules() {
    echo "Creating basic local rules..."
    cat > "$RULES_DIR/local.rules" << EOF
# Local rules
alert tcp any any -> \$HOME_NET 22 (msg:"SSH Connection Attempt"; flow:to_server,established; classtype:network-scan; sid:1000001; rev:1;)
alert icmp any any -> \$HOME_NET any (msg:"ICMP Ping"; itype:8; classtype:network-scan; sid:1000002; rev:1;)
EOF
}


test_config() {
    echo "Testing Snort configuration..."
    snort -T -c $SNORT_CONF
    if [ $? -eq 0 ]; then
        echo "Configuration test successful"
    else
        echo "Configuration test failed"
        exit 1
    fi
}


echo "Starting Snort NIDS setup..."
setup_directories
setup_interface
update_rules
configure_snort
create_local_rules
test_config

echo "Setup complete. To start Snort in NIDS mode, run:"
echo "snort -c $SNORT_CONF -i $INTERFACE -D"