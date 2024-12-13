#!/bin/bash


SNORT_HOME="/usr/local/snort"
INTERFACE="wlo1"  #curernt wireless interface
LOG_DIR="/var/log/snort"


setup_directories() {
    echo "Creating necessary directories..."
    mkdir -p $SNORT_HOME
    mkdir -p $LOG_DIR
    mkdir -p $SNORT_HOME/etc/rules
    mkdir -p $SNORT_HOME/etc/so_rules
    mkdir -p $SNORT_HOME/etc/lists
    chmod -R 750 $LOG_DIR
    chmod -R 750 $SNORT_HOME
}

#promiscuous mode
setup_interface() {
    echo "Setting up network interface..."
    ip link set $INTERFACE promisc on
    ip link show $INTERFACE | grep PROMISC
}

#config
configure_snort() {
    echo "Configuring Snort 3..."
    cat > $SNORT_HOME/etc/snort.lua << EOF
---------------------------------------------------------------------------
-- Snort++ configuration
---------------------------------------------------------------------------

HOME_NET = '[192.168.0.0/24]'  -- Modify this to match your network
EXTERNAL_NET = '! \$HOME_NET'

-- Configure DAQ
daq =
{
    module = 'pcap',
    snaplen = 1518,
    variables = 
    {
        buffer_size_mb = 256
    }
}

-- Configure traffic processing
detection =
{
    pcre_match_limit = 3500,
    pcre_match_limit_recursion = 3500,
    hyperscan_literals = true,
    max_pattern_len = 20000
}

-- Configure basic processing
process =
{
    daemon = false,
    dirty_pig = true,
    show_year = true,
    timezone = 'utc'
}

-- Configure output logging
alert_csv =
{
    file = true,
    fields = 'timestamp pkt_num proto pkt_gen pkt_len dir src_ap dst_ap rule action',
    limit = 10,
}

alert_fast =
{
    file = true,
    packet = false,
    limit = 10,
}

-- Basic rule to detect ping
local_rules =
[[
alert icmp any any -> \$HOME_NET any ( msg:"ICMP Ping Detected"; sid:10000001; gid:1; rev:1; )
alert tcp any any -> \$HOME_NET 22 ( msg:"SSH Connection Attempt"; flow:to_server,established; sid:10000002; gid:1; rev:1; )
]]
EOF
}


test_config() {
    echo "Testing Snort 3 configuration..."
    snort -c $SNORT_HOME/etc/snort.lua --warn-all
    if [ $? -eq 0 ]; then
        echo "Configuration test successful"
    else
        echo "Configuration test failed"
        exit 1
    fi
}

# Main execution
echo "Starting Snort 3 NIDS setup..."
setup_directories
setup_interface
configure_snort
test_config

echo "Setup complete. To start Snort in NIDS mode, run:"
echo "sudo snort -c $SNORT_HOME/etc/snort.lua -i $INTERFACE -l $LOG_DIR"