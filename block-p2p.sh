#!/bin/bash

# ---------------------------------------------------
# BitTorrent Traffic Blocking with iptables + ipset
# ---------------------------------------------------
#  - Deep Packet Inspection (up to 1500 bytes)
#  - Temporary IP address blocking
#  - Handling of ignore lists (DNS, specific ranges, server IPs)
# ---------------------------------------------------

# Verify if running as root
if [ "$(id -u)" != "0" ]; then
   echo "This script must be run as root" >&2
   exit 1
fi

# ---------------------------------------------------
# CONFIGURATION
# ---------------------------------------------------
IPSET_NAME="torrent_block"

# Detect the default interface automatically
default_int=$(ip route list | grep '^default' | grep -oP 'dev \K\S+')

# Define the interfaces you want to monitor/block
# Add or modify your interfaces here and add the default interface if not already included
INITIAL_INTERFACES=("eth0")

# Function to add the default interface if not in the initial list
add_default_interface() {
    local default_interface="$1"
    local exists=false

    for intf in "${INITIAL_INTERFACES[@]}"; do
        if [ "$intf" == "$default_interface" ]; then
            exists=true
            break
        fi
    done

    if [ "$exists" = false ] && [ -n "$default_interface" ]; then
        INTERFACES=("${INITIAL_INTERFACES[@]}" "$default_interface")
    else
        INTERFACES=("${INITIAL_INTERFACES[@]}")
    fi
}
add_default_interface "$default_int"

LOG_PREFIX="TORRENT_BLOCK"
MAX_ENTRIES=100000
BLOCK_DURATION=18000  # Duration in seconds (5 hours)
HIGH_PORTS="6881:65535"

# Paths for the log file (adjust according to your system)
LOG_FILE="/var/log/kern.log"
if [ ! -f "$LOG_FILE" ]; then
    LOG_FILE="/var/log/messages"
fi

# ---------------------------------------------------
# COLLECTION OF LOCAL SERVER IPs
# ---------------------------------------------------
# Get all local server IPs (excluding loopback)
SERVER_IPS=$(ip -o addr show | awk '!/^[0-9]+: lo:/ && $3 == "inet" {split($4, a, "/"); print a[1]}')

# Function to verify server IPs (or main client)
is_server_ip() {
    local ip=$1
    for server_ip in $SERVER_IPS; do
        if [ "$ip" == "$server_ip" ]; then
            return 0
        fi
    done
    return 1
}

# ---------------------------------------------------
# LIST OF DNS IPs TO IGNORE
# ---------------------------------------------------
is_dns_ip() {
    local ip=$1
    local dns_ips=("8.8.8.8" "8.8.4.4" "1.1.1.1" "1.0.0.1")
    for dns_ip in "${dns_ips[@]}"; do
        if [ "$ip" == "$dns_ip" ]; then
            return 0
        fi
    done
    return 1
}

# ---------------------------------------------------
# LIST OF IP RANGES TO IGNORE
# ---------------------------------------------------
# The following ranges will be completely ignored:
#   - 10.9.0.0/22 (10.9.0.0 - 10.9.3.255)
#   - 10.8.0.0/22 (10.8.0.0 - 10.8.3.255)
is_ignored_ip_range() {
    local ip=$1

    if [[ $ip =~ ^10\.9\.[0-3]\.[0-9]{1,3}$ ]] || [[ $ip =~ ^10\.8\.[0-3]\.[0-9]{1,3}$ ]]; then
        return 0
    fi
    return 1
}

# ---------------------------------------------------
# CREATE OR CLEAN IPSET
# ---------------------------------------------------
if ! ipset list -n | grep -qw "$IPSET_NAME"; then
    # If it doesn't exist, create it
    ipset create "$IPSET_NAME" hash:ip maxelem "$MAX_ENTRIES"
fi

# Clean existing iptables rules related to this ipset
iptables-save | grep -v "$IPSET_NAME" | iptables-restore

# ---------------------------------------------------
# INSERT BIDIRECTIONAL BLOCKING RULES
# ---------------------------------------------------
for chain in INPUT OUTPUT FORWARD; do
    iptables -I "$chain" -m set --match-set "$IPSET_NAME" src -j DROP
    iptables -I "$chain" -m set --match-set "$IPSET_NAME" dst -j DROP
done

# ---------------------------------------------------
# DEEP PACKET INSPECTION (DPI) PATTERNS
# ---------------------------------------------------
patterns=(
    "BitTorrent"
    "d1:ad2:id"
    "d1:q"
    "magnet:?"
    "announce.php?passkey="
    "peer_id="
    "info_hash"
    "GET /announce"
    "GET /scrape"
    "ut_hub"
    "azureus"
    "x-peer-id"
    "qbittorrent"
    "uTorrent/"
    "Transmission"
    "Deluge"
    "find_node"
    "protocol=BitTorrent"
    "BitTorrent protocol"
)

# ---------------------------------------------------
# ADD INSPECTION RULES
# ---------------------------------------------------
# The first 1500 bytes in TCP/UDP traffic are inspected
# and any of the strings defined in "patterns" are searched for.
for intf in "${INTERFACES[@]}"; do
    for protocol in tcp udp; do
        for str in "${patterns[@]}"; do
            # Outgoing traffic (FORWARD -o)
            iptables -I FORWARD -o "$intf" -p "$protocol" --dport "$HIGH_PORTS" \
                -m string --string "$str" --algo bm --from 0 --to 1500 \
                -j LOG --log-prefix "$LOG_PREFIX OUT: "
            # Incoming traffic (FORWARD -i)
            iptables -I FORWARD -i "$intf" -p "$protocol" --sport "$HIGH_PORTS" \
                -m string --string "$str" --algo bm --from 0 --to 1500 \
                -j LOG --log-prefix "$LOG_PREFIX IN: "
        done
    done
done

# ---------------------------------------------------
# FUNCTION TO BLOCK TORRENT CONNECTIONS (Remote IPs only)
# ---------------------------------------------------
block_offenders() {
    echo "Monitoring logs in: $LOG_FILE"
    tail -Fn0 "$LOG_FILE" | while read -r line; do
        if echo "$line" | grep -q "$LOG_PREFIX"; then
            # Extract source and destination IPs from the log
            src_ip=$(echo "$line" | grep -oP 'SRC=\K[0-9.]+')
            dst_ip=$(echo "$line" | grep -oP 'DST=\K[0-9.]+')

            for ip in "$src_ip" "$dst_ip"; do
                if [[ $ip =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
                    if is_server_ip "$ip"; then
                        echo "Ignoring server IP: $ip"
                    elif is_dns_ip "$ip"; then
                        echo "Ignoring DNS IP: $ip"
                    elif is_ignored_ip_range "$ip"; then
                        echo "Ignoring IP within non-blocked range: $ip"
                    else
                        # Block the IP only if it's not already in the ipset
                        if ! ipset test "$IPSET_NAME" "$ip" 2>/dev/null; then
                            echo "Blocking suspicious IP: $ip"
                            ipset add "$IPSET_NAME" "$ip"
                            # Schedule unblocking after BLOCK_DURATION
                            (
                                sleep "$BLOCK_DURATION"
                                ipset del "$IPSET_NAME" "$ip" 2>/dev/null && \
                                    echo "Unblocked IP: $ip"
                            ) &
                        fi
                    fi
                fi
            done
        fi
    done
}

# ---------------------------------------------------
# CLEANUP FUNCTION
# ---------------------------------------------------
cleanup() {
    echo -e "\n[+] Cleaning iptables rules and ipset..."
    iptables-save | grep -v "$IPSET_NAME" | iptables-restore
    ipset destroy "$IPSET_NAME"
    exit 0
}

# Capture signals to clean rules on exit
trap cleanup SIGINT SIGTERM

# ---------------------------------------------------
# START
# ---------------------------------------------------
echo "[+] BitTorrent blocking script running."
echo "[+] IPSET: $IPSET_NAME  |  Deep packet inspection active."
echo "[+] Monitored interfaces: ${INTERFACES[@]}"
block_offenders
