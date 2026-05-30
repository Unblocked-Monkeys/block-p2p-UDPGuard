# BitTorrent Traffic Blocker using iptables + ipset

# Advanced Overview and Operational Considerations

This script was designed with a dual objective: **to dynamically block BitTorrent traffic** while **not limiting the user experience**. It was designed to block only torrent traffic (thus avoiding DMCA-related issues) without affecting other services, such as gaming or general browsing.

The mechanism is based on advanced **Deep Packet Inspection (DPI)** techniques. It scans the first 1500 bytes of each TCP/UDP packet in the port range `6881:65535`, looking for patterns and signatures characteristic of BitTorrent traffic. This method is effective even when clients (such as uTorrent) partially encrypt traffic, as many still expose enough information during the handshake or initial negotiations to be identified. Thus, the script progressively blocks each IP address involved in the BitTorrent packet exchange; once all routes are blocked, the download is interrupted (0 bytes transferred), and the offending user's IP is eventually blocked.

> Thanks for sharing your experiences, @UnknownDev2018. The script has proven to be very comprehensive, as even with clients that encrypt traffic, most BitTorrent connections can be detected. However, if a client evades detection or if traffic is redirected entirely over HTTPS, the effectiveness of the string matching could be reduced, as the inspected content would be encrypted and not display the usual signatures.

# NO BLOCK GAMING

This Bash script is designed to **block BitTorrent traffic** on Linux systems using iptables and ipset. It employs **Deep Packet Inspection (DPI)** to detect BitTorrent patterns and temporarily block suspicious IP addresses. **Importantly, it does not block any ports**—it only monitors the port range `6881:65535` for BitTorrent-related traffic, leaving all online gaming ports completely unaffected.

## Features

- **Deep Packet Inspection (DPI):**  
  Inspects the first 1500 bytes of TCP/UDP packets on the port range `6881:65535` to detect BitTorrent patterns without blocking the ports.

- **Dynamic Blocking:**  
  Automatically adds suspicious IPs to an ipset, temporarily blocking them if BitTorrent traffic is detected.

- **Gaming Traffic Unaffected:**  
  The script solely monitors the specified port range for BitTorrent activity. **Gaming ports remain open and fully functional**.

- **Intelligent Exclusions:**  
  Excludes local server IPs, known DNS servers, and specific IP ranges to avoid unintended disruptions.

- **Multi-Interface Monitoring:**  
  Automatically detects and monitors multiple network interfaces, including the default interface, ensuring comprehensive traffic supervision.

- **Automatic Cleanup:**  
  On termination, the script cleans up iptables rules and destroys the ipset, restoring the system’s original configuration.

## Requirements

- **Operating System:** Linux (Debian/Ubuntu or similar)
- **Permissions:** Must be run as `root`
- **Dependencies:** `iptables`, `ipset`, `ipcalc`, `rsyslog`, `grep`, `awk`, `coreutils`
- **Kernel Module:** `xt_string` (required for string matching in iptables)

## Installation

Update your system and install the required packages:

```bash
sudo apt update
sudo apt upgrade -y
sudo apt install -y iptables ipset ipcalc rsyslog grep coreutils

Load the `xt_string` module if it’s not already loaded:

```bash
sudo modprobe xt_string
lsmod | grep xt_string
```

Ensure that `/var/log/kern.log` exists; otherwise, the script will use `/var/log/messages`.

## Usage

1. **Make the script executable:**

   ```bash
   chmod +x torrent_block.sh
   ```

2. **Run the script as root:**

   ```bash
   sudo ./torrent_block.sh
   ```

3. **Monitor the ipset:**

   ```bash
   sudo ipset list torrent_block
   ```

4. **Stop the script:**  
   Press `Ctrl+C` or send a termination signal to clean up the iptables rules and ipset.

## Configuration

- **IPSET_NAME:** Name of the ipset (default: `torrent_block`)
- **INTERFACES:** List of network interfaces to monitor (default: `tun0`, `tun1`, `eth0`, plus the detected default interface)
- **BLOCK_DURATION:** Duration (in seconds) for which an IP remains blocked (default: 18000 seconds or 5 hours)
- **HIGH_PORTS:** Port range to inspect (default: `6881:65535`)
- **Exclusions:**  
  - Local server IPs  
  - Known DNS servers (`8.8.8.8`, `8.8.4.4`, `1.1.1.1`, `1.0.0.1`)  
  - RFC1918 private ranges (`10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`) when `IGNORE_PRIVATE_RANGES=1` (default)  
  - Any IPs listed in `EXTRA_IGNORE_IPS`
- **IGNORE_PRIVATE_RANGES:** Set to `1` (default) to never block RFC1918 private ranges. **Keep this enabled when the monitored traffic is decapsulated VPN/tunnel client traffic whose inner source addresses fall in a private pool** — otherwise the script blocks its own clients and collapses throughput. Set to `0` only if you genuinely want to police private ranges.
- **EXTRA_IGNORE_IPS:** Space-separated list of additional IPs that must never be blocked. Use this for per-deployment infrastructure that all client traffic is forwarded through (e.g. an upstream exit/proxy node or a parallel ingress), so you don't have to edit function bodies. Override at runtime:

  ```bash
  EXTRA_IGNORE_IPS="203.0.113.10 198.51.100.20" sudo ./block-p2p.sh
  ```
- **DPI Patterns:** Modify or extend the list of BitTorrent-related strings as needed.

## How It Works

1. **Interface Detection:**  
   Automatically detects the default interface and adds it to the monitoring list.

2. **Setup:**  
   Creates or cleans the ipset and inserts iptables rules to block traffic from/to IPs in the set.

3. **Deep Packet Inspection:**  
   Uses iptables rules to inspect TCP/UDP traffic for BitTorrent patterns and logs any matches.

4. **Blocking Offenders:**  
   Monitors logs, extracts source and destination IPs, and adds non-excluded IPs to the ipset. Unblocks them after the defined `BLOCK_DURATION`.

5. **Cleanup:**  
   On termination, removes iptables rules and destroys the ipset to restore the system’s original state.

## Contributing

Contributions are welcome! Fork the repository and submit pull requests with your improvements.

## License

Distributed under the [MIT License](LICENSE).

Security Notice
Warning: This script modifies firewall rules in real-time. Ensure you understand the security implications and have recovery options available. Test in a safe environment before using in production.
