# GuardianIDS
Signature and Anomaly-based Intrusion Detection and Prevention System (NIDPS)


## Overview
GuardianIDS is a Python-based Network Intrusion Detection System (NIDS) that combines signature-based and anomaly-based detection techniques to identify and prevent malicious network activities. The system monitors TCP traffic in real-time, detects suspicious patterns, and automatically blocks potential attackers using iptables firewall rules.

## Key Features
| Detection Type       | Implemented Attacks          | Prevention |
|----------------------|------------------------------|------------|
| **Anomaly-Based**    | Multiple port scanning (>6 ports/15s) | ✔️ Auto-block |
|                      | Sequential port scanning | ✔️ Auto-block |
| **Signature-Based**  | OS fingerprinting (5+ flag combos/20s) | ✔️ Auto-block |

Additional Features:
- Real-time traffic monitoring (inbound/outbound)
- Interactive CLI management interface
- Persistent attack logging (IDS.log)
- Dynamic IP blocking/unblocking
- Attack simulation module

## Installation
### Prerequisites
```bash
sudo apt-get install hping3 iptables python3-pip
```

### Python Dependencies
```bash
pip install scapy python-nmap numpy sklearn rich art colorama
```

## File Structure
```
GuardianIDS/
├── cli.py                # Main CLI interface
├── cli_utils.py          # CLI functionality implementation
├── intruder_detector.py  # Core detection algorithms
├── traffic_monitor.py    # Packet capture and analysis
├── test_validation.py    # Attack simulation module
├── ids.log               # Generated intrusion logs
└── README.md
```

## Usage
### Starting the System
```bash
sudo python3 cli.py
```

### CLI Menu Options
- Toggle IDS - Start/stop intrusion detection
- Live Traffic - Monitor incoming/outgoing packets
- View Logs - Inspect detected intrusions
- Blocked IPs - List currently blocked addresses
- Clear Blocks - Remove all IP blocks
- Unblock IP - Remove specific IP block
- Exit - Shutdown system

### Running Attack Simulations
```bash
sudo python3 test_validation.py
```

Simulation Options:
- Normal traffic generation
- Port scanning attacks
- SYN/ACK flood attacks


## Testing Validation
The system was verified against:
- Normal browsing traffic (false positive test)
- Nmap port scans (-sS, -sT)
- hping3 SYN floods
- Manual TCP flag manipulation
- Sequential port scans

## Conclusion
GuardianIDS successfully implements:
✔️ Dual detection methodologies (signature + anomaly)  
✔️ Real-time prevention via iptables  
✔️ Comprehensive logging per assignment specs  
✔️ Interactive management interface  

For academic use in IIIT Hyderabad's System and Network Security course (CSS.470). Not recommended for production environments without additional hardening.
