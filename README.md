
# GuardianIDS 🛡️
## Signature and Anomaly-based Intrusion Detection and Prevention System 
**Network Intrusion Detection and Prevention System**  
*System and Network Security (CSS.470) - Lab Assignment 3*
*IIIT Hyderabad*


## Overview
GuardianIDS is a Python-based Network Intrusion Detection System (NIDS) that combines signature-based and anomaly-based detection techniques to identify and prevent malicious network activities. The system monitors TCP traffic in real-time, detects suspicious patterns, and automatically blocks potential attackers using iptables firewall rules.

## Key Features
| Detection Type       | Implemented Attacks          | Prevention |
|----------------------|------------------------------|------------|
| **Anomaly-Based**    | Multiple port scanning (>6 ports/15s) | ✔️ Auto-block |
|                      | Sequential port scanning( > 6 ports/15s) | ✔️ Auto-block |
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
__20_lab3/
├── cli.py                # Main CLI interface
├── cli_utils.py          # CLI functionality  implementation
├── intruder_detector.py  # Core detection algorithms
├── traffic_monitor.py    # Packet capture and analysis
├── test_validation.py    # Attack simulation module
├── ids.log               # Generated intrusion logs
└── README.md
```

## Usage
### Starting the System
```bash
python3 cli.py
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
python3 test_validation.py
```

Sure! Here's the markdown (MD) code for documenting your intrusion detection system's detection logic:


### Detection Logic

### 1.  Port Scanning 

### Description:
- Monitors the number of *unique destination ports* accessed by a source IP within a specified time window.
- Identifies potential port scanning behavior based on unusually high numbers of accessed ports.

### Detection Criteria:
- If the number of unique destination ports accessed by a source IP exceeds `PORT_THRESHOLD`:
  - Log the event.
  - Block the source IP using `iptables`.

---

### 2. Sequential Port Scanning 

### Description:
- Detects scanning of *sequential* ports by a source IP (e.g., 80, 81, 82, ...).
- Identifies attackers scanning for open ports in a linear manner.

### Detection Criteria:
- If the number of consecutive ports accessed by a source IP exceeds `SEQ_THRESHOLD`:
  - Log the event.
  - Block the source IP using `iptables`.

---

### 3. OS Fingerprinting Detection - SYN /ACK/FIN

### Description:
- Monitors *unique TCP flag combinations* used by a source IP within a time window.
- Detects attempts to perform OS fingerprinting (using crafted TCP packets).

### Detection Criteria:
- If the number of unique TCP flag combinations from a source IP exceeds `OS_FP_THRESHOLD`:
  - Log the event.
  - Block the source IP using `iptables`.



### Testing and Validation:
The system is validated by simulating the following:
- Normal traffic generation
- Port scanning attacks
- SYN/ACK flood attacks





## Conclusion
GuardianIDS successfully implements:

✔️ Dual detection methodologies (signature + anomaly)  
✔️ Real-time prevention via iptables  
✔️ Comprehensive logging per assignment specs  
✔️ Interactive management interface  



