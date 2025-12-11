import time
from scapy.all import sniff, IP, TCP
import subprocess


scan_tracker = {}
os_fp_tracker = {}

PORT_THRESHOLD   = 6   # more than or equal to 6 unique ports indicates abnormal behavior
TIME_WINDOW      = 15  # seconds for port scanning
SEQ_THRESHOLD    = 6  # more than or equal to 6 sequential ports to flag sequential scanning

OS_FP_THRESHOLD   = 6  # 5+ unique TCP flag combinations indicates possible OS fingerprinting
OS_FP_TIME_WINDOW = 20  

def detect_anomaly_based(src_ip, unique_ports, current_time):
    # Anomaly-Based Detection: Multiple Port Scanning
    if len(unique_ports) >= PORT_THRESHOLD:
        timestamps = [t for (t, _) in scan_tracker.get(src_ip, [])]
        time_span = int(current_time - min(timestamps)) if timestamps else 0
        timestamp_str = time.strftime("%y-%m-%d %H:%M:%S", time.localtime(current_time))
        targeted_ports = ", ".join(map(str, sorted(unique_ports)))
        log_entry = f"{timestamp_str} — Port Scanning — {src_ip} — {targeted_ports} — {time_span}s\n"
        with open("ids.log", "a") as log_file:
            log_file.write(log_entry)


     
        result = subprocess.run(["sudo", "iptables", "-C", "INPUT", "-s", src_ip, "-j", "DROP"], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        if result.returncode != 0:  # If the IP is not already blocked
            subprocess.run(["sudo", "iptables", "-I", "INPUT", "1", "-s", src_ip, "-j", "DROP"], check=True)
        scan_tracker[src_ip] = []

def detect_sequential_scan(src_ip, unique_ports, current_time):
   
    sorted_ports = sorted(unique_ports)
    if len(sorted_ports) >= SEQ_THRESHOLD:
        consecutive_count = 1
        max_consecutive = 1
        for i in range(1, len(sorted_ports)):
            if sorted_ports[i] == sorted_ports[i-1] + 1:
                consecutive_count += 1
                max_consecutive = max(max_consecutive, consecutive_count)
            else:
                consecutive_count = 1
        if max_consecutive >= SEQ_THRESHOLD:
            timestamps = [t for (t, _) in scan_tracker.get(src_ip, [])]
            time_span = int(current_time - min(timestamps)) if timestamps else 0
            timestamp_str = time.strftime("%y-%m-%d %H:%M:%S", time.localtime(current_time))
            targeted_ports = ", ".join(map(str, sorted_ports))
            log_entry = f"{timestamp_str} — Sequential Port Scanning — {src_ip} — {targeted_ports} — {time_span}s\n"
            with open("ids.log", "a") as log_file:
                log_file.write(log_entry)

            result = subprocess.run(["sudo", "iptables", "-C", "INPUT", "-s", src_ip, "-j", "DROP"], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            if result.returncode != 0:  # If the IP is not already blocked
                subprocess.run(["sudo", "iptables", "-I", "INPUT", "1", "-s", src_ip, "-j", "DROP"], check=True)
            scan_tracker[src_ip] = []

def detect_os_fingerprinting(src_ip, unique_flags, current_time):
    # Signature-Based OS Fingerprinting Detection
    if len(unique_flags) >= OS_FP_THRESHOLD:
        timestamps = [t for (t, flag) in os_fp_tracker.get(src_ip, [])]
        time_span = int(current_time - min(timestamps)) if timestamps else 0
        timestamp_str = time.strftime("%y-%m-%d %H:%M:%S", time.localtime(current_time))
        flagged = ", ".join(sorted(unique_flags))
        log_entry = f"{timestamp_str} — OS Fingerprinting — {src_ip} — {flagged} — {time_span}s\n"
        with open("ids.log", "a") as log_file:
            log_file.write(log_entry)
            
        result = subprocess.run(["sudo", "iptables", "-C", "INPUT", "-s", src_ip, "-j", "DROP"], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        if result.returncode != 0:  
            subprocess.run(["sudo", "iptables", "-I", "INPUT", "1", "-s", src_ip, "-j", "DROP"], check=True)
        os_fp_tracker[src_ip] = []

def port_scan_callback(packet):
    # Process only TCP packets
    if not packet.haslayer(IP) or not packet.haslayer(TCP):
        return

    ip_layer = packet.getlayer(IP)
    tcp_layer = packet.getlayer(TCP)
    src_ip    = ip_layer.src
    dst_port  = tcp_layer.dport
    current_time = time.time()

    if src_ip not in scan_tracker:
        scan_tracker[src_ip] = []
    scan_tracker[src_ip].append((current_time, dst_port))
    scan_tracker[src_ip] = [
        (t, port) for (t, port) in scan_tracker[src_ip]
        if current_time - t <= TIME_WINDOW
    ]

    #OS_finger_Print
    if src_ip not in os_fp_tracker:
        os_fp_tracker[src_ip] = []
    flag_combo = str(tcp_layer.flags)
    os_fp_tracker[src_ip].append((current_time, flag_combo))
    os_fp_tracker[src_ip] = [
        (t, flag) for (t, flag) in os_fp_tracker[src_ip]
        if current_time - t <= OS_FP_TIME_WINDOW
    ]
    unique_flags = set(flag for (t, flag) in os_fp_tracker[src_ip])


    unique_ports = set(port for (t, port) in scan_tracker[src_ip])
    detect_anomaly_based(src_ip, unique_ports, current_time)
    detect_sequential_scan(src_ip, unique_ports, current_time)
    detect_os_fingerprinting(src_ip, unique_flags, current_time)

def detect_port_scanning():
    print("Starting anomaly-based port scanning detection...")
    try:
        sniff(filter="tcp and outbound", store=False, prn=port_scan_callback)
    except KeyboardInterrupt:
        print("Detection stopped by user.")

# if __name__ == "__main__":
#     detect_port_scanning()