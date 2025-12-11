from scapy.all import sniff, IP, TCP, send
import time
import threading

def packet_callback(packet, count):
    timestamp = time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(packet.time))
    src_ip = dst_ip = src_port = dst_port = protocol = "N/A"

    if packet.haslayer(IP):
        ip_layer = packet.getlayer(IP)
        src_ip = ip_layer.src
        dst_ip = ip_layer.dst

        if packet.haslayer(TCP):
            tcp_layer = packet.getlayer(TCP)
            src_port = tcp_layer.sport
            dst_port = tcp_layer.dport
            protocol = "TCP"
        else:
            protocol = ip_layer.proto

    if protocol == "TCP" and src_ip == dst_ip and src_port > dst_port:
        return
    print(f"Packet {count} -> Time: {timestamp}, Src: {src_ip}:{src_port}, Dst: {dst_ip}:{dst_port}, Protocol: {protocol}")

def create_sniffer(filter_expr, stop_event):
    count = 1
    skip_next = False

    def wait_for_input():
        nonlocal skip_next
        input("Press Enter to stop sniffing...\n")
        stop_event.set()
        skip_next = True
        # Send dummy packet to exit the blocking sniff call.
        dummy_pkt = IP(dst="127.0.0.1") / TCP(dport=12345, sport=54321, flags="S")
        send(dummy_pkt, verbose=0)

    thread = threading.Thread(target=wait_for_input)
    thread.daemon = True
    thread.start()

    def cb(packet):
        nonlocal count, skip_next
        if skip_next:
            skip_next = False
            return
        packet_callback(packet, count)
        count += 1
    sniff(filter=filter_expr, store=False, prn=cb, stop_filter=lambda _: stop_event.is_set())



def listen_incoming():
    print("Listening for inbound TCP packets...")
    stop_event = threading.Event()
    create_sniffer("tcp and inbound", stop_event)

def listen_outgoing():
    print("Listening for outbound TCP packets...")
    stop_event = threading.Event()
    create_sniffer("tcp and outbound", stop_event)
