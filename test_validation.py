
import subprocess
from scapy.all import IP, TCP
import random
from art import text2art
from rich.console import Console
from rich.table import Table

console = Console()

DEFAULT_SRC_IP = "127.0.0.1"  

def generate_normal_traffic():
    
    pkt = IP(src=DEFAULT_SRC_IP, dst="127.0.0.1") / TCP(sport=12345, dport=80, flags="AP")
    return pkt

def generate_syn_flood(target_port, count=5):
   
    packets = []
    for i in range(count):
        pkt = IP(src=DEFAULT_SRC_IP, dst="127.0.0.1") / TCP(sport=1024+i, dport=target_port, flags="S")
        packets.append(pkt)
    return packets

def generate_port_scan(start_port, end_port):

    packets = []
    source_port = 40000  # fixed source port
    for dport in range(start_port, end_port+1):
        pkt = IP(src=DEFAULT_SRC_IP, dst="127.0.0.1") / TCP(sport=source_port, dport=dport, flags="S")
        packets.append(pkt)
    return packets

def generate_hping3_attack(packets):
  
    print("Packets Size ", len(packets))
    c = 0
    for pkt in packets:
        c += 1
        ip_layer = pkt.getlayer(IP)
        tcp_layer = pkt.getlayer(TCP)
        if not (ip_layer and tcp_layer):
            continue
        
        src_ip = ip_layer.src
        dst_ip = ip_layer.dst
        sport = tcp_layer.sport
        dport = tcp_layer.dport
        flags = str(tcp_layer.flags)

   
        command = ["sudo", "hping3", "-c", "1", "-a", src_ip, "-s", str(sport), "-p", str(dport)]

        flag_mapping = {
            'S': "-S",
            'A': "-A",
            'P': "-P",
            'F': "-F",
            'R': "-R",
            'U': "-U"
        }
        for flag in flags:
            if flag in flag_mapping:
                command.append(flag_mapping[flag])
        
        command.append(dst_ip)

        try:
            result = subprocess.run(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, check=True)
            print(f"{c}. Packet: IP {src_ip} : {sport} -> {dst_ip} : {dport} | Flags: {tcp_layer.flags}")
        except subprocess.CalledProcessError as e:
            print("Error running hping3 attack for packet:", e.stderr)

def analyze_packet(pkt):
    ip_layer = pkt.getlayer(IP)
    tcp_layer = pkt.getlayer(TCP)
    
    src_ip = ip_layer.src if ip_layer else "N/A"
    dst_ip = ip_layer.dst if ip_layer else "N/A"
    sport = tcp_layer.sport if tcp_layer else "N/A"
    dport = tcp_layer.dport if tcp_layer else "N/A"
    flags = tcp_layer.flags if tcp_layer else "N/A"
    protocol = "TCP" if tcp_layer else "Unknown"
    
    print(f"Analyse: Packet -> Source IP: {src_ip}, Destination IP: {dst_ip}, Source Port: {sport}, Destination Port: {dport}, Protocol: {protocol}, Flags: {flags}")





def print_attack_menu():
 
    title = text2art("AttackSim", font="small")
    console.print(f"[bold red]{title}[/bold red]")

    console.print("[magenta]========================================[/magenta]")
    from rich import box
    table = Table(box=None, show_header=False)
    table.add_column("Option", style="cyan", justify="center")
    table.add_column("Action", style="red")
    table.add_row("1", "🌐 Generate Normal Traffic (Safe Simulation)")
    table.add_row("2", "🔍 Simulate Port Scanning Attack")
    table.add_row("3", "💥 Launch SYN / ACK / FIN Flood Attack")
    table.add_row("4", "🚪 Exit the Attack Simulator")
    console.print(table)
    console.print("[magenta]========================================[/magenta]")

def get_user_choice():
    return console.input("[cyan]Enter your choice (1/2/3/4): [/cyan]").strip()







def main():
    while True:
        
        print_attack_menu()
        choice = get_user_choice()

        if choice not in {'1', '2', '3', '4'}:
            console.print("[red]Invalid choice. Please try again.[/red]")
            continue
        elif choice == "4":
            console.print("[bold green]Exiting.[/bold green]")
            break

        packets = []
        
        src_port = int(input("Attacker Port: "))
        
        if choice == "1":
            count = int(input("Enter the number of normal packets to generate: ").strip())
            for _ in range(count):
                dst_port = random.randint(1024, 65535)
                pkt = IP(src=DEFAULT_SRC_IP, dst="127.0.0.1") / TCP(sport=src_port, dport=dst_port, flags="AP")
                packets.append(pkt)
    
        elif choice == "2":
            num_requests = int(input("Enter the number of ports to scan: ").strip())
            start_port = int(input("Enter the starting port for Port Scan: ").strip())
            for i in range(num_requests):
                dport = start_port + i
                packets.append(IP(src=DEFAULT_SRC_IP, dst="127.0.0.1") / TCP(sport=src_port, dport=dport, flags="S"))
        
        elif choice == "3":
            unique_combinations = set()        
            total_pack = int(input("Enter the number of random mix Packets: ").strip())
            flag_options = ["S", "A", "F", "SA", "SF", "AF", "SAF"]
            for _ in range(total_pack):
                dport = 9010
                flag = random.choice(flag_options)
                packets.append(IP(src=DEFAULT_SRC_IP, dst="127.0.0.1") / TCP(sport=src_port, dport=dport, flags=flag))
                unique_combinations.add(flag)
            
        print("\nExecuting hping3 based test attack:")
        generate_hping3_attack(packets)

if __name__ == "__main__":
    main()
