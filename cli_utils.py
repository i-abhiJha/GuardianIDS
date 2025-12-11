
import threading
import time
import subprocess
from colorama import Fore, Back, Style, init
from traffic_monitor import *
from intruder_detector import *
from cli_utils import *



ids_thread = None
ids_stop_event = threading.Event()

def start_GuardianIDS():
    print(Fore.BLUE + "\nGuardianIDS is now running!")
    while not ids_stop_event.is_set():
        detect_port_scanning()
        time.sleep(10)
    print(Fore.RED + "\nGuardianIDS stopped.")

def toggle_IDS():
    global ids_thread, ids_stop_event
    if ids_thread is None or not ids_thread.is_alive():
        # Start the IDS
        ids_stop_event.clear()
        ids_thread = threading.Thread(target=start_GuardianIDS, daemon=True)
        ids_thread.start()
        print(Fore.GREEN + "\nGuardianIDS started.")
    else:
        # Stop the IDS
        ids_stop_event.set()
        ids_thread.join(timeout=1)
        print(Fore.GREEN + "\nGuardianIDS stopped.")

def live_traffic():
    print(Fore.BLUE + "\nViewing Live Traffic")
    print(Fore.YELLOW + "\n1. View Incoming Traffic")
    print(Fore.YELLOW + "2. View Outgoing Traffic")
    choice = input(Fore.CYAN + "Enter your choice (1-2): ").strip()
    if choice == "1":
        print(Fore.GREEN + "\nDisplaying Incoming Traffic...")
        listen_incoming()  
        print(Fore.GREEN + "\nDisplaying Outgoing Traffic...")
        listen_outgoing()
    else:
        print(Fore.RED + "\nInvalid choice, returning to the menu...")
   

def view_intrusion_logs():
    log_path = "./ids.log"
    print(Fore.BLUE + "\nViewing Intrusion Logs")
    try:
        with open(log_path, "r") as logfile:
            logs = logfile.read()
            print(Fore.GREEN + logs)
    except FileNotFoundError:
        print(Fore.RED + "\nNo intrusion logs found.")
    finally:
        input(Fore.MAGENTA + "\nPress Enter to return to the menu...")
    
    
   

def display_blocked_ips():
    print(Fore.BLUE + "\nDisplaying Blocked IPs:")
    try:
        result = subprocess.run(["sudo", "iptables", "-L", "INPUT", "-n"], capture_output=True, text=True)
        print(Fore.GREEN + result.stdout)
    except Exception as e:
        print(Fore.RED + f"\nError retrieving blocked IPs: {e}")
    finally:
        input(Fore.MAGENTA + "\nPress Enter to return to the menu...")
   

def clear_block_list():
    print(Fore.BLUE + "\nClearing Block List:")
    try:
        subprocess.run(["sudo", "iptables", "-F", "INPUT"], check=True)
        print(Fore.GREEN + "\nBlock list cleared.")
    except Exception as e:
        print(Fore.RED + f"\nError clearing block list: {e}")
    finally:
        input(Fore.MAGENTA + "\nPress Enter to return to the menu...")
   

def unblock_ip():
    ip_to_unblock = input(Fore.CYAN + "\nEnter the IP address to unblock: ").strip()
    if ip_to_unblock:
        print(Fore.BLUE + f"\nAttempting to unblock IP: {ip_to_unblock}")
        try:
            subprocess.run(["sudo", "iptables", "-D", "INPUT", "-s", ip_to_unblock, "-j", "DROP"], check=True)
            print(Fore.GREEN + f"\nIP {ip_to_unblock} unblocked successfully.")
        except Exception as e:
            print(Fore.RED + f"\nError unblocking IP {ip_to_unblock}: {e}")
    else:
        print(Fore.RED + "\nNo IP provided.")
    input(Fore.MAGENTA + "\nPress Enter to return to the menu...")
