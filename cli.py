import os
import sys
import threading

import subprocess
from colorama import Fore, Back, Style, init
from traffic_monitor import *
from intruder_detector import *
from rich.console import Console
from rich.table import Table
from art import text2art

from cli_utils import *


console = Console()
init(autoreset=True)








def clear_screen():
    os.system('cls' if os.name == 'nt' else 'clear')

def print_menu():
    clear_screen()
    
    title = text2art("GuardianIDS", font="small")
    console.print(f"[bold blue]{title}[/bold blue]")
    console.print("[yellow]========================================[/yellow]")

 
   
    table = Table(box=None, show_header=False)
    table.add_column("Option", style="cyan", justify="center")
    table.add_column("Action", style="green")
    table.add_row("1", "🔒 Toggle IDS On/Off")
    table.add_row("2", "📡 Monitor Live Network Traffic")
    table.add_row("3", "📝 Inspect Intrusion Records")
    table.add_row("4", "🚫 List Blocked IP Addresses")
    table.add_row("5", "♻️ Clear All Blocked IPs")
    table.add_row("6", "🔓 Unblock Specific IP")
    table.add_row("7", "⏻ Shutdown GuardianIDS")
    console.print(table)
    console.print("[yellow]========================================[/yellow]")

def main():
    while True:
        print_menu()
        choice = input(Fore.CYAN + "Enter your choice (1-7): ").strip()
        
        if choice == '1':
            toggle_IDS()
           
        elif choice == '2':
            live_traffic()
        elif choice == '3':
            view_intrusion_logs()
        elif choice == '4':
            display_blocked_ips()
        elif choice == '5':
            clear_block_list()
        elif choice == '6':
            unblock_ip()
        elif choice == '7':
            print(Fore.RED + "\nExiting... Closing all threads...")
            if ids_thread and ids_thread.is_alive():
                ids_stop_event.set()
                ids_thread.join(timeout=1)
            print(Fore.RED + "Goodbye!")
            sys.exit(0)
        else:
            print(Fore.RED + "\nInvalid choice! Please try again.")
            input(Fore.MAGENTA + "\nPress Enter to return to the menu...")

           

if __name__ == "__main__":
    try:
       
        if os.geteuid() != 0:
            print(Fore.RED + "This script requires sudo privileges. Restarting with sudo...")
            subprocess.call(["sudo", sys.executable] + sys.argv)
            sys.exit(0)
    except AttributeError:
        print(Fore.RED + "Sudo check is not supported on this platform.")
    
    main()