import sys
import time
import threading
from core.sniffer import PacketSniffer

def print_banner():
    banner = r"""
    ================================================
       ____        _eViper NDS                     
      |  _ \      | |                              
      | |_) |_   _| |_ ___  Viper                  
      |  _ <| | | | __/ _ \                        
      | |_) | |_| | ||  __/                        
      |____/ \__, |\__\___|                        
              __/ |                                
             |___/    Network Detection System     
    ================================================
    Stage 2: Protocol Parsing Engine
    """
    print(banner)

def main():
    print_banner()
    sniffer = PacketSniffer()

    print("[*] Detecting available network interfaces...")
    try:
        interfaces = sniffer.get_interfaces()
    except Exception as e:
        print(f"[!] Error detecting interfaces: {e}")
        print("[!] Ensure you are running with sufficient privileges (e.g., sudo).")
        sys.exit(1)

    if not interfaces:
        print("[!] No network interfaces found.")
        sys.exit(1)

    print("\nAvailable Interfaces:")
    for idx, iface in enumerate(interfaces):
        print(f"  [{idx}] {iface}")

    selected_iface = None
    while selected_iface is None:
        try:
            choice = input(f"\nSelect an interface [0-{len(interfaces)-1}]: ")
            idx = int(choice)
            if 0 <= idx < len(interfaces):
                selected_iface = interfaces[idx]
            else:
                print("[!] Invalid choice. Out of range.")
        except ValueError:
            print("[!] Please enter a valid number.")
        except KeyboardInterrupt:
            print("\n[*] Exiting.")
            sys.exit(0)

    print(f"\n[*] Selected interface: {selected_iface}")
    sniffer.set_interface(selected_iface)

    print("\nCommands:")
    print("  start [live] - Start packet capture (add 'live' for real-time parsing stream)")
    print("  stop         - Stop packet capture")
    print("  stat  - Show packet count")
    print("  exit  - Quit the application")

    while True:
        try:
            cmd = input("\nByteViper> ").strip().lower()
            
            if cmd.startswith("start"):
                if sniffer.is_running():
                    print("[!] Capture is already running.")
                else:
                    live_mode = "live" in cmd
                    try:
                        mode_str = "LIVE" if live_mode else "SILENT"
                        print(f"[*] Starting capture on {selected_iface} in {mode_str} mode...")
                        sniffer.start(live=live_mode)
                        print("[+] Capture started successfully.")
                    except Exception as e:
                        print(f"[!] Failed to start capture: {e}")
                        print("[!] Are you running as root/sudo?")
            
            elif cmd == "stop":
                if not sniffer.is_running():
                    print("[!] Capture is not currently running.")
                else:
                    print("[*] Stopping capture...")
                    sniffer.stop()
                    print(f"[+] Capture stopped. Total packets seen: {sniffer.get_packet_count()}")
            
            elif cmd == "stat":
                if sniffer.is_running():
                    print(f"[*] Live Packet Count: {sniffer.get_packet_count()}")
                else:
                    print(f"[*] Last Packet Count: {sniffer.get_packet_count()} (Capture is stopped)")
            
            elif cmd == "exit":
                if sniffer.is_running():
                    print("[*] Stopping capture before exit...")
                    sniffer.stop()
                print("[*] Shutting down ByteViper NDS.")
                break
            
            elif cmd != "":
                print("[!] Unknown command.")
                
        except KeyboardInterrupt:
            if sniffer.is_running():
                sniffer.stop()
            print("\n[*] Shutting down ByteViper NDS.")
            break

if __name__ == "__main__":
    main()
