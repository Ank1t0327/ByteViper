import sys
import time
import threading
from core.sniffer import PacketSniffer
from core.session import session_tracker
from core.rules import rule_engine
from core.anomaly import anomaly_engine
from core.threat_intel import threat_intel
from web.app import start_web_server
from web.streamer import streamer

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
    
    print("[*] Initializing Threat Intelligence feeds in background...")
    threat_intel.update_feeds_async()
    
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
    print("  dashboard    - Start web dashboard for live traffic monitoring")
    print("  sessions     - Show active flow sessions")
    print("  alerts       - Show triggered security alerts")
    print("  stop         - Stop packet capture")
    print("  stat         - Show packet count")
    print("  exit         - Quit the application")

    # Link the sniffer callback to the web streamer, session tracker, and rule engine
    sniffer.register_callback(streamer.add_packet)
    sniffer.register_callback(session_tracker.process_packet)
    sniffer.register_callback(rule_engine.process_packet)
    sniffer.register_callback(anomaly_engine.process_packet)
    
    # Link rule engine alerts to streamer
    rule_engine.register_callback(streamer.add_alert)
    anomaly_engine.register_callback(streamer.add_alert)
    
    web_server_running = False

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
            
            elif cmd == "dashboard":
                if not web_server_running:
                    print("[*] Starting Web Dashboard on http://127.0.0.1:5000 ...")
                    start_web_server()
                    web_server_running = True
                
                if not sniffer.is_running():
                    print("[*] Auto-starting capture for dashboard...")
                    try:
                        sniffer.start(live=False)
                        print("[+] Capture started in background.")
                    except Exception as e:
                        print(f"[!] Failed to start capture: {e}")
                else:
                    print("[*] Capture is already running.")
            
            elif cmd == "sessions":
                sessions = session_tracker.get_active_sessions()
                if not sessions:
                    print("[-] No active sessions.")
                else:
                    print(f"\n{'Protocol':<8} {'State':<15} {'Endpoint A':<25} {'Endpoint B':<25} {'Packets':<10} {'Bytes'}")
                    print("-" * 95)
                    for s in sessions[-20:]: # show last 20
                        print(f"{s['protocol']:<8} {s['state']:<15} {s['endpoint_a']:<25} {s['endpoint_b']:<25} {s['packet_count']:<10} {s['total_bytes']}")
                    print("-" * 95)
                    print(f"Total Sessions: {len(sessions)}")

            elif cmd == "alerts":
                alerts = streamer.get_alerts_since(0)
                if not alerts:
                    print("[-] No alerts triggered.")
                else:
                    print(f"\n{'Severity':<10} {'Rule':<20} {'Source IP':<15} {'Description'}")
                    print("-" * 80)
                    for a in alerts[-20:]:
                        print(f"{a['severity']:<10} {a['rule_name']:<20} {a['src_ip']:<15} {a['description']}")
                    print("-" * 80)
                    print(f"Total Alerts: {len(alerts)}")

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
