# ByteViper NDS 

ByteViper is a lightweight, Python-based Network Detection System (NDS). Designed as a progressive, multi-stage cybersecurity portfolio project, it aims to evolve from a simple packet capture engine into a robust, feature-rich network traffic analysis tool.

> **Status:** Packet Capture and Protocol Parsing Engine Active.

##  Features

*   **Live Packet Capture:** Asynchronously capture packets on a selected network interface without dropping them.
*   **Protocol Parsing Engine:** Decodes Ethernet, ARP, IPv4, IPv6, ICMP, TCP, UDP, DNS, and HTTP packets.
*   **Header Extraction:** Extracts critical fields like MAC/IP addresses, ports, sequence numbers, TTL, and flags.
*   **Interface Detection:** Automatically detects available system network interfaces.
*   **Threaded Engine:** Core packet sniffing runs in a background thread, keeping the interactive CLI fully responsive.
*   **Live Statistics:** View a live packet counter and real-time structured packet decodes while the capture is running.
*   **Modular Architecture:** Cleanly separated core engine and CLI for future scalability.

##  Prerequisites

*   Python 3.8+
*   `sudo` privileges (required to interact with raw network sockets for packet capture)

##  Installation

1.  Clone the repository:
    ```bash
    git clone https://github.com/Ank1t0327/ByteViper.git
    cd ByteViper
    ```

2.  Create and activate a virtual environment (recommended):
    ```bash
    python3 -m venv venv
    source venv/bin/activate
    ```

3.  Install dependencies:
    ```bash
    pip install -r requirements.txt
    ```

##  Usage

Run the main application script with elevated privileges:

```bash
sudo python3 src/main.py
```

### CLI Commands
Once inside the ByteViper interactive shell, you can use the following commands:
*   `start [live]` - Begins packet capture on the selected interface. Add `live` for a real-time parsing stream.
*   `stat`  - Displays the current number of captured packets.
*   `stop`  - Halts the packet capture process.
*   `exit`  - Safely stops any running captures and exits the application.

##  Project Roadmap

This project is built in iterative stages to add real capabilities step-by-step:

- [x] **Project Foundation & Network Packet Capture** - Core engine built with Python and Scapy.
- [x] **Protocol Parsing Engine** - Structured data extraction for L2-L7 protocols.
- [ ] **Detection Rules and Alerts** - *Pending* (Focusing on identifying malicious traffic)

---
\n## Stage 3: Live Dashboard\nRun `dashboard` command in the CLI to launch the live web dashboard.
\n## Stage 4: Session Tracking\nThe engine now tracks full 5-tuple flows and performs basic TCP state analysis.
