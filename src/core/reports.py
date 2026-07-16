import json
import csv
import io
import os
import time
from core.db import db_manager

def generate_json_report():
    """Generates a complete JSON dump of packets, alerts, and sessions."""
    report_data = {
        "generated_at": time.time(),
        "packets": db_manager.get_packets(limit=2000),
        "alerts": db_manager.get_alerts(limit=2000),
        "sessions": db_manager.get_sessions(limit=2000)
    }
    return json.dumps(report_data, indent=2)

def generate_alerts_csv():
    """Generates a CSV string representing triggered security alerts."""
    alerts = db_manager.get_alerts(limit=2000)
    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(["ID", "Timestamp", "Rule Name", "Severity", "Description", "Source IP"])
    for a in alerts:
        writer.writerow([
            a.get("id"),
            a.get("timestamp"),
            a.get("rule_name"),
            a.get("severity"),
            a.get("description"),
            a.get("src_ip")
        ])
    return output.getvalue()

def generate_packets_csv():
    """Generates a CSV string representing captured packets."""
    packets = db_manager.get_packets(limit=2000)
    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(["ID", "Timestamp", "Length", "Protocol", "Source IP", "Destination IP", "Summary"])
    for p in packets:
        writer.writerow([
            p.get("id"),
            p.get("timestamp"),
            p.get("length"),
            p.get("protocol"),
            p.get("src_ip"),
            p.get("dst_ip"),
            p.get("summary")
        ])
    return output.getvalue()

def generate_pcap_report():
    """Generates a raw PCAP byte stream of captured packets."""
    from web.streamer import streamer
    from scapy.all import wrpcap
    import tempfile
    
    raw_packets = streamer.get_raw_packets()
    
    # Write to a temp file and read back
    with tempfile.NamedTemporaryFile(suffix=".pcap", delete=False) as tmp:
        tmp_name = tmp.name
        
    try:
        wrpcap(tmp_name, raw_packets)
        with open(tmp_name, "rb") as f:
            pcap_bytes = f.read()
    finally:
        if os.path.exists(tmp_name):
            os.remove(tmp_name)
            
    return pcap_bytes
