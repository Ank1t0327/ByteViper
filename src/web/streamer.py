import threading
from collections import deque

class PacketStreamer:
    def __init__(self, max_history=2000):
        self.packets = deque(maxlen=max_history)
        self.alerts = deque(maxlen=max_history)
        self.raw_packets = deque(maxlen=max_history)
        self.lock = threading.Lock()

    def add_packet(self, packet_data):
        with self.lock:
            self.packets.append(packet_data)

    def get_packets_since(self, timestamp=0.0):
        with self.lock:
            return [p for p in self.packets if p.get('timestamp', 0) > timestamp]

    def get_all_packets(self):
        with self.lock:
            return list(self.packets)
            
    def add_alert(self, alert_data):
        with self.lock:
            self.alerts.append(alert_data)
            
    def get_alerts_since(self, timestamp=0.0):
        with self.lock:
            return [a for a in self.alerts if a.get('timestamp', 0) > timestamp]

    def add_raw_packet(self, raw_pkt):
        with self.lock:
            self.raw_packets.append(raw_pkt)

    def get_raw_packets(self):
        with self.lock:
            return list(self.raw_packets)
    
    def clear(self):
        with self.lock:
            self.packets.clear()
            self.alerts.clear()
            self.raw_packets.clear()

# Global streamer instance
streamer = PacketStreamer()
