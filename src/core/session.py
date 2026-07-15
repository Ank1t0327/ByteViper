import time
import threading

class SessionTracker:
    def __init__(self):
        self.sessions = {}
        self.lock = threading.Lock()

    def process_packet(self, parsed_data):
        layers = parsed_data.get('layers', [])
        if not layers:
            return

        src_ip = None
        dst_ip = None
        protocol = None
        src_port = None
        dst_port = None
        flags = None

        for layer in layers:
            l_type = layer.get('layer')
            if l_type in ['IPv4', 'IPv6']:
                src_ip = layer.get('src_ip')
                dst_ip = layer.get('dst_ip')
            elif l_type == 'TCP':
                protocol = 'TCP'
                src_port = layer.get('src_port')
                dst_port = layer.get('dst_port')
                flags = layer.get('flags', '')
            elif l_type == 'UDP':
                protocol = 'UDP'
                src_port = layer.get('src_port')
                dst_port = layer.get('dst_port')

        if not src_ip or not dst_ip or not protocol:
            return

        # 5-tuple for bidirectional tracking
        endpoint1 = f"{src_ip}:{src_port}"
        endpoint2 = f"{dst_ip}:{dst_port}"
        
        endpoints = tuple(sorted([endpoint1, endpoint2]))
        session_key = (endpoints[0], endpoints[1], protocol)

        pkt_length = parsed_data.get('length', 0)
        timestamp = parsed_data.get('timestamp', time.time())

        with self.lock:
            if session_key not in self.sessions:
                self.sessions[session_key] = {
                    'session_id': f"{protocol}_{endpoints[0]}_{endpoints[1]}",
                    'protocol': protocol,
                    'endpoint_a': endpoints[0],
                    'endpoint_b': endpoints[1],
                    'start_time': timestamp,
                    'last_time': timestamp,
                    'packet_count': 1,
                    'total_bytes': pkt_length,
                    'state': 'NEW'
                }
            else:
                sess = self.sessions[session_key]
                sess['last_time'] = timestamp
                sess['packet_count'] += 1
                sess['total_bytes'] += pkt_length

            # State machine
            sess = self.sessions[session_key]
            if protocol == 'TCP' and flags:
                if 'S' in flags and 'A' not in flags:
                    # If it's a new SYN, it's SYN_SENT. If already established, ignore.
                    if sess['state'] == 'NEW':
                        sess['state'] = 'SYN_SENT'
                elif 'S' in flags and 'A' in flags:
                    sess['state'] = 'ESTABLISHED'
                elif 'F' in flags or 'R' in flags:
                    sess['state'] = 'CLOSED'
                elif sess['state'] == 'NEW' and 'A' in flags:
                    # Picked up mid-stream
                    sess['state'] = 'ESTABLISHED'
            elif protocol == 'UDP':
                sess['state'] = 'ACTIVE'

    def get_active_sessions(self):
        with self.lock:
            return list(self.sessions.values())

# Global session tracker instance
session_tracker = SessionTracker()
