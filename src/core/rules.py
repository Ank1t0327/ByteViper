import time

class Alert:
    def __init__(self, rule_name, severity, description, src_ip):
        self.timestamp = time.time()
        self.rule_name = rule_name
        self.severity = severity # 'INFO', 'LOW', 'MEDIUM', 'HIGH', 'CRITICAL'
        self.description = description
        self.src_ip = src_ip
        
    def to_dict(self):
        return {
            "timestamp": self.timestamp,
            "rule_name": self.rule_name,
            "severity": self.severity,
            "description": self.description,
            "src_ip": self.src_ip
        }

class BaseRule:
    def __init__(self):
        self.name = self.__class__.__name__

    def evaluate(self, parsed_data) -> list:
        return []

class BlacklistIPRule(BaseRule):
    def __init__(self):
        super().__init__()
        self.blacklist = {'198.51.100.42', '203.0.113.7', '185.15.59.224'} # Mock malicious IPs

    def evaluate(self, parsed_data):
        alerts = []
        layers = parsed_data.get('layers', [])
        for layer in layers:
            if layer.get('layer') in ['IPv4', 'IPv6']:
                src = layer.get('src_ip')
                dst = layer.get('dst_ip')
                if src in self.blacklist:
                    alerts.append(Alert(self.name, "CRITICAL", f"Traffic from blacklisted IP: {src}", src))
                elif dst in self.blacklist:
                    alerts.append(Alert(self.name, "CRITICAL", f"Traffic to blacklisted IP: {dst}", src))
        return alerts

class PortScanRule(BaseRule):
    def __init__(self):
        super().__init__()
        self.ip_ports = {} 
        self.ip_times = {} 
        self.threshold = 15 # 15 unique ports within 5 seconds

    def evaluate(self, parsed_data):
        alerts = []
        layers = parsed_data.get('layers', [])
        
        src_ip = None
        dst_port = None
        for layer in layers:
            if layer.get('layer') in ['IPv4', 'IPv6']:
                src_ip = layer.get('src_ip')
            if 'dst_port' in layer:
                dst_port = layer.get('dst_port')
        
        if src_ip and dst_port:
            now = time.time()
            if src_ip not in self.ip_ports:
                self.ip_ports[src_ip] = set()
                self.ip_times[src_ip] = []
            
            self.ip_ports[src_ip].add(dst_port)
            self.ip_times[src_ip].append(now)
            
            self.ip_times[src_ip] = [t for t in self.ip_times[src_ip] if now - t <= 5.0]
            
            if len(self.ip_ports[src_ip]) > self.threshold and len(self.ip_times[src_ip]) > self.threshold:
                alerts.append(Alert(self.name, "HIGH", f"Port Scan detected from {src_ip}", src_ip))
                self.ip_ports[src_ip] = set()
                self.ip_times[src_ip] = []
                
        return alerts

class SynFloodRule(BaseRule):
    def __init__(self):
        super().__init__()
        self.syn_counts = {}
        self.threshold = 30 # 30 SYN packets per second

    def evaluate(self, parsed_data):
        alerts = []
        layers = parsed_data.get('layers', [])
        
        src_ip = None
        is_syn = False
        
        for layer in layers:
            if layer.get('layer') in ['IPv4', 'IPv6']:
                src_ip = layer.get('src_ip')
            if layer.get('layer') == 'TCP':
                flags = layer.get('flags', '')
                if 'S' in flags and 'A' not in flags:
                    is_syn = True
        
        if src_ip and is_syn:
            now = time.time()
            if src_ip not in self.syn_counts:
                self.syn_counts[src_ip] = []
                
            self.syn_counts[src_ip].append(now)
            self.syn_counts[src_ip] = [t for t in self.syn_counts[src_ip] if now - t <= 1.0]
            
            if len(self.syn_counts[src_ip]) > self.threshold:
                alerts.append(Alert(self.name, "HIGH", f"SYN Flood detected from {src_ip}", src_ip))
                self.syn_counts[src_ip] = []
                
        return alerts

class DnsTunnelingRule(BaseRule):
    def __init__(self):
        super().__init__()
    
    def evaluate(self, parsed_data):
        alerts = []
        layers = parsed_data.get('layers', [])
        src_ip = None
        for layer in layers:
            if layer.get('layer') in ['IPv4', 'IPv6']:
                src_ip = layer.get('src_ip')
            if layer.get('layer') == 'DNS':
                qname = layer.get('qname')
                if qname and len(qname) > 60:
                    alerts.append(Alert(self.name, "MEDIUM", f"Suspiciously long DNS query (Tunneling?): {qname[:20]}...", src_ip))
        return alerts

class LargeTransferRule(BaseRule):
    def __init__(self):
        super().__init__()

    def evaluate(self, parsed_data):
        alerts = []
        if parsed_data.get('length', 0) > 10000:
            src_ip = "Unknown"
            for layer in parsed_data.get('layers', []):
                if layer.get('layer') in ['IPv4', 'IPv6']:
                    src_ip = layer.get('src_ip')
            alerts.append(Alert(self.name, "LOW", f"Abnormally large packet detected ({parsed_data.get('length')} bytes)", src_ip))
        return alerts

class RuleEngine:
    def __init__(self):
        self.rules = [
            BlacklistIPRule(),
            PortScanRule(),
            SynFloodRule(),
            DnsTunnelingRule(),
            LargeTransferRule()
        ]
        self.callbacks = []

    def register_callback(self, callback):
        self.callbacks.append(callback)

    def process_packet(self, parsed_data):
        for rule in self.rules:
            try:
                alerts = rule.evaluate(parsed_data)
                for alert in alerts:
                    for cb in self.callbacks:
                        cb(alert.to_dict())
            except Exception:
                pass

# Global rule engine instance
rule_engine = RuleEngine()
