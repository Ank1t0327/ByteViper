import time
import re
import base64
from feeds.updater import threat_intel

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

class ThreatIntelIPRule(BaseRule):
    def evaluate(self, parsed_data):
        alerts = []
        layers = parsed_data.get('layers', [])
        for layer in layers:
            if layer.get('layer') in ['IPv4', 'IPv6']:
                src = layer.get('src_ip')
                dst = layer.get('dst_ip')
                if src and threat_intel.check_ip(src):
                    alerts.append(Alert(self.name, "CRITICAL", f"Threat Intel: Traffic from malicious IP: {src}", src))
                if dst and threat_intel.check_ip(dst):
                    alerts.append(Alert(self.name, "CRITICAL", f"Threat Intel: Traffic to malicious IP: {dst}", src or "Unknown"))
        return alerts

class ThreatIntelDomainRule(BaseRule):
    def evaluate(self, parsed_data):
        alerts = []
        layers = parsed_data.get('layers', [])
        src_ip = None
        for layer in layers:
            if layer.get('layer') in ['IPv4', 'IPv6']:
                src_ip = layer.get('src_ip')
            if layer.get('layer') == 'DNS':
                qname = layer.get('qname')
                if qname and threat_intel.check_domain(qname):
                    alerts.append(Alert(self.name, "CRITICAL", f"Threat Intel: Malicious DNS Domain query: {qname}", src_ip or "Unknown"))
        return alerts

class ShellCommandRule(BaseRule):
    def __init__(self):
        super().__init__()
        self.pattern = re.compile(
            r"\b(wget|curl|chmod|whoami|id|uname|netcat|nc|powershell|cmd\.exe|bin/sh|bin/bash|sh\s+-i|bash\s+-i)\b", 
            re.IGNORECASE
        )

    def evaluate(self, parsed_data):
        alerts = []
        payload_str = parsed_data.get('payload', '')
        if not payload_str:
            return alerts
        
        match = self.pattern.search(payload_str)
        if match:
            src_ip = "Unknown"
            for layer in parsed_data.get('layers', []):
                if layer.get('layer') in ['IPv4', 'IPv6']:
                    src_ip = layer.get('src_ip')
            alerts.append(Alert(
                self.name, 
                "HIGH", 
                f"DPI: Suspicious shell command/utility detected in payload: '{match.group(0)}'", 
                src_ip
            ))
        return alerts

class SqlInjectionRule(BaseRule):
    def __init__(self):
        super().__init__()
        self.pattern = re.compile(
            r"(\'\s*or\s*\'?\d+\'?\s*=\s*\'?\d+|\bunion\s+select\b|\bdrop\s+table\b|\bselect\s+.*\s+from\b|--|\/\*|\*\/)", 
            re.IGNORECASE
        )

    def evaluate(self, parsed_data):
        alerts = []
        payload_str = parsed_data.get('payload', '')
        if not payload_str:
            return alerts
        
        match = self.pattern.search(payload_str)
        if match:
            src_ip = "Unknown"
            for layer in parsed_data.get('layers', []):
                if layer.get('layer') in ['IPv4', 'IPv6']:
                    src_ip = layer.get('src_ip')
            alerts.append(Alert(
                self.name, 
                "HIGH", 
                f"DPI: Potential SQL Injection attempt: '{match.group(0)}'", 
                src_ip
            ))
        return alerts

class CredentialLeakRule(BaseRule):
    def __init__(self):
        super().__init__()
        self.pattern = re.compile(
            r"\b(password|passwd|pwd|pass|secret|api_key|apikey|bearer|authorization)\b\s*[:=]\s*\S+", 
            re.IGNORECASE
        )

    def evaluate(self, parsed_data):
        alerts = []
        payload_str = parsed_data.get('payload', '')
        if not payload_str:
            return alerts
        
        dst_port = None
        src_ip = "Unknown"
        for layer in parsed_data.get('layers', []):
            if layer.get('layer') in ['IPv4', 'IPv6']:
                src_ip = layer.get('src_ip')
            if 'dst_port' in layer:
                dst_port = layer.get('dst_port')
        
        match = self.pattern.search(payload_str)
        if match:
            severity = "HIGH" if dst_port in [80, 23, 21] else "MEDIUM"
            alerts.append(Alert(
                self.name, 
                severity, 
                f"DPI: Sensitive credentials transmitted in plaintext (matched: '{match.group(1)}')", 
                src_ip
            ))
        return alerts

class MalwareSignatureRule(BaseRule):
    def __init__(self):
        super().__init__()
        self.tool_pattern = re.compile(
            r"\b(mimikatz|cobaltstrike|metasploit|sqlmap|hydra|dirbuster|gobuster|w3af|nikto)\b", 
            re.IGNORECASE
        )

    def evaluate(self, parsed_data):
        alerts = []
        
        http_ua = None
        for layer in parsed_data.get('layers', []):
            if layer.get('layer') == 'HTTP Request':
                http_ua = layer.get('user_agent')
        
        src_ip = "Unknown"
        for layer in parsed_data.get('layers', []):
            if layer.get('layer') in ['IPv4', 'IPv6']:
                src_ip = layer.get('src_ip')
                
        if http_ua:
            match = self.tool_pattern.search(http_ua)
            if match:
                alerts.append(Alert(
                    self.name, 
                    "CRITICAL", 
                    f"Malware Signature: Malicious User-Agent '{match.group(0)}' detected", 
                    src_ip
                ))
                return alerts
        
        payload_str = parsed_data.get('payload', '')
        if payload_str:
            match = self.tool_pattern.search(payload_str)
            if match:
                alerts.append(Alert(
                    self.name, 
                    "CRITICAL", 
                    f"Malware Signature: Malicious tool/C2 keyword '{match.group(0)}' detected in payload", 
                    src_ip
                ))
        return alerts

class EncodedDataRule(BaseRule):
    def __init__(self):
        super().__init__()
        self.b64_pattern = re.compile(r"[A-Za-z0-9+/]{32,}={0,2}")
        self.malicious_pattern = re.compile(
            r"\b(wget|curl|chmod|whoami|id|uname|nc|netcat|bash|powershell|cmd\.exe|union\s+select|drop\s+table)\b",
            re.IGNORECASE
        )

    def evaluate(self, parsed_data):
        alerts = []
        payload_str = parsed_data.get('payload', '')
        if not payload_str:
            return alerts
        
        src_ip = "Unknown"
        for layer in parsed_data.get('layers', []):
            if layer.get('layer') in ['IPv4', 'IPv6']:
                src_ip = layer.get('src_ip')

        matches = self.b64_pattern.findall(payload_str)
        for match in matches:
            try:
                decoded = base64.b64decode(match).decode('utf-8', errors='ignore')
                inner_match = self.malicious_pattern.search(decoded)
                if inner_match:
                    alerts.append(Alert(
                        self.name,
                        "CRITICAL",
                        f"DPI: Encoded Payload contains malicious command: '{inner_match.group(0)}'",
                        src_ip
                    ))
                    break
            except Exception:
                pass
        return alerts

class RuleEngine:
    def __init__(self):
        self.rules = [
            BlacklistIPRule(),
            PortScanRule(),
            SynFloodRule(),
            DnsTunnelingRule(),
            LargeTransferRule(),
            ThreatIntelIPRule(),
            ThreatIntelDomainRule(),
            ShellCommandRule(),
            SqlInjectionRule(),
            CredentialLeakRule(),
            MalwareSignatureRule(),
            EncodedDataRule()
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
