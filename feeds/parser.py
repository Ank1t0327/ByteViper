import re

def parse_feodo_ips(content: str) -> set:
    """Parses Feodo Tracker IP blocklist."""
    ips = set()
    if not content:
        return ips
        
    for line in content.splitlines():
        line = line.strip()
        if line and not line.startswith("#"):
            match = re.search(r"\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b", line)
            if match:
                ips.add(match.group(0))
    return ips

def parse_urlhaus_domains(content: str) -> set:
    """Parses URLhaus domain blocklist."""
    domains = set()
    if not content:
        return domains
        
    for line in content.splitlines():
        line = line.strip()
        if line and not line.startswith("#"):
            parts = line.split()
            if len(parts) >= 2 and (parts[0] == "127.0.0.1" or parts[0] == "0.0.0.0"):
                domain = parts[1].strip().lower()
                if domain and domain != "localhost":
                    domains.add(domain)
    return domains
