import os
import json
import time
import urllib.request
import threading
import re
import shutil

# Default seed lists in case of no network / first run
DEFAULT_MALICIOUS_IPS = {
    "185.15.59.224",
    "198.51.100.42",
    "203.0.113.7",
    "192.185.10.15",
    "91.219.28.2",
    "45.143.203.95"
}

DEFAULT_MALICIOUS_DOMAINS = {
    "malware-c2.net",
    "bad-domain.ru",
    "phishing-scam.com",
    "dast.threatintel.org",
    "c2server.xyz",
    "super-malicious-domain.com"
}

BASE_DIR = os.path.dirname(os.path.dirname(os.path.dirname(__file__)))
CACHE_DIR = os.path.join(BASE_DIR, "cache")
DATA_DIR = os.path.join(BASE_DIR, "data")
CACHE_FILE = os.path.join(CACHE_DIR, "threat_intel_cache.json")
STARTER_CACHE_FILE = os.path.join(DATA_DIR, "starter_cache.json")

class ThreatIntelEngine:
    def __init__(self):
        self.malicious_ips = set(DEFAULT_MALICIOUS_IPS)
        self.malicious_domains = set(DEFAULT_MALICIOUS_DOMAINS)
        self.last_updated = 0.0
        self.is_updating = False
        self.lock = threading.Lock()
        
        # Ensure cache dir exists
        os.makedirs(CACHE_DIR, exist_ok=True)
        
        # Check if cache file is present, if not copy starter cache
        if not os.path.exists(CACHE_FILE):
            if os.path.exists(STARTER_CACHE_FILE):
                shutil.copy(STARTER_CACHE_FILE, CACHE_FILE)
            else:
                self.save_cache()
                
        # Load from cache
        self.load_cache()

    def load_cache(self):
        if os.path.exists(CACHE_FILE):
            try:
                with open(CACHE_FILE, "r") as f:
                    data = json.load(f)
                    
                    ips = data.get("ips", [])
                    if ips:
                        self.malicious_ips = set(ips)
                    else:
                        self.malicious_ips = set(DEFAULT_MALICIOUS_IPS)
                        
                    domains = data.get("domains", [])
                    if domains:
                        self.malicious_domains = set(domains)
                    else:
                        self.malicious_domains = set(DEFAULT_MALICIOUS_DOMAINS)
                        
                    self.last_updated = data.get("last_updated", 0.0)
            except Exception:
                pass

    def save_cache(self):
        try:
            with open(CACHE_FILE, "w") as f:
                json.dump({
                    "version": "1.0",
                    "ips": list(self.malicious_ips),
                    "domains": list(self.malicious_domains),
                    "last_updated": self.last_updated
                }, f, indent=2)
        except Exception:
            pass

    def check_ip(self, ip: str) -> bool:
        if not ip:
            return False
        with self.lock:
            return ip in self.malicious_ips

    def check_domain(self, domain: str) -> bool:
        if not domain:
            return False
        # Normalize domain (lowercase, remove trailing dot)
        domain = domain.lower().strip().rstrip(".")
        with self.lock:
            if domain in self.malicious_domains:
                return True
            # Check subdomains (e.g. mal.c2server.xyz matches c2server.xyz)
            for d in self.malicious_domains:
                if domain.endswith("." + d):
                    return True
            return False

    def get_status(self) -> dict:
        with self.lock:
            return {
                "last_updated": self.last_updated,
                "is_updating": self.is_updating,
                "num_ips": len(self.malicious_ips),
                "num_domains": len(self.malicious_domains)
            }

    def update_feeds(self):
        """Perform the actual blocking update request."""
        with self.lock:
            if self.is_updating:
                return
            self.is_updating = True

        try:
            new_ips = set()
            new_domains = set()

            # 1. Fetch IP blocklist from Feodo Tracker
            try:
                req = urllib.request.Request(
                    "https://feodotracker.abuse.ch/downloads/ipblocklist.txt",
                    headers={"User-Agent": "ByteViper-NDS/1.0"}
                )
                with urllib.request.urlopen(req, timeout=5) as response:
                    content = response.read().decode("utf-8", errors="ignore")
                    for line in content.splitlines():
                        line = line.strip()
                        if line and not line.startswith("#"):
                            match = re.search(r"\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b", line)
                            if match:
                                new_ips.add(match.group(0))
            except Exception:
                # If network fails, keep existing/fallback IPs
                pass

            # 2. Fetch Domain blocklist from URLhaus hostfile
            try:
                req = urllib.request.Request(
                    "https://urlhaus.abuse.ch/downloads/hostfile/",
                    headers={"User-Agent": "ByteViper-NDS/1.0"}
                )
                with urllib.request.urlopen(req, timeout=5) as response:
                    content = response.read().decode("utf-8", errors="ignore")
                    for line in content.splitlines():
                        line = line.strip()
                        if line and not line.startswith("#"):
                            parts = line.split()
                            if len(parts) >= 2 and (parts[0] == "127.0.0.1" or parts[0] == "0.0.0.0"):
                                domain = parts[1].strip().lower()
                                if domain and domain != "localhost":
                                    new_domains.add(domain)
            except Exception:
                # If network fails, keep existing/fallback domains
                pass

            # Update state if we got new feeds, otherwise merge/fallback to defaults
            with self.lock:
                if new_ips:
                    self.malicious_ips = new_ips.union(DEFAULT_MALICIOUS_IPS)
                if new_domains:
                    self.malicious_domains = new_domains.union(DEFAULT_MALICIOUS_DOMAINS)
                
                self.last_updated = time.time()
                self.save_cache()

        finally:
            with self.lock:
                self.is_updating = False

    def update_feeds_async(self) -> bool:
        if self.is_updating:
            return False
            
        # 24-hour expiry check
        if (time.time() - self.last_updated) < 86400:
            return False
            
        t = threading.Thread(target=self.update_feeds, daemon=True)
        t.start()
        return True

# Global instance
threat_intel = ThreatIntelEngine()
