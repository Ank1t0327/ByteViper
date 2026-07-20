import os
import json
import time
import threading
import shutil
from config.settings import CACHE_DIR, CACHE_FILE, STARTER_CACHE_FILE, FEODO_URL, URLHAUS_URL, DEFAULT_MALICIOUS_IPS, DEFAULT_MALICIOUS_DOMAINS
from feeds.downloader import download_text_feed
from feeds.parser import parse_feodo_ips, parse_urlhaus_domains

class ThreatIntelEngine:
    def __init__(self):
        self.malicious_ips = set(DEFAULT_MALICIOUS_IPS)
        self.malicious_domains = set(DEFAULT_MALICIOUS_DOMAINS)
        self.last_updated = 0.0
        self.is_updating = False
        self.lock = threading.Lock()
        
        os.makedirs(CACHE_DIR, exist_ok=True)
        
        if not os.path.exists(CACHE_FILE):
            if os.path.exists(STARTER_CACHE_FILE):
                shutil.copy(STARTER_CACHE_FILE, CACHE_FILE)
            else:
                self.save_cache()
                
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
        domain = domain.lower().strip().rstrip(".")
        with self.lock:
            if domain in self.malicious_domains:
                return True
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
        with self.lock:
            if self.is_updating:
                return
            self.is_updating = True

        try:
            feodo_content = download_text_feed(FEODO_URL)
            new_ips = parse_feodo_ips(feodo_content)
            
            urlhaus_content = download_text_feed(URLHAUS_URL)
            new_domains = parse_urlhaus_domains(urlhaus_content)

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
            
        if (time.time() - self.last_updated) < 86400:
            return False
            
        t = threading.Thread(target=self.update_feeds, daemon=True)
        t.start()
        return True

# Global instance
threat_intel = ThreatIntelEngine()
