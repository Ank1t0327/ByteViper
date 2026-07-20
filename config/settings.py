import os

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
CACHE_DIR = os.path.join(BASE_DIR, "cache")
DATA_DIR = os.path.join(BASE_DIR, "data")
CACHE_FILE = os.path.join(CACHE_DIR, "threat_intel_cache.json")
STARTER_CACHE_FILE = os.path.join(DATA_DIR, "starter_cache.json")

FEODO_URL = "https://feodotracker.abuse.ch/downloads/ipblocklist.txt"
URLHAUS_URL = "https://urlhaus.abuse.ch/downloads/hostfile/"

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
