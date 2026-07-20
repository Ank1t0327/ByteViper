import urllib.request
import urllib.error

def download_text_feed(url: str, timeout: int = 5) -> str:
    """Downloads a text feed from a URL and returns it as a string."""
    try:
        req = urllib.request.Request(
            url,
            headers={"User-Agent": "ByteViper-NDS/1.0"}
        )
        with urllib.request.urlopen(req, timeout=timeout) as response:
            return response.read().decode("utf-8", errors="ignore")
    except Exception:
        return ""
