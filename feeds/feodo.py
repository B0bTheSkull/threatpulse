"""Feodo Tracker C2 IP blocklist."""
import json
import time
from pathlib import Path
import requests

FEODO_URL = "https://feodotracker.abuse.ch/downloads/ipblocklist.json"
CACHE_FILE = Path(".cache_feodo.json")
CACHE_TTL = 3600  # 1 hour
TIMEOUT = 20


def _load_cache():
    if CACHE_FILE.exists():
        try:
            data = json.loads(CACHE_FILE.read_text())
            if time.time() - data.get("fetched_at", 0) < CACHE_TTL:
                return data.get("blocklist", [])
        except Exception:
            pass
    return None


def _fetch_and_cache():
    r = requests.get(FEODO_URL, timeout=TIMEOUT)
    r.raise_for_status()
    blocklist = r.json()
    CACHE_FILE.write_text(json.dumps({"fetched_at": time.time(), "blocklist": blocklist}))
    return blocklist


def get_blocklist():
    cached = _load_cache()
    if cached is not None:
        return cached
    return _fetch_and_cache()


def lookup_ip(ip):
    """Check if an IP is in the Feodo C2 blocklist."""
    try:
        blocklist = get_blocklist()
        for entry in blocklist:
            if entry.get("ip_address") == ip:
                return {
                    "source": "Feodo Tracker",
                    "found": True,
                    "ip": ip,
                    "port": entry.get("port"),
                    "status": entry.get("status"),
                    "malware": entry.get("malware"),
                    "first_seen": entry.get("first_seen"),
                    "last_seen": entry.get("last_seen"),
                    "country": entry.get("country")
                }
        return {"source": "Feodo Tracker", "found": False}
    except Exception as e:
        return {"source": "Feodo Tracker", "error": str(e)}
