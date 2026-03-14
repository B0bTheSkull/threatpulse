"""AlienVault OTX threat intelligence (requires OTX_API_KEY env var)."""
import os
import requests

OTX_BASE = "https://otx.alienvault.com/api/v1"
TIMEOUT = 15


def _key():
    return os.environ.get("OTX_API_KEY", "")


def _available():
    return bool(_key())


def lookup_ip(ip):
    if not _available():
        return {"source": "OTX", "skipped": True, "reason": "OTX_API_KEY not set"}
    try:
        headers = {"X-OTX-API-KEY": _key()}
        r = requests.get(f"{OTX_BASE}/indicators/IPv4/{ip}/general", headers=headers, timeout=TIMEOUT)
        r.raise_for_status()
        data = r.json()
        pulse_count = data.get("pulse_info", {}).get("count", 0)
        return {
            "source": "OTX",
            "found": pulse_count > 0,
            "pulse_count": pulse_count,
            "reputation": data.get("reputation", 0),
            "country": data.get("country_name"),
            "asn": data.get("asn"),
            "pulses": [p.get("name") for p in data.get("pulse_info", {}).get("pulses", [])[:5]]
        }
    except Exception as e:
        return {"source": "OTX", "error": str(e)}


def lookup_domain(domain):
    if not _available():
        return {"source": "OTX", "skipped": True, "reason": "OTX_API_KEY not set"}
    try:
        headers = {"X-OTX-API-KEY": _key()}
        r = requests.get(f"{OTX_BASE}/indicators/domain/{domain}/general", headers=headers, timeout=TIMEOUT)
        r.raise_for_status()
        data = r.json()
        pulse_count = data.get("pulse_info", {}).get("count", 0)
        return {
            "source": "OTX",
            "found": pulse_count > 0,
            "pulse_count": pulse_count,
            "alexa": data.get("alexa"),
            "pulses": [p.get("name") for p in data.get("pulse_info", {}).get("pulses", [])[:5]]
        }
    except Exception as e:
        return {"source": "OTX", "error": str(e)}


def lookup_hash(file_hash):
    if not _available():
        return {"source": "OTX", "skipped": True, "reason": "OTX_API_KEY not set"}
    try:
        headers = {"X-OTX-API-KEY": _key()}
        r = requests.get(f"{OTX_BASE}/indicators/file/{file_hash}/general", headers=headers, timeout=TIMEOUT)
        r.raise_for_status()
        data = r.json()
        pulse_count = data.get("pulse_info", {}).get("count", 0)
        return {
            "source": "OTX",
            "found": pulse_count > 0,
            "pulse_count": pulse_count,
            "malware_families": data.get("malware_families", []),
            "pulses": [p.get("name") for p in data.get("pulse_info", {}).get("pulses", [])[:5]]
        }
    except Exception as e:
        return {"source": "OTX", "error": str(e)}
