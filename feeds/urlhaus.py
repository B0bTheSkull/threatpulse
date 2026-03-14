"""abuse.ch URLhaus feed queries."""
import requests

BASE_URL = "https://urlhaus-api.abuse.ch/v1"
TIMEOUT = 15


def lookup_url(url):
    try:
        r = requests.post(f"{BASE_URL}/url/", data={"url": url}, timeout=TIMEOUT)
        r.raise_for_status()
        data = r.json()
        if data.get("query_status") == "is_listed":
            return {
                "source": "URLhaus",
                "found": True,
                "threat": data.get("threat"),
                "url_status": data.get("url_status"),
                "date_added": data.get("date_added"),
                "tags": data.get("tags", []),
                "urls_on_host": data.get("urls_on_host"),
                "raw": data
            }
        return {"source": "URLhaus", "found": False}
    except Exception as e:
        return {"source": "URLhaus", "error": str(e)}


def lookup_host(host):
    try:
        r = requests.post(f"{BASE_URL}/host/", data={"host": host}, timeout=TIMEOUT)
        r.raise_for_status()
        data = r.json()
        if data.get("query_status") == "is_listed":
            urls = data.get("urls", [])
            return {
                "source": "URLhaus",
                "found": True,
                "host": host,
                "url_count": len(urls),
                "blacklists": data.get("blacklists", {}),
                "recent_urls": [u.get("url") for u in urls[:5]],
                "raw": data
            }
        return {"source": "URLhaus", "found": False}
    except Exception as e:
        return {"source": "URLhaus", "error": str(e)}
