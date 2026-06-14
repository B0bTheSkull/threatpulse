"""Tests for feed parsers (HTTP responses mocked)."""
import json
from unittest.mock import patch, MagicMock

import pytest

from feeds import feodo, urlhaus, malwarebazaar, otx


def _resp(json_data, status=200):
    r = MagicMock()
    r.status_code = status
    r.json.return_value = json_data
    r.raise_for_status.return_value = None
    return r


# ---- Feodo ----

FEODO_SAMPLE = [
    {"ip_address": "185.220.101.45", "port": 443, "status": "online",
     "malware": "Dridex", "first_seen": "2024-01-01", "last_seen": "2024-02-01",
     "country": "DE"},
    {"ip_address": "10.0.0.9", "port": 80, "status": "offline",
     "malware": "Emotet", "country": "US"},
]


def test_feodo_lookup_found(tmp_path):
    feodo.CACHE_FILE = tmp_path / "cache.json"
    with patch("feeds.feodo.requests.get", return_value=_resp(FEODO_SAMPLE)):
        res = feodo.lookup_ip("185.220.101.45")
    assert res["found"] is True
    assert res["malware"] == "Dridex"
    assert res["port"] == 443


def test_feodo_lookup_not_found(tmp_path):
    feodo.CACHE_FILE = tmp_path / "cache.json"
    with patch("feeds.feodo.requests.get", return_value=_resp(FEODO_SAMPLE)):
        res = feodo.lookup_ip("8.8.8.8")
    assert res["found"] is False


def test_feodo_uses_cache(tmp_path):
    cache = tmp_path / "cache.json"
    feodo.CACHE_FILE = cache
    import time
    cache.write_text(json.dumps({"fetched_at": time.time(), "blocklist": FEODO_SAMPLE}))
    # requests.get must NOT be called when a fresh cache exists
    with patch("feeds.feodo.requests.get", side_effect=AssertionError("network used")):
        res = feodo.lookup_ip("185.220.101.45")
    assert res["found"] is True


def test_feodo_stale_cache_refetches(tmp_path):
    cache = tmp_path / "cache.json"
    feodo.CACHE_FILE = cache
    cache.write_text(json.dumps({"fetched_at": 0, "blocklist": []}))  # expired
    with patch("feeds.feodo.requests.get", return_value=_resp(FEODO_SAMPLE)) as g:
        res = feodo.lookup_ip("185.220.101.45")
    assert g.called
    assert res["found"] is True


def test_feodo_error_returns_error_dict(tmp_path):
    feodo.CACHE_FILE = tmp_path / "cache.json"
    with patch("feeds.feodo.requests.get", side_effect=Exception("boom")):
        res = feodo.lookup_ip("1.2.3.4")
    assert "error" in res


# ---- URLhaus ----

def test_urlhaus_url_listed():
    data = {"query_status": "is_listed", "threat": "malware_download",
            "url_status": "online", "date_added": "2024-01-01",
            "tags": ["elf", "mirai"], "urls_on_host": 3}
    with patch("feeds.urlhaus.requests.post", return_value=_resp(data)):
        res = urlhaus.lookup_url("http://bad.example/payload")
    assert res["found"] is True
    assert res["threat"] == "malware_download"
    assert res["tags"] == ["elf", "mirai"]


def test_urlhaus_url_not_listed():
    with patch("feeds.urlhaus.requests.post",
               return_value=_resp({"query_status": "no_results"})):
        res = urlhaus.lookup_url("http://good.example")
    assert res["found"] is False


def test_urlhaus_host_truncates_recent_urls():
    urls = [{"url": f"http://bad.example/{i}"} for i in range(10)]
    data = {"query_status": "is_listed", "urls": urls, "blacklists": {"spamhaus": "listed"}}
    with patch("feeds.urlhaus.requests.post", return_value=_resp(data)):
        res = urlhaus.lookup_host("bad.example")
    assert res["found"] is True
    assert res["url_count"] == 10
    assert len(res["recent_urls"]) == 5


# ---- MalwareBazaar ----

def test_malwarebazaar_hash_found():
    data = {"query_status": "ok", "data": [{
        "sha256_hash": "abc123", "file_type": "exe", "file_name": "evil.exe",
        "signature": "AgentTesla", "tags": ["exe", "AgentTesla"]}]}
    with patch("feeds.malwarebazaar.requests.post", return_value=_resp(data)):
        res = malwarebazaar.lookup_hash("abc123")
    assert res["found"] is True
    assert res["signature"] == "AgentTesla"


def test_malwarebazaar_hash_not_found():
    with patch("feeds.malwarebazaar.requests.post",
               return_value=_resp({"query_status": "hash_not_found"})):
        res = malwarebazaar.lookup_hash("deadbeef")
    assert res["found"] is False
    assert res["status"] == "hash_not_found"


# ---- OTX ----

def test_otx_skipped_without_key(monkeypatch):
    monkeypatch.delenv("OTX_API_KEY", raising=False)
    res = otx.lookup_ip("1.2.3.4")
    assert res["skipped"] is True


def test_otx_found_with_key(monkeypatch):
    monkeypatch.setenv("OTX_API_KEY", "FAKE-TEST-KEY")
    data = {"pulse_info": {"count": 2, "pulses": [{"name": "p1"}, {"name": "p2"}]},
            "reputation": 5, "country_name": "RU", "asn": "AS1234"}
    with patch("feeds.otx.requests.get", return_value=_resp(data)):
        res = otx.lookup_ip("1.2.3.4")
    assert res["found"] is True
    assert res["pulse_count"] == 2
    assert res["pulses"] == ["p1", "p2"]


def test_otx_clean_when_no_pulses(monkeypatch):
    monkeypatch.setenv("OTX_API_KEY", "FAKE-TEST-KEY")
    data = {"pulse_info": {"count": 0, "pulses": []}}
    with patch("feeds.otx.requests.get", return_value=_resp(data)):
        res = otx.lookup_domain("good.example")
    assert res["found"] is False
