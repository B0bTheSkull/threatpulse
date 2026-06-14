"""Tests for the multi-feed lookup orchestrator and dashboard history."""
from unittest.mock import patch

import lookup as lookup_module


def test_unknown_type_returns_error():
    res = lookup_module.lookup("x", "bogus")
    assert res == [{"error": "Unknown IOC type: bogus"}]


def test_ip_queries_three_sources():
    with patch("feeds.urlhaus.lookup_host", return_value={"source": "URLhaus", "found": False}), \
         patch("feeds.feodo.lookup_ip", return_value={"source": "Feodo", "found": False}), \
         patch("feeds.otx.lookup_ip", return_value={"source": "OTX", "skipped": True}):
        res = lookup_module.lookup("1.2.3.4", "ip")
    assert res["sources_queried"] == 3
    assert res["threat_level"] == "CLEAN"


def test_threat_level_malicious_when_any_found():
    with patch("feeds.urlhaus.lookup_host", return_value={"source": "URLhaus", "found": False}), \
         patch("feeds.feodo.lookup_ip", return_value={"source": "Feodo", "found": True}), \
         patch("feeds.otx.lookup_ip", return_value={"source": "OTX", "skipped": True}):
        res = lookup_module.lookup("1.2.3.4", "ip")
    assert res["threat_level"] == "MALICIOUS"


def test_error_results_do_not_count_as_found():
    with patch("feeds.urlhaus.lookup_url",
               return_value={"source": "URLhaus", "error": "timeout"}):
        res = lookup_module.lookup("http://x", "url")
    assert res["threat_level"] == "CLEAN"


def test_skipped_results_do_not_count_as_found():
    with patch("feeds.malwarebazaar.lookup_hash",
               return_value={"source": "MB", "found": False}), \
         patch("feeds.otx.lookup_hash",
               return_value={"source": "OTX", "skipped": True, "found": True}):
        # 'found' on a skipped result must be ignored
        res = lookup_module.lookup("deadbeef", "hash")
    assert res["threat_level"] == "CLEAN"


def test_hash_queries_two_sources():
    with patch("feeds.malwarebazaar.lookup_hash", return_value={"found": False}), \
         patch("feeds.otx.lookup_hash", return_value={"skipped": True}):
        res = lookup_module.lookup("abc", "hash")
    assert res["sources_queried"] == 2
    assert res["type"] == "hash"


# ---- dashboard history ----

def _load_app(tmp_path):
    from dashboard import app as app_module
    app_module.HISTORY_FILE = tmp_path / "hist.json"
    return app_module


def test_history_save_and_get(tmp_path):
    app_module = _load_app(tmp_path)
    app_module.save_history("1.2.3.4", "ip", {"threat_level": "MALICIOUS"})
    hist = app_module.get_history()
    assert len(hist) == 1
    assert hist[0]["ioc"] == "1.2.3.4"
    assert hist[0]["threat_level"] == "MALICIOUS"


def test_history_most_recent_first(tmp_path):
    app_module = _load_app(tmp_path)
    app_module.save_history("a", "domain", {"threat_level": "CLEAN"})
    app_module.save_history("b", "domain", {"threat_level": "CLEAN"})
    hist = app_module.get_history()
    assert hist[0]["ioc"] == "b"
    assert hist[1]["ioc"] == "a"


def test_history_caps_at_100(tmp_path):
    app_module = _load_app(tmp_path)
    for i in range(105):
        app_module.save_history(f"ioc{i}", "ip", {"threat_level": "CLEAN"})
    assert len(app_module.get_history()) == 100


def test_history_missing_file_returns_empty(tmp_path):
    app_module = _load_app(tmp_path)
    assert app_module.get_history() == []


def test_history_corrupt_file_returns_empty(tmp_path):
    app_module = _load_app(tmp_path)
    app_module.HISTORY_FILE.write_text("{not valid json")
    assert app_module.get_history() == []
