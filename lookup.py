"""Orchestrate multi-feed IOC lookups."""
from feeds import urlhaus, malwarebazaar, feodo, otx


def lookup(ioc, ioc_type):
    """
    Look up an IOC across all available feeds.
    ioc_type: 'ip', 'domain', 'url', 'hash'
    """
    results = []

    if ioc_type == "ip":
        results.append(urlhaus.lookup_host(ioc))
        results.append(feodo.lookup_ip(ioc))
        results.append(otx.lookup_ip(ioc))

    elif ioc_type == "domain":
        results.append(urlhaus.lookup_host(ioc))
        results.append(otx.lookup_domain(ioc))

    elif ioc_type == "url":
        results.append(urlhaus.lookup_url(ioc))

    elif ioc_type == "hash":
        results.append(malwarebazaar.lookup_hash(ioc))
        results.append(otx.lookup_hash(ioc))

    else:
        return [{"error": f"Unknown IOC type: {ioc_type}"}]

    # Determine overall threat level
    any_found = any(r.get("found") for r in results if not r.get("error") and not r.get("skipped"))
    threat_level = "MALICIOUS" if any_found else "CLEAN"

    return {
        "ioc": ioc,
        "type": ioc_type,
        "threat_level": threat_level,
        "sources_queried": len(results),
        "results": results
    }
