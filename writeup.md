---
title: "ThreatPulse: Tired of Checking 5 Tabs for Every IOC, So I Built This"
date: 2024-11-03
tags: [threat-intel, blue-team, soc, python, ioc, flask]
excerpt: "Every time an alert fired, I'd end up with five browser tabs open — URLhaus, MalwareBazaar, VirusTotal, OTX, Feodo. ThreatPulse collapses that into a single CLI command."
---

# ThreatPulse: Tired of Checking 5 Tabs for Every IOC, So I Built This

Here's my incident response workflow before ThreatPulse:

1. Alert fires with a suspicious IP
2. Open URLhaus, paste the IP
3. Open Feodo Tracker, paste the IP
4. Open AlienVault OTX, paste the IP
5. Open VirusTotal, paste the IP
6. Aggregate results manually in my head
7. Write it up

Every. Single. Time.

It's not that any individual step is hard. It's that the context-switching is constant, and when you're triaging 10 alerts in a queue, it adds up. I wanted a single command that hits all the feeds I care about and gives me a verdict. So I built ThreatPulse.

## The Feeds

I'm a big fan of the free threat intel ecosystem. There's genuinely excellent data available without paying for a commercial platform:

**abuse.ch** runs multiple projects that are invaluable for blue teamers:
- **URLhaus** tracks malicious URLs and hosts in near-real-time. It has a simple REST API — POST a URL or host and get back threat metadata, associated tags, and blocklist status.
- **MalwareBazaar** is a malware sample repository with hash lookups. If you've got a suspicious file hash from an EDR alert, this will tell you if it's a known malware sample and what family it belongs to.

**Feodo Tracker** maintains a blocklist of known C2 IP addresses for malware families like Emotet, Cobalt Strike, and QakBot. The JSON download is cached locally (refreshed every hour) so lookups are instant.

**AlienVault OTX** has a massive pulse-based threat intel database. The free API key gives you generous rate limits and access to crowdsourced threat indicators with context about campaigns and actors.

## The Architecture

The lookup system is built around a simple orchestrator (`lookup.py`) that decides which feeds to query based on IOC type:

```python
def lookup(ioc, ioc_type):
    if ioc_type == "ip":
        results = [urlhaus.lookup_host(ioc), feodo.lookup_ip(ioc), otx.lookup_ip(ioc)]
    elif ioc_type == "hash":
        results = [malwarebazaar.lookup_hash(ioc), otx.lookup_hash(ioc)]
    # ...
```

Each feed module is independent. If one API is down, the others still return results. OTX checks gracefully skip if the API key isn't set — no crashes, just a note that it was skipped.

The Feodo blocklist is handled differently because it's a bulk download rather than a per-query API. The feed module downloads the full JSON blocklist on first run, caches it locally with a 1-hour TTL, and does lookups against the local cache. This makes Feodo lookups instant even for bulk queries.

## CLI vs Dashboard

I built both interfaces because they serve different workflows.

The **CLI** is for when I'm in an active investigation and want to check an IOC quickly without leaving the terminal. It's one command:

```bash
python threatpulse.py lookup --ioc 185.220.101.45 --type ip
```

The **Flask dashboard** is for when I want to share results with someone, or when I'm doing a review of multiple alerts and want a browser-based interface with the lookup history visible. The dark-themed UI keeps a running history of recent lookups with their threat level so you can see at a glance what you've already checked.

## What It's Found

In the first month of running this during alert triage, ThreatPulse flagged:
- Several Tor exit node IPs that had been triggering authentication alerts — confirmed C2 communication patterns in the Feodo list
- A suspicious domain in a phishing email that URLhaus had listed 3 hours earlier — faster than my previous manual workflow would have caught it
- A file hash from an EDR quarantine that MalwareBazaar identified as Emotet with a confidence of 95%

The tool isn't replacing a proper SOAR or SIEM. But for a quick first-pass IOC enrichment step, it's eliminated a lot of the manual tab-juggling from my workflow.

## Limitations

The honest assessment:

**Rate limits**: abuse.ch and OTX both have rate limits. For bulk lookups of hundreds of IOCs, you'll want to add delays between requests. The CLI doesn't currently throttle.

**No VirusTotal**: VT's free API is heavily rate-limited and requires registration. I left it out for now but it's on the roadmap.

**Coverage gaps**: No feed covers everything. An IOC being listed as CLEAN means it's not in these specific feeds — not that it's definitively safe.

## Running It

```bash
pip install -r requirements.txt

# Optional: add OTX key
export OTX_API_KEY="your_key"

python threatpulse.py lookup --ioc 185.220.101.45 --type ip

# Start the dashboard
python threatpulse.py serve
```

It's become a regular part of my alert triage workflow. If you're doing any volume of SOC work, I think you'll find it useful too.

---

*Code: [B0bTheSkull/threatpulse](https://github.com/B0bTheSkull/threatpulse)*
