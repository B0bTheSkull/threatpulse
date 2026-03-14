# ThreatPulse

> **Threat intelligence aggregator — CLI IOC lookup + web dashboard.**
> Query multiple free threat intel feeds in one shot. Supports IPs, domains, URLs, and file hashes.

![Python](https://img.shields.io/badge/python-3.8%2B-blue?style=flat-square&logo=python)
![License](https://img.shields.io/badge/license-MIT-green?style=flat-square)
![Flask](https://img.shields.io/badge/dashboard-Flask-red?style=flat-square)

---

## Data Sources

| Feed | Types | Auth Required |
|------|-------|--------------|
| **abuse.ch URLhaus** | URL, Host/IP, Domain | No |
| **abuse.ch MalwareBazaar** | File hashes (MD5/SHA1/SHA256) | No |
| **Feodo Tracker** | IP (C2 blocklist) | No |
| **AlienVault OTX** | IP, Domain, Hash | Free API key |

---

## Installation

```bash
git clone https://github.com/B0bTheSkull/threatpulse.git
cd threatpulse
pip install -r requirements.txt
```

**Optional — AlienVault OTX (free):**
```bash
# Sign up at https://otx.alienvault.com and get a free API key
export OTX_API_KEY="your_key_here"
```

---

## Usage

### CLI Lookups

```bash
# Look up a suspicious IP
python threatpulse.py lookup --ioc 185.220.101.45 --type ip

# Look up a domain
python threatpulse.py lookup --ioc malware-host.example.com --type domain

# Look up a URL
python threatpulse.py lookup --ioc "https://malicious.example.com/payload.exe" --type url

# Look up a file hash
python threatpulse.py lookup --ioc d41d8cd98f00b204e9800998ecf8427e --type hash

# Save results to JSON
python threatpulse.py lookup --ioc 185.220.101.45 --type ip --output result.json
```

### Feed Management

```bash
# Refresh cached Feodo Tracker blocklist
python threatpulse.py feed --update

# Show blocklist statistics
python threatpulse.py feed --stats
```

### Web Dashboard

```bash
python threatpulse.py serve
# Open http://localhost:5000
```

---

## Example Output

```
╔══════════════════════════════════════════╗
║       ThreatPulse v1.0                   ║
║  Threat Intelligence Aggregator          ║
╚══════════════════════════════════════════╝

IOC:          185.220.101.45
Type:         ip
Threat Level: MALICIOUS
Sources:      3 queried

  [URLhaus]
    ⚠ FOUND — listed as malicious
    Host: 185.220.101.45
    Url count: 12
    Blacklists: {'spamhaus_dbl': 'not listed', 'surbl': 'listed'}
    Recent urls: https://185.220.101.45/payload.exe, ...

  [Feodo Tracker]
    ⚠ FOUND — listed as malicious
    Ip: 185.220.101.45
    Port: 443
    Malware: Emotet
    Status: online
    Country: DE

  [OTX]
    ⚠ FOUND — listed as malicious
    Pulse count: 47
    Country: Germany
    Pulses: Emotet Campaign Q1, Tor Exit Nodes, ...
```

---

## Web Dashboard

Run `python threatpulse.py serve` and navigate to `http://localhost:5000` for a dark-themed dashboard with:
- **IOC lookup** — enter any indicator and select type
- **Recent lookups** table with threat level badges
- Color-coded results per source

---

## Roadmap

- [ ] Shodan integration
- [ ] VirusTotal API support
- [ ] Bulk IOC lookup from file
- [ ] Slack/webhook alerting on malicious findings
- [ ] MISP integration

---

## License

MIT
