#!/usr/bin/env python3
"""
ThreatPulse - Threat Intelligence Aggregator
CLI IOC lookup + web dashboard.
"""

import argparse
import json
import sys

import lookup as lookup_module
from feeds import feodo

RESET = "\033[0m"
RED = "\033[91m"
GREEN = "\033[32m"
YELLOW = "\033[33m"
CYAN = "\033[36m"
BOLD = "\033[1m"
WHITE = "\033[37m"


def banner():
    print(f"""
{CYAN}╔══════════════════════════════════════════╗{RESET}
{CYAN}║       ThreatPulse v1.0                   ║{RESET}
{CYAN}║  Threat Intelligence Aggregator          ║{RESET}
{CYAN}╚══════════════════════════════════════════╝{RESET}
""")


def print_result(result):
    ioc = result.get("ioc")
    ioc_type = result.get("type")
    threat_level = result.get("threat_level", "UNKNOWN")

    level_color = RED if threat_level == "MALICIOUS" else GREEN
    print(f"\n{BOLD}IOC:{RESET}          {ioc}")
    print(f"{BOLD}Type:{RESET}         {ioc_type}")
    print(f"{BOLD}Threat Level:{RESET} {level_color}{BOLD}{threat_level}{RESET}")
    print(f"{BOLD}Sources:{RESET}      {result.get('sources_queried', 0)} queried\n")

    for src in result.get("results", []):
        source = src.get("source", "?")
        print(f"  {CYAN}[{source}]{RESET}")

        if src.get("error"):
            print(f"    {YELLOW}Error: {src['error']}{RESET}")
        elif src.get("skipped"):
            print(f"    {WHITE}{src.get('reason', 'Skipped')}{RESET}")
        elif src.get("found"):
            print(f"    {RED}⚠ FOUND — listed as malicious{RESET}")
            for k, v in src.items():
                if k in ("source", "found", "raw") or v is None:
                    continue
                if isinstance(v, list):
                    v = ", ".join(str(i) for i in v[:5])
                print(f"    {k.replace('_', ' ').capitalize()}: {v}")
        else:
            print(f"    {GREEN}✓ Not listed{RESET}")
    print()


def cmd_lookup(args):
    banner()
    result = lookup_module.lookup(args.ioc, args.type)
    print_result(result)

    if args.output:
        with open(args.output, "w") as f:
            json.dump(result, f, indent=2)
        print(f"{CYAN}[*]{RESET} Results saved to {args.output}")


def cmd_feed(args):
    banner()
    if args.update:
        print(f"{CYAN}[*]{RESET} Refreshing Feodo Tracker blocklist...")
        try:
            # Force refresh by removing cache
            from pathlib import Path
            cache = Path(".cache_feodo.json")
            if cache.exists():
                cache.unlink()
            blocklist = feodo.get_blocklist()
            print(f"{GREEN}[✓]{RESET} Feodo blocklist updated: {len(blocklist)} entries")
        except Exception as e:
            print(f"{RED}[!]{RESET} Failed to update Feodo: {e}")

    if args.stats:
        try:
            blocklist = feodo.get_blocklist()
            malware_counts = {}
            for entry in blocklist:
                m = entry.get("malware", "unknown")
                malware_counts[m] = malware_counts.get(m, 0) + 1
            print(f"\n{BOLD}Feodo Tracker Blocklist Stats{RESET}")
            print(f"Total IPs: {len(blocklist)}")
            print("\nBy malware family:")
            for m, count in sorted(malware_counts.items(), key=lambda x: -x[1]):
                print(f"  {m}: {count}")
        except Exception as e:
            print(f"{RED}[!]{RESET} Error: {e}")


def cmd_serve(args):
    banner()
    print(f"{CYAN}[*]{RESET} Starting web dashboard on http://0.0.0.0:{args.port}")
    print(f"{CYAN}[*]{RESET} Open http://localhost:{args.port} in your browser")
    print(f"{CYAN}[*]{RESET} Press Ctrl+C to stop\n")
    import sys
    from pathlib import Path
    sys.path.insert(0, str(Path(__file__).parent))
    from dashboard.app import app
    app.run(host="0.0.0.0", port=args.port, debug=False)


def main():
    parser = argparse.ArgumentParser(
        description="ThreatPulse — Threat intelligence aggregator",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python threatpulse.py lookup --ioc 185.220.101.45 --type ip
  python threatpulse.py lookup --ioc malware.example.com --type domain
  python threatpulse.py lookup --ioc d41d8cd98f00b204e9800998ecf8427e --type hash
  python threatpulse.py feed --update
  python threatpulse.py feed --stats
  python threatpulse.py serve

Environment:
  OTX_API_KEY   AlienVault OTX API key (free at otx.alienvault.com)
        """
    )
    subparsers = parser.add_subparsers(dest="command")

    # lookup subcommand
    lookup_p = subparsers.add_parser("lookup", help="Look up an IOC")
    lookup_p.add_argument("--ioc", required=True, help="The indicator to look up")
    lookup_p.add_argument("--type", required=True, choices=["ip", "domain", "url", "hash"],
                          help="IOC type")
    lookup_p.add_argument("--output", help="Save results to JSON file")

    # feed subcommand
    feed_p = subparsers.add_parser("feed", help="Manage threat intel feeds")
    feed_p.add_argument("--update", action="store_true", help="Refresh cached feeds")
    feed_p.add_argument("--stats", action="store_true", help="Show feed statistics")

    # serve subcommand
    serve_p = subparsers.add_parser("serve", help="Start web dashboard")
    serve_p.add_argument("--port", type=int, default=5000, help="Port to listen on (default: 5000)")

    args = parser.parse_args()

    if args.command == "lookup":
        cmd_lookup(args)
    elif args.command == "feed":
        cmd_feed(args)
    elif args.command == "serve":
        cmd_serve(args)
    else:
        parser.print_help()


if __name__ == "__main__":
    main()
