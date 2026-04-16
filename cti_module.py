#!/usr/bin/env python3
"""
╔══════════════════════════════════════════════════════════════╗
║    CTI Automation Module  v1.0  —  Threat Intelligence      ║
║    AlienVault OTX + Abuse.ch → Zeek Intel Framework         ║
╚══════════════════════════════════════════════════════════════╝

Pulls live threat intelligence and feeds Zeek intel framework:
  • AlienVault OTX: Fast-flux, DGA, C2 domain pulses
  • Abuse.ch URLhaus: Active malware C2 domains
  • Abuse.ch DNSBL: Known botnet C2 IPs
  • Feodo Tracker: C2 IPs (Emotet, Dridex, TrickBot)

Usage:
  python cti_module.py --fetch --output /opt/zeek/intel/
  python cti_module.py --fetch --demo           # no real API calls
  python cti_module.py --daemon --interval 3600 # refresh every hour

  # With OTX API key (free at otx.alienvault.com):
  export OTX_API_KEY="your_key_here"
  python cti_module.py --fetch --output /opt/zeek/intel/

Output:
  zeek_intel_domains.dat  — Zeek intel format, domain indicators
  zeek_intel_ips.dat      — Zeek intel format, IP indicators
  cti_summary.json        — Machine-readable feed statistics
"""

import argparse
import json
import logging
import os
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import NamedTuple
from urllib.request import Request, urlopen
from urllib.error import URLError, HTTPError

# ──────────────────────────────────────────────────────────────
# Config
# ──────────────────────────────────────────────────────────────

FEEDS = {
    "abusech_urlhaus_domains": {
        "url": "https://urlhaus.abuse.ch/downloads/text/",
        "type": "url_list",
        "indicator_type": "Intel::DOMAIN",
        "source": "Abuse.ch URLhaus",
        "description": "Active malware distribution / C2 domains",
    },
    "feodotracker_ips": {
        "url": "https://feodotracker.abuse.ch/downloads/ipblocklist.txt",
        "type": "ip_list",
        "indicator_type": "Intel::ADDR",
        "source": "Feodo Tracker",
        "description": "Emotet / Dridex / TrickBot / QakBot C2 IPs",
    },
    "abusech_dnsbl": {
        "url": "https://dnsbl.abuse.ch/download/",
        "type": "domain_list",
        "indicator_type": "Intel::DOMAIN",
        "source": "Abuse.ch DNSBL",
        "description": "Botnet C2 domains",
    },
}

OTX_API_KEY = os.environ.get("OTX_API_KEY", "")
OTX_PULSES = [
    "fast-flux",
    "dns-tunneling",
    "c2-domain",
    "dga",
]

REQUEST_TIMEOUT = 15
MAX_INDICATORS_PER_FEED = 50_000

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s  %(levelname)-8s  %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
log = logging.getLogger("cti")


# ──────────────────────────────────────────────────────────────
# Data model
# ──────────────────────────────────────────────────────────────

class Indicator(NamedTuple):
    value: str           # domain or IP
    itype: str           # Intel::DOMAIN | Intel::ADDR
    source: str
    description: str
    confidence: int      # 0–100


# ──────────────────────────────────────────────────────────────
# Fetchers
# ──────────────────────────────────────────────────────────────

def _fetch_url(url: str, headers: dict = None) -> str:
    """Simple HTTP GET. Returns response body as text."""
    req = Request(url, headers=headers or {
        "User-Agent": "dns-purple-lab/1.0 (defensive-research)"
    })
    try:
        with urlopen(req, timeout=REQUEST_TIMEOUT) as resp:
            return resp.read().decode("utf-8", errors="replace")
    except HTTPError as e:
        log.warning("HTTP %d fetching %s", e.code, url)
        return ""
    except URLError as e:
        log.warning("Network error fetching %s: %s", url, e.reason)
        return ""


def fetch_abusech_urlhaus() -> list:
    """Parse URLhaus text feed → domain indicators."""
    log.info("Fetching Abuse.ch URLhaus...")
    raw = _fetch_url(FEEDS["abusech_urlhaus_domains"]["url"])
    indicators = []
    for line in raw.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        # Lines are full URLs like http://evil.com/malware.exe
        try:
            from urllib.parse import urlparse
            parsed = urlparse(line)
            domain = parsed.netloc.split(":")[0].lower()
            if domain and "." in domain and len(domain) > 4:
                indicators.append(Indicator(
                    value=domain,
                    itype="Intel::DOMAIN",
                    source="Abuse.ch URLhaus",
                    description="Active malware C2/distribution",
                    confidence=85,
                ))
        except Exception:
            continue
        if len(indicators) >= MAX_INDICATORS_PER_FEED:
            break
    log.info("  URLhaus: %d domain indicators", len(indicators))
    return indicators


def fetch_feodotracker() -> list:
    """Parse Feodo Tracker IP blocklist → IP indicators."""
    log.info("Fetching Feodo Tracker C2 IPs...")
    raw = _fetch_url(FEEDS["feodotracker_ips"]["url"])
    indicators = []
    for line in raw.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        # Lines: IP,PORT,MALWARE_FAMILY,FIRST_SEEN,LAST_ONLINE,STATUS
        parts = line.split(",")
        ip = parts[0].strip()
        malware = parts[2].strip() if len(parts) > 2 else "unknown"
        status = parts[5].strip() if len(parts) > 5 else "unknown"
        if ip and status.lower() == "online":
            indicators.append(Indicator(
                value=ip,
                itype="Intel::ADDR",
                source="Feodo Tracker",
                description=f"C2 IP — {malware}",
                confidence=90,
            ))
    log.info("  Feodo Tracker: %d IP indicators", len(indicators))
    return indicators


def fetch_otx_pulses(tag: str) -> list:
    """Fetch OTX pulse indicators by tag (requires API key)."""
    if not OTX_API_KEY:
        log.warning("OTX_API_KEY not set — skipping OTX feed for tag '%s'", tag)
        return []

    log.info("Fetching OTX pulses for tag: %s", tag)
    url = f"https://otx.alienvault.com/api/v1/pulses/subscribed?tags={tag}&limit=50"
    headers = {"X-OTX-API-KEY": OTX_API_KEY}
    raw = _fetch_url(url, headers=headers)
    if not raw:
        return []

    indicators = []
    try:
        data = json.loads(raw)
        for pulse in data.get("results", []):
            pulse_name = pulse.get("name", "OTX Pulse")
            for ioc in pulse.get("indicators", []):
                ioc_type = ioc.get("type", "")
                ioc_val = ioc.get("indicator", "").lower().strip()
                if not ioc_val:
                    continue
                if ioc_type in ("domain", "hostname"):
                    indicators.append(Indicator(
                        value=ioc_val,
                        itype="Intel::DOMAIN",
                        source=f"OTX/{pulse_name[:40]}",
                        description=f"OTX pulse tag={tag}",
                        confidence=75,
                    ))
                elif ioc_type == "IPv4":
                    indicators.append(Indicator(
                        value=ioc_val,
                        itype="Intel::ADDR",
                        source=f"OTX/{pulse_name[:40]}",
                        description=f"OTX pulse tag={tag}",
                        confidence=75,
                    ))
    except (json.JSONDecodeError, KeyError):
        log.warning("Failed to parse OTX response for tag: %s", tag)

    log.info("  OTX [%s]: %d indicators", tag, len(indicators))
    return indicators


def generate_demo_indicators() -> list:
    """Synthetic indicators for demo mode (no real API calls)."""
    log.info("[DEMO] Generating synthetic threat intelligence indicators")
    return [
        Indicator("fastflux-c2.example-bad.net", "Intel::DOMAIN", "Demo/Feodo", "Fast-flux C2", 90),
        Indicator("dga-xkqzrtvwpl.evil.io",       "Intel::DOMAIN", "Demo/DGA",   "DGA domain",   85),
        Indicator("185.220.101.99",                "Intel::ADDR",   "Demo/Feodo", "Emotet C2 IP", 95),
        Indicator("exfil-beacon.attacker.net",     "Intel::DOMAIN", "Demo/OTX",   "DNS exfil C2", 80),
        Indicator("tunnel.c2-hidden.com",          "Intel::DOMAIN", "Demo/OTX",   "DNS tunnel",   80),
        Indicator("10.200.0.50",                   "Intel::ADDR",   "Demo/Lab",   "Lab test IP",  70),
    ]


# ──────────────────────────────────────────────────────────────
# Deduplication + scoring
# ──────────────────────────────────────────────────────────────

def deduplicate(indicators: list) -> list:
    """Keep highest-confidence indicator per unique value."""
    best: dict = {}
    for ind in indicators:
        key = (ind.value, ind.itype)
        if key not in best or ind.confidence > best[key].confidence:
            best[key] = ind
    return list(best.values())


def filter_whitelist(indicators: list) -> list:
    """Remove known-good domains to reduce false positives."""
    whitelist = {
        "google.com", "googleapis.com", "cloudflare.com",
        "microsoft.com", "apple.com", "amazon.com",
        "github.com", "cloudfront.net", "akamai.net",
    }
    before = len(indicators)
    filtered = [i for i in indicators
                if not any(i.value.endswith(w) for w in whitelist)]
    removed = before - len(filtered)
    if removed:
        log.info("  Whitelist: removed %d known-good indicators", removed)
    return filtered


# ──────────────────────────────────────────────────────────────
# Zeek intel format writer
# ──────────────────────────────────────────────────────────────

ZEEK_INTEL_HEADER = (
    "#fields\tindicator\tindicator_type\tmeta.source\t"
    "meta.desc\tmeta.confidence\tmeta.lastseen\n"
    "#types\tstring\tenum\tstring\tstring\tcount\ttime\n"
)

def write_zeek_intel(indicators: list, output_dir: Path, itype_filter: str) -> Path:
    """
    Write Zeek intel file for given indicator type.
    Zeek format: tab-separated, #fields header required.
    """
    suffix = "domains" if "DOMAIN" in itype_filter else "ips"
    path = output_dir / f"zeek_intel_{suffix}.dat"
    now_ts = str(int(time.time()))

    selected = [i for i in indicators if i.itype == itype_filter]
    with open(path, "w") as f:
        f.write(ZEEK_INTEL_HEADER)
        for ind in selected:
            # Escape tabs/newlines in description
            desc = ind.description.replace("\t", " ").replace("\n", " ")
            src = ind.source.replace("\t", " ")
            f.write(f"{ind.value}\t{ind.itype}\t{src}\t"
                    f"{desc}\t{ind.confidence}\t{now_ts}\n")

    log.info("  Wrote %d %s indicators → %s", len(selected), suffix, path)
    return path


def write_summary(indicators: list, output_dir: Path, elapsed: float) -> Path:
    """Write JSON summary for dashboards / CI."""
    path = output_dir / "cti_summary.json"
    by_source: dict = {}
    for ind in indicators:
        by_source.setdefault(ind.source, 0)
        by_source[ind.source] += 1

    summary = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "elapsed_seconds": round(elapsed, 2),
        "total_indicators": len(indicators),
        "domains": sum(1 for i in indicators if i.itype == "Intel::DOMAIN"),
        "ips":     sum(1 for i in indicators if i.itype == "Intel::ADDR"),
        "by_source": by_source,
        "feeds_used": list(by_source.keys()),
    }
    path.write_text(json.dumps(summary, indent=2))
    log.info("  Summary → %s", path)
    return path


# ──────────────────────────────────────────────────────────────
# Zeek reload helper
# ──────────────────────────────────────────────────────────────

def reload_zeek_intel():
    """Signal Zeek to reload intel files (requires zeekctl in PATH)."""
    import subprocess
    try:
        result = subprocess.run(
            ["zeekctl", "deploy"],
            capture_output=True, text=True, timeout=30
        )
        if result.returncode == 0:
            log.info("  Zeek intel reloaded successfully")
        else:
            log.warning("  zeekctl deploy failed: %s", result.stderr[:200])
    except FileNotFoundError:
        log.info("  zeekctl not found — reload manually: zeekctl deploy")
    except subprocess.TimeoutExpired:
        log.warning("  zeekctl deploy timed out")


# ──────────────────────────────────────────────────────────────
# Elasticsearch publisher (optional)
# ──────────────────────────────────────────────────────────────

def publish_to_elasticsearch(indicators: list, es_url: str):
    """
    Bulk-index CTI indicators to Elasticsearch.
    Useful for Kibana dashboards.
    """
    try:
        import json as _json
        from urllib.request import Request as _Req, urlopen as _open

        bulk_body = ""
        for ind in indicators:
            meta = _json.dumps({"index": {"_index": "cti-indicators"}})
            doc = _json.dumps({
                "@timestamp": datetime.now(timezone.utc).isoformat(),
                "indicator": ind.value,
                "type": ind.itype,
                "source": ind.source,
                "description": ind.description,
                "confidence": ind.confidence,
            })
            bulk_body += meta + "\n" + doc + "\n"

        req = _Req(
            f"{es_url}/_bulk",
            data=bulk_body.encode(),
            headers={"Content-Type": "application/x-ndjson"},
            method="POST",
        )
        with _open(req, timeout=10) as resp:
            result = _json.loads(resp.read())
            errors = result.get("errors", False)
            log.info("  ES bulk index: errors=%s, items=%d",
                     errors, len(result.get("items", [])))
    except Exception as e:
        log.warning("  ES publish failed: %s", e)


# ──────────────────────────────────────────────────────────────
# Main runner
# ──────────────────────────────────────────────────────────────

def run_fetch(output_dir: Path, demo: bool, reload_zeek: bool,
              es_url: str = "") -> dict:
    t_start = time.monotonic()
    all_indicators = []

    if demo:
        all_indicators = generate_demo_indicators()
    else:
        # Real feeds
        all_indicators += fetch_abusech_urlhaus()
        all_indicators += fetch_feodotracker()
        for tag in OTX_PULSES:
            all_indicators += fetch_otx_pulses(tag)

    log.info("Raw indicators: %d — deduplicating...", len(all_indicators))
    all_indicators = deduplicate(all_indicators)
    all_indicators = filter_whitelist(all_indicators)
    log.info("Final indicators: %d", len(all_indicators))

    output_dir.mkdir(parents=True, exist_ok=True)
    write_zeek_intel(all_indicators, output_dir, "Intel::DOMAIN")
    write_zeek_intel(all_indicators, output_dir, "Intel::ADDR")
    elapsed = time.monotonic() - t_start
    summary = write_summary(all_indicators, output_dir, elapsed)

    if reload_zeek:
        reload_zeek_intel()

    if es_url:
        log.info("Publishing to Elasticsearch: %s", es_url)
        publish_to_elasticsearch(all_indicators, es_url)

    log.info("CTI refresh complete in %.1fs", elapsed)
    return json.loads(summary.read_text())


def run_daemon(output_dir: Path, interval: int, es_url: str):
    log.info("CTI daemon started — refresh every %ds", interval)
    while True:
        try:
            run_fetch(output_dir, demo=False, reload_zeek=True, es_url=es_url)
        except KeyboardInterrupt:
            log.info("Daemon stopped.")
            break
        except Exception as e:
            log.error("Fetch error: %s — retrying in %ds", e, interval)
        log.info("Next refresh in %ds...", interval)
        time.sleep(interval)


def main():
    ap = argparse.ArgumentParser(
        description="CTI Automation Module — OTX + Abuse.ch → Zeek Intel"
    )
    ap.add_argument("--fetch",    action="store_true", help="Run one-shot fetch")
    ap.add_argument("--daemon",   action="store_true", help="Run as daemon")
    ap.add_argument("--demo",     action="store_true", help="Use synthetic indicators")
    ap.add_argument("--output",   default="./intel",   help="Output directory")
    ap.add_argument("--interval", type=int, default=3600,
                    help="Daemon refresh interval seconds (default: 3600)")
    ap.add_argument("--reload-zeek", action="store_true",
                    help="Call zeekctl deploy after writing intel files")
    ap.add_argument("--elasticsearch", default="",
                    help="Elasticsearch URL (e.g. http://localhost:9200)")
    args = ap.parse_args()

    output_dir = Path(args.output)

    if args.daemon:
        run_daemon(output_dir, args.interval, args.elasticsearch)
    elif args.fetch or args.demo:
        summary = run_fetch(
            output_dir,
            demo=args.demo,
            reload_zeek=args.reload_zeek,
            es_url=args.elasticsearch,
        )
        print("\nCTI Summary:")
        print(json.dumps(summary, indent=2))
    else:
        ap.print_help()


if __name__ == "__main__":
    main()
