#!/usr/bin/env python3
"""
╔══════════════════════════════════════════════════════════════╗
║    C2 Profile Library  v1.0  —  Detection Fingerprints      ║
║    Public-research-based network signatures for Blue Team   ║
╚══════════════════════════════════════════════════════════════╝

PURPOSE — DETECTION ONLY:
  This module contains network-observable signatures of known C2
  frameworks, derived exclusively from public academic research,
  vendor threat reports, and open-source documentation.

  Use this to:
    • Enrich dns_anomaly_detector.py alerts with framework attribution
    • Generate targeted Sigma/Zeek detection rules
    • Understand what "normal" vs "C2" traffic looks like

  NOT included:
    • Implementation code for any C2 framework
    • Payloads, shellcode, or staging mechanisms
    • Anything that enables attack — only detection

Sources:
  • Recorded Future / CrowdStrike public threat reports
  • Zeek community analysis threads
  • Academic papers (IEEE S&P, USENIX, Black Hat whitepapers)
  • MITRE ATT&CK documented techniques

Usage:
  python c2_profiles.py --list
  python c2_profiles.py --profile merlin --sigma
  python c2_profiles.py --match --conn conn.log
  python c2_profiles.py --demo
"""

import argparse
import json
import re
import sys
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import List, Optional


# ──────────────────────────────────────────────────────────────
# C2 Profile data model
# ──────────────────────────────────────────────────────────────

@dataclass
class C2Profile:
    name: str
    family: str                   # malware family or framework name
    transport: str                # DNS | DoH | DoT | DoQ | HTTPS
    mitre_technique: str
    description: str

    # Network-observable DNS/connection signatures
    dns_query_type: List[str]     # TXT, A, CNAME, NULL
    subdomain_pattern: str        # regex describing encoded subdomains
    apex_tld_preference: List[str]# observed TLD preferences
    ttl_range: tuple              # (min_ttl, max_ttl) observed
    session_duration_sec: tuple   # (min, max) typical C2 session
    beacon_interval_sec: tuple    # (min, max) typical check-in interval

    # QUIC/TLS specific (for DoH/DoQ profiles)
    quic_history_patterns: List[str] = field(default_factory=list)
    tls_ja3_fragments: List[str]  = field(default_factory=list)
    payload_size_bytes: tuple     = (0, 0)  # typical C2 beacon payload

    # Detection guidance
    detection_notes: str = ""
    false_positive_context: str = ""
    sources: List[str] = field(default_factory=list)


# ──────────────────────────────────────────────────────────────
# Profile library — public research only
# ──────────────────────────────────────────────────────────────

PROFILES = {

    # ── Merlin C2 (open-source, well-documented) ──────────────
    "merlin": C2Profile(
        name="Merlin",
        family="Merlin C2 Framework",
        transport="DoQ",
        mitre_technique="T1071.004",
        description=(
            "Open-source C2 framework supporting HTTP/1.1, HTTP/2, HTTP/3(QUIC), "
            "DNS-over-QUIC, and DNS-over-HTTPS. Go-based agent. "
            "Documented in SANS/academic literature."
        ),
        dns_query_type=["A", "AAAA"],
        subdomain_pattern=r"^[a-f0-9]{8,32}\.[a-f0-9]{4,16}\.",
        apex_tld_preference=[".com", ".net", ".io"],
        ttl_range=(30, 120),
        session_duration_sec=(3600, 86400),   # 1h–24h (persistent session)
        beacon_interval_sec=(30, 300),
        quic_history_patterns=[
            "ISishIH",   # Most commonly observed
            "ISIsiH",    # Variant
            "ISish",     # Partial / truncated session
        ],
        tls_ja3_fragments=[
            # JA3 fragments from public Zeek community analysis
            # NOT full JA3 hashes to avoid enabling blocklist bypass
            "771,4865-4866-4867",  # TLS 1.3 Go default cipher suite order
        ],
        payload_size_bytes=(200, 500),
        detection_notes=(
            "Key signature: QUIC session on UDP/853 lasting >1h. "
            "Zeek history starts with 'ISi' — legitimate QUIC starts 'II'. "
            "Low resp/orig byte ratio (0.2–0.4) typical of C2 waiting for commands. "
            "Beacon interval is configurable — look for uniform inter-packet timing."
        ),
        false_positive_context="Long-lived QUIC video streams (different port/payload profile).",
        sources=[
            "https://github.com/Ne0nd0g/merlin (public docs)",
            "Zeek community analysis threads",
            "SANS SEC599 course materials",
        ],
    ),

    # ── DNS Exfiltration (generic pattern) ───────────────────
    "dns_exfil_generic": C2Profile(
        name="DNS Exfiltration (Generic)",
        family="Covert Channel",
        transport="DNS",
        mitre_technique="T1048.003",
        description=(
            "Generic slow-drip DNS exfiltration pattern observed across "
            "multiple malware families (DNScat2, custom tools). "
            "Data encoded in subdomain labels."
        ),
        dns_query_type=["A", "TXT", "CNAME", "NULL"],
        subdomain_pattern=r"^[a-z2-7]{30,63}\.",   # Base32 encoded
        apex_tld_preference=[".com", ".net", ".info", ".biz"],
        ttl_range=(0, 30),
        session_duration_sec=(300, 86400 * 7),     # Minutes to weeks
        beacon_interval_sec=(20, 300),
        payload_size_bytes=(15, 50),               # Per query: ~30B
        detection_notes=(
            "Key signatures: Shannon entropy > 3.8 on subdomain; "
            "unique subdomain ratio > 80% per apex; "
            "consistent low-frequency queries over long time window. "
            "TXT query type strongly preferred by DNScat2."
        ),
        false_positive_context=(
            "CDN health checks (different frequency profile). "
            "XMPP over DNS (known service, specific apex)."
        ),
        sources=[
            "dnsdmpster.com public research",
            "Academic: 'Detecting DNS Tunneling' (Homem et al.)",
            "Zscaler ThreatLabz blog posts",
        ],
    ),

    # ── Fast Flux (DarkCloud / Sandiflux) ────────────────────
    "fastflux_darkcloud": C2Profile(
        name="Fast Flux (DarkCloud/Sandiflux pattern)",
        family="Fast Flux Infrastructure",
        transport="DNS",
        mitre_technique="T1568.001",
        description=(
            "Double-flux botnet infrastructure. Both A records AND NS records "
            "rotate rapidly. IP pool: >94% residential/ISP addresses. "
            "Observed in DarkCloud and Sandiflux botnets."
        ),
        dns_query_type=["A", "NS"],
        subdomain_pattern=r"^[a-z]{5,12}\.",
        apex_tld_preference=[".ru", ".cn", ".pw", ".top", ".xyz"],
        ttl_range=(3, 30),                         # Extremely low TTL
        session_duration_sec=(0, 30),              # Connections are short
        beacon_interval_sec=(60, 600),
        payload_size_bytes=(0, 0),
        detection_notes=(
            "Key signatures: TTL < 60s; NS records also rotating; "
            "ASN diversity across A record IPs (residential CGNAT ranges); "
            "domain age < 30 days (fresh registrations). "
            "IP geolocation shows mix of residential ISPs globally."
        ),
        false_positive_context="Legitimate CDNs with low TTL (different: stable NS, known apex).",
        sources=[
            "CrowdStrike 'Fast Flux 101' whitepaper",
            "Trend Micro DarkCloud analysis (2022)",
            "RIPE NCC BGP + DNS routing analysis reports",
        ],
    ),

    # ── DGA (Conficker/Mirai style) ───────────────────────────
    "dga_conficker_style": C2Profile(
        name="DGA Domains (Conficker/Mirai pattern)",
        family="Domain Generation Algorithm",
        transport="DNS",
        mitre_technique="T1568.002",
        description=(
            "Pseudo-random domain generation using seeded algorithm. "
            "Produces consonant-heavy, high-entropy, low-vowel domains. "
            "Bot tries thousands daily; only attacker-registered ones resolve."
        ),
        dns_query_type=["A"],
        subdomain_pattern=r"",   # DGA hits apex directly, no subdomain
        apex_tld_preference=[".com", ".net", ".org", ".biz"],
        ttl_range=(300, 3600),
        session_duration_sec=(5, 60),
        beacon_interval_sec=(60, 3600),
        payload_size_bytes=(0, 200),
        detection_notes=(
            "Key signatures: domain consonant ratio > 65%; "
            "Shannon entropy of domain label > 3.5; "
            "high NXDOMAIN rate from same source IP (trying unregistered DGA domains); "
            "domain age very recent if successfully resolved."
        ),
        false_positive_context="Randomly generated test domains by developers (isolated source IP).",
        sources=[
            "Academic: 'From Throw-Away Traffic to Bots' (Kührer et al.)",
            "USENIX Security DGA corpus analysis",
            "Mitre ATT&CK T1568.002 documented examples",
        ],
    ),

    # ── Cobalt Strike DNS Beacon ──────────────────────────────
    "cobaltstrike_dns": C2Profile(
        name="Cobalt Strike DNS Beacon",
        family="Cobalt Strike",
        transport="DNS",
        mitre_technique="T1071.004",
        description=(
            "Cobalt Strike's DNS beacon mode uses A, AAAA, or TXT record types "
            "for C2 communication. Documented extensively in public threat reports. "
            "Signatures derived from CrowdStrike/Recorded Future public research."
        ),
        dns_query_type=["A", "AAAA", "TXT"],
        # Public research shows typical CS DNS beacon label structure
        subdomain_pattern=r"^[a-f0-9]{8}\.[a-f0-9]{4,8}\.",
        apex_tld_preference=[".com", ".net"],
        ttl_range=(1, 10),                          # Very low TTL observed
        session_duration_sec=(60, 3600),
        beacon_interval_sec=(60, 600),              # Default: 60s ± jitter
        quic_history_patterns=[],
        tls_ja3_fragments=[],
        payload_size_bytes=(0, 48),                 # A record: only 4B IP response
        detection_notes=(
            "Key signatures: very low TTL (1–10s); "
            "mixed A/TXT queries to same apex; "
            "fixed beacon interval ± small jitter; "
            "source IP makes queries at consistent rate regardless of user activity. "
            "Often uses 'malleable C2 profiles' — apex domain may look legitimate."
        ),
        false_positive_context=(
            "Legitimate monitoring tools with low-TTL health checks. "
            "Verify with endpoint telemetry — beacon source should be suspicious process."
        ),
        sources=[
            "CrowdStrike 'Malleable C2 Profiles' public research",
            "Recorded Future 'Cobalt Strike' threat report (2022)",
            "Rapid7 threat intelligence blog",
            "VirusTotal graph public analyses",
        ],
    ),

}


# ──────────────────────────────────────────────────────────────
# Sigma rule generator
# ──────────────────────────────────────────────────────────────

def generate_sigma_rule(profile: C2Profile) -> str:
    rule_id = profile.name.lower().replace(" ", "_").replace("/", "_")
    ttl_cond = f"id.resp_ttl|lt: {profile.ttl_range[1] + 1}" if profile.ttl_range[1] < 60 else ""
    duration_cond = ""
    if profile.session_duration_sec[0] > 0:
        duration_cond = f"duration|gt: {profile.session_duration_sec[0]}"

    history_cond = ""
    if profile.quic_history_patterns:
        history_cond = "\n  ".join(
            f"history|startswith: '{p}'" for p in profile.quic_history_patterns
        )

    return f"""title: {profile.name} — {profile.transport} C2 Detection
id: auto-generated-{rule_id}
status: experimental
description: |
  {profile.description[:200]}
  Source: {', '.join(profile.sources[:2])}
logsource:
  product: zeek
  service: {"conn" if profile.transport in ("DoQ","DoH") else "dns"}
detection:
  selection:
    {"proto: udp" if profile.transport == "DoQ" else "proto: tcp" if profile.transport in ("DoH","HTTPS") else ""}
    {duration_cond}
    {history_cond}
  condition: selection
falsepositives:
  - {profile.false_positive_context}
level: {"high" if profile.mitre_technique == "T1071.004" else "medium"}
tags:
  - attack.{profile.mitre_technique.lower().replace(".", "_")}
references:
{chr(10).join(f"  - {s}" for s in profile.sources)}
"""


# ──────────────────────────────────────────────────────────────
# Profile matching against Zeek conn.log
# ──────────────────────────────────────────────────────────────

def match_profiles_to_conn(conn_log_path: str) -> List[dict]:
    """
    Check a Zeek conn.log for indicators matching known C2 profiles.
    Returns list of match results.
    """
    try:
        lines = Path(conn_log_path).read_text(errors="replace").splitlines()
    except FileNotFoundError:
        print(f"[ERROR] File not found: {conn_log_path}")
        return []

    matches = []

    for line in lines:
        if line.startswith("#") or not line.strip():
            continue
        # Try JSON
        try:
            r = json.loads(line)
        except json.JSONDecodeError:
            continue

        duration = float(r.get("duration", 0) or 0)
        history = r.get("history", "")
        dst_port = str(r.get("id.resp_p", ""))
        proto = r.get("proto", "")
        src = r.get("id.orig_h", "")
        dst = r.get("id.resp_h", "")

        for pname, prof in PROFILES.items():
            hit_reasons = []

            # Duration check
            if prof.session_duration_sec[0] > 0 and duration >= prof.session_duration_sec[0]:
                hit_reasons.append(f"long_session({duration/3600:.1f}h)")

            # QUIC history pattern
            for pat in prof.quic_history_patterns:
                if history.startswith(pat):
                    hit_reasons.append(f"quic_history({history}→{pat})")
                    break

            if hit_reasons:
                matches.append({
                    "src": src,
                    "dst": f"{dst}:{dst_port}",
                    "profile": prof.name,
                    "framework": prof.family,
                    "transport": prof.transport,
                    "mitre": prof.mitre_technique,
                    "reasons": hit_reasons,
                    "detection_notes": prof.detection_notes[:200],
                })

    return matches


# ──────────────────────────────────────────────────────────────
# CLI
# ──────────────────────────────────────────────────────────────

def main():
    ap = argparse.ArgumentParser(
        description="C2 Profile Library — detection fingerprints from public research"
    )
    ap.add_argument("--list",    action="store_true", help="List all profiles")
    ap.add_argument("--profile", metavar="NAME",      help="Show profile details")
    ap.add_argument("--sigma",   action="store_true", help="Generate Sigma rule")
    ap.add_argument("--match",   action="store_true", help="Match profiles against conn.log")
    ap.add_argument("--conn",    metavar="FILE",       help="Zeek conn.log to match")
    ap.add_argument("--demo",    action="store_true",  help="Demo output")
    ap.add_argument("--json",    metavar="FILE",        help="Write profile library to JSON")
    args = ap.parse_args()

    if args.list:
        print("\nAvailable C2 Detection Profiles:\n")
        for name, prof in PROFILES.items():
            print(f"  {name:<30} {prof.transport:<8} MITRE: {prof.mitre_technique}  — {prof.family}")
        print(f"\n  Total: {len(PROFILES)} profiles")
        return

    if args.profile:
        name = args.profile.lower()
        if name not in PROFILES:
            print(f"[ERROR] Profile '{name}' not found. Use --list to see available profiles.")
            sys.exit(1)
        prof = PROFILES[name]
        if args.sigma:
            print(generate_sigma_rule(prof))
        else:
            print(json.dumps(asdict(prof), indent=2))
        return

    if args.match and args.conn:
        matches = match_profiles_to_conn(args.conn)
        if not matches:
            print("[OK] No C2 profile matches found in conn.log")
        else:
            print(f"\n[!] {len(matches)} C2 profile match(es):\n")
            for m in matches:
                print(f"  Profile   : {m['profile']} ({m['framework']})")
                print(f"  Transport : {m['transport']}  MITRE: {m['mitre']}")
                print(f"  Connection: {m['src']} → {m['dst']}")
                print(f"  Reasons   : {' | '.join(m['reasons'])}")
                print(f"  Note      : {m['detection_notes']}")
                print()
        return

    if args.json:
        out = {name: asdict(prof) for name, prof in PROFILES.items()}
        Path(args.json).write_text(json.dumps(out, indent=2))
        print(f"[+] Profile library written to {args.json}")
        return

    if args.demo:
        print("\n=== C2 Profile Library Demo ===\n")
        print("Available profiles:")
        for name, prof in PROFILES.items():
            print(f"  • {prof.name} ({prof.transport}) — {prof.mitre_technique}")

        print("\n--- Merlin Sigma Rule ---\n")
        print(generate_sigma_rule(PROFILES["merlin"]))

        print("\n--- Cobalt Strike DNS detection notes ---\n")
        cs = PROFILES["cobaltstrike_dns"]
        print(f"Transport      : {cs.transport}")
        print(f"Session length : {cs.session_duration_sec[0]}–{cs.session_duration_sec[1]}s")
        print(f"Beacon interval: {cs.beacon_interval_sec[0]}–{cs.beacon_interval_sec[1]}s")
        print(f"TTL range      : {cs.ttl_range[0]}–{cs.ttl_range[1]}s")
        print(f"Detection notes:")
        for line in cs.detection_notes.split(". "):
            if line.strip():
                print(f"  • {line.strip()}")
        return

    ap.print_help()


if __name__ == "__main__":
    main()
