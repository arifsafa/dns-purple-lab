#!/usr/bin/env python3
"""
╔══════════════════════════════════════════════════════════════╗
║         DNS Anomaly Detector  v2.0  — Blue Team             ║
║         ML-powered DNS exfiltration & C2 detection          ║
╚══════════════════════════════════════════════════════════════╝

Detects:
  • DNS exfiltration via entropy & subdomain analysis
  • Slow-drip covert channels (behavioral baseline)
  • DGA (Domain Generation Algorithm) domains
  • Fast-flux patterns
  • DNS tunneling (high query rate to single apex)

Input sources:
  --zeek    Zeek dns.log  (JSON or TSV)
  --pcap    PCAP file     (requires scapy)
  --demo    Synthetic data (no input needed)

Output:
  Console alerts + optional --json / --csv report

Usage:
  python dns_anomaly_detector.py --demo
  python dns_anomaly_detector.py --zeek dns.log
  python dns_anomaly_detector.py --zeek dns.log --json report.json
  python dns_anomaly_detector.py --pcap capture.pcap --csv alerts.csv

Requirements:
  pip install dnspython scapy scikit-learn numpy

Legal:
  Defensive research and authorized testing only.
"""

import argparse
import base64
import csv
import json
import math
import re
import sys
from collections import Counter, defaultdict
from dataclasses import asdict, dataclass, field
from datetime import datetime, timedelta
from pathlib import Path
from typing import List, Optional, Tuple

try:
    import numpy as np
    from sklearn.ensemble import IsolationForest
    ML_AVAILABLE = True
except ImportError:
    ML_AVAILABLE = False

# ──────────────────────────────────────────────────────────────
# Config / Thresholds
# ──────────────────────────────────────────────────────────────

CFG = {
    "entropy_threshold":       3.8,   # Shannon entropy — Base32/64 encoded text spikes here
    "subdomain_len_threshold": 40,    # Characters in subdomain label
    "label_depth_threshold":   5,     # Dot count in FQDN
    "hex_ratio_threshold":     0.50,  # Hex-encoded payloads have dense [0-9a-f]
    "digit_ratio_threshold":   0.40,  # Numeric-heavy: possible encoding
    "query_rate_window_min":   60,    # Rolling window (minutes) for rate analysis
    "slow_drip_min_queries":   15,    # Minimum queries before slow-drip check
    "slow_drip_unique_ratio":  0.80,  # % unique subdomains to same apex = exfil
    "tunnel_qpm_threshold":    30,    # Queries/min to same apex = tunneling
    "dga_consonant_ratio":     0.65,  # DGA domains often lack vowels
    "whitelist_apexes": {             # Never alert on these
        "google.com", "googleapis.com", "gstatic.com",
        "microsoft.com", "windowsupdate.com", "akamaitechnologies.com",
        "cloudflare.com", "amazonaws.com", "fastly.net",
        "office365.com", "outlook.com", "live.com",
        "apple.com", "icloud.com", "stackoverflow.com", "stackexchange.com",
    },
}

# ──────────────────────────────────────────────────────────────
# Data models
# ──────────────────────────────────────────────────────────────

@dataclass
class DNSRecord:
    timestamp: str
    src_ip: str
    query: str
    qtype: str = "A"
    rcode: str = ""
    answer: str = ""
    ttl: int = 0

@dataclass
class Alert:
    severity: str          # CRITICAL / HIGH / MEDIUM / LOW
    category: str
    src_ip: str
    query: str
    timestamp: str
    score: float
    reasons: List[str]
    evidence: dict = field(default_factory=dict)

    def color_severity(self) -> str:
        colors = {"CRITICAL": "\033[91m", "HIGH": "\033[91m",
                  "MEDIUM": "\033[93m", "LOW": "\033[94m"}
        reset = "\033[0m"
        return f"{colors.get(self.severity, '')}{self.severity}{reset}"


# ──────────────────────────────────────────────────────────────
# Feature extraction
# ──────────────────────────────────────────────────────────────

def shannon_entropy(s: str) -> float:
    if not s:
        return 0.0
    c = Counter(s.lower())
    t = len(s)
    return -sum((n/t) * math.log2(n/t) for n in c.values())

def extract_parts(fqdn: str) -> Tuple[str, str]:
    """Returns (subdomain, apex)."""
    parts = fqdn.rstrip(".").lower().split(".")
    if len(parts) <= 2:
        return "", ".".join(parts)
    return ".".join(parts[:-2]), ".".join(parts[-2:])

def is_whitelisted(apex: str) -> bool:
    return apex in CFG["whitelist_apexes"]

def vowel_ratio(s: str) -> float:
    if not s:
        return 0.5
    vowels = sum(1 for c in s.lower() if c in "aeiou")
    letters = sum(1 for c in s if c.isalpha())
    return vowels / letters if letters else 0.0

def looks_like_dga(apex: str) -> Tuple[bool, str]:
    """Heuristics for DGA domains."""
    domain = apex.split(".")[0]
    if len(domain) < 8:
        return False, ""
    vr = vowel_ratio(domain)
    digit_ratio = sum(c.isdigit() for c in domain) / len(domain)
    entropy = shannon_entropy(domain)
    reasons = []
    if 1 - vr > CFG["dga_consonant_ratio"]:
        reasons.append(f"low_vowel_ratio({vr:.2f})")
    if digit_ratio > 0.30:
        reasons.append(f"high_digit_ratio({digit_ratio:.2f})")
    if entropy > 3.5 and len(domain) > 12:
        reasons.append(f"high_entropy({entropy:.2f})")
    return bool(reasons), ",".join(reasons)

def extract_features(record: DNSRecord) -> dict:
    sub, apex = extract_parts(record.query)
    ent = shannon_entropy(sub) if sub else 0.0
    sub_len = len(sub)
    labels = record.query.rstrip(".").split(".")
    label_count = len(labels)
    longest_label = max((len(l) for l in labels), default=0)
    digit_ratio = sum(c.isdigit() for c in sub) / len(sub) if sub else 0.0
    hex_chars = set("0123456789abcdef")
    hex_ratio = sum(c in hex_chars for c in sub.lower()) / len(sub) if sub else 0.0
    return {
        "entropy": ent,
        "subdomain_length": sub_len,
        "label_count": label_count,
        "longest_label": longest_label,
        "digit_ratio": digit_ratio,
        "hex_ratio": hex_ratio,
        "vowel_ratio": vowel_ratio(sub) if sub else 0.5,
        "sub": sub,
        "apex": apex,
    }


# ──────────────────────────────────────────────────────────────
# Per-query detection
# ──────────────────────────────────────────────────────────────

def analyze_query(record: DNSRecord) -> Optional[Alert]:
    if not record.query:
        return None
    feat = extract_features(record)
    if is_whitelisted(feat["apex"]):
        return None

    reasons = []
    score = 0.0

    if feat["entropy"] > CFG["entropy_threshold"]:
        reasons.append(f"high_entropy({feat['entropy']:.3f})")
        score += 40

    if feat["subdomain_length"] > CFG["subdomain_len_threshold"]:
        reasons.append(f"long_subdomain({feat['subdomain_length']}chars)")
        score += 25

    if feat["label_count"] > CFG["label_depth_threshold"]:
        reasons.append(f"deep_labels({feat['label_count']})")
        score += 15

    if feat["hex_ratio"] > CFG["hex_ratio_threshold"] and feat["subdomain_length"] > 20:
        reasons.append(f"hex_encoded({feat['hex_ratio']:.0%})")
        score += 20

    if feat["digit_ratio"] > CFG["digit_ratio_threshold"] and feat["subdomain_length"] > 15:
        reasons.append(f"digit_heavy({feat['digit_ratio']:.0%})")
        score += 10

    dga, dga_reason = looks_like_dga(feat["apex"])
    if dga:
        reasons.append(f"dga_apex({dga_reason})")
        score += 30

    if not reasons:
        return None

    severity = "CRITICAL" if score >= 70 else "HIGH" if score >= 50 else "MEDIUM"
    return Alert(
        severity=severity,
        category="dns_exfiltration_candidate",
        src_ip=record.src_ip,
        query=record.query,
        timestamp=record.timestamp,
        score=min(score, 100.0),
        reasons=reasons,
        evidence=feat,
    )


# ──────────────────────────────────────────────────────────────
# Behavioral / time-series analysis
# ──────────────────────────────────────────────────────────────

class BehavioralEngine:
    """
    Tracks per-(src_ip, apex) query history.
    Detects slow-drip exfil, DNS tunneling, and fast-flux patterns.
    """

    def __init__(self):
        self.log: dict = defaultdict(list)   # (src, apex) → [(ts, subdomain, ttl)]
        self.ttl_log: dict = defaultdict(list) # apex → [ttl values]

    def ingest(self, record: DNSRecord):
        sub, apex = extract_parts(record.query)
        try:
            ts = datetime.fromisoformat(record.timestamp)
        except ValueError:
            ts = datetime.utcnow()
        self.log[(record.src_ip, apex)].append((ts, sub))
        if record.ttl > 0:
            self.ttl_log[apex].append(record.ttl)

    def run(self) -> List[Alert]:
        alerts = []
        alerts.extend(self._check_slow_drip())
        alerts.extend(self._check_tunneling())
        alerts.extend(self._check_fast_flux())
        return alerts

    def _check_slow_drip(self) -> List[Alert]:
        alerts = []
        for (src, apex), entries in self.log.items():
            if is_whitelisted(apex):
                continue
            subs = [s for _, s in entries if s]
            if len(subs) < CFG["slow_drip_min_queries"]:
                continue
            unique_ratio = len(set(subs)) / len(subs)
            if unique_ratio < CFG["slow_drip_unique_ratio"]:
                continue

            # Check for consistent, low-frequency pattern (not burst)
            if len(entries) < 2:
                continue
            times = sorted(t for t, _ in entries)
            intervals = [(times[i+1] - times[i]).total_seconds()
                         for i in range(len(times)-1)]
            avg_interval = sum(intervals) / len(intervals) if intervals else 0
            # Slow drip: long average interval + high unique subdomain ratio
            if avg_interval > 20 and unique_ratio > CFG["slow_drip_unique_ratio"]:
                score = min(30 + int(unique_ratio * 60), 100)
                alerts.append(Alert(
                    severity="HIGH",
                    category="slow_drip_exfiltration",
                    src_ip=src,
                    query=f"*.{apex}",
                    timestamp=times[-1].isoformat(),
                    score=float(score),
                    reasons=[
                        f"total_queries({len(subs)})",
                        f"unique_subdomain_ratio({unique_ratio:.0%})",
                        f"avg_interval({avg_interval:.0f}s)",
                    ],
                    evidence={
                        "apex": apex,
                        "query_count": len(subs),
                        "unique_subdomains": len(set(subs)),
                        "unique_ratio": round(unique_ratio, 3),
                        "avg_interval_seconds": round(avg_interval, 1),
                        "sample_subdomains": list(set(subs))[:3],
                    },
                ))
        return alerts

    def _check_tunneling(self) -> List[Alert]:
        """High query rate to single apex = DNS tunnel."""
        alerts = []
        window = timedelta(minutes=CFG["query_rate_window_min"])
        for (src, apex), entries in self.log.items():
            if is_whitelisted(apex):
                continue
            if len(entries) < 10:
                continue
            now = max(t for t, _ in entries)
            recent = [(t, s) for t, s in entries if t > now - window]
            qpm = len(recent) / CFG["query_rate_window_min"]
            if qpm < CFG["tunnel_qpm_threshold"]:
                continue
            alerts.append(Alert(
                severity="HIGH",
                category="dns_tunnel_high_rate",
                src_ip=src,
                query=f"*.{apex}",
                timestamp=now.isoformat(),
                score=min(50 + qpm, 100),
                reasons=[f"queries_per_min({qpm:.1f})", f"window({CFG['query_rate_window_min']}min)"],
                evidence={"qpm": round(qpm, 1), "window_count": len(recent)},
            ))
        return alerts

    def _check_fast_flux(self) -> List[Alert]:
        """Rapidly changing TTLs on same apex = fast-flux infrastructure."""
        alerts = []
        for apex, ttls in self.ttl_log.items():
            if is_whitelisted(apex) or len(ttls) < 5:
                continue
            if all(t == ttls[0] for t in ttls):
                continue
            min_ttl = min(ttls)
            max_ttl = max(ttls)
            variance = max_ttl - min_ttl
            if min_ttl < 60 and variance > 300:
                alerts.append(Alert(
                    severity="MEDIUM",
                    category="fast_flux_indicator",
                    src_ip="",
                    query=apex,
                    timestamp=datetime.utcnow().isoformat(),
                    score=60.0,
                    reasons=[f"min_ttl({min_ttl}s)", f"ttl_variance({variance}s)"],
                    evidence={"min_ttl": min_ttl, "max_ttl": max_ttl,
                              "variance": variance, "samples": len(ttls)},
                ))
        return alerts


# ──────────────────────────────────────────────────────────────
# ML anomaly detection (Isolation Forest)
# ──────────────────────────────────────────────────────────────

def run_isolation_forest(records: List[DNSRecord]) -> List[Alert]:
    """
    Unsupervised anomaly detection over query feature vectors.
    Flags statistical outliers even if heuristics missed them.
    Requires scikit-learn.
    """
    if not ML_AVAILABLE:
        return []
    if len(records) < 30:
        return []

    feature_vecs = []
    for r in records:
        feat = extract_features(r)
        feature_vecs.append([
            feat["entropy"],
            feat["subdomain_length"] / 100,
            feat["label_count"] / 10,
            feat["digit_ratio"],
            feat["hex_ratio"],
            1 - feat["vowel_ratio"],
        ])

    X = np.array(feature_vecs)
    clf = IsolationForest(contamination=0.05, random_state=42, n_estimators=100)
    preds = clf.fit_predict(X)
    scores = clf.score_samples(X)

    alerts = []
    for i, (pred, score) in enumerate(zip(preds, scores)):
        if pred == -1:  # anomaly
            r = records[i]
            feat = extract_features(r)
            if is_whitelisted(feat["apex"]):
                continue
            # Normalize isolation score to 0-100 anomaly score
            anomaly_score = max(0, min(100, (-score + 0.5) * 200))
            alerts.append(Alert(
                severity="MEDIUM",
                category="ml_statistical_anomaly",
                src_ip=r.src_ip,
                query=r.query,
                timestamp=r.timestamp,
                score=round(anomaly_score, 1),
                reasons=[f"isolation_forest_outlier(score={score:.4f})"],
                evidence={
                    "entropy": feat["entropy"],
                    "subdomain_length": feat["subdomain_length"],
                    "label_count": feat["label_count"],
                    "hex_ratio": feat["hex_ratio"],
                },
            ))
    return alerts


# ──────────────────────────────────────────────────────────────
# Parsers
# ──────────────────────────────────────────────────────────────

def parse_zeek_dns(path: str) -> List[DNSRecord]:
    records = []
    try:
        lines = Path(path).read_text(errors="replace").splitlines()
    except FileNotFoundError:
        print(f"[ERROR] File not found: {path}", file=sys.stderr)
        return records

    # Detect JSON
    if lines and lines[0].strip().startswith("{"):
        for line in lines:
            line = line.strip()
            if not line:
                continue
            try:
                d = json.loads(line)
                q = d.get("query", "")
                if not q or q == "-":
                    continue
                records.append(DNSRecord(
                    timestamp=str(d.get("ts", "")),
                    src_ip=str(d.get("id.orig_h", "")),
                    query=q,
                    qtype=str(d.get("qtype_name", "A")),
                    rcode=str(d.get("rcode_name", "")),
                    ttl=int(d["TTLs"][0]) if d.get("TTLs") else 0,
                ))
            except (json.JSONDecodeError, KeyError, TypeError, ValueError):
                continue
        return records

    # TSV
    headers = []
    for line in lines:
        if line.startswith("#fields"):
            headers = line.split("\t")[1:]
            continue
        if line.startswith("#"):
            continue
        parts = line.split("\t")
        if not headers or len(parts) < len(headers):
            continue
        row = dict(zip(headers, parts))
        q = row.get("query", "-")
        if not q or q == "-":
            continue
        ttl = 0
        try:
            ttl_raw = row.get("TTLs", "0").split(",")[0]
            ttl = int(float(ttl_raw)) if ttl_raw and ttl_raw != "-" else 0
        except (ValueError, AttributeError):
            pass
        records.append(DNSRecord(
            timestamp=row.get("ts", ""),
            src_ip=row.get("id.orig_h", ""),
            query=q,
            qtype=row.get("qtype_name", "A"),
            rcode=row.get("rcode_name", ""),
            ttl=ttl,
        ))
    return records


def parse_pcap(path: str) -> List[DNSRecord]:
    try:
        from scapy.all import rdpcap, DNS, DNSQR, IP
    except ImportError:
        print("[ERROR] scapy not installed: pip install scapy", file=sys.stderr)
        return []
    records = []
    try:
        pkts = rdpcap(path)
    except Exception as e:
        print(f"[ERROR] Cannot read pcap: {e}", file=sys.stderr)
        return []
    for pkt in pkts:
        if not (pkt.haslayer(DNS) and pkt.haslayer(DNSQR)):
            continue
        if pkt[DNS].qr != 0:  # queries only
            continue
        src = pkt[IP].src if pkt.haslayer(IP) else ""
        qname = pkt[DNSQR].qname.decode(errors="replace").rstrip(".")
        if not qname:
            continue
        records.append(DNSRecord(
            timestamp=datetime.utcfromtimestamp(float(pkt.time)).isoformat(),
            src_ip=src,
            query=qname,
            qtype=str(pkt[DNSQR].qtype),
        ))
    return records


def generate_demo_records() -> List[DNSRecord]:
    """Rich synthetic dataset: benign + multiple attack patterns."""
    now = datetime.utcnow()
    records = []

    # ── Benign traffic ───────────────────────────────────────
    benign = [
        "google.com", "api.github.com", "login.microsoftonline.com",
        "cdn.cloudflare.com", "update.apple.com", "www.stackoverflow.com",
        "fonts.googleapis.com", "s3.amazonaws.com",
    ]
    for i, d in enumerate(benign * 8):
        records.append(DNSRecord(
            timestamp=(now + timedelta(seconds=i * 7)).isoformat(),
            src_ip="10.0.0.5",
            query=d, qtype="A", rcode="NOERROR", ttl=300
        ))

    # ── Slow-drip exfiltration ───────────────────────────────
    payload = b"CORP_DB_DUMP:employee_id,salary,ssn,card_number"
    chunks = [payload[i:i+20] for i in range(0, len(payload), 20)]
    for i, chunk in enumerate(chunks):
        enc = base64.b32encode(chunk).decode().rstrip("=").lower()
        records.append(DNSRecord(
            timestamp=(now + timedelta(seconds=i * 45)).isoformat(),
            src_ip="10.0.0.23",  # compromised workstation
            query=f"{enc}.c2.evil-domain.net",
            qtype="TXT", rcode="NXDOMAIN", ttl=0
        ))

    # ── High-entropy one-off queries ─────────────────────────
    hq = [
        "MFRA2YTKOJQWY2LTEB3WC3DMEBHGKY3PNVSSA.attacker.io",
        "aHR0cHM6Ly9zZWNyZXQuc2VydmVyLmNvbS9sZWFr.c2.io",
        "6b616d696e73747261766572736b69793130313031.x.io",
    ]
    for h in hq:
        records.append(DNSRecord(
            timestamp=now.isoformat(),
            src_ip="10.0.0.42",
            query=h, qtype="A", rcode="NXDOMAIN", ttl=0
        ))

    # ── DGA-looking domains ──────────────────────────────────
    dga_domains = [
        "xkqzrtvwplmnsb.com", "hfgjklwxzqvb.net",
        "mznbsxrtvplqw.org", "wkqzxbfmplnvr.io",
    ]
    for i, d in enumerate(dga_domains):
        records.append(DNSRecord(
            timestamp=(now + timedelta(seconds=i * 3)).isoformat(),
            src_ip="10.0.0.99",
            query=d, qtype="A", rcode="NXDOMAIN", ttl=5
        ))

    # ── Fast-flux (inconsistent TTLs) ───────────────────────
    for i in range(8):
        records.append(DNSRecord(
            timestamp=(now + timedelta(seconds=i * 60)).isoformat(),
            src_ip="10.0.0.50",
            query="cdn.fastflux-domain.ru",
            qtype="A", rcode="NOERROR", ttl=[5, 10, 5, 8, 5, 12, 5, 7][i]
        ))

    return records


# ──────────────────────────────────────────────────────────────
# Reporting
# ──────────────────────────────────────────────────────────────

SEV_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}

def print_report(alerts: List[Alert], total_queries: int):
    print()
    print("╔══════════════════════════════════════════════════════╗")
    print("║          DNS Anomaly Detector — Report               ║")
    print("╚══════════════════════════════════════════════════════╝")
    print(f"  Queries analyzed : {total_queries}")
    print(f"  Total alerts     : {len(alerts)}")
    critical = sum(1 for a in alerts if a.severity == "CRITICAL")
    high     = sum(1 for a in alerts if a.severity == "HIGH")
    medium   = sum(1 for a in alerts if a.severity == "MEDIUM")
    print(f"  CRITICAL: {critical}  HIGH: {high}  MEDIUM: {medium}")
    print()

    sorted_alerts = sorted(alerts, key=lambda a: SEV_ORDER.get(a.severity, 9))
    for i, a in enumerate(sorted_alerts, 1):
        bar = "█" * int(a.score / 10) + "░" * (10 - int(a.score / 10))
        print(f"  ── Alert #{i} {'─'*40}")
        print(f"  [{bar}] {a.score:.0f}/100  {a.color_severity()}")
        print(f"  Category  : {a.category}")
        print(f"  Source IP : {a.src_ip or '(behavioral)'}")
        print(f"  Query     : {a.query[:80]}")
        print(f"  Time      : {a.timestamp}")
        print(f"  Reasons   : {' | '.join(a.reasons)}")
        if a.evidence:
            ev_str = json.dumps({k: v for k, v in a.evidence.items()
                                  if k not in ("sub", "apex")}, indent=4)
            for line in ev_str.splitlines():
                print(f"             {line}")
        print()

    print("══════════════════════════════════════════════════════")


def write_json(alerts: List[Alert], path: str):
    data = [asdict(a) for a in alerts]
    Path(path).write_text(json.dumps(data, indent=2))
    print(f"[+] JSON report written: {path}")


def write_csv(alerts: List[Alert], path: str):
    if not alerts:
        return
    fields = ["severity", "category", "src_ip", "query", "timestamp", "score", "reasons"]
    with open(path, "w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=fields)
        w.writeheader()
        for a in alerts:
            w.writerow({
                "severity": a.severity,
                "category": a.category,
                "src_ip": a.src_ip,
                "query": a.query[:120],
                "timestamp": a.timestamp,
                "score": a.score,
                "reasons": "; ".join(a.reasons),
            })
    print(f"[+] CSV report written: {path}")


# ──────────────────────────────────────────────────────────────
# Main
# ──────────────────────────────────────────────────────────────

def main():
    ap = argparse.ArgumentParser(
        description="DNS Anomaly Detector — ML-powered Blue Team tool",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    src = ap.add_mutually_exclusive_group()
    src.add_argument("--zeek",  metavar="FILE", help="Zeek dns.log (TSV or JSON)")
    src.add_argument("--pcap",  metavar="FILE", help="PCAP file (requires scapy)")
    src.add_argument("--demo",  action="store_true", help="Run with synthetic demo data")

    ap.add_argument("--json",   metavar="FILE", help="Write JSON report")
    ap.add_argument("--csv",    metavar="FILE", help="Write CSV report")
    ap.add_argument("--no-ml",  action="store_true", help="Skip Isolation Forest")
    ap.add_argument("--quiet",  action="store_true", help="Only show CRITICAL/HIGH")
    args = ap.parse_args()

    if args.demo:
        records = generate_demo_records()
        print(f"[DEMO] {len(records)} synthetic records (benign + 4 attack patterns)")
    elif args.zeek:
        records = parse_zeek_dns(args.zeek)
        print(f"[INFO] Loaded {len(records)} records from {args.zeek}")
    elif args.pcap:
        records = parse_pcap(args.pcap)
        print(f"[INFO] Loaded {len(records)} DNS queries from {args.pcap}")
    else:
        ap.print_help()
        sys.exit(0)

    if not records:
        print("[WARN] No records to analyze.")
        sys.exit(0)

    # Per-query analysis
    per_query = [a for r in records if (a := analyze_query(r)) is not None]

    # Behavioral analysis
    engine = BehavioralEngine()
    for r in records:
        engine.ingest(r)
    behavioral = engine.run()

    # ML analysis
    ml_alerts = []
    if not args.no_ml and ML_AVAILABLE:
        ml_alerts = run_isolation_forest(records)
        # Deduplicate: skip ML alerts already caught by heuristics
        heuristic_queries = {a.query for a in per_query + behavioral}
        ml_alerts = [a for a in ml_alerts if a.query not in heuristic_queries]

    all_alerts = per_query + behavioral + ml_alerts

    if args.quiet:
        all_alerts = [a for a in all_alerts if a.severity in ("CRITICAL", "HIGH")]

    print_report(all_alerts, len(records))

    if args.json:
        write_json(all_alerts, args.json)
    if args.csv:
        write_csv(all_alerts, args.csv)

    # Exit code: 1 if any HIGH+, useful for CI/CD pipelines
    has_critical = any(a.severity in ("CRITICAL", "HIGH") for a in all_alerts)
    sys.exit(1 if has_critical else 0)


if __name__ == "__main__":
    main()
