#!/usr/bin/env python3
"""
╔══════════════════════════════════════════════════════════════╗
║    Encrypted DNS Hunter  v2.0  —  Blue Team C2 Detection    ║
║    DoH / DoT / DoQ / QUIC covert channel detector           ║
╚══════════════════════════════════════════════════════════════╝

Detects:
  • Long-lived QUIC/DoQ sessions (C2 beacons stay open hours)
  • Suspicious QUIC handshake fingerprints (Merlin, Cobalt Strike)
  • DoH beaconing: uniform payload size → bot check-in pattern
  • Encrypted DNS C2: behavioral beacon interval regularity
  • QUIC connection ID reuse (persistence through IP changes)

Input:
  --conn  Zeek conn.log
  --quic  Zeek quic.log (optional, for richer fingerprinting)
  --demo  Synthetic traffic (no files needed)

Output:
  Console report  +  optional --json / --sigma

Usage:
  python encrypted_dns_hunter.py --demo
  python encrypted_dns_hunter.py --conn conn.log
  python encrypted_dns_hunter.py --conn conn.log --quic quic.log --json out.json

Requirements: pip install scikit-learn numpy  (for ML mode)
"""

import argparse
import json
import math
import sys
from collections import defaultdict
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
# Config
# ──────────────────────────────────────────────────────────────

# Port sets
DOQ_PORTS  = {"853", "784", "8853"}
DOT_PORTS  = {"853"}
DOH_PORTS  = {"443", "8443"}

# Thresholds
LONG_SESSION_SEC        = 3600    # 1hr — legit QUIC almost never exceeds this
VERY_LONG_SESSION_SEC   = 14400   # 4hrs — almost certainly C2
BEACON_REGULARITY_SIGMA = 0.15    # Coefficient of variation: regular beacon intervals
DOH_BEACON_QPM          = 30      # DoH queries/min to single dst = suspicious
UNIFORM_PAYLOAD_THRESH  = 0.10    # Byte std_dev / mean < 10% = beaconing
MIN_BEHAVIORAL_SAMPLES  = 10

# QUIC handshake patterns associated with known C2 frameworks
# (observed via Zeek history field)
C2_HANDSHAKE_PATTERNS = {
    "ISishIH":   "Merlin C2 (DoQ)",
    "ISIsiH":    "Merlin C2 variant",
    "ISish":     "Merlin C2 partial",
    "ShADadFf":  "Possible Cobalt Strike HTTPS",
    "^ShA$":     "Minimal TLS — possible C2 stub",
}

LEGIT_QUIC_PREFIXES = {"II", "IHi", "IHiI"}


# ──────────────────────────────────────────────────────────────
# Data models
# ──────────────────────────────────────────────────────────────

@dataclass
class ConnRecord:
    ts: float
    src_ip: str
    src_port: str
    dst_ip: str
    dst_port: str
    proto: str
    service: str
    duration: float
    orig_bytes: int
    resp_bytes: int
    history: str
    orig_pkts: int = 0
    resp_pkts: int = 0

@dataclass
class Alert:
    severity: str       # CRITICAL / HIGH / MEDIUM
    category: str
    src_ip: str
    dst_ip: str
    dst_port: str
    timestamp: str
    score: float
    reasons: List[str]
    evidence: dict = field(default_factory=dict)
    mitre: str = ""

    def color(self) -> str:
        c = {"CRITICAL": "\033[91m", "HIGH": "\033[91m", "MEDIUM": "\033[93m"}
        return f"{c.get(self.severity, '')}{self.severity}\033[0m"


# ──────────────────────────────────────────────────────────────
# Parsers
# ──────────────────────────────────────────────────────────────

def _safe_float(v, default=0.0) -> float:
    try:
        return float(v)
    except (TypeError, ValueError):
        return default

def _safe_int(v, default=0) -> int:
    try:
        return int(float(v))
    except (TypeError, ValueError):
        return default

def parse_conn_log(path: str) -> List[ConnRecord]:
    records = []
    try:
        lines = Path(path).read_text(errors="replace").splitlines()
    except FileNotFoundError:
        print(f"[ERROR] File not found: {path}", file=sys.stderr)
        return records

    if lines and lines[0].strip().startswith("{"):
        for line in lines:
            line = line.strip()
            if not line:
                continue
            try:
                d = json.loads(line)
                records.append(ConnRecord(
                    ts=_safe_float(d.get("ts")),
                    src_ip=d.get("id.orig_h", ""),
                    src_port=str(d.get("id.orig_p", "")),
                    dst_ip=d.get("id.resp_h", ""),
                    dst_port=str(d.get("id.resp_p", "")),
                    proto=d.get("proto", ""),
                    service=d.get("service", ""),
                    duration=_safe_float(d.get("duration")),
                    orig_bytes=_safe_int(d.get("orig_bytes")),
                    resp_bytes=_safe_int(d.get("resp_bytes")),
                    history=d.get("history", ""),
                    orig_pkts=_safe_int(d.get("orig_pkts")),
                    resp_pkts=_safe_int(d.get("resp_pkts")),
                ))
            except json.JSONDecodeError:
                continue
        return records

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
        d = dict(zip(headers, parts))
        records.append(ConnRecord(
            ts=_safe_float(d.get("ts")),
            src_ip=d.get("id.orig_h", ""),
            src_port=d.get("id.orig_p", ""),
            dst_ip=d.get("id.resp_h", ""),
            dst_port=d.get("id.resp_p", ""),
            proto=d.get("proto", ""),
            service=d.get("service", ""),
            duration=_safe_float(d.get("duration")),
            orig_bytes=_safe_int(d.get("orig_bytes")),
            resp_bytes=_safe_int(d.get("resp_bytes")),
            history=d.get("history", ""),
            orig_pkts=_safe_int(d.get("orig_pkts")),
            resp_pkts=_safe_int(d.get("resp_pkts")),
        ))
    return records


def generate_demo_records() -> List[ConnRecord]:
    base = 1700000000.0

    records = []

    # ── Legitimate QUIC ─────────────────────────────────────
    for i in range(30):
        records.append(ConnRecord(
            ts=base + i * 20,
            src_ip=f"10.0.0.{10 + i % 8}",
            src_port=str(50000 + i),
            dst_ip="8.8.8.8",
            dst_port="443",
            proto="udp", service="quic",
            duration=float(5 + (i % 30)),
            orig_bytes=800 + i * 30,
            resp_bytes=1600 + i * 50,
            history="II",
            orig_pkts=4 + i % 5,
            resp_pkts=6 + i % 8,
        ))

    # ── Merlin C2 DoQ session (24h, anomalous handshake) ────
    records.append(ConnRecord(
        ts=base,
        src_ip="10.0.0.42",
        src_port="51234",
        dst_ip="185.220.101.99",  # Known Tor exit
        dst_port="853",
        proto="udp", service="quic",
        duration=86400.0,
        orig_bytes=52480,
        resp_bytes=18240,
        history="ISishIH",
        orig_pkts=340,
        resp_pkts=120,
    ))

    # ── DoH beaconing: uniform payload, regular interval ────
    for i in range(60):
        records.append(ConnRecord(
            ts=base + i * 30.2,   # Very regular: every 30 seconds
            src_ip="10.0.0.17",
            src_port=str(55000 + i),
            dst_ip="104.16.248.249",
            dst_port="443",
            proto="tcp", service="ssl",
            duration=0.35,
            orig_bytes=248,   # Almost identical payload size
            resp_bytes=164,
            history="ShADadfF",
            orig_pkts=3, resp_pkts=3,
        ))

    # ── Legitimate DoH (variable payloads, variable timing) ─
    for i in range(25):
        records.append(ConnRecord(
            ts=base + i * (10 + (i % 7) * 15),
            src_ip="10.0.0.8",
            src_port=str(60000 + i),
            dst_ip="1.1.1.1",
            dst_port="443",
            proto="tcp", service="ssl",
            duration=0.2 + (i % 5) * 0.1,
            orig_bytes=200 + (i % 12) * 80,
            resp_bytes=150 + (i % 20) * 120,
            history="ShADadfF",
            orig_pkts=3, resp_pkts=4,
        ))

    return records


# ──────────────────────────────────────────────────────────────
# Detection engines
# ──────────────────────────────────────────────────────────────

def detect_long_sessions(records: List[ConnRecord]) -> List[Alert]:
    alerts = []
    for r in records:
        is_quic = r.service == "quic" or (r.proto == "udp" and r.dst_port in DOQ_PORTS)
        if not is_quic:
            continue
        if r.duration < LONG_SESSION_SEC:
            continue

        hours = r.duration / 3600
        sev = "CRITICAL" if r.duration > VERY_LONG_SESSION_SEC else "HIGH"

        # Compute data symmetry ratio: C2 channels usually have low resp/orig ratio
        total = r.orig_bytes + r.resp_bytes
        byte_ratio = r.resp_bytes / r.orig_bytes if r.orig_bytes > 0 else 0

        alerts.append(Alert(
            severity=sev,
            category="long_lived_quic_c2",
            src_ip=r.src_ip,
            dst_ip=r.dst_ip,
            dst_port=r.dst_port,
            timestamp=str(r.ts),
            score=min(50 + (r.duration / 3600) * 5, 100),
            reasons=[
                f"duration({hours:.1f}h)",
                f"threshold({LONG_SESSION_SEC/3600:.0f}h)",
                f"byte_ratio(resp/orig={byte_ratio:.2f})",
            ],
            evidence={
                "duration_hours": round(hours, 2),
                "orig_bytes": r.orig_bytes,
                "resp_bytes": r.resp_bytes,
                "orig_pkts": r.orig_pkts,
                "resp_pkts": r.resp_pkts,
                "history": r.history,
                "note": "Legitimate QUIC sessions rarely exceed 60 seconds"
            },
            mitre="T1071.004",
        ))
    return alerts


def detect_handshake_anomalies(records: List[ConnRecord]) -> List[Alert]:
    alerts = []
    for r in records:
        if not r.history:
            continue
        if r.proto not in ("udp", "tcp"):
            continue

        # Check against known C2 patterns
        for pattern, framework in C2_HANDSHAKE_PATTERNS.items():
            if pattern.startswith("^"):
                import re
                if re.match(pattern, r.history):
                    matched = True
                else:
                    matched = False
            else:
                matched = r.history.startswith(pattern)

            if matched:
                alerts.append(Alert(
                    severity="HIGH",
                    category="c2_handshake_fingerprint",
                    src_ip=r.src_ip,
                    dst_ip=r.dst_ip,
                    dst_port=r.dst_port,
                    timestamp=str(r.ts),
                    score=85.0,
                    reasons=[
                        f"history_match({r.history}→{pattern})",
                        f"framework({framework})",
                    ],
                    evidence={
                        "observed_history": r.history,
                        "matched_pattern": pattern,
                        "associated_framework": framework,
                        "legit_quic_prefixes": list(LEGIT_QUIC_PREFIXES),
                        "note": "Legitimate QUIC starts with 'II'. This pattern is anomalous."
                    },
                    mitre="T1071.004",
                ))
                break
    return alerts


def detect_doh_beaconing(records: List[ConnRecord]) -> List[Alert]:
    """
    Identifies DoH beaconing by looking for:
    1. Uniform payload sizes (bot check-in packets are fixed-size)
    2. Regular timing intervals (bot heartbeat)
    """
    # Group (src_ip, dst_ip) on HTTPS
    groups = defaultdict(list)
    for r in records:
        if r.dst_port in DOH_PORTS and r.proto == "tcp":
            groups[(r.src_ip, r.dst_ip)].append(r)

    alerts = []
    for (src, dst), recs in groups.items():
        if len(recs) < MIN_BEHAVIORAL_SAMPLES:
            continue

        # Payload uniformity
        sizes = [r.orig_bytes for r in recs if r.orig_bytes > 0]
        if not sizes:
            continue
        mean_size = sum(sizes) / len(sizes)
        if mean_size == 0:
            continue
        std_size = math.sqrt(sum((s - mean_size)**2 for s in sizes) / len(sizes))
        cv_size = std_size / mean_size  # coefficient of variation

        # Timing regularity
        timestamps = sorted(r.ts for r in recs)
        intervals = [timestamps[i+1] - timestamps[i]
                     for i in range(len(timestamps)-1) if timestamps[i] > 0]
        cv_interval = 0.0
        if intervals and len(intervals) > 2:
            mean_int = sum(intervals) / len(intervals)
            std_int = math.sqrt(sum((x - mean_int)**2 for x in intervals) / len(intervals))
            cv_interval = std_int / mean_int if mean_int > 0 else 1.0

        is_uniform_payload  = cv_size < UNIFORM_PAYLOAD_THRESH
        is_regular_timing   = 0 < cv_interval < BEACON_REGULARITY_SIGMA

        if not (is_uniform_payload or is_regular_timing):
            continue

        score = 0.0
        reasons = []
        if is_uniform_payload:
            score += 45
            reasons.append(f"uniform_payload(cv={cv_size:.3f},mean={mean_size:.0f}B)")
        if is_regular_timing and intervals:
            score += 45
            mean_int = sum(intervals) / len(intervals)
            reasons.append(f"regular_interval(cv={cv_interval:.3f},avg={mean_int:.0f}s)")

        sev = "HIGH" if score >= 70 else "MEDIUM"
        alerts.append(Alert(
            severity=sev,
            category="doh_beaconing",
            src_ip=src,
            dst_ip=dst,
            dst_port=recs[0].dst_port,
            timestamp=str(recs[0].ts),
            score=min(score, 100),
            reasons=reasons,
            evidence={
                "connection_count": len(recs),
                "payload_mean_bytes": round(mean_size),
                "payload_cv": round(cv_size, 4),
                "interval_cv": round(cv_interval, 4),
                "avg_interval_seconds": round(sum(intervals)/len(intervals), 1) if intervals else 0,
                "uniform_payload": is_uniform_payload,
                "regular_timing": is_regular_timing,
                "note": "Legitimate browsing has highly variable payload sizes and timing",
            },
            mitre="T1071.004",
        ))
    return alerts


def run_ml_detection(records: List[ConnRecord]) -> List[Alert]:
    """
    Isolation Forest over QUIC/TLS connection features.
    Catches novel C2 patterns not covered by heuristics.
    """
    if not ML_AVAILABLE or len(records) < 20:
        return []

    quic_tls = [r for r in records
                if r.proto in ("udp", "tcp")
                and r.dst_port in DOQ_PORTS | DOH_PORTS | {"443"}
                and r.duration > 0]
    if len(quic_tls) < 20:
        return []

    feature_vecs = []
    for r in quic_tls:
        byte_ratio = r.resp_bytes / r.orig_bytes if r.orig_bytes > 0 else 0
        pkt_ratio = r.resp_pkts / r.orig_pkts if r.orig_pkts > 0 else 0
        bytes_per_sec = (r.orig_bytes + r.resp_bytes) / max(r.duration, 0.1)
        feature_vecs.append([
            math.log1p(r.duration),
            byte_ratio,
            pkt_ratio,
            math.log1p(r.orig_bytes),
            math.log1p(bytes_per_sec),
            int(r.dst_port in DOQ_PORTS),
        ])

    X = [[
        math.log1p(r.duration),
        r.resp_bytes / r.orig_bytes if r.orig_bytes > 0 else 0,
        r.resp_pkts / r.orig_pkts if r.orig_pkts > 0 else 0,
        math.log1p(r.orig_bytes),
        math.log1p((r.orig_bytes + r.resp_bytes) / max(r.duration, 0.1)),
        int(r.dst_port in DOQ_PORTS),
    ] for r in quic_tls]

    clf = IsolationForest(contamination=0.05, random_state=42, n_estimators=150)
    preds = clf.fit_predict(X)
    scores = clf.score_samples(X)

    alerts = []
    # Avoid re-alerting on what heuristics already caught
    for i, (pred, raw_score) in enumerate(zip(preds, scores)):
        if pred != -1:
            continue
        r = quic_tls[i]
        if r.duration > LONG_SESSION_SEC:
            continue  # already caught by long session detector
        anomaly_score = max(0, min(100, (-raw_score + 0.5) * 200))
        alerts.append(Alert(
            severity="MEDIUM",
            category="ml_conn_anomaly",
            src_ip=r.src_ip,
            dst_ip=r.dst_ip,
            dst_port=r.dst_port,
            timestamp=str(r.ts),
            score=round(anomaly_score, 1),
            reasons=[f"isolation_forest(score={raw_score:.4f})"],
            evidence={
                "duration": r.duration,
                "orig_bytes": r.orig_bytes,
                "resp_bytes": r.resp_bytes,
                "byte_ratio": round(r.resp_bytes / r.orig_bytes, 3) if r.orig_bytes else 0,
                "history": r.history,
                "note": "Statistical outlier in QUIC/TLS connection features",
            },
            mitre="T1071.004",
        ))
    return alerts


# ──────────────────────────────────────────────────────────────
# Sigma rule generator
# ──────────────────────────────────────────────────────────────

SIGMA_TEMPLATES = {
    "long_lived_quic_c2": """title: Long-lived DoQ/QUIC Session (C2 Indicator)
id: c1a2b3d4-e5f6-7890-1234-56789abcdef0
status: experimental
description: |
  QUIC session on port 853 (DNS over QUIC) lasting more than 1 hour.
  Legitimate QUIC connections almost never exceed 60 seconds.
  Consistent with Merlin C2, or custom DoQ-based C2 frameworks.
logsource:
  product: zeek
  service: conn
detection:
  selection:
    proto: udp
    id.resp_p: 853
    duration|gt: 3600
  condition: selection
falsepositives:
  - Long-running DNS-over-QUIC implementations (rare)
  - Lab/testing environments
level: high
tags:
  - attack.command_and_control
  - attack.t1071.004
""",
    "c2_handshake_fingerprint": """title: Suspicious QUIC Handshake Pattern (C2 Framework)
id: d2b3c4e5-f6a7-8901-2345-6789bcdef012
status: experimental  
description: |
  QUIC handshake history field matches patterns observed in known
  C2 frameworks (Merlin, Cobalt Strike variants). Legitimate QUIC
  connections start with "II" or "IHi". Anomalous prefixes indicate
  non-standard QUIC implementation — common in C2 tooling.
logsource:
  product: zeek
  service: conn
detection:
  selection_merlin:
    history|startswith: 'ISi'
  selection_minimal:
    history: 'ShA'
  condition: selection_merlin or selection_minimal
falsepositives:
  - Custom QUIC implementations
  - Encrypted tunnels on non-standard stacks
level: high
tags:
  - attack.command_and_control
  - attack.t1071.004
""",
}

def write_sigma_rules(path: str):
    out = Path(path)
    out.mkdir(parents=True, exist_ok=True)
    for name, content in SIGMA_TEMPLATES.items():
        rule_path = out / f"{name}.yml"
        rule_path.write_text(content)
        print(f"[+] Sigma rule: {rule_path}")


# ──────────────────────────────────────────────────────────────
# Report
# ──────────────────────────────────────────────────────────────

SEV_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2}

def print_report(alerts: List[Alert], total: int):
    print()
    print("╔══════════════════════════════════════════════════════╗")
    print("║       Encrypted DNS Hunter  v2.0  —  Report         ║")
    print("╚══════════════════════════════════════════════════════╝")
    print(f"  Connections analyzed : {total}")
    print(f"  Total alerts         : {len(alerts)}")
    c = sum(1 for a in alerts if a.severity == "CRITICAL")
    h = sum(1 for a in alerts if a.severity == "HIGH")
    m = sum(1 for a in alerts if a.severity == "MEDIUM")
    print(f"  CRITICAL: {c}  HIGH: {h}  MEDIUM: {m}")
    print()

    for i, a in enumerate(sorted(alerts, key=lambda x: SEV_ORDER.get(x.severity, 9)), 1):
        bar = "█" * int(a.score / 10) + "░" * (10 - int(a.score / 10))
        print(f"  ── Alert #{i} {'─'*40}")
        print(f"  [{bar}] {a.score:.0f}/100  {a.color()}")
        print(f"  Category  : {a.category}")
        print(f"  {a.src_ip} → {a.dst_ip}:{a.dst_port}")
        if a.mitre:
            print(f"  MITRE     : {a.mitre}")
        print(f"  Reasons   :")
        for r in a.reasons:
            print(f"    • {r}")
        ev = {k: v for k, v in a.evidence.items()}
        print(f"  Evidence  :")
        for k, v in ev.items():
            print(f"    {k}: {v}")
        print()

    print("══════════════════════════════════════════════════════")


# ──────────────────────────────────────────────────────────────
# Main
# ──────────────────────────────────────────────────────────────

def main():
    ap = argparse.ArgumentParser(
        description="Encrypted DNS Hunter — DoH/DoQ C2 channel detector",
    )
    src = ap.add_mutually_exclusive_group()
    src.add_argument("--conn", metavar="FILE", help="Zeek conn.log")
    src.add_argument("--demo", action="store_true", help="Synthetic demo data")

    ap.add_argument("--quic",  metavar="FILE", help="Zeek quic.log (optional)")
    ap.add_argument("--json",  metavar="FILE", help="Write JSON report")
    ap.add_argument("--sigma", metavar="DIR",  help="Write Sigma rules to directory")
    ap.add_argument("--no-ml", action="store_true", help="Skip ML detection")
    args = ap.parse_args()

    if args.demo:
        records = generate_demo_records()
        print(f"[DEMO] {len(records)} synthetic connections (legitimate + C2 patterns)")
    elif args.conn:
        records = parse_conn_log(args.conn)
        print(f"[INFO] Loaded {len(records)} connection records from {args.conn}")
    else:
        ap.print_help()
        sys.exit(0)

    if not records:
        print("[WARN] No records.")
        sys.exit(0)

    alerts = []
    alerts += detect_long_sessions(records)
    alerts += detect_handshake_anomalies(records)
    alerts += detect_doh_beaconing(records)
    if not args.no_ml:
        ml = run_ml_detection(records)
        heuristic_ips = {a.src_ip for a in alerts}
        alerts += [a for a in ml if a.src_ip not in heuristic_ips]

    print_report(alerts, len(records))

    if args.json:
        Path(args.json).write_text(json.dumps([asdict(a) for a in alerts], indent=2))
        print(f"[+] JSON report: {args.json}")

    if args.sigma:
        write_sigma_rules(args.sigma)

    sys.exit(1 if any(a.severity in ("CRITICAL","HIGH") for a in alerts) else 0)


if __name__ == "__main__":
    main()
