# TypoFuzz

<div align="center">

```
 ████████╗██╗   ██╗██████╗  ██████╗ ███████╗██╗   ██╗███████╗███████╗
    ██╔══╝╚██╗ ██╔╝██╔══██╗██╔═══██╗██╔════╝██║   ██║╚════██║╚════██║
    ██║    ╚████╔╝ ██████╔╝██║   ██║█████╗  ██║   ██║    ██╔╝    ██╔╝
    ██║     ╚██╔╝  ██╔═══╝ ██║   ██║██╔══╝  ██║   ██║   ██╔╝    ██╔╝
    ██║      ██║   ██║     ╚██████╔╝██║     ╚██████╔╝   ██║     ██║
    ╚═╝      ╚═╝   ╚═╝      ╚═════╝ ╚═╝      ╚═════╝    ╚═╝     ╚═╝
```

**Typosquatting / Phishing Domain Hunter & OSINT Tool**

[![Python](https://img.shields.io/badge/Python-3.10%2B-3776AB?style=flat-square&logo=python&logoColor=white)](https://python.org)
[![License: MIT](https://img.shields.io/badge/License-MIT-green?style=flat-square)](LICENSE)
[![Platform](https://img.shields.io/badge/Platform-Linux%20%7C%20macOS%20%7C%20Windows-lightgrey?style=flat-square)]()
[![Security](https://img.shields.io/badge/Purpose-Defensive%20Security-red?style=flat-square)]()

*Detect, analyze, and report phishing & typosquatting domains impersonating your target.*

</div>

---

## Table of Contents

- [Features](#-features)
- [Architecture](#-architecture)
- [Installation](#-installation)
- [Usage](#-usage)
- [Variation Types](#-variation-types)
- [Risk Scoring](#-risk-scoring)
- [Threat Intelligence](#-threat-intelligence)
- [Output Formats](#-output-formats)
- [Examples](#-examples)
- [Legal Disclaimer](#%EF%B8%8F-legal-disclaimer)

---

## Features

```
┌─────────────────────────────────────────────────────────────────┐
│     Domain Variation Engine                                    │
│      ├── Keyboard typos (QWERTY adjacency)                      │
│      ├── Character insertion / deletion / transposition         │
│      ├── Homoglyphs (visually similar Unicode characters)       │
│      ├── TLD variations (.com → .co, .net, .io …)               │
│      ├── Subdomain abuse (login.target.com, target.secure.com)  │
│      ├── Bitsquatting (bit-flip attack vector)                  │
│      └── Combosquatting (targetlogin.com, securetarget.com)     │
│                                                                 │
│     DNS & Network Intelligence                                 │
│      ├── A / AAAA / MX / NS / CNAME / TXT records              │
│      ├── IPv4 + IPv6 resolution                                 │
│      └── Parallel multi-threaded DNS queries                    │
│                                                                 │
│     HTTP/HTTPS Analysis                                        │
│      ├── Status code checks                                     │
│      ├── Redirect chain tracking                                │
│      ├── Page title extraction                                  │
│      └── Parked domain detection                                │
│                                                                 │
│     SSL Certificate Analysis                                   │
│      ├── Validity check                                         │
│      ├── Issuer & SAN analysis                                  │
│      ├── Self-signed / wildcard detection                       │
│      └── SSL grade (A/B/C/F)                                    │
│                                                                 │
│     WHOIS Intelligence                                         │
│      ├── Registrar information                                  │
│      ├── Registration date (recently registered → high risk)    │
│      └── Name server analysis                                   │
│                                                                 │
│     Threat Intelligence (Multi-Source)                        │
│      ├── VirusTotal API v3                                      │
│      ├── URLhaus (Abuse.ch) — free, no key required             │
│      └── AlienVault OTX — free, no key required                 │
│                                                                 │
│     Risk Scoring Engine (0–100)                                │
│      ├── 70-100 → 🔴 HIGH RISK                                  │
│      ├── 40-69  → 🟡 MEDIUM RISK                                │
│      └── 0-39   → 🟢 LOW RISK                                   │
│                                                                 │
│     Output Formats                                             │
│      ├──  Interactive HTML report                             │
│      ├──  JSON (for API / SIEM integration)                   │
│      └──  CSV (for Excel / spreadsheet analysis)              │
└─────────────────────────────────────────────────────────────────┘
```

---

## Architecture

```
typofuzz/
│
├── typofuzz.py             ← Main CLI entry point
│
├── modules/
│   ├── __init__.py
│   ├── generators.py       ← Domain variation generation engine
│   ├── dns_check.py        ← DNS record lookup
│   ├── whois_check.py      ← WHOIS data retrieval
│   ├── http_check.py       ← HTTP/HTTPS analysis
│   ├── ssl_check.py        ← SSL certificate inspection
│   ├── threat_intel.py     ← Threat intelligence integration
│   ├── risk_scorer.py      ← Risk scoring engine
│   └── reporter.py         ← HTML / JSON / CSV report generator
│
├── reports/                ← Generated reports (auto-created)
├── requirements.txt
├── config.yaml
└── README.md
```

---

## Installation

### Requirements

- Python 3.10+
- pip

### Step-by-Step Setup

```bash
# 1. Clone the repository
git clone https://github.com/sevvallaydogann/typofuzz.git
cd typofuzz

# 2. Create a virtual environment (recommended)
python -m venv venv
source venv/bin/activate        # Linux/macOS
# venv\Scripts\activate         # Windows

# 3. Install dependencies
pip install -r requirements.txt

# 4. Make executable (Linux/macOS)
chmod +x typofuzz.py
```

### Quick Test

```bash
python typofuzz.py --help
```

---

## Usage

### Basic Usage

```bash
python typofuzz.py <domain>
```

```bash
python typofuzz.py google.com
```

### All Options

```
usage: typofuzz [-h] [-t N] [-o FORMAT] [--output-dir DIR]
                [--vt-key KEY] [--keywords KW1,KW2]
                [--show-all] [--bitsquatting] [--combosquatting]
                [--no-http] [--no-ssl] [--no-whois] [--no-intel]
                [--no-homoglyphs] [--no-typos] [--no-tld]
                [--no-subdomains]
                domain

Positional Arguments:
  domain                Target domain (e.g. google.com)

General Options:
  -t, --threads N       Number of parallel threads (default: 10)
  -o, --output FORMAT   Output format: html,json,csv (default: html)
  --output-dir DIR      Report output directory (default: reports/)
  --show-all            Also show unregistered domains in the table

API Keys:
  --vt-key KEY          VirusTotal API key

Variation Options:
  --bitsquatting        Include bitsquatting variations
  --combosquatting      Include combosquatting variations
  --keywords KW1,KW2    Extra keywords for combosquatting

Skip Options (--no-*):
  --no-http             Skip HTTP checks
  --no-ssl              Skip SSL checks
  --no-whois            Skip WHOIS lookups
  --no-intel            Skip threat intelligence checks
  --no-homoglyphs       Skip homoglyph variations
  --no-typos            Skip keyboard typo variations
  --no-tld              Skip TLD variations
  --no-subdomains       Skip subdomain abuse variations
```

---

## Variation Types

| Type | Description | Example (google.com) |
|------|-------------|----------------------|
| `missing-char` | One character removed | `gogle.com`, `oogle.com` |
| `extra-char` | Extra character inserted | `gooogle.com`, `googlle.com` |
| `transposition` | Two adjacent chars swapped | `googel.com`, `oggle.com` |
| `keyboard-typo` | Adjacent key on QWERTY layout | `foogle.com`, `goigle.com` |
| `double-char` | Character typed twice | `ggoogle.com`, `gooogle.com` |
| `homoglyph` | Visually similar Unicode char | `gооgle.com` (Cyrillic 'о') |
| `tld-variation` | Different TLD used | `google.net`, `google.io` |
| `subdomain-abuse` | Target used as subdomain | `login.google.com`, `google.secure.info` |
| `bitsquatting` | Bit-flip character substitution | `eoogle.com`, `hogle.com` |
| `combosquatting` | Keyword combination | `googlelogin.com`, `securegoogle.com` |
| `hyphenation` | Hyphen added or removed | `g-oogle.com`, `go-ogle.com` |
| `missing-dot` | Missing dot (common mobile typo) | `wwwgoogle.com` |

---

## Risk Scoring

Each domain receives a composite **risk score from 0 to 100**:

| Signal | Points |
|--------|--------|
| Domain is registered | +20 |
| Active HTTP website | +15 |
| Has MX records (email phishing potential) | +20 |
| Valid SSL certificate | +10 |
| Registered within the last 90 days | +15 |
| Threat intelligence match | +30 |
| Homoglyph variation type | +5 |
| Subdomain abuse pattern | +3 |
| Suspicious page title | +5 |
| Parked domain | −5 |

| Score | Risk Level | Meaning |
|-------|-----------|---------|
| 70–100 | 🔴 HIGH | Likely active phishing — immediate investigation required |
| 40–69 | 🟡 MEDIUM | Suspicious — monitoring and detailed review recommended |
| 10–39 | 🟢 LOW | Registered but no active threat indicators |
| 0–9 | ⚪ MINIMAL | Not registered or no risk signals detected |

---

## Threat Intelligence

### Supported Sources

| Source | API Key Required | Free Tier |
|--------|-----------------|-----------|
| [VirusTotal](https://virustotal.com) | ✅ Yes | 4 requests/min |
| [URLhaus (Abuse.ch)](https://urlhaus.abuse.ch) | ❌ No | Unlimited |
| [AlienVault OTX](https://otx.alienvault.com) | ❌ No | Unlimited |

### Getting a VirusTotal API Key

1. Go to [virustotal.com](https://virustotal.com)
2. Create a free account
3. Copy your key from the API Keys section

```bash
python typofuzz.py mybank.com --vt-key YOUR_API_KEY_HERE
```

---

## Output Formats

### HTML Report (Default)

Dark-themed interactive table with search/filter, color-coded risk levels, and full scan details.

```bash
python typofuzz.py paypal.com --output html
# → reports/typofuzz_paypal_com_20240215_143022.html
```

### JSON

For SIEM integration, automation, and downstream processing.

```bash
python typofuzz.py paypal.com --output json
```

```json
{
  "meta": {
    "target": "paypal.com",
    "scan_time": "2024-02-15T14:30:22",
    "total_variations": 1247,
    "registered_count": 43,
    "high_risk_count": 7
  },
  "results": [...]
}
```

### CSV

For Excel or Google Sheets analysis.

```bash
python typofuzz.py paypal.com --output csv
# or multiple formats at once:
python typofuzz.py paypal.com --output html,json,csv
```

---

## Examples

```bash
# Quick basic scan
python typofuzz.py example.com

# Full scan with all variation types enabled
python typofuzz.py mybank.com --bitsquatting --combosquatting

# VirusTotal integration + all output formats
python typofuzz.py paypal.com \
  --vt-key YOUR_KEY \
  --output html,json,csv \
  --threads 20

# Combosquatting with custom keywords
python typofuzz.py mycompany.com \
  --combosquatting \
  --keywords login,portal,intranet,vpn

# DNS-only fast scan (skip HTTP, SSL, WHOIS, intel)
python typofuzz.py example.com \
  --no-ssl --no-whois --no-intel \
  --threads 50

# Show all results including unregistered domains
python typofuzz.py example.com --show-all

# Custom report output directory
python typofuzz.py example.com --output-dir /tmp/scan-results
```

---

## Advanced Usage

### Automated Scanning with Cron

```bash
# Scan every night at 02:00 and log results
0 2 * * * /path/to/venv/bin/python /opt/typofuzz/typofuzz.py \
  mycompany.com --vt-key $VT_KEY --output json \
  >> /var/log/typofuzz.log 2>&1
```

### CI/CD Pipeline Integration

```yaml
# .github/workflows/domain-monitor.yml
name: Domain Monitoring
on:
  schedule:
    - cron: '0 6 * * *'
jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - run: pip install -r requirements.txt
      - run: python typofuzz.py ${{ vars.TARGET_DOMAIN }} --vt-key ${{ secrets.VT_KEY }} --output json
      - uses: actions/upload-artifact@v4
        with:
          name: typofuzz-report
          path: reports/
```

---


### Roadmap

- [ ] Shodan / Censys integration
- [ ] PhishTank API integration
- [ ] DMARC / DKIM / SPF analysis
- [ ] Screenshot capture (Playwright)
- [ ] Slack / Discord / Telegram alerts
- [ ] Web UI (Flask / FastAPI dashboard)
- [ ] Docker support
- [ ] SIEM export (Splunk / Elastic)


