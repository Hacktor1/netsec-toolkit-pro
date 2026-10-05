# NetSec Toolkit Pro — Security Auditing Toolkit

A modular Python toolkit for network security auditing, featuring port scanning, WiFi analysis, packet sniffing, password auditing, vulnerability detection, and unified HTML reporting.

## Modules

| Module | Description |
|--------|-------------|
| **scan-ports** | TCP port scanner with banner grabbing and service fingerprinting |
| **wifi-scan** | WiFi network discovery with security analysis and vulnerability detection |
| **sniff** | Network packet capture and suspicious traffic analysis |
| **crack-hash** | Password hash cracker (MD5, SHA1, SHA256) using wordlists |
| **generate-wordlist** | Targeted password wordlist generator with mutation rules |
| **vuln-detect** | Service fingerprinting and CVE lookup |
| **audit** | Comprehensive multi-phase security audit with unified report |

## Installation

```bash
pip install -e .
```

## Requirements

- Python 3.8+
- `requests` (for CVE API lookups)

### System dependencies (optional, for real packet capture)

```bash
# Port scanning and banner grabbing work with stdlib only
# For enhanced features, install optional deps:
pip install cryptography
```

## Usage

```bash
# Port scan with banner grabbing
netsec scan-ports --target 192.168.1.1 --ports 1-1000

# WiFi scan (simulated mode by default)
netsec wifi-scan

# Sniff packets
netsec sniff --packets 50

# Crack a hash
netsec crack-hash --hash 5f4dcc3b5aa765d61d8327deb882cf99

# Generate wordlist
netsec generate-wordlist --words "admin,password,root" --output list.txt

# Full audit
netsec audit --target 192.168.1.1

# Verbose mode
netsec audit --target 10.0.0.1 --verbose
```

## Architecture

```
netsec_toolkit/
├── __init__.py          # Package info
├── __main__.py          # CLI entry point
├── config.py            # Configuration management
├── modules/
│   ├── port_scanner.py     # TCP scanning + banner grab
│   ├── wifi_scanner.py     # WiFi discovery + analysis (optional)
│   ├── sniffer.py          # Packet capture + anomaly detection
│   ├── password_auditor.py # Wordlist gen + hash cracking
│   └── vuln_detector.py    # Service fingerprinting + CVE lookup
├── core/
│   ├── reporter.py         # Unified HTML report engine
│   └── result_store.py     # Central result storage
├── utils/
│   ├── validators.py       # Input validation
│   └── formatters.py       # Console output formatting
└── config.yaml             # Default configuration
```
