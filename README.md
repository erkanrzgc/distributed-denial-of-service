# distributed-denial-of-service

[![Python](https://img.shields.io/badge/python-3.11+-blue?logo=python)](https://www.python.org/)
[![Tests](https://img.shields.io/badge/tests-40%2F40-brightgreen)](tests/)
[![License](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![TUI](https://img.shields.io/badge/TUI-Textual-purple?logo=textual)](https://textual.textualize.io/)
[![Platform](https://img.shields.io/badge/platform-linux%20%7C%20osx-lightgrey)]()

**DDoS toolkit for red team operations, stress testing, and defensive security research.**

> **Warning**: This tool is for **educational purposes and authorized testing only**. Unauthorized use is illegal. Read the [disclaimer](DISCLAIMER.md).

## Quick Start

```bash
git clone https://github.com/erkanrzgc/distributed-denial-of-service.git
cd distributed-denial-of-service
pip install -r requirements.txt
python3 ddos.py
```

### CLI Mode

```bash
# Recon — scan target, detect tech stack & suggest attacks
python3 ddos.py recon --target example.com

# Attack — 3s HTTP flood at 1000 req/s
python3 ddos.py --no-tui attack http-flood --target https://test.local --rate 1000 --duration 3s

# Stress test — 30s ramp-up with latency percentiles
python3 ddos.py --no-tui stress http --target https://api.com --duration 30s --ramp-up 10:100:15s

# Defense — reverse proxy with built-in WAF
python3 ddos.py --no-tui defend proxy --listen :8080 --backend http://app:3000

# Detection — live traffic monitor
python3 ddos.py --no-tui detect monitor --interface eth0
```

## Features

- **TUI Dashboard** — Full terminal interface with mouse + keyboard navigation, live stats, 4 themes (dark, light, neon, matrix)
- **8 Attack Vectors** — HTTP flood, SYN flood, UDP flood, Slowloris, Slow Read, Layer 7 simulation, ICMP flood, DNS/NTP amplification
- **7 Defense Modules** — Async reverse proxy with embedded WAF, sliding-window rate limiter, iptables/nftables firewall, proof-of-work challenge-response, burst-detection traffic shaper, multi-pattern WAF scanner, PII/entropy data guard
- **5 Detection Modules** — Real-time packet capture, baseline anomaly detection, Shannon entropy analysis, attack fingerprint tracking, webhook/email/Slack alert dispatch
- **Stress Testing** — Latency percentiles (p50/p95/p99), ramp-up mode, HTTP status code breakdown, error classification, request-count termination
- **Data Leak Protection** — Real-time PII regex scanning, entropy-based encrypted/exfiltrated data detection, SQLi/XSS/path-traversal/command-injection pattern matching
- **Per-Target Logging** — Every attack, defense, and detection session auto-generates a timestamped log under `logs/{target}/`
- **Modular Plugin System** — Add new attack, defense, or detection modules as single files; auto-registered via `__init_subclass__`
- **CLI + TUI Dual Mode** — Run interactively in the terminal UI or script from the command line

## Architecture

```
.
├── attack/          ⚔️  8 attack modules
├── defense/         🛡️  7 defense modules
├── detection/       🔍  5 detection modules
├── core/            🧠  Config, session manager, event bus, engine
├── ui/              🖥️  Textual TUI (screens, widgets, 4 themes)
├── utils/           🔧  Network, packets, crypto, IP utils, histogram, profiler, validators, log writer
├── tests/           🧪  40 unit/integration tests
├── config/          ⚙️  Default YAML configuration
├── ddos.py          ▶️  Entry point (TUI + CLI)
└── logs/            📝  Auto-generated per-target session logs
```

## Modules

### Attack
| Module | Type | Description |
|--------|------|-------------|
| `http-flood` | Layer 7 | HTTP/HTTPS load & stress test with latency, ramp-up, status tracking |
| `syn-flood` | Layer 4 | TCP SYN flood via raw sockets with IP spoofing |
| `udp-flood` | Layer 4 | UDP packet flood with configurable payload |
| `slowloris` | Layer 7 | Partial HTTP header attack exhausting connection pool |
| `slow-read` | Layer 7 | Slow response reading consuming server resources |
| `layer7` | Layer 7 | Human-like browsing behaviour simulation |
| `icmp-flood` | Layer 3 | ICMP echo request (ping) flood |
| `amplification` | Layer 4 | DNS/NTP/SSDP amplification simulation |

### Defense
| Module | Description |
|--------|-------------|
| `reverse-proxy` | Async reverse proxy with embedded WAF, rate limiting, data guard |
| `rate-limiter` | Token bucket + sliding window rate limiting with auto-block |
| `dynamic-firewall` | iptables/nftables auto-blocking on connection thresholds |
| `challenge` | Proof-of-work challenge-response for unverified clients |
| `traffic-shaper` | Burst detection and per-IP traffic profiling |
| `waf` | SQLi, XSS, path traversal, command injection pattern matching |
| `data-guard` | PII scanning, Shannon entropy analysis, body size enforcement |

### Detection
| Module | Description |
|--------|-------------|
| `monitor` | Real-time packet capture with per-protocol statistics |
| `anomaly` | Baseline collection → z-score anomaly detection engine |
| `entropy` | Shannon entropy for DDoS detection and data exfiltration alerts |
| `fingerprint` | Attack pattern fingerprinting, grouping, and known-signature matching |
| `alert` | Multi-channel alert dispatch (webhook, email, Slack) |

## Stress Testing

The `http-flood` module doubles as a performance load tester with latency tracking.

```bash
# 30-second stress test with live latency percentiles
python3 ddos.py stress http --target https://api.com --duration 30s --concurrent 50

# Stop after 10,000 requests
python3 ddos.py stress http --target https://api.com --duration 0 --requests 10000

# Ramp-up from 10 to 100 workers over 15 seconds
python3 ddos.py stress http --target https://api.com --duration 60s --ramp-up 10:100:15s
```

Each test reports: **p50/p95/p99 latency**, **HTTP status code breakdown**, **error type classification**, and **bandwidth usage**.

## CLI Commands

```bash
$ python3 ddos.py attack --help
Commands: http-flood, syn-flood, udp-flood, slowloris, slow-read,
          layer7, icmp-flood, amplification

$ python3 ddos.py stress --help
Commands: http

$ python3 ddos.py defend --help
Commands: proxy, rate-limit, data-guard

$ python3 ddos.py detect --help
Commands: monitor, anomaly, entropy, fingerprint, alert

$ python3 ddos.py recon --target example.com    # scan & profile target
$ python3 ddos.py config                        # view/edit config
$ python3 ddos.py report                        # session reports (json/html/csv)
$ python3 ddos.py interfaces                    # list network interfaces
```

## Configuration

```bash
# View current config
python3 ddos.py config

# Change default attack rate
python3 ddos.py config --set attack.default_rate=5000

# Set Slack alert webhook
python3 ddos.py config --set alert.slack_webhook=https://hooks.slack.com/...
```

Or edit `~/.config/ddos-toolkit/config.yaml` directly.

## Requirements

| Component | Minimum |
|-----------|---------|
| Python | 3.11+ |
| OS | Linux, macOS |
| Root | Required only for SYN flood and firewall (optional) |
| Dependencies | textual, rich, click, aiohttp, scapy, pydantic, structlog |

## Testing

```bash
pip install pytest pytest-asyncio
python3 -m pytest tests/ -v
# 40 passed
```

## Disclaimer

This tool is for **educational and authorized testing only**. Unauthorized use against systems you do not own is illegal. See [DISCLAIMER.md](DISCLAIMER.md) for full legal references by country.

## Security

Found a vulnerability? See [SECURITY.md](SECURITY.md).

## License

[MIT](LICENSE) © erkanrzgc
