# DDoS Toolkit

[![Python](https://img.shields.io/badge/python-3.11+-blue?logo=python)](https://www.python.org/)
[![Tests](https://img.shields.io/badge/tests-40%2F40-brightgreen)](tests/)
[![License](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![TUI](https://img.shields.io/badge/TUI-Textual-purple?logo=textual)](https://textual.textualize.io/)
[![Platform](https://img.shields.io/badge/platform-linux%20%7C%20osx-lightgrey)]()

**Attack · Defense · Detection — All in One Terminal**

> **Warning**: This tool is for **educational purposes and authorized testing only**. Unauthorized use is illegal. Read the [disclaimer](DISCLAIMER.md).

## Quick Start

```bash
git clone https://github.com/erkanrzgc/distributed-denial-of-service.git
cd distributed-denial-of-service
pip install -r requirements.txt
python3 main.py
```

### CLI Mode

```bash
# Attack — 2 second HTTP flood at 1000 req/s
python3 cli.py --no-tui attack http-flood --target http://test.local --rate 1000 --duration 2

# Defense — reverse proxy with built-in WAF
python3 cli.py --no-tui defend proxy --listen :8080 --backend http://app:3000

# Detection — live traffic monitor
python3 cli.py --no-tui detect monitor --interface eth0

# Show available network interfaces
python3 cli.py --no-tui interfaces
```

## Features

- **TUI Dashboard** — Full terminal interface with mouse support, live stats, 4 themes (dark, light, neon, matrix)
- **8 Attack Vectors** — HTTP flood, SYN flood, UDP flood, Slowloris, Slow Read, Layer 7 simulation, ICMP flood, DNS/NTP amplification
- **7 Defense Modules** — Async reverse proxy with embedded WAF, sliding-window rate limiter, iptables/nftables firewall, proof-of-work challenge-response, burst-detection traffic shaper, multi-pattern WAF scanner, PII/entropy data guard
- **5 Detection Modules** — Real-time packet capture, baseline anomaly detection, Shannon entropy analysis, attack fingerprint tracking, webhook/email/Slack alert dispatch
- **Data Leak Protection** — Real-time PII regex scanning, entropy-based encrypted/exfiltrated data detection, SQLi/XSS/path-traversal/command-injection pattern matching
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
├── utils/           🔧  Network, packet crafting, crypto, IP utilities
├── tests/           🧪  40 unit/integration tests
├── config/          ⚙️  Default YAML configuration
├── cli.py           ⌨️  Click-based CLI
└── main.py          ▶️  Entry point
```

## Modules

### Attack
| Module | Type | Description |
|--------|------|-------------|
| `http-flood` | Layer 7 | Concurrent HTTP flood with configurable method, body, headers |
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

## CLI Commands

```bash
$ python3 cli.py attack --help

Commands: http-flood, syn-flood, udp-flood, slowloris, slow-read,
          layer7, icmp-flood, amplification

$ python3 cli.py defend --help

Commands: proxy, rate-limit, data-guard

$ python3 cli.py detect --help

Commands: monitor, anomaly, entropy

$ python3 cli.py config --help    # read/write config
$ python3 cli.py report --help    # session reports (json/html/terminal)
$ python3 cli.py interfaces       # list network interfaces
```

## Configuration

```bash
# View current config
python3 cli.py config

# Change default attack rate
python3 cli.py config --set attack.default_rate=5000

# Set Slack alert webhook
python3 cli.py config --set alert.slack_webhook=https://hooks.slack.com/...
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

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md). Adding a new module takes one file — inherit from `BaseAttacker`, `BaseDefender`, or `BaseDetector` and it auto-registers.

## Disclaimer

This tool is for **educational and authorized testing only**. Unauthorized use against systems you do not own is illegal. See [DISCLAIMER.md](DISCLAIMER.md) for full legal references by country.

## Security

Found a vulnerability? See [SECURITY.md](SECURITY.md).

## Contributors

<!-- ALL-CONTRIBUTORS-LIST:START -->
| [<img src="https://github.com/erkanrzgc.png" width="100px;" alt="erkanrzgc"/><br/><sub><b>erkanrzgc</b></sub>](https://github.com/erkanrzgc) |
|:---:|
| 💻 📖 🔧 |
<!-- ALL-CONTRIBUTORS-LIST:END -->

## License

[MIT](LICENSE) © erkanrzgc
