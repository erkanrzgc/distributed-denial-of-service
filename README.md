<p align="center">
  <img src="https://img.shields.io/badge/python-3.11+-blue?style=for-the-badge&logo=python&logoColor=white" alt="Python">
  <img src="https://img.shields.io/badge/license-MIT-green?style=for-the-badge" alt="License">
  <img src="https://img.shields.io/badge/build-passing-brightgreen?style=for-the-badge" alt="Build">
  <img src="https://img.shields.io/badge/tests-40%2F40-brightgreen?style=for-the-badge" alt="Tests">
  <img src="https://img.shields.io/badge/TUI-Textual-purple?style=for-the-badge&logo=textual&logoColor=white" alt="TUI">
  <img src="https://img.shields.io/badge/platform-linux%20%7C%20osx-lightgrey?style=for-the-badge" alt="Platform">
</p>

<h1 align="center">DDoS Toolkit</h1>

<p align="center">
  <strong>Attack · Defense · Detection — All in One Terminal</strong>
</p>

<p align="center">
  <a href="#features">Features</a> ·
  <a href="#-quick-start">Quick Start</a> ·
  <a href="#-screenshots">Screenshots</a> ·
  <a href="#-architecture">Architecture</a> ·
  <a href="#-cli-usage">CLI</a> ·
  <a href="#-modules">Modules</a> ·
  <a href="#-disclaimer">Disclaimer</a>
</p>

---

> **Warning**: This tool is for **educational purposes and authorized testing only**. Using it against systems without permission is illegal. Read the [disclaimer](DISCLAIMER.md).

---

## Features

- **Text User Interface** — Full terminal dashboard with mouse support, live stats, and dark/light/neon/matrix themes
- **8 Attack Modules** — HTTP flood, SYN flood, UDP flood, Slowloris, Slow Read, Layer 7, ICMP flood, Amplification
- **7 Defense Modules** — Reverse proxy, rate limiter, dynamic firewall, challenge-response, traffic shaper, WAF, data leak guard
- **5 Detection Modules** — Real-time monitor, anomaly detection (ML-baseline), entropy analysis, fingerprint tracking, alert system
- **Data Leak Protection** — PII scanning, entropy analysis, SQLi/XSS/CMDi detection in real-time
- **CLI + TUI** — Both command-line mode and interactive terminal UI

## Quick Start

```bash
git clone https://github.com/erkanrzgc/distributed-denial-of-service.git
cd distributed-denial-of-service
pip install -r requirements.txt
python3 main.py
```

### CLI Mode

```bash
# Attack
python3 cli.py --no-tui attack http-flood --target http://test.local --rate 1000 --duration 10

# Defense
python3 cli.py --no-tui defend proxy --listen :8080 --backend http://app:3000 --rate-limit 100

# Detection  
python3 cli.py --no-tui detect monitor --interface eth0 --threshold 5000

# Show network interfaces
python3 cli.py --no-tui interfaces
```

## Screenshots

```
┌──────────────────────────────────────────────────┐
│  DDoS Toolkit v1.0          Session: running     │
│──────────────────────────────────────────────────│
│                                                   │
│   ATTACK: http-flood → https://target.com        │
│   ┌──────────┬──────────┬──────────┬────────┐   │
│   │ Packets  │ Rate     │ Success  │ BW     │   │
│   │ 142,857  │ 10,000/s │ 98.3%    │845Mbps │   │
│   └──────────┴──────────┴──────────┴────────┘   │
│                                                   │
│   Log: 14:32:01 [OK] HTTP 200 — 12ms             │
│   Log: 14:32:01 [OK] HTTP 200 — 8ms              │
│                                                   │
└──────────────────────────────────────────────────┘
```

## Architecture

```
.
├── attack/      # ⚔️  8 attack modules (HTTP, SYN, UDP, Slowloris...)
├── defense/     # 🛡️  7 defense modules (WAF, Rate limiter, Firewall...)
├── detection/   # 🔍  5 detection modules (Monitor, Anomaly, Entropy...)
├── core/        # 🧠  Config, session manager, event bus, engine
├── ui/          # 🖥️  Textual TUI (screens, widgets, themes)
├── utils/       # 🔧  Network, packet crafting, crypto, ip utils
├── tests/       # 🧪  40 unit tests
├── config/      # ⚙️  Default YAML configuration
└── cli.py       # ⌨️  Click-based CLI interface
```

## CLI Usage

```bash
$ python3 cli.py attack --help

Commands:
  http-flood      HTTP/HTTPS request flood
  syn-flood       TCP SYN packet flood
  udp-flood       UDP packet flood
  slowloris       Connection exhaustion
  slow-read       Response draining
  layer7          App-layer simulation
  icmp-flood      Ping flood
  amplification   DNS/NTP amplification

$ python3 cli.py defend --help

Commands:
  proxy           Reverse proxy with WAF + rate limiting
  rate-limit      Sliding window rate limiter
  data-guard      PII/entropy data leak protection

$ python3 cli.py detect --help

Commands:
  monitor         Live traffic monitoring
  anomaly         Baseline-based anomaly detection
  entropy         Traffic/data entropy analysis
```

## Modules

### Attack Modules
| Module | Type | Description |
|--------|------|-------------|
| `http-flood` | Layer 7 | Concurrent HTTP request flood with configurable method, headers, body |
| `syn-flood` | Layer 4 | TCP SYN flood via raw sockets with optional IP spoofing |
| `udp-flood` | Layer 4 | UDP packet flood with configurable payload size |
| `slowloris` | Layer 7 | Slow HTTP header attack consuming connection pool |
| `slow-read` | Layer 7 | Slow response reading exhausting server resources |
| `layer7` | Layer 7 | Application-layer human-like browsing simulation |
| `icmp-flood` | Layer 3 | ICMP echo request (ping) flood |
| `amplification` | Layer 4 | DNS/NTP/SSDP amplification attack simulation |

### Defense Modules
| Module | Description |
|--------|-------------|
| `reverse-proxy` | Async reverse proxy with built-in WAF, rate limiting, data guard |
| `rate-limiter` | Token bucket + sliding window rate limiting |
| `dynamic-firewall` | iptables/nftables integration with auto-blocking |
| `challenge` | Proof-of-Work challenge-response for unverified clients |
| `traffic-shaper` | Burst detection and traffic analysis |
| `waf` | SQLi, XSS, path traversal, command injection pattern detection |
| `data-guard` | PII scanning, entropy analysis, body size enforcement |

### Detection Modules
| Module | Description |
|--------|-------------|
| `monitor` | Real-time packet capture and traffic statistics |
| `anomaly` | Baseline machine learning anomaly detection |
| `entropy` | Shannon entropy analysis for DDoS and data exfiltration |
| `fingerprint` | Attack pattern fingerprinting and grouping |
| `alert` | Webhook, email, and Slack alert dispatch |

## Advanced Configuration

```bash
# View all settings
python3 cli.py config

# Change default attack rate
python3 cli.py config --set attack.default_rate=5000

# Set alert webhook
python3 cli.py config --set alert.webhook_url=https://hooks.slack.com/...
```

Or edit `~/.config/ddos-toolkit/config.yaml` directly.

## System Requirements

| Component | Minimum |
|-----------|---------|
| Python | 3.11+ |
| OS | Linux, macOS |
| Root | Required for SYN flood and firewall (optional) |
| Dependencies | See [requirements.txt](requirements.txt) |

## Testing

```bash
pip install pytest pytest-asyncio
python3 -m pytest tests/ -v
# 40 passed in 0.30s
```

## Disclaimer

This tool is provided for **educational and authorized testing purposes only**. Unauthorized use against systems you do not own is **illegal** and may result in criminal prosecution.

See [DISCLAIMER.md](DISCLAIMER.md) for full legal details.

## Security

Found a vulnerability? Please see [SECURITY.md](SECURITY.md) for responsible disclosure.

## License

MIT — See [LICENSE](LICENSE) for details.

---

<p align="center">
  <sub>Built with Python, Textual, and a passion for cybersecurity education.</sub>
</p>
