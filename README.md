# SatScan - Intelligent Satellite Cybersecurity Auditor

**AI-Enhanced CCSDS TM/TC Link Security Scanner**

![SatScan Banner](https://via.placeholder.com/800x250/0A2540/FFFFFF?text=SatScan+-+Satellite+Cybersecurity)

## Overview

SatScan is a lightweight, Python-based tool designed to parse, audit, and analyze CCSDS Telemetry (TM) and Telecommand (TC) packets for security anomalies. It combines deterministic rule-based checks, lightweight ML anomaly detection, and local LLM (Ollama) explanations — purpose-built for operators, red teams, and mission engineers securing high-assurance satellite systems.

**Key Use Cases**:
- Rapid auditing of ground station captures
- Replay/spoofing detection in LEO constellations
- Training and education (Hack-A-Sat, CubeSat teams)
- Integration into Azure SOAR pipelines

---

## Features

- **CCSDS Parsing**: Supports TM/TC frames, Space Packets, raw binary, and PCAP
- **Security Checks**: Replay detection, authentication gaps, weak crypto hints, header anomalies
- **MITRE SPARTA Mapping**: Automatic mapping to space-specific ATT&CK techniques
- **AI Layer**: Local Ollama explanations + agentic investigation
- **ML Anomaly Detection**: Isolation Forest on sequence and payload patterns
- **Reporting**: Rich HTML, PDF, and JSON (Azure Sentinel ready)
- **Deployment**: Docker, CLI, optional Streamlit UI

---

## Quick Start

### 1. Installation

```bash
git clone https://github.com/ben-jiles/SatScan.git
cd SatScan
pip install -e .[ai,dev]
```

### 2. Generate Test Samples

```bash
python -c "
from src.parser.ccsds_parser import CCSDSParser
from pathlib import Path
CCSDSParser().generate_synthetic_samples(Path('samples/synthetic'))
"
```

### 3. Run Scans

```bash
# Basic parse
satscan parse samples/synthetic/replay_attack.bin --output table

# Full AI-powered security scan
satscan scan samples/synthetic/replay_attack.bin --ai --ml --output html

# With agent investigation
satscan scan samples/synthetic/replay_attack.bin --ai --agent "Analyze potential replay attack and recommend mitigations"
```

---

## Command Reference

| Command | Description |
|---------|-------------|
| `satscan parse <file>` | Parse packets only |
| `satscan scan <file>` | Full security audit |
| `satscan version` | Show version info |

**Options**:
- `--ai` → Enable LLM explanations
- `--ml` → Enable ML anomaly detection
- `--agent "prompt"` → Run agentic reasoning
- `--output html/json/pdf`

---

## Architecture

```
SatScan/
├── src/parser/          → CCSDS parsing
├── src/checks/          → Rule engine + SPARTA
├── src/ai/              → Ollama + ML
├── src/reporter.py      → Multi-format reports
└── src/cli.py           → Typer CLI
```

---

## For Satellite Operators (Starshield / NRO Context)

- Focuses on real threats: RF spoofing, command replay, weak link encryption
- Designed for air-gapped / high-assurance environments
- Extensible to ground station ICS/SCADA log correlation
- Future: Azure Functions + Sentinel integration

---

## Development & Contributing

See `docs/getting_started.md` and `docs/contributing.md`.

**Pre-commit hooks** and full CI/CD are enabled.

---

## License

MIT License — Free to use, modify, and contribute.

---

**Built for securing the next generation of proliferated LEO constellations.**

*Questions? Open an issue or reach out.*
