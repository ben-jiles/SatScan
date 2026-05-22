# Getting Started with SatScan

## Installation
```bash
git clone https://github.com/yourusername/SatScan.git
cd SatScan
pip install -e .[ai]
```

## Quickstart
```bash
# Parse only
satscan parse samples/synthetic/replay_attack.bin --output table

# Full AI-powered scan
satscan scan samples/synthetic/replay_attack.bin --ai --ml --output html
```

## Hardware (Ground Station)
- RTL-SDR + GNU Radio for live captures
- Save as ```.pcap``` or raw bninary

```text

**`docs/threat_models.md`**
```markdown
# Threat Models - Starshield / LEO Focus

- **IA-0001**: RF Jamming / Spoofing
- **LM-0005**: Command Link Tampering (Replay, Injection)
- **EX-0009**: Weak Encryption on TM/TC links

SatScan maps directly to MITRE SPARTA.
```
