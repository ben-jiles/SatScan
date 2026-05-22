from typing import List, Dict
from collections import defaultdict
from .base import SecurityCheck
from src.parser.packet_models import ParsedPacket

class ReplayCheck(SecurityCheck):
    name = "Replay Detection"
    description = "Detects potential replay attacks via duplicate or out-of-order sequence counters (critical for TC links)."

    def run(self, packets: List[ParsedPacket]) -> List[Dict]:
        findings = []
        seq_map = defaultdict(list)

        for i, pkt in enumerate(packets):
            seq = pkt.header.sequence_count
            scid = pkt.header.scid
            key = (scid, pkt.header.vcid)
            seq_map[key].append((i, seq))

        for key, entries in seq_map.items():
            seqs = [s for _, s in entries]
            if len(seqs) != len(set(seqs)):
                findings.append(self._create_finding(
                    packet_index=entries[0][0],
                    description=f"Duplicate sequence counters detected for SCID/VCID {key} - possible replay attack.",
                    severity="HIGH",
                    sparta_id="LM-0005"  # Command Link Tampering / Replay
                ))

            # Check for large gaps or rollback (simplified)
            if len(seqs) > 1 and max(seqs) - min(seqs) > 1000 and sorted(seqs) != seqs:
                findings.append(self._create_finding(
                    packet_index=entries[0][0],
                    description="Sequence counter anomalies detected - potential replay or injection.",
                    severity="MEDIUM",
                    sparta_id="IA-0001"
                ))

        return findings
