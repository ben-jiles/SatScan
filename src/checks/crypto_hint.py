from typing import List, Dict
from .base import SecurityCheck
from src.parser.packet_models import ParsedPacket

class CryptoHintCheck(SecurityCheck):
    name = "Crypto Weakness Hint"
    description = "Flags unencrypted payloads or known weak patterns."

    def run(self, packets: List[ParsedPacket]) -> List[Dict]:
        findings = []
        for i, pkt in enumerate(packets):
            # Simple heuristic: very short or repetitive payloads often indicate no encryption
            if len(pkt.payload) < 32 or pkt.payload.count(pkt.payload[:8]) > 3:
                findings.append(self._create_finding(
                    packet_index=i,
                    description="Payload appears unencrypted or uses weak/obvious patterns.",
                    severity="MEDIUM",
                    sparta_id="EX-0009",  # Exploit Code Flaws / Weak Crypto
                    recommendation="Implement CCSDS SDLS confidentiality services."
                ))
        return findings
