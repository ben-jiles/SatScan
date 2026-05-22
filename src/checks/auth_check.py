from typing import List, Dict
from .base import SecurityCheck
from src.parser.packet_models import ParsedPacket

class AuthCheck(SecurityCheck):
    name = "Authentication Check"
    description = "Detects missing or weak authentication fields (e.g., no SDLS, plain TC)."

    def run(self, packets: List[ParsedPacket]) -> List[Dict]:
        findings = []
        for i, pkt in enumerate(packets):
            # Placeholder: In full parser, check for security headers / MAC / SDLS flags
            if len(pkt.payload) > 0 and not pkt.metadata.get("has_auth_header", False):
                findings.append(self._create_finding(
                    packet_index=i,
                    description="Packet lacks visible authentication (SDLS or equivalent). High risk of spoofing.",
                    severity="HIGH",
                    sparta_id="LM-0005",  # Command Link Tampering
                    recommendation="Enable CCSDS SDLS authentication + anti-replay counters."
                ))
        return findings
