from typing import List, Dict
from .base import SecurityCheck
from src.parser.packet_models import ParsedPacket

class AnomalyDetectorCheck(SecurityCheck):
    name = "General Anomaly Detector"
    description = "Detects malformed headers, unexpected APIDs, etc."

    def run(self, packets: List[ParsedPacket]) -> List[Dict]:
        findings = []
        for i, pkt in enumerate(packets):
            if pkt.header.apid is None or pkt.header.apid > 2047:  # CCSDS limit
                findings.append(self._create_finding(
                    packet_index=i,
                    description="Invalid or out-of-range APID detected.",
                    severity="MEDIUM",
                    sparta_id="IA-0006"
                ))
            if pkt.header.packet_length != len(pkt.payload):
                findings.append(self._create_finding(
                    packet_index=i,
                    description="Packet length mismatch - possible tampering.",
                    severity="HIGH"
                ))
        return findings
