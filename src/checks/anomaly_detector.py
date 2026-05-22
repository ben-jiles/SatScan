from typing import List, Dict
from .base import SecurityCheck
from src.parser.packet_models import ParsedPacket
from src.ai.ml_anomaly import MLAnomalyDetector

class AnomalyDetectorCheck(SecurityCheck):
    name = "General Anomaly Detector"
    description = "Detects malformed headers + ML-based statistical anomalies."

    def __init__(self, enable_ml: bool = True):
        self.ml_detector = MLAnomalyDetector() if enable_ml else None

    def run(self, packets: List[ParsedPacket]) -> List[Dict]:
        findings = []

        # Rule-based checks (from Task 1)
        for i, pkt in enumerate(packets):
            if pkt.header.apid is None or pkt.header.apid > 2047:
                findings.append(self._create_finding(
                    packet_index=i,
                    description="Invalid or out-of-range APID detected.",
                    severity="MEDIUM",
                    sparta_id="IA-0006"
                ))
            if pkt.header.packet_length != len(pkt.payload) + 6:  # Basic header size
                findings.append(self._create_finding(
                    packet_index=i,
                    description="Packet length mismatch - possible corruption or tampering.",
                    severity="HIGH"
                ))

        # ML-based anomalies
        if self.ml_detector:
            ml_findings = self.ml_detector.detect_anomalies(packets)
            findings.extend(ml_findings)

        return findings
