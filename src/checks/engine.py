from typing import List, Dict
from src.parser.packet_models import ParsedPacket
from .replay_check import ReplayCheck
from .auth_check import AuthCheck
from .crypto_hint import CryptoHintCheck
from .anomaly_detector import AnomalyDetectorCheck
from src.sparta_mapper import SpartaMapper

class SecurityCheckEngine:
    def __init__(self, enable_ml: bool = True):
        self.checks = [
            ReplayCheck(),
            AuthCheck(),
            CryptoHintCheck(),
            AnomalyDetectorCheck(enable_ml=enable_ml)
        ]

    def run_all(self, packets: List[ParsedPacket]) -> List[Dict]:
        all_findings = []
        for check in self.checks:
            findings = check.run(packets)
            for f in findings:
                SpartaMapper.enrich_finding(f)
            all_findings.extend(findings)
        return all_findings
