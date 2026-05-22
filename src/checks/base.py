from abc import ABC, abstractmethod
from typing import List, Dict
from src.parser.packet_models import ParsedPacket

class SecurityCheck(ABC):
    """Base class for all SatScan security checks."""

    name: str
    description: str
    severity_levels = {"HIGH": 3, "MEDIUM": 2, "LOW": 1}

    @abstractmethod
    def run(self, packets: List[ParsedPacket]) -> List[Dict]:
        """Run check and return findings."""
        pass

    def _create_finding(self, packet_index: int, description: str, severity: str = "MEDIUM",
                       sparta_id: str = None, recommendation: str = None) -> Dict:
        return {
            "id": f"{self.name}_{packet_index}",
            "check_type": self.name,
            "description": description,
            "severity": severity,
            "sparta_id": sparta_id,
            "packet_index": packet_index,
            "recommendation": recommendation or "Review link configuration and enable SDLS where possible."
        }
