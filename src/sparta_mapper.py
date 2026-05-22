"""
MITRE SPARTA Mapper for SatScan
Maps findings to MITRE SPARTA (Space Attack Tactics & Techniques)
"""

from typing import Dict, Optional

class SpartaMapper:
    """Maps security findings to MITRE SPARTA tactics/techniques."""

    # Key SPARTA mappings relevant to CCSDS TM/TC and Starshield
    MAPPINGS = {
        "Replay Detection": {
            "tactic": "Impact",
            "technique": "LM-0005 - Command Link Tampering",
            "sparta_id": "LM-0005",
            "description": "Adversary may attempt to replay valid commands to disrupt satellite operations."
        },
        "Authentication Check": {
            "tactic": "Initial Access",
            "technique": "IA-0003 - Valid Accounts",
            "sparta_id": "LM-0005",
            "description": "Lack of authentication allows spoofing of telecommands."
        },
        "Crypto Weakness Hint": {
            "tactic": "Defense Evasion",
            "technique": "EX-0009 - Weak Encryption",
            "sparta_id": "EX-0009",
            "description": "Unencrypted or weakly encrypted payloads are susceptible to eavesdropping and injection."
        },
        "General Anomaly Detector": {
            "tactic": "Initial Access",
            "technique": "IA-0001 - RF Interference / Jamming",
            "sparta_id": "IA-0001",
            "description": "Anomalous packets may indicate RF spoofing or jamming attempts."
        }
    }

    @staticmethod
    def enrich_finding(finding: Dict) -> Dict:
        """Enrich a finding with SPARTA mapping."""
        check_type = finding.get("check_type")
        if check_type in SpartaMapper.MAPPINGS:
            mapping = SpartaMapper.MAPPINGS[check_type]
            finding["sparta_id"] = mapping["sparta_id"]
            finding["tactic"] = mapping["tactic"]
            finding["technique"] = mapping["technique"]
            finding["sparta_description"] = mapping["description"]
        return finding

    @staticmethod
    def get_all_tactics() -> Dict:
        """Return full mapping for documentation."""
        return SpartaMapper.MAPPINGS
