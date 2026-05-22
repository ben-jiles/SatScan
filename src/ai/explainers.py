from typing import List, Dict
from .ollama_client import SatScanAI

def enrich_findings_with_ai(findings: List[Dict], model: str = "llama3.2") -> List[Dict]:
    """Batch enrich findings with AI explanations."""
    ai = SatScanAI(model=model)
    for finding in findings:
        finding["ai_explanation"] = ai.explain_finding(finding)
    return findings
