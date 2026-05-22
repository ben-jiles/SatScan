import pytest
from src.ai.ollama_client import SatScanAI

def test_ai_explanation():
    ai = SatScanAI(model="llama3.2:3b")
    finding = {"description": "Duplicate sequence counters", "severity": "HIGH", "check_type": "Replay Detection"}
    explanation = ai.explain_finding(finding)
    assert isinstance(explanation, str)
    assert len(explanation) > 10
