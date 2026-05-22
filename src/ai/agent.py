from typing import List, Dict
from .ollama_client import SatScanAI

class SatScanAgent:
    """Simple agent for deeper investigation."""

    def __init__(self, model: str = "llama3.2"):
        self.ai = SatScanAI(model)

    def investigate(self, query: str, findings: List[Dict], packets_count: int) -> str:
        """Run agentic analysis."""
        return self.ai.run_agent(
            investigation_prompt=query,
            findings=findings
        )
