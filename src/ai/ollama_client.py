import logging
from typing import Dict, List, Optional, Any
import ollama
from pathlib import Path

from src.config import SatScanConfig

logger = logging.getLogger(__name__)

class SatScanAI:
    """Core AI client for explanations and agentic reasoning."""

    def __init__(self, model: str = None):
        self.config = SatScanConfig()
        self.model = model or self.config.default_model
        self._ensure_model()

    def _ensure_model(self):
        """Pull model if not available (graceful in air-gapped)."""
        try:
            models = ollama.list()
            if not any(m['name'].startswith(self.model) for m in models.get('models', [])):
                logger.info(f"Pulling model {self.model}...")
                ollama.pull(self.model)
        except Exception as e:
            logger.warning(f"Could not check/pull model (air-gapped?): {e}")

    def explain_finding(self, finding: Dict, context: str = "") -> str:
        """Generate natural language explanation + operator guidance."""
        prompt_path = Path("models/prompts/explain_finding.txt")
        system_prompt = prompt_path.read_text() if prompt_path.exists() else self._default_explain_prompt()

        user_content = f"""
Finding: {finding.get('description')}
Check Type: {finding.get('check_type')}
Severity: {finding.get('severity')}
SPARTA: {finding.get('sparta_id')} - {finding.get('technique', '')}
Context: {context}
"""

        try:
            response = ollama.chat(
                model=self.model,
                messages=[
                    {"role": "system", "content": system_prompt},
                    {"role": "user", "content": user_content}
                ],
                temperature=0.3
            )
            return response['message']['content'].strip()
        except Exception as e:
            logger.error(f"AI explanation failed: {e}")
            return "AI explanation unavailable (Ollama not running or model issue)."

    def run_agent(self, investigation_prompt: str, findings: List[Dict]) -> str:
        """Lightweight agentic investigation."""
        context = "\n".join([f"- {f['description']} ({f.get('sparta_id')})" for f in findings])
        
        prompt = f"""
You are a senior satellite cybersecurity analyst for Starshield / NRO missions.
Findings:
{context}

User Request: {investigation_prompt}

Provide prioritized recommendations, potential TTPs, and mitigation steps.
"""
        try:
            response = ollama.chat(
                model=self.model,
                messages=[{"role": "user", "content": prompt}],
                temperature=0.4
            )
            return response['message']['content'].strip()
        except Exception as e:
            return f"Agent unavailable: {str(e)}"

    def _default_explain_prompt(self) -> str:
        return """You are an expert satellite cybersecurity analyst specializing in CCSDS TM/TC links for proliferated LEO constellations like Starshield.
Focus on military relevance, SPARTA mapping, and actionable recommendations for operators."""
