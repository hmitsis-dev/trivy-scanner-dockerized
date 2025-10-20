from __future__ import annotations

from functools import lru_cache
from typing import Any, Dict, Optional

from .config import settings

try:
    from llama_cpp import Llama  # type: ignore
except ImportError:  # pragma: no cover - optional dependency
    Llama = None  # type: ignore


class AIClient:
    def __init__(self) -> None:
        if not settings.ai_enabled:
            self.enabled = False
            self.model = None
            return
        if Llama is None:
            raise RuntimeError("AI remediation enabled but llama-cpp-python is not installed")
        self.model = Llama(
            model_path=settings.ai_model_path,
            n_ctx=settings.ai_context_tokens,
            temperature=settings.ai_temperature,
            n_batch=256,
        )
        self.enabled = True

    def generate_remediation(self, report: Dict[str, Any]) -> Optional[str]:
        if not self.enabled or self.model is None:
            return None
        summary = _build_prompt(report)
        output = self.model(
            prompt=summary,
            max_tokens=settings.ai_max_output_tokens,
            stop=["</s>", "###"],
        )
        choices = output.get("choices")
        if not choices:
            return None
        text = choices[0].get("text")
        if not text:
            return None
        return text.strip()


def _build_prompt(report: Dict[str, Any]) -> str:
    high_risk = []
    for result in report.get("Results", []) or []:
        target = result.get("Target", "unknown")
        vulns = result.get("Vulnerabilities", []) or []
        for vuln in vulns[:10]:  # limit prompt size
            description = (vuln.get("Description") or "").replace("\n", " ")
            high_risk.append(
                f"- [{vuln.get('Severity')}] {vuln.get('VulnerabilityID')} in {target}: {description[:160]}"
            )
    findings = "\n".join(high_risk) or "- No vulnerabilities reported"
    return (
        "You are an experienced security engineer. Given the following Trivy findings, "
        "suggest concise remediation steps and, where possible, provide configuration or dependency changes.\n\n"
        f"Findings:\n{findings}\n\n"
        "Respond with actionable steps in bullet points, keeping each recommendation to a single sentence."
    )


@lru_cache(maxsize=1)
def get_ai_client() -> AIClient:
    return AIClient()
