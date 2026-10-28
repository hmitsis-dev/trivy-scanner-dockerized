from __future__ import annotations

from typing import Any

from .config import Settings
from .scanner import iter_findings

MAX_PROMPT_FINDINGS = 10


class AIClient:
    def __init__(self, settings: Settings) -> None:
        try:
            from llama_cpp import Llama
        except ImportError as exc:  # pragma: no cover - optional dependency
            raise RuntimeError(
                "AI remediation enabled but llama-cpp-python is not installed (pip install 'trivy-scanner-api[ai]')"
            ) from exc
        self.settings = settings
        self.model = Llama(model_path=settings.ai_model_path, n_ctx=settings.ai_context_tokens, n_batch=256)

    def generate_remediation(self, report: dict[str, Any]) -> str | None:
        output = self.model(
            prompt=build_prompt(report),
            max_tokens=self.settings.ai_max_output_tokens,
            temperature=self.settings.ai_temperature,
            stop=["</s>", "###"],
        )
        choices = output.get("choices")
        if not choices:
            return None
        text = choices[0].get("text")
        return text.strip() if text else None


def build_prompt(report: dict[str, Any]) -> str:
    lines = []
    for finding in iter_findings(report):
        if len(lines) >= MAX_PROMPT_FINDINGS:
            break
        identifier = finding.get("VulnerabilityID") or finding.get("ID") or finding.get("RuleID")
        description = (finding.get("Description") or finding.get("Title") or "").replace("\n", " ")
        lines.append(f"- [{finding.get('Severity')}] {identifier} in {finding['target']}: {description[:160]}")
    findings = "\n".join(lines) or "- No findings reported"
    return (
        "You are an experienced security engineer. Given the following Trivy findings, "
        "suggest concise remediation steps and, where possible, provide configuration or dependency changes.\n\n"
        f"Findings:\n{findings}\n\n"
        "Respond with actionable steps in bullet points, keeping each recommendation to a single sentence."
    )
