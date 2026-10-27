from __future__ import annotations

from typing import Any

import httpx


def format_text(payload: dict[str, Any]) -> str:
    counts = ", ".join(f"{name}: {count}" for name, count in payload.get("severity_counts", {}).items())
    text = f"Trivy scan {payload.get('status', 'completed')} ({counts}). Report: {payload.get('report_uri')}"
    if payload.get("ai_recommendation"):
        text += f"\n{payload['ai_recommendation']}"
    return text


def send_webhook(url: str | None, payload: dict[str, Any], headers: dict[str, str] | None = None) -> None:
    if not url:
        return
    # Slack and Teams incoming webhooks require a top-level "text" field.
    body = {"text": format_text(payload), **payload}
    with httpx.Client(timeout=10.0) as client:
        response = client.post(url, headers=headers or {}, json=body)
        response.raise_for_status()
