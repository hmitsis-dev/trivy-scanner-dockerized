from __future__ import annotations

import json
from typing import Any, Dict

import httpx

from .config import settings


def send_webhook(payload: Dict[str, Any]) -> None:
    if not settings.webhook_url:
        return
    headers = {"Content-Type": "application/json"}
    for header in settings.webhook_headers:
        if ":" not in header:
            continue
        key, value = header.split(":", 1)
        headers[key.strip()] = value.strip()
    with httpx.Client(timeout=10.0) as client:
        response = client.post(settings.webhook_url, headers=headers, content=json.dumps(payload))
        response.raise_for_status()
