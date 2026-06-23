"""OpenAI-compatible chat-completions client."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

import httpx


class ProviderError(RuntimeError):
    """A safe provider error without request secrets or provider payloads."""


@dataclass(frozen=True)
class Usage:
    prompt_tokens: int = 0
    completion_tokens: int = 0
    reported: bool = True


@dataclass(frozen=True)
class Completion:
    content: str
    usage: Usage


def _endpoint(base_url: str) -> str:
    normalized = base_url.rstrip("/")
    if normalized.endswith("/chat/completions"):
        return normalized
    if normalized.endswith("/v1"):
        return f"{normalized}/chat/completions"
    return f"{normalized}/v1/chat/completions"


async def chat_completion(
    *,
    base_url: str,
    api_key: str,
    model_name: str,
    messages: list[dict[str, str]],
    temperature: float = 0.1,
    max_tokens: int | None = None,
) -> Completion:
    request_body: dict[str, Any] = {"model": model_name, "messages": messages, "temperature": temperature}
    if max_tokens is not None:
        request_body["max_tokens"] = max_tokens
    try:
        async with httpx.AsyncClient(timeout=httpx.Timeout(60.0, connect=10.0)) as client:
            response = await client.post(
                _endpoint(base_url),
                headers={"Authorization": f"Bearer {api_key}"},
                json=request_body,
            )
    except httpx.HTTPError as exc:
        raise ProviderError("Could not reach the configured model provider") from exc

    if response.status_code >= 400:
        raise ProviderError(f"Model provider returned HTTP {response.status_code}")

    try:
        payload: dict[str, Any] = response.json()
        content = payload["choices"][0]["message"]["content"]
        if not isinstance(content, str) or not content.strip():
            raise ValueError("empty completion")
        raw_usage = payload.get("usage")
        has_complete_usage = isinstance(raw_usage, dict) and "prompt_tokens" in raw_usage and "completion_tokens" in raw_usage
        raw_usage = raw_usage if isinstance(raw_usage, dict) else {}
        usage = Usage(
            prompt_tokens=int(raw_usage.get("prompt_tokens") or 0),
            completion_tokens=int(raw_usage.get("completion_tokens") or 0),
            reported=has_complete_usage,
        )
        return Completion(content=content.strip(), usage=usage)
    except (KeyError, IndexError, TypeError, ValueError) as exc:
        raise ProviderError("Model provider returned an invalid chat-completions response") from exc
