"""OpenAI-compatible chat-completions client."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

import httpx


class ProviderError(RuntimeError):
    """A safe provider error without request secrets or provider payloads."""

    def __init__(self, message: str, status_code: int | None = None) -> None:
        super().__init__(message)
        self.status_code = status_code


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


def _models_endpoint(base_url: str) -> str:
    normalized = base_url.rstrip("/")
    if normalized.endswith("/chat/completions"):
        normalized = normalized.removesuffix("/chat/completions")
    if normalized.endswith("/v1"):
        return f"{normalized}/models"
    return f"{normalized}/v1/models"


def _raise_for_provider_error(response: httpx.Response) -> None:
    if response.status_code < 400:
        return
    if response.status_code == 429:
        retry_after = response.headers.get("retry-after")
        suffix = f" Retry after {retry_after} seconds." if retry_after and retry_after.isdecimal() else " Retry later."
        raise ProviderError(f"Model provider rate limited the request.{suffix}", status_code=429)
    raise ProviderError(f"Model provider returned HTTP {response.status_code}", status_code=response.status_code)


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
        # Model providers are configured explicitly per model. Do not inherit unrelated
        # SOCKS/HTTP proxy variables from the host process.
        async with httpx.AsyncClient(timeout=httpx.Timeout(60.0, connect=10.0), trust_env=False) as client:
            response = await client.post(
                _endpoint(base_url),
                headers={"Authorization": f"Bearer {api_key}"},
                json=request_body,
            )
    except httpx.HTTPError as exc:
        raise ProviderError("Could not reach the configured model provider") from exc

    _raise_for_provider_error(response)

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


async def available_models(*, base_url: str, api_key: str) -> list[str]:
    """Retrieve model IDs from an OpenAI-compatible ``/v1/models`` endpoint."""
    try:
        async with httpx.AsyncClient(timeout=httpx.Timeout(30.0, connect=10.0), trust_env=False) as client:
            response = await client.get(
                _models_endpoint(base_url),
                headers={"Authorization": f"Bearer {api_key}"},
            )
    except httpx.HTTPError as exc:
        raise ProviderError("Could not reach the configured model provider") from exc
    _raise_for_provider_error(response)
    try:
        data = response.json().get("data")
        if not isinstance(data, list):
            raise ValueError("missing data array")
        models = {entry["id"].strip() for entry in data if isinstance(entry, dict) and isinstance(entry.get("id"), str) and entry["id"].strip()}
        return sorted(models, key=str.casefold)[:1000]
    except (AttributeError, TypeError, ValueError) as exc:
        raise ProviderError("Model provider returned an invalid models response") from exc
