"""OpenAI-compatible chat-completions client."""

from __future__ import annotations

import os
import json
from ipaddress import ip_address
from dataclasses import dataclass
from typing import Any, AsyncIterator
from urllib.parse import urlparse

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


@dataclass(frozen=True)
class CompletionChunk:
    content: str = ""
    usage: Usage | None = None
    finish_reason: str | None = None


def _is_local_or_private_base_url(base_url: str) -> bool:
    hostname = urlparse(base_url).hostname
    if not hostname:
        return False
    normalized = hostname.casefold()
    if normalized in {"localhost", "localhost.localdomain"} or normalized.endswith(".localhost"):
        return True
    try:
        address = ip_address(normalized)
    except ValueError:
        return False
    return address.is_loopback or address.is_private or address.is_link_local


def _trust_environment_proxy(base_url: str) -> bool:
    """Allow deployments with an explicit outbound proxy to reach providers.

    Provider traffic is always initiated from server-side configuration. Honour
    standard proxy variables by default, while allowing hardened/direct-only
    deployments to opt out with ``PROVIDER_TRUST_ENV=false``.
    """
    if _is_local_or_private_base_url(base_url):
        return False
    value = os.getenv("PROVIDER_TRUST_ENV", "true").strip().lower()
    return value in {"1", "true", "yes", "on"}


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


def _provider_headers(api_key: str) -> dict[str, str]:
    stripped = api_key.strip()
    if not stripped:
        return {}
    return {"Authorization": f"Bearer {stripped}"}


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
        async with httpx.AsyncClient(
            timeout=httpx.Timeout(60.0, connect=10.0), trust_env=_trust_environment_proxy(base_url)
        ) as client:
            response = await client.post(
                _endpoint(base_url),
                headers=_provider_headers(api_key),
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


def _usage_from_payload(payload: dict[str, Any]) -> Usage | None:
    raw_usage = payload.get("usage")
    if not isinstance(raw_usage, dict):
        return None
    has_complete_usage = "prompt_tokens" in raw_usage and "completion_tokens" in raw_usage
    return Usage(
        prompt_tokens=int(raw_usage.get("prompt_tokens") or 0),
        completion_tokens=int(raw_usage.get("completion_tokens") or 0),
        reported=has_complete_usage,
    )


async def stream_chat_completion(
    *,
    base_url: str,
    api_key: str,
    model_name: str,
    messages: list[dict[str, str]],
    temperature: float = 0.1,
    max_tokens: int | None = None,
) -> AsyncIterator[CompletionChunk]:
    request_body: dict[str, Any] = {
        "model": model_name,
        "messages": messages,
        "temperature": temperature,
        "stream": True,
        "stream_options": {"include_usage": True},
    }
    if max_tokens is not None:
        request_body["max_tokens"] = max_tokens
    try:
        async with httpx.AsyncClient(
            timeout=httpx.Timeout(120.0, connect=10.0), trust_env=_trust_environment_proxy(base_url)
        ) as client:
            async with client.stream(
                "POST",
                _endpoint(base_url),
                headers=_provider_headers(api_key),
                json=request_body,
            ) as response:
                _raise_for_provider_error(response)
                async for line in response.aiter_lines():
                    stripped = line.strip()
                    if not stripped or stripped.startswith(":"):
                        continue
                    if not stripped.startswith("data:"):
                        continue
                    data = stripped.removeprefix("data:").strip()
                    if data == "[DONE]":
                        break
                    try:
                        payload = json.loads(data)
                    except json.JSONDecodeError as exc:
                        raise ProviderError("Model provider returned an invalid streaming response") from exc
                    usage = _usage_from_payload(payload)
                    choices = payload.get("choices")
                    content = ""
                    finish_reason = None
                    if isinstance(choices, list) and choices:
                        choice = choices[0] if isinstance(choices[0], dict) else {}
                        delta = choice.get("delta") if isinstance(choice, dict) else {}
                        message = choice.get("message") if isinstance(choice, dict) else {}
                        if isinstance(delta, dict):
                            raw_content = delta.get("content")
                            content = raw_content if isinstance(raw_content, str) else ""
                        elif isinstance(message, dict):
                            raw_content = message.get("content")
                            content = raw_content if isinstance(raw_content, str) else ""
                        raw_finish_reason = choice.get("finish_reason") if isinstance(choice, dict) else None
                        finish_reason = raw_finish_reason if isinstance(raw_finish_reason, str) else None
                    if content or usage or finish_reason:
                        yield CompletionChunk(content=content, usage=usage, finish_reason=finish_reason)
    except ProviderError:
        raise
    except httpx.HTTPError as exc:
        raise ProviderError("Could not reach the configured model provider") from exc


async def available_models(*, base_url: str, api_key: str) -> list[str]:
    """Retrieve model IDs from an OpenAI-compatible ``/v1/models`` endpoint."""
    try:
        async with httpx.AsyncClient(
            timeout=httpx.Timeout(30.0, connect=10.0), trust_env=_trust_environment_proxy(base_url)
        ) as client:
            response = await client.get(
                _models_endpoint(base_url),
                headers=_provider_headers(api_key),
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
