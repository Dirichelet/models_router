"""Lazy local GGUF inference for redaction and classification.

The optional llama-cpp dependency is deliberately imported only when a local
model is configured. Normal OpenAI-compatible deployments do not need it.
"""

from __future__ import annotations

import asyncio
from dataclasses import dataclass
from pathlib import Path
from threading import Lock
from typing import Any

from .provider import Completion, Usage


class LocalModelError(ValueError):
    """A local GGUF model could not be loaded or did not return text."""


def local_runtime_error() -> str | None:
    """Return an actionable setup error without loading a model into memory."""
    try:
        import llama_cpp  # noqa: F401
    except ImportError:
        return "Local GGUF support requires `uv sync --extra local-gguf` before startup"
    return None


@dataclass(frozen=True)
class LocalModelOptions:
    path: Path
    chat_format: str | None
    context_tokens: int
    gpu_layers: int
    threads: int


class LocalGGUFModel:
    """One serialized llama.cpp model instance; llama.cpp contexts are not thread-safe."""

    def __init__(self, options: LocalModelOptions) -> None:
        runtime_error = local_runtime_error()
        if runtime_error:
            raise LocalModelError(runtime_error)
        try:
            from llama_cpp import Llama

            kwargs: dict[str, Any] = {
                "model_path": str(options.path),
                "n_ctx": options.context_tokens,
                "n_gpu_layers": options.gpu_layers,
                "verbose": False,
            }
            if options.chat_format:
                kwargs["chat_format"] = options.chat_format
            if options.threads > 0:
                kwargs["n_threads"] = options.threads
            self._model = Llama(**kwargs)
        except Exception as exc:
            raise LocalModelError(f"Could not load local GGUF model {options.path.name}: {exc}") from exc
        self._lock = Lock()

    def complete(self, messages: list[dict[str, str]], temperature: float, max_tokens: int | None) -> Completion:
        try:
            with self._lock:
                response = self._model.create_chat_completion(
                    messages=messages,
                    temperature=temperature,
                    max_tokens=max_tokens,
                )
            choices = response.get("choices") if isinstance(response, dict) else None
            message = choices[0].get("message") if isinstance(choices, list) and choices else None
            content = message.get("content") if isinstance(message, dict) else None
            if not isinstance(content, str) or not content.strip():
                raise LocalModelError("Local GGUF model returned an empty completion")
            return Completion(content=content.strip(), usage=Usage(reported=False))
        except LocalModelError:
            raise
        except Exception as exc:
            raise LocalModelError(f"Local GGUF inference failed: {exc}") from exc


_models: dict[LocalModelOptions, LocalGGUFModel] = {}
_models_lock = Lock()


def _model(options: LocalModelOptions) -> LocalGGUFModel:
    with _models_lock:
        if options not in _models:
            _models[options] = LocalGGUFModel(options)
        return _models[options]


async def local_chat_completion(
    options: LocalModelOptions,
    messages: list[dict[str, str]],
    temperature: float = 0.1,
    max_tokens: int | None = None,
) -> Completion:
    """Run blocking GGUF inference without blocking FastAPI's event loop."""
    return await asyncio.to_thread(_model(options).complete, messages, temperature, max_tokens)
