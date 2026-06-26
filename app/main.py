"""HTTP application for the privacy-aware model router."""

from __future__ import annotations

import asyncio
import hashlib
import hmac
import json
import logging
import re
import sqlite3
import time
import uuid
from collections import defaultdict, deque
from contextlib import asynccontextmanager
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path
from time import monotonic
from typing import Annotated, Any, AsyncIterator, Literal
from urllib.parse import urlparse

from fastapi import Cookie, Depends, FastAPI, Header, HTTPException, Request, Response, status
from fastapi.middleware.httpsredirect import HTTPSRedirectMiddleware
from fastapi.middleware.trustedhost import TrustedHostMiddleware
from fastapi.responses import FileResponse, StreamingResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field, ValidationError, field_validator
from starlette.middleware.base import BaseHTTPMiddleware

from .config import Settings
from .database import DEFAULT_RULES, Database
from .local_models import LocalModelOptions, local_chat_completion, local_runtime_error
from .provider import Completion, CompletionChunk, ProviderError, Usage, available_models as fetch_provider_models, chat_completion, stream_chat_completion
from .redaction import (
    KeywordRule as RedactionKeywordRule,
    LocalRedactorOptions,
    local_redact,
    local_redactor_runtime_error,
)
from .security import PasswordHasher, SecretBox, new_token, token_hash, validate_password_strength


logger = logging.getLogger(__name__)
settings = Settings.from_environment()
database = Database(settings.database_path)
secret_box = SecretBox(settings.fernet_key)
SESSION_COOKIE = "models_router_session"
STATIC_DIR = Path(__file__).parent / "static"
SENSITIVE_VALUE_PATTERNS = (
    re.compile(r"[A-Za-z0-9.!#$%&'*+/=?^_`{|}~-]+@[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?(?:\.[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?)+"),
    re.compile(r"(?<!\d)(?:\+?86[-\s]?)?1[3-9]\d{9}(?!\d)"),
    re.compile(r"(?<!\d)\d{15,19}(?:[Xx])?(?!\d)"),
    re.compile(r"(?<!\d)\d{6,14}(?!\d)"),
    re.compile(r"\b(?:sk|rk|pk|api)[_-][A-Za-z0-9_-]{16,}\b", re.IGNORECASE),
)


class PrivacyVerificationError(ValueError):
    """Raised before a redaction failure can be sent to routing or target providers."""


@dataclass
class ChatRun:
    user_id: int
    redactor_name: str | None = None
    router_name: str | None = None
    selected: sqlite3.Row | None = None
    redacted: str | None = None
    redaction_verified: bool = False
    redaction_applied: bool = False
    routing_reason: str | None = None
    prompt_tokens: int = 0
    completion_tokens: int = 0
    total_cost: float = 0.0
    cost_known: bool = True


def utc_now() -> datetime:
    return datetime.now(UTC)


def utc_text(value: datetime | None = None) -> str:
    return (value or utc_now()).isoformat()


class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next: Any) -> Response:
        response = await call_next(request)
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["Referrer-Policy"] = "same-origin"
        response.headers["Permissions-Policy"] = "camera=(), microphone=(), geolocation=()"
        response.headers["Content-Security-Policy"] = (
            "default-src 'self'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'; "
            "connect-src 'self'; img-src 'self' data:; style-src 'self'; script-src 'self'"
        )
        if settings.cookie_secure:
            response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
        return response


class LoginRateLimiter:
    """Process-local guard against password guessing. Deploy one app process per Compose stack."""

    def __init__(self, limit: int = 5, window_seconds: int = 60) -> None:
        self.limit = limit
        self.window_seconds = window_seconds
        self._attempts: dict[str, deque[float]] = defaultdict(deque)

    def allow(self, identity: str) -> bool:
        now = monotonic()
        attempts = self._attempts[identity]
        while attempts and attempts[0] < now - self.window_seconds:
            attempts.popleft()
        return len(attempts) < self.limit

    def fail(self, identity: str) -> None:
        self._attempts[identity].append(monotonic())

    def succeed(self, identity: str) -> None:
        self._attempts.pop(identity, None)


login_limiter = LoginRateLimiter()


class Credentials(BaseModel):
    username: str = Field(min_length=3, max_length=64, pattern=r"^[A-Za-z0-9_.-]+$")
    password: str = Field(min_length=12, max_length=256)

    @field_validator("password")
    @classmethod
    def validate_password_strength(cls, value: str) -> str:
        return validate_password_strength(value)


class BootstrapCredentials(Credentials):
    bootstrap_token: str = Field(default="", max_length=512)


class PasswordChange(BaseModel):
    current_password: str = Field(min_length=1, max_length=256)
    new_password: str = Field(min_length=12, max_length=256)

    @field_validator("new_password")
    @classmethod
    def validate_new_password_strength(cls, value: str) -> str:
        return Credentials.validate_password_strength(value)


def normalize_openai_v1_base_url(value: str) -> str:
    normalized = value.rstrip("/")
    parsed = urlparse(normalized)
    if parsed.scheme not in {"http", "https"} or not parsed.netloc:
        raise ValueError("base_url must be a complete http(s) URL")
    if not parsed.path.rstrip("/").endswith("/v1"):
        raise ValueError("base_url must end with /v1, for example https://provider.example/v1")
    return normalized


class ModelCreate(BaseModel):
    name: str = Field(min_length=1, max_length=80)
    role: Literal["router", "target"]
    base_url: str = Field(min_length=8, max_length=500)
    api_key: str = Field(min_length=1, max_length=1000)
    model_name: str = Field(min_length=1, max_length=200)
    input_price_per_million: float = Field(default=0, ge=0, le=1_000_000)
    output_price_per_million: float = Field(default=0, ge=0, le=1_000_000)
    is_active: bool = True

    @field_validator("base_url")
    @classmethod
    def validate_base_url(cls, value: str) -> str:
        return normalize_openai_v1_base_url(value)


class ModelUpdate(BaseModel):
    name: str | None = Field(default=None, min_length=1, max_length=80)
    role: Literal["router", "target"] | None = None
    base_url: str | None = Field(default=None, min_length=8, max_length=500)
    api_key: str | None = Field(default=None, max_length=1000)
    model_name: str | None = Field(default=None, min_length=1, max_length=200)
    input_price_per_million: float | None = Field(default=None, ge=0, le=1_000_000)
    output_price_per_million: float | None = Field(default=None, ge=0, le=1_000_000)
    is_active: bool | None = None

    @field_validator("base_url")
    @classmethod
    def validate_base_url(cls, value: str | None) -> str | None:
        if value is None:
            return value
        return ModelCreate.validate_base_url(value)


class ModelBatchCreate(BaseModel):
    models: list[ModelCreate] = Field(min_length=1, max_length=100)


class ProviderModelsRequest(BaseModel):
    base_url: str = Field(min_length=8, max_length=500)
    api_key: str = Field(min_length=1, max_length=1000)

    @field_validator("base_url")
    @classmethod
    def validate_base_url(cls, value: str) -> str:
        return normalize_openai_v1_base_url(value)


class RulesUpdate(BaseModel):
    redaction: str = Field(min_length=1, max_length=12_000)
    routing: str = Field(min_length=1, max_length=12_000)


class KeywordRuleCreate(BaseModel):
    phrase: str = Field(min_length=1, max_length=200)
    replacement: str = Field(default="[KEYWORD]", min_length=1, max_length=80)
    is_fuzzy: bool = False
    is_active: bool = True


class KeywordRuleUpdate(BaseModel):
    phrase: str | None = Field(default=None, min_length=1, max_length=200)
    replacement: str | None = Field(default=None, min_length=1, max_length=80)
    is_fuzzy: bool | None = None
    is_active: bool | None = None


class ChatHistoryMessage(BaseModel):
    role: Literal["user", "assistant"]
    content: str = Field(min_length=1, max_length=settings.max_message_chars)


class ChatRequest(BaseModel):
    message: str = Field(min_length=1, max_length=settings.max_message_chars)
    context: list[ChatHistoryMessage] = Field(default_factory=list, max_length=16)


class OpenAIMessage(BaseModel):
    role: str = Field(min_length=1, max_length=32)
    content: str | list[dict[str, Any]] | None = None
    tool_calls: list[dict[str, Any]] | None = None


class OpenAIChatCompletionRequest(BaseModel):
    model: str = Field(default="models-router", min_length=1, max_length=200)
    messages: list[OpenAIMessage] = Field(min_length=1, max_length=100)
    stream: bool = False
    temperature: float | None = Field(default=None, ge=0, le=2)


@asynccontextmanager
async def lifespan(_: FastAPI):
    database.initialize()
    yield


app = FastAPI(title="Models Router", version="0.1.0", lifespan=lifespan, docs_url=None, redoc_url=None)
app.add_middleware(TrustedHostMiddleware, allowed_hosts=settings.trusted_hosts)
if settings.force_https:
    app.add_middleware(HTTPSRedirectMiddleware)
app.add_middleware(SecurityHeadersMiddleware)
app.mount("/static", StaticFiles(directory=STATIC_DIR), name="static")


def _cookie_options() -> dict[str, Any]:
    return {
        "httponly": True,
        "secure": settings.cookie_secure,
        "samesite": "strict",
        "max_age": settings.session_hours * 60 * 60,
        "path": "/",
    }


def _unauthorized() -> HTTPException:
    return HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Authentication required")


def _service_api_unauthorized() -> HTTPException:
    return HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Invalid service API key",
        headers={"WWW-Authenticate": "Bearer"},
    )


def current_user(request: Request) -> dict[str, Any]:
    raw_token = request.cookies.get(SESSION_COOKIE)
    if not raw_token:
        raise _unauthorized()
    with database.connection() as connection:
        row = connection.execute(
            """
            SELECT users.id, users.username, sessions.csrf_hash, sessions.expires_at
            FROM sessions JOIN users ON users.id = sessions.user_id
            WHERE sessions.token_hash = ?
            """,
            (token_hash(raw_token),),
        ).fetchone()
        if not row:
            raise _unauthorized()
        expires_at = datetime.fromisoformat(row["expires_at"])
        if expires_at <= utc_now():
            connection.execute("DELETE FROM sessions WHERE token_hash = ?", (token_hash(raw_token),))
            raise _unauthorized()
        return dict(row)


def service_api_user(authorization: Annotated[str | None, Header(alias="Authorization")] = None) -> dict[str, Any]:
    if not authorization or not authorization.startswith("Bearer "):
        raise _service_api_unauthorized()
    raw_key = authorization.removeprefix("Bearer ").strip()
    if not raw_key.startswith("mr_"):
        raise _service_api_unauthorized()
    with database.connection() as connection:
        row = connection.execute(
            """
            SELECT users.id, users.username
            FROM service_api_keys JOIN users ON users.id = service_api_keys.user_id
            WHERE service_api_keys.key_hash = ?
            """,
            (token_hash(raw_key),),
        ).fetchone()
    if not row:
        raise _service_api_unauthorized()
    return dict(row)


def _openai_content_to_text(content: str | list[dict[str, Any]] | None) -> str:
    if isinstance(content, str):
        return content.strip()
    if not isinstance(content, list):
        return ""
    parts: list[str] = []
    for part in content:
        if not isinstance(part, dict):
            continue
        text = part.get("text") or part.get("input_text") or part.get("output_text")
        if isinstance(text, str):
            parts.append(text)
        elif isinstance(text, dict) and isinstance(text.get("value"), str):
            parts.append(text["value"])
    return "\n".join(parts).strip()


def _openai_messages_to_conversation(messages: list[OpenAIMessage]) -> str:
    rendered: list[str] = []
    for message in messages:
        content = _openai_content_to_text(message.content)
        if not content and message.tool_calls:
            content = f"Tool calls requested: {json.dumps(message.tool_calls, ensure_ascii=False)}"
        if content:
            rendered.append(f"[{message.role.upper()}]\n{content}")
    conversation = "\n\n".join(rendered).strip()
    if not conversation:
        raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail="messages must contain text content")
    return conversation


def _chat_request_from_openai_messages(messages: list[OpenAIMessage]) -> ChatRequest:
    conversation = _openai_messages_to_conversation(messages)
    try:
        return ChatRequest(message=conversation)
    except ValidationError as exc:
        raise HTTPException(
            status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
            detail=f"messages exceed the configured limit of {settings.max_message_chars} characters",
        ) from exc


def csrf_user(
    user: Annotated[dict[str, Any], Depends(current_user)],
    csrf_token: Annotated[str | None, Header(alias="X-CSRF-Token")] = None,
) -> dict[str, Any]:
    provided_hash = hashlib.sha256(csrf_token.encode("utf-8")).hexdigest() if csrf_token else ""
    if not csrf_token or not hmac.compare_digest(provided_hash, user["csrf_hash"]):
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Invalid CSRF token")
    return user


def _set_session(response: Response, user_id: int) -> str:
    session_token = new_token()
    csrf_token = new_token()
    expires_at = utc_now() + timedelta(hours=settings.session_hours)
    with database.connection() as connection:
        connection.execute(
            "INSERT INTO sessions(token_hash, csrf_hash, user_id, expires_at, created_at) VALUES (?, ?, ?, ?, ?)",
            (token_hash(session_token), token_hash(csrf_token), user_id, utc_text(expires_at), utc_text()),
        )
    response.set_cookie(SESSION_COOKIE, session_token, **_cookie_options())
    return csrf_token


def _serialise_model(row: sqlite3.Row) -> dict[str, Any]:
    try:
        secret_box.decrypt(row["api_key_encrypted"])
        credential_ready = True
    except ValueError:
        credential_ready = False
    return {
        "id": row["id"],
        "name": row["name"],
        "role": row["role"],
        "base_url": row["base_url"],
        "model_name": row["model_name"],
        "input_price_per_million": row["input_price_per_million"],
        "output_price_per_million": row["output_price_per_million"],
        "is_active": bool(row["is_active"]),
        "has_api_key": bool(row["api_key_encrypted"]),
        "credential_ready": credential_ready,
        "created_at": row["created_at"],
        "updated_at": row["updated_at"],
    }


def _rules() -> dict[str, str]:
    with database.connection() as connection:
        rows = connection.execute("SELECT name, content FROM rules").fetchall()
    return {row["name"]: row["content"] for row in rows}


def _keyword_rules(user_id: int) -> tuple[RedactionKeywordRule, ...]:
    with database.connection() as connection:
        rows = connection.execute(
            "SELECT phrase, replacement, is_fuzzy FROM keyword_rules WHERE user_id = ? AND is_active = 1 ORDER BY length(phrase) DESC, id ASC",
            (user_id,),
        ).fetchall()
    return tuple(
        RedactionKeywordRule(
            phrase=row["phrase"],
            replacement=row["replacement"],
            fuzzy=bool(row["is_fuzzy"]),
        )
        for row in rows
    )


def _local_classifier_options(path: Path) -> LocalModelOptions:
    return LocalModelOptions(
        path=path,
        chat_format=settings.local_gguf_chat_format,
        context_tokens=settings.local_gguf_context_tokens,
        gpu_layers=settings.local_gguf_gpu_layers,
        threads=settings.local_gguf_threads,
    )


def _local_classifier_label(path: Path) -> str:
    return f"本地 GGUF：{path.name}"


def _local_redactor_options() -> LocalRedactorOptions:
    if not settings.local_redactor_model_path:
        raise RuntimeError("Local redactor is not configured")
    return LocalRedactorOptions(
        privacy_filter_path=settings.local_redactor_model_path,
        chinese_ner_path=settings.local_chinese_ner_model_path,
        device=settings.local_redactor_device,
        min_score=settings.local_redactor_min_score,
    )


def _local_redactor_label(path: Path) -> str:
    return f"本地 Transformers：{path.name}"


def _active_pipeline() -> tuple[sqlite3.Row | None, sqlite3.Row | None, list[sqlite3.Row]]:
    with database.connection() as connection:
        redactor = connection.execute(
            "SELECT * FROM models WHERE role = 'redactor' AND is_active = 1 ORDER BY id DESC LIMIT 1"
        ).fetchone()
        router = connection.execute(
            "SELECT * FROM models WHERE role = 'router' AND is_active = 1 ORDER BY id DESC LIMIT 1"
        ).fetchone()
        targets = connection.execute(
            "SELECT * FROM models WHERE role = 'target' AND is_active = 1 ORDER BY id ASC"
        ).fetchall()
    # Redaction is deliberately never delegated to a Provider. Legacy rows remain
    # visible for migration but cannot enter the request pipeline.
    redactor = None
    if settings.local_classifier_model_path:
        router = None
    if not targets:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail="Configure at least one active target model first",
        )
    if settings.local_redactor_model_path and (runtime_error := local_redactor_runtime_error()):
        raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail=runtime_error)
    if settings.local_classifier_model_path and (runtime_error := local_runtime_error()):
        raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail=runtime_error)
    invalid_required_models = []
    for model in (redactor, router):
        if not model:
            continue
        try:
            secret_box.decrypt(model["api_key_encrypted"])
        except ValueError:
            invalid_required_models.append(model["name"])
    if invalid_required_models:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=f"Re-enter the API Key for: {', '.join(invalid_required_models)}",
        )
    available_targets = []
    for model in targets:
        try:
            secret_box.decrypt(model["api_key_encrypted"])
            available_targets.append(model)
        except ValueError:
            continue
    if not available_targets:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail="Re-enter the API Key for at least one active target model",
        )
    return redactor, router, available_targets


def _pipeline_status() -> dict[str, Any]:
    with database.connection() as connection:
        redactor = connection.execute(
            "SELECT name, api_key_encrypted FROM models WHERE role = 'redactor' AND is_active = 1 ORDER BY id DESC LIMIT 1"
        ).fetchone()
        router = connection.execute(
            "SELECT name, api_key_encrypted FROM models WHERE role = 'router' AND is_active = 1 ORDER BY id DESC LIMIT 1"
        ).fetchone()
        targets = connection.execute("SELECT name, api_key_encrypted FROM models WHERE role = 'target' AND is_active = 1").fetchall()
    redactor = None
    if settings.local_classifier_model_path:
        router = None
    invalid_required_credentials = []
    for model in (redactor, router):
        if not model:
            continue
        try:
            secret_box.decrypt(model["api_key_encrypted"])
        except ValueError:
            invalid_required_credentials.append(model["name"])
    invalid_targets = []
    for model in targets:
        try:
            secret_box.decrypt(model["api_key_encrypted"])
        except ValueError:
            invalid_targets.append(model["name"])
    invalid_credentials = [*invalid_required_credentials, *invalid_targets]
    available_targets = len(targets) - len(invalid_targets)
    runtime_errors = []
    if settings.local_redactor_model_path and (error := local_redactor_runtime_error()):
        runtime_errors.append(error)
    if settings.local_classifier_model_path and (error := local_runtime_error()):
        runtime_errors.append(error)
    runtime_error = "; ".join(runtime_errors) or None
    return {
        "redactor": (
            _local_redactor_label(settings.local_redactor_model_path)
            if settings.local_redactor_model_path
            else None
        ),
        "router": (
            _local_classifier_label(settings.local_classifier_model_path)
            if settings.local_classifier_model_path
            else router["name"] if router else None
        ),
        "redaction_mode": "local" if settings.local_redactor_model_path else "disabled",
        "routing_mode": "local" if settings.local_classifier_model_path else "provider" if router else "default",
        "active_targets": len(targets),
        "available_targets": available_targets,
        "invalid_credentials": invalid_credentials,
        "invalid_required_credentials": invalid_required_credentials,
        "invalid_targets": invalid_targets,
        "local_runtime_error": runtime_error,
        "ready": bool(available_targets and not invalid_required_credentials and not runtime_error),
    }


async def _invoke(
    model: sqlite3.Row,
    messages: list[dict[str, str]],
    temperature: float = 0.1,
    max_tokens: int | None = None,
) -> Completion:
    return await chat_completion(
        base_url=model["base_url"],
        api_key=secret_box.decrypt(model["api_key_encrypted"]),
        model_name=model["model_name"],
        messages=messages,
        temperature=temperature,
        max_tokens=max_tokens,
    )


async def _stream_invoke(
    model: sqlite3.Row,
    messages: list[dict[str, str]],
    temperature: float = 0.1,
    max_tokens: int | None = None,
) -> AsyncIterator[CompletionChunk]:
    async for chunk in stream_chat_completion(
        base_url=model["base_url"],
        api_key=secret_box.decrypt(model["api_key_encrypted"]),
        model_name=model["model_name"],
        messages=messages,
        temperature=temperature,
        max_tokens=max_tokens,
    ):
        yield chunk


def _cost(model: sqlite3.Row, usage: Usage) -> float:
    return round(
        (usage.prompt_tokens * float(model["input_price_per_million"]) + usage.completion_tokens * float(model["output_price_per_million"]))
        / 1_000_000,
        8,
    )


def _leaked_sensitive_values(original: str, redacted: str) -> list[str]:
    """Find high-confidence raw values that a redactor failed to remove.

    This is a fail-closed guard, not a replacement for the configurable redaction model.
    It deliberately only checks formats with a low false-positive risk.
    """
    redacted_normalized = redacted.casefold()
    leaked: list[str] = []
    for pattern in SENSITIVE_VALUE_PATTERNS:
        for match in pattern.finditer(original):
            value = match.group(0)
            if value.casefold() in redacted_normalized and value not in leaked:
                leaked.append(value)
    return leaked


def _choose_target(router_answer: str, targets: list[sqlite3.Row]) -> tuple[sqlite3.Row, str]:
    by_id = {target["id"]: target for target in targets}
    by_name = {target["name"]: target for target in targets}
    candidate: dict[str, Any] = {}
    match = re.search(r"\{.*?\}", router_answer, re.DOTALL)
    if match:
        try:
            decoded = json.loads(match.group(0))
            if isinstance(decoded, dict):
                candidate = decoded
        except json.JSONDecodeError:
            pass
    raw_model_id = candidate.get("model_id")
    if isinstance(raw_model_id, str) and raw_model_id.isdecimal():
        raw_model_id = int(raw_model_id)
    selected = by_id.get(raw_model_id)
    if selected is None and isinstance(candidate.get("model_name"), str):
        selected = by_name.get(candidate["model_name"])
    if selected is None:
        selected = min(
            targets,
            key=lambda target: float(target["input_price_per_million"]) + float(target["output_price_per_million"]),
        )
        return selected, "Router response was invalid; selected the lowest configured price target."
    reason = str(candidate.get("reason") or "Selected by routing model.")[:500]
    return selected, reason


def _default_choose_target(message: str, targets: list[sqlite3.Row]) -> tuple[sqlite3.Row, str]:
    """Choose a cost tier deterministically when no classifier model is configured.

    A provider's price is not a quality guarantee, but it is the only comparable
    signal available without a classifier. The default therefore uses the
    cheapest tier for simple work, the middle tier for medium work, and the
    highest-priced tier for complex work.
    """
    normalized = message.casefold()
    complexity_terms = (
        "推理", "证明", "架构", "调试", "分析", "比较", "优化", "算法", "复杂", "多步骤",
        "implement", "debug", "reasoning", "architecture", "algorithm", "analy", "compare", "optimiz",
    )
    score = sum(term in normalized for term in complexity_terms)
    if len(message) > 800:
        score += 1
    if len(message) > 2_500:
        score += 1
    if "```" in message:
        score += 1
    ordered = sorted(
        targets,
        key=lambda target: (
            float(target["input_price_per_million"]) + float(target["output_price_per_million"]),
            target["id"],
        ),
    )
    if score >= 3:
        return ordered[-1], "默认难度/费率路由：复杂任务，选择最高费率候选模型。"
    if score >= 1:
        return ordered[len(ordered) // 2], "默认难度/费率路由：中等任务，选择中间费率候选模型。"
    return ordered[0], "默认难度/费率路由：简单任务，选择最低费率候选模型。"


def _conversation_input(message: str, context: list[ChatHistoryMessage]) -> str:
    """Keep browser chat context in the request only; it is never persisted raw."""
    if not context:
        return message
    turns = [f"[{turn.role.upper()}]\n{turn.content.strip()}" for turn in context]
    turns.append(f"[USER]\n{message}")
    return "\n\n".join(turns)


def _target_messages(redaction_applied: bool, redacted: str) -> list[dict[str, str]]:
    return [
        {
            "role": "system",
            "content": (
                "Answer the user helpfully. The supplied conversation has already been redacted; "
                "never request the original sensitive data."
                if redaction_applied
                else "Answer the user helpfully. The supplied conversation was not redacted; do not request unnecessary sensitive data."
            ),
        },
        {"role": "user", "content": redacted},
    ]


def _chat_result(run: ChatRun, answer: str, call_id: int) -> dict[str, Any]:
    return {
        "call_id": call_id,
        "answer": answer,
        "redacted_message": run.redacted if run.redaction_applied else None,
        "redaction_applied": run.redaction_applied,
        "selected_model": run.selected["name"] if run.selected else None,
        "routing_reason": run.routing_reason,
        "prompt_tokens": run.prompt_tokens,
        "completion_tokens": run.completion_tokens,
        "total_cost": round(run.total_cost, 8),
        "cost_known": run.cost_known,
    }


def _sse(event: str, data: dict[str, Any] | str) -> str:
    encoded = data if isinstance(data, str) else json.dumps(data, ensure_ascii=False)
    return f"event: {event}\ndata: {encoded}\n\n"


def _record_call(
    *,
    user_id: int,
    redactor_name: str | None,
    router_name: str | None,
    target_name: str | None,
    redacted_message: str | None,
    routing_reason: str | None,
    prompt_tokens: int,
    completion_tokens: int,
    total_cost: float,
    cost_known: bool,
    status_name: str,
    kind: Literal["chat", "connection_test"] = "chat",
    error_message: str | None = None,
) -> int:
    with database.connection() as connection:
        cursor = connection.execute(
            """
            INSERT INTO calls(
                created_at, user_id, redactor_model_name, router_model_name, selected_model_name,
                redacted_message, routing_reason, prompt_tokens, completion_tokens, total_cost, cost_known, kind, status, error_message
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                utc_text(), user_id, redactor_name, router_name, target_name, redacted_message,
                routing_reason, prompt_tokens, completion_tokens, total_cost, int(cost_known), kind, status_name, error_message,
            ),
        )
        return int(cursor.lastrowid)


@app.get("/", include_in_schema=False)
def index() -> FileResponse:
    return FileResponse(STATIC_DIR / "index.html")


@app.get("/api/health")
def health() -> dict[str, str]:
    return {"status": "ok"}


@app.get("/api/auth/state")
def auth_state() -> dict[str, bool]:
    with database.connection() as connection:
        has_user = connection.execute("SELECT 1 FROM users LIMIT 1").fetchone() is not None
    return {"bootstrap_required": not has_user, "bootstrap_token_required": bool(settings.bootstrap_token)}


@app.post("/api/auth/bootstrap", status_code=status.HTTP_201_CREATED)
def bootstrap(credentials: BootstrapCredentials, response: Response) -> dict[str, Any]:
    if settings.bootstrap_token and not hmac.compare_digest(credentials.bootstrap_token, settings.bootstrap_token):
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Invalid bootstrap token")
    with database.connection() as connection:
        if connection.execute("SELECT 1 FROM users LIMIT 1").fetchone():
            raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="Initial account already exists")
        try:
            cursor = connection.execute(
                "INSERT INTO users(username, password_hash, created_at) VALUES (?, ?, ?)",
                (credentials.username, PasswordHasher.hash(credentials.password), utc_text()),
            )
        except sqlite3.IntegrityError as exc:
            raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="Username already exists") from exc
        user_id = int(cursor.lastrowid)
    return {"username": credentials.username, "csrf_token": _set_session(response, user_id)}


@app.post("/api/auth/login")
def login(credentials: Credentials, response: Response, request: Request) -> dict[str, Any]:
    client_ip = request.client.host if request.client else "unknown"
    if not login_limiter.allow(client_ip):
        raise HTTPException(status_code=status.HTTP_429_TOO_MANY_REQUESTS, detail="Too many login attempts; try again later")
    with database.connection() as connection:
        user = connection.execute(
            "SELECT id, username, password_hash FROM users WHERE username = ?", (credentials.username,)
        ).fetchone()
    if not user or not PasswordHasher.verify(credentials.password, user["password_hash"]):
        login_limiter.fail(client_ip)
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid username or password")
    login_limiter.succeed(client_ip)
    return {"username": user["username"], "csrf_token": _set_session(response, int(user["id"]))}


@app.post("/api/auth/logout", status_code=status.HTTP_204_NO_CONTENT)
def logout(
    request: Request,
    response: Response,
    _: Annotated[dict[str, Any], Depends(csrf_user)],
) -> Response:
    raw_token = request.cookies.get(SESSION_COOKIE)
    if raw_token:
        with database.connection() as connection:
            connection.execute("DELETE FROM sessions WHERE token_hash = ?", (token_hash(raw_token),))
    response.delete_cookie(SESSION_COOKIE, path="/")
    return response


@app.get("/api/auth/me")
def me(user: Annotated[dict[str, Any], Depends(current_user)]) -> dict[str, Any]:
    return {"id": user["id"], "username": user["username"]}


@app.get("/api/auth/csrf")
def refresh_csrf_token(
    request: Request,
    user: Annotated[dict[str, Any], Depends(current_user)],
) -> dict[str, str]:
    """Issue a fresh in-memory CSRF token after a browser page reload.

    The session cookie is HttpOnly, so JavaScript cannot recover the prior token.
    Rotating it server-side keeps the token unavailable to scripts outside this origin.
    """
    raw_session_token = request.cookies.get(SESSION_COOKIE)
    if not raw_session_token:
        raise _unauthorized()
    csrf_token = new_token()
    with database.connection() as connection:
        updated = connection.execute(
            "UPDATE sessions SET csrf_hash = ? WHERE token_hash = ? AND user_id = ?",
            (token_hash(csrf_token), token_hash(raw_session_token), user["id"]),
        ).rowcount
    if updated != 1:
        raise _unauthorized()
    return {"csrf_token": csrf_token}


@app.get("/api/service-key")
def service_key_status(user: Annotated[dict[str, Any], Depends(current_user)]) -> dict[str, Any]:
    with database.connection() as connection:
        row = connection.execute(
            "SELECT key_prefix, created_at FROM service_api_keys WHERE user_id = ?", (user["id"],)
        ).fetchone()
    return {"active": bool(row), "prefix": row["key_prefix"] if row else None, "created_at": row["created_at"] if row else None}


@app.post("/api/service-key", status_code=status.HTTP_201_CREATED)
def create_service_key(user: Annotated[dict[str, Any], Depends(csrf_user)]) -> dict[str, str]:
    raw_key = f"mr_{new_token()}"
    prefix = f"{raw_key[:14]}…"
    with database.connection() as connection:
        connection.execute("DELETE FROM service_api_keys WHERE user_id = ?", (user["id"],))
        connection.execute(
            "INSERT INTO service_api_keys(key_hash, key_prefix, user_id, created_at) VALUES (?, ?, ?, ?)",
            (token_hash(raw_key), prefix, user["id"], utc_text()),
        )
    return {"api_key": raw_key, "prefix": prefix}


@app.delete("/api/service-key")
def revoke_service_key(user: Annotated[dict[str, Any], Depends(csrf_user)]) -> dict[str, bool]:
    with database.connection() as connection:
        revoked = connection.execute("DELETE FROM service_api_keys WHERE user_id = ?", (user["id"],)).rowcount > 0
    return {"revoked": revoked}


@app.put("/api/auth/password")
def change_password(
    change: PasswordChange,
    response: Response,
    user: Annotated[dict[str, Any], Depends(csrf_user)],
) -> dict[str, str]:
    if hmac.compare_digest(change.current_password, change.new_password):
        raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail="New password must differ from the current password")
    with database.connection() as connection:
        account = connection.execute("SELECT password_hash FROM users WHERE id = ?", (user["id"],)).fetchone()
        if not account or not PasswordHasher.verify(change.current_password, account["password_hash"]):
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Current password is incorrect")
        connection.execute("UPDATE users SET password_hash = ? WHERE id = ?", (PasswordHasher.hash(change.new_password), user["id"]))
        connection.execute("DELETE FROM sessions WHERE user_id = ?", (user["id"],))
    return {"csrf_token": _set_session(response, int(user["id"]))}


@app.get("/api/models")
def list_models(_: Annotated[dict[str, Any], Depends(current_user)]) -> list[dict[str, Any]]:
    with database.connection() as connection:
        rows = connection.execute("SELECT * FROM models ORDER BY role, id").fetchall()
    return [_serialise_model(row) for row in rows]


@app.get("/api/pipeline/status")
def pipeline_status(_: Annotated[dict[str, Any], Depends(current_user)]) -> dict[str, Any]:
    return _pipeline_status()


@app.post("/api/provider-models")
async def provider_models(
    request: ProviderModelsRequest,
    _: Annotated[dict[str, Any], Depends(csrf_user)],
) -> dict[str, list[str]]:
    try:
        return {"models": await fetch_provider_models(base_url=request.base_url, api_key=request.api_key)}
    except ProviderError as exc:
        raise HTTPException(status_code=status.HTTP_502_BAD_GATEWAY, detail=str(exc)[:300]) from exc


@app.post("/api/models/{model_id}/available-models")
async def saved_model_available_models(
    model_id: int,
    _: Annotated[dict[str, Any], Depends(csrf_user)],
) -> dict[str, list[str]]:
    with database.connection() as connection:
        model = connection.execute("SELECT role, base_url, api_key_encrypted FROM models WHERE id = ?", (model_id,)).fetchone()
    if not model:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Model not found")
    if model["role"] == "redactor":
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail="Provider redactors are disabled; configure LOCAL_REDACTOR_MODEL_PATH on the server instead",
        )
    try:
        return {"models": await fetch_provider_models(base_url=model["base_url"], api_key=secret_box.decrypt(model["api_key_encrypted"]))}
    except (ProviderError, ValueError) as exc:
        raise HTTPException(status_code=status.HTTP_502_BAD_GATEWAY, detail=str(exc)[:300]) from exc


@app.post("/api/models", status_code=status.HTTP_201_CREATED)
def create_model(
    model: ModelCreate,
    _: Annotated[dict[str, Any], Depends(csrf_user)],
) -> dict[str, Any]:
    now = utc_text()
    with database.connection() as connection:
        if model.is_active and model.role == "router":
            connection.execute("UPDATE models SET is_active = 0, updated_at = ? WHERE role = ?", (now, model.role))
        try:
            cursor = connection.execute(
                """
                INSERT INTO models(
                    name, role, base_url, api_key_encrypted, model_name, input_price_per_million,
                    output_price_per_million, is_active, created_at, updated_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    model.name.strip(), model.role, model.base_url, secret_box.encrypt(model.api_key), model.model_name.strip(),
                    model.input_price_per_million, model.output_price_per_million, int(model.is_active), now, now,
                ),
            )
        except sqlite3.IntegrityError as exc:
            raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="Model name already exists") from exc
        row = connection.execute("SELECT * FROM models WHERE id = ?", (cursor.lastrowid,)).fetchone()
    return _serialise_model(row)


@app.post("/api/models/batch", status_code=status.HTTP_201_CREATED)
def create_target_models_batch(
    batch: ModelBatchCreate,
    _: Annotated[dict[str, Any], Depends(csrf_user)],
) -> dict[str, list[dict[str, Any]]]:
    """Create several active target models selected from one provider in one transaction."""
    if any(model.role != "target" for model in batch.models):
        raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail="Batch creation supports target models only")
    names = [model.name.strip() for model in batch.models]
    if len(names) != len(set(names)):
        raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail="Each selected model needs a unique display name")
    now = utc_text()
    with database.connection() as connection:
        rows: list[sqlite3.Row] = []
        try:
            for model in batch.models:
                cursor = connection.execute(
                    """
                    INSERT INTO models(
                        name, role, base_url, api_key_encrypted, model_name, input_price_per_million,
                        output_price_per_million, is_active, created_at, updated_at
                    ) VALUES (?, 'target', ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        model.name.strip(), model.base_url, secret_box.encrypt(model.api_key), model.model_name.strip(),
                        model.input_price_per_million, model.output_price_per_million, int(model.is_active), now, now,
                    ),
                )
                rows.append(connection.execute("SELECT * FROM models WHERE id = ?", (cursor.lastrowid,)).fetchone())
        except sqlite3.IntegrityError as exc:
            raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="One or more model names already exist") from exc
    return {"models": [_serialise_model(row) for row in rows]}


@app.put("/api/models/{model_id}")
def update_model(
    model_id: int,
    update: ModelUpdate,
    _: Annotated[dict[str, Any], Depends(csrf_user)],
) -> dict[str, Any]:
    data = update.model_dump(exclude_unset=True)
    with database.connection() as connection:
        current = connection.execute("SELECT * FROM models WHERE id = ?", (model_id,)).fetchone()
        if not current:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Model not found")
        effective_role = data.get("role", current["role"])
        effective_active = data.get("is_active", bool(current["is_active"]))
        if effective_active and effective_role == "router":
            connection.execute(
                "UPDATE models SET is_active = 0, updated_at = ? WHERE role = ? AND id != ?",
                (utc_text(), effective_role, model_id),
            )
        assignments: list[str] = []
        values: list[Any] = []
        for field in (
            "name", "role", "base_url", "model_name", "input_price_per_million", "output_price_per_million", "is_active",
        ):
            if field in data:
                assignments.append(f"{field} = ?")
                values.append(data[field].strip() if field in {"name", "model_name"} else data[field])
        if data.get("api_key"):
            assignments.append("api_key_encrypted = ?")
            values.append(secret_box.encrypt(data["api_key"]))
        if not assignments:
            return _serialise_model(current)
        assignments.append("updated_at = ?")
        values.extend([utc_text(), model_id])
        try:
            connection.execute(f"UPDATE models SET {', '.join(assignments)} WHERE id = ?", values)
        except sqlite3.IntegrityError as exc:
            raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="Model name already exists") from exc
        row = connection.execute("SELECT * FROM models WHERE id = ?", (model_id,)).fetchone()
    return _serialise_model(row)


@app.delete("/api/models/{model_id}", status_code=status.HTTP_204_NO_CONTENT)
def delete_model(model_id: int, _: Annotated[dict[str, Any], Depends(csrf_user)]) -> Response:
    with database.connection() as connection:
        if connection.execute("DELETE FROM models WHERE id = ?", (model_id,)).rowcount == 0:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Model not found")
    return Response(status_code=status.HTTP_204_NO_CONTENT)


@app.post("/api/models/{model_id}/test")
async def test_model_connection(
    model_id: int,
    user: Annotated[dict[str, Any], Depends(csrf_user)],
) -> dict[str, Any]:
    with database.connection() as connection:
        model = connection.execute("SELECT * FROM models WHERE id = ?", (model_id,)).fetchone()
    if not model:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Model not found")
    if model["role"] == "redactor":
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail="Provider redactors are disabled; configure LOCAL_REDACTOR_MODEL_PATH on the server instead",
        )
    call_names = {
        "redactor_name": model["name"] if model["role"] == "redactor" else None,
        "router_name": model["name"] if model["role"] == "router" else None,
        "target_name": model["name"] if model["role"] == "target" else None,
    }
    try:
        completion = await _invoke(
            model,
            [
                {"role": "system", "content": "You are a connectivity check. Reply exactly with: connection-ok"},
                {"role": "user", "content": "connection-test"},
            ],
            temperature=0,
            max_tokens=12,
        )
        call_id = _record_call(
            user_id=user["id"], **call_names, redacted_message=None, routing_reason="Configuration connection test",
            prompt_tokens=completion.usage.prompt_tokens, completion_tokens=completion.usage.completion_tokens,
            total_cost=_cost(model, completion.usage), cost_known=completion.usage.reported,
            status_name="succeeded", kind="connection_test",
        )
        return {
            "call_id": call_id,
            "model_name": model["name"],
            "response_preview": completion.content[:120],
            "prompt_tokens": completion.usage.prompt_tokens,
            "completion_tokens": completion.usage.completion_tokens,
            "total_cost": _cost(model, completion.usage),
            "cost_known": completion.usage.reported,
        }
    except (ProviderError, ValueError) as exc:
        safe_error = str(exc)[:300]
        _record_call(
            user_id=user["id"], **call_names, redacted_message=None, routing_reason="Configuration connection test",
            prompt_tokens=0, completion_tokens=0, total_cost=0, cost_known=False,
            status_name="failed", kind="connection_test", error_message=safe_error,
        )
        raise HTTPException(status_code=status.HTTP_502_BAD_GATEWAY, detail=safe_error) from exc


@app.get("/api/rules")
def get_rules(_: Annotated[dict[str, Any], Depends(current_user)]) -> dict[str, str]:
    return _rules()


@app.get("/api/rules/defaults")
def default_rules(_: Annotated[dict[str, Any], Depends(current_user)]) -> dict[str, str]:
    return DEFAULT_RULES.copy()


@app.put("/api/rules")
def update_rules(rules: RulesUpdate, _: Annotated[dict[str, Any], Depends(csrf_user)]) -> dict[str, str]:
    now = utc_text()
    with database.connection() as connection:
        for name, content in (("redaction", rules.redaction), ("routing", rules.routing)):
            connection.execute(
                """
                INSERT INTO rules(name, content, updated_at) VALUES (?, ?, ?)
                ON CONFLICT(name) DO UPDATE SET content = excluded.content, updated_at = excluded.updated_at
                """,
                (name, content.strip(), now),
            )
    return _rules()


def _serialise_keyword_rule(row: sqlite3.Row) -> dict[str, Any]:
    result = dict(row)
    result["is_fuzzy"] = bool(result["is_fuzzy"])
    result["is_active"] = bool(result["is_active"])
    return result


@app.get("/api/keyword-rules")
def list_keyword_rules(user: Annotated[dict[str, Any], Depends(current_user)]) -> list[dict[str, Any]]:
    with database.connection() as connection:
        rows = connection.execute(
            "SELECT * FROM keyword_rules WHERE user_id = ? ORDER BY is_active DESC, length(phrase) DESC, id ASC",
            (user["id"],),
        ).fetchall()
    return [_serialise_keyword_rule(row) for row in rows]


@app.post("/api/keyword-rules", status_code=status.HTTP_201_CREATED)
def create_keyword_rule(
    rule: KeywordRuleCreate,
    user: Annotated[dict[str, Any], Depends(csrf_user)],
) -> dict[str, Any]:
    phrase, replacement = rule.phrase.strip(), rule.replacement.strip()
    if not phrase or not replacement:
        raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail="Keyword phrase and replacement cannot be blank")
    now = utc_text()
    with database.connection() as connection:
        try:
            cursor = connection.execute(
                """
                INSERT INTO keyword_rules(user_id, phrase, replacement, is_fuzzy, is_active, created_at, updated_at)
                VALUES (?, ?, ?, ?, ?, ?, ?)
                """,
                (user["id"], phrase, replacement, int(rule.is_fuzzy), int(rule.is_active), now, now),
            )
        except sqlite3.IntegrityError as exc:
            raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="This keyword already exists") from exc
        row = connection.execute("SELECT * FROM keyword_rules WHERE id = ?", (cursor.lastrowid,)).fetchone()
    return _serialise_keyword_rule(row)


@app.put("/api/keyword-rules/{rule_id}")
def update_keyword_rule(
    rule_id: int,
    update: KeywordRuleUpdate,
    user: Annotated[dict[str, Any], Depends(csrf_user)],
) -> dict[str, Any]:
    data = update.model_dump(exclude_unset=True)
    with database.connection() as connection:
        current = connection.execute("SELECT * FROM keyword_rules WHERE id = ? AND user_id = ?", (rule_id, user["id"])).fetchone()
        if not current:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Keyword rule not found")
        assignments: list[str] = []
        values: list[Any] = []
        for field in ("phrase", "replacement", "is_fuzzy", "is_active"):
            if field not in data:
                continue
            value = data[field]
            if field in {"phrase", "replacement"}:
                value = value.strip()
                if not value:
                    raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail=f"{field} cannot be blank")
            assignments.append(f"{field} = ?")
            values.append(value)
        if not assignments:
            return _serialise_keyword_rule(current)
        assignments.append("updated_at = ?")
        values.extend((utc_text(), rule_id, user["id"]))
        try:
            connection.execute(f"UPDATE keyword_rules SET {', '.join(assignments)} WHERE id = ? AND user_id = ?", values)
        except sqlite3.IntegrityError as exc:
            raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="This keyword already exists") from exc
        row = connection.execute("SELECT * FROM keyword_rules WHERE id = ?", (rule_id,)).fetchone()
    return _serialise_keyword_rule(row)


@app.delete("/api/keyword-rules/{rule_id}", status_code=status.HTTP_204_NO_CONTENT)
def delete_keyword_rule(rule_id: int, user: Annotated[dict[str, Any], Depends(csrf_user)]) -> Response:
    with database.connection() as connection:
        if connection.execute("DELETE FROM keyword_rules WHERE id = ? AND user_id = ?", (rule_id, user["id"])).rowcount == 0:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Keyword rule not found")
    return Response(status_code=status.HTTP_204_NO_CONTENT)


@app.get("/api/calls")
def list_calls(
    user: Annotated[dict[str, Any], Depends(current_user)],
    limit: int = 50,
) -> list[dict[str, Any]]:
    limit = max(1, min(limit, 100))
    with database.connection() as connection:
        rows = connection.execute(
            """
            SELECT id, created_at, kind, redactor_model_name, router_model_name, selected_model_name,
                   redacted_message, routing_reason, prompt_tokens, completion_tokens, total_cost, status, error_message
                   , cost_known
            FROM calls WHERE user_id = ? ORDER BY id DESC LIMIT ?
            """,
            (user["id"], limit),
        ).fetchall()
    return [dict(row) for row in rows]


@app.delete("/api/calls")
def clear_calls(user: Annotated[dict[str, Any], Depends(csrf_user)]) -> dict[str, int]:
    with database.connection() as connection:
        deleted_count = connection.execute("DELETE FROM calls WHERE user_id = ?", (user["id"],)).rowcount
    return {"deleted_count": deleted_count}


@app.get("/api/stats")
def stats(user: Annotated[dict[str, Any], Depends(current_user)]) -> dict[str, Any]:
    with database.connection() as connection:
        row = connection.execute(
            """
            SELECT COUNT(*) AS total_calls,
                   SUM(CASE WHEN status = 'succeeded' THEN 1 ELSE 0 END) AS successful_calls,
                   COALESCE(SUM(CASE WHEN cost_known = 1 THEN total_cost ELSE 0 END), 0) AS total_cost,
                   SUM(CASE WHEN cost_known = 0 THEN 1 ELSE 0 END) AS unknown_cost_calls
            FROM calls WHERE user_id = ?
            """
            ,
            (user["id"],),
        ).fetchone()
    return dict(row)


@app.get("/api/evaluation")
def evaluation_signals(user: Annotated[dict[str, Any], Depends(current_user)]) -> dict[str, int]:
    """Expose operational quality signals without claiming unlabelled semantic accuracy."""
    with database.connection() as connection:
        row = connection.execute(
            """
            SELECT
                SUM(CASE WHEN kind = 'chat' THEN 1 ELSE 0 END) AS chat_calls,
                SUM(CASE WHEN kind = 'chat' AND status = 'succeeded' THEN 1 ELSE 0 END) AS successful_chat_calls,
                SUM(CASE WHEN kind = 'chat' AND error_message LIKE 'Automated de-identification check%' THEN 1 ELSE 0 END) AS privacy_blocks,
                SUM(CASE WHEN kind = 'chat' AND routing_reason LIKE 'Router response was invalid%' THEN 1 ELSE 0 END) AS routing_fallbacks,
                SUM(CASE WHEN kind = 'chat' AND status = 'succeeded' AND cost_known = 1 THEN 1 ELSE 0 END) AS known_cost_chat_calls
            FROM calls WHERE user_id = ?
            """
            ,
            (user["id"],),
        ).fetchone()
    return {key: int(value or 0) for key, value in dict(row).items()}


@app.post("/api/chat")
async def chat(
    payload: ChatRequest,
    user: Annotated[dict[str, Any], Depends(csrf_user)],
) -> dict[str, Any]:
    run = ChatRun(user_id=user["id"])
    target_messages = await _prepare_chat_run(payload, user, run)
    try:
        answer = await _invoke(run.selected, target_messages)
        run.prompt_tokens += answer.usage.prompt_tokens
        run.completion_tokens += answer.usage.completion_tokens
        run.total_cost += _cost(run.selected, answer.usage)
        run.cost_known = run.cost_known and answer.usage.reported
        run.total_cost = round(run.total_cost, 8)
        call_id = _record_call(
            user_id=run.user_id, redactor_name=run.redactor_name, router_name=run.router_name, target_name=run.selected["name"],
            redacted_message=run.redacted if run.redaction_applied else None, routing_reason=run.routing_reason, prompt_tokens=run.prompt_tokens,
            completion_tokens=run.completion_tokens, total_cost=run.total_cost, cost_known=run.cost_known, status_name="succeeded",
        )
        return _chat_result(run, answer.content, call_id)
    except (ProviderError, ValueError) as exc:
        safe_error = str(exc)[:300]
        _record_chat_failure(run, safe_error)
        raise HTTPException(status_code=status.HTTP_502_BAD_GATEWAY, detail=safe_error) from exc
    except Exception as exc:  # Keep implementation failures out of the client response and audit payload.
        logger.exception("Unexpected chat pipeline failure")
        _record_chat_failure(run, "Unexpected pipeline failure")
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Unexpected pipeline failure") from exc


async def _prepare_chat_run(
    payload: ChatRequest,
    user: dict[str, Any],
    run: ChatRun,
) -> list[dict[str, str]]:
    message = payload.message.strip()
    if not message:
        raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail="Message cannot be empty")
    redactor, router, targets = _active_pipeline()
    rules = _rules()
    keyword_rules = _keyword_rules(user["id"])
    conversation = _conversation_input(message, payload.context)
    run.redaction_applied = bool(settings.local_redactor_model_path)
    run.redactor_name = (
        _local_redactor_label(settings.local_redactor_model_path)
        if settings.local_redactor_model_path
        else None
    )
    run.router_name = (
        _local_classifier_label(settings.local_classifier_model_path)
        if settings.local_classifier_model_path
        else router["name"] if router else "内置难度/费率路由"
    )

    try:
        if settings.local_redactor_model_path:
            run.redacted = (await asyncio.to_thread(local_redact, _local_redactor_options(), conversation, keyword_rules)).text
        else:
            run.redacted = conversation

        if run.redaction_applied:
            leaked_values = _leaked_sensitive_values(conversation, run.redacted)
            if leaked_values:
                raise PrivacyVerificationError(
                    "Automated de-identification check blocked sensitive content before routing or target inference"
                )
            run.redaction_verified = True

        candidates = [
            {
                "model_id": item["id"],
                "model_name": item["name"],
                "provider_model": item["model_name"],
                "input_price_per_million": item["input_price_per_million"],
                "output_price_per_million": item["output_price_per_million"],
            }
            for item in targets
        ]
        router_system = (
            f"{rules['routing']}\n\n"
            "Select exactly one candidate for the processed conversation. Reply only with JSON in this shape: "
            '{"model_id": 123, "reason": "brief explanation"}.\n\n'
            f"Candidates:\n{json.dumps(candidates, ensure_ascii=False)}"
        )
        if router:
            routing = await _invoke(
                router,
                [{"role": "system", "content": router_system}, {"role": "user", "content": run.redacted}],
                temperature=0,
            )
            run.prompt_tokens += routing.usage.prompt_tokens
            run.completion_tokens += routing.usage.completion_tokens
            run.total_cost += _cost(router, routing.usage)
            run.cost_known = run.cost_known and routing.usage.reported
            run.selected, run.routing_reason = _choose_target(routing.content, targets)
        elif settings.local_classifier_model_path:
            routing = await local_chat_completion(
                _local_classifier_options(settings.local_classifier_model_path),
                [{"role": "system", "content": router_system}, {"role": "user", "content": run.redacted}],
                temperature=0,
            )
            run.selected, run.routing_reason = _choose_target(routing.content, targets)
        else:
            run.selected, run.routing_reason = _default_choose_target(run.redacted, targets)
        return _target_messages(run.redaction_applied, run.redacted)
    except (ProviderError, ValueError) as exc:
        safe_error = str(exc)[:300]
        _record_chat_failure(run, safe_error)
        raise HTTPException(status_code=status.HTTP_502_BAD_GATEWAY, detail=safe_error) from exc
    except Exception as exc:
        logger.exception("Unexpected chat pipeline failure")
        _record_chat_failure(run, "Unexpected pipeline failure")
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Unexpected pipeline failure") from exc


def _record_chat_failure(run: ChatRun, safe_error: str) -> int:
    return _record_call(
        user_id=run.user_id, redactor_name=run.redactor_name, router_name=run.router_name,
        target_name=run.selected["name"] if run.selected else None,
        redacted_message=run.redacted if run.redaction_verified and run.redaction_applied else None,
        routing_reason=run.routing_reason, prompt_tokens=run.prompt_tokens, completion_tokens=run.completion_tokens,
        total_cost=round(run.total_cost, 8), cost_known=run.cost_known, status_name="failed", error_message=safe_error,
    )


async def _stream_chat_events(run: ChatRun, target_messages: list[dict[str, str]]) -> AsyncIterator[str]:
    answer_parts: list[str] = []
    yield _sse(
        "meta",
        {
            "redacted_message": run.redacted if run.redaction_applied else None,
            "redaction_applied": run.redaction_applied,
            "selected_model": run.selected["name"],
            "routing_reason": run.routing_reason,
        },
    )
    try:
        async for chunk in _stream_invoke(run.selected, target_messages):
            if chunk.content:
                answer_parts.append(chunk.content)
                yield _sse("delta", {"content": chunk.content})
            if chunk.usage:
                run.prompt_tokens += chunk.usage.prompt_tokens
                run.completion_tokens += chunk.usage.completion_tokens
                run.total_cost += _cost(run.selected, chunk.usage)
                run.cost_known = run.cost_known and chunk.usage.reported
        answer = "".join(answer_parts).strip()
        if not answer:
            raise ProviderError("Model provider returned an empty streaming response")
        run.total_cost = round(run.total_cost, 8)
        call_id = _record_call(
            user_id=run.user_id, redactor_name=run.redactor_name, router_name=run.router_name, target_name=run.selected["name"],
            redacted_message=run.redacted if run.redaction_applied else None, routing_reason=run.routing_reason, prompt_tokens=run.prompt_tokens,
            completion_tokens=run.completion_tokens, total_cost=run.total_cost, cost_known=run.cost_known, status_name="succeeded",
        )
        yield _sse("done", _chat_result(run, answer, call_id))
    except (ProviderError, ValueError) as exc:
        safe_error = str(exc)[:300]
        _record_chat_failure(run, safe_error)
        yield _sse("error", {"detail": safe_error})
    except Exception:
        logger.exception("Unexpected streaming chat pipeline failure")
        _record_chat_failure(run, "Unexpected pipeline failure")
        yield _sse("error", {"detail": "Unexpected pipeline failure"})


@app.post("/api/chat/stream")
async def chat_stream(
    payload: ChatRequest,
    user: Annotated[dict[str, Any], Depends(csrf_user)],
) -> StreamingResponse:
    run = ChatRun(user_id=user["id"])
    target_messages = await _prepare_chat_run(payload, user, run)
    return StreamingResponse(
        _stream_chat_events(run, target_messages),
        media_type="text/event-stream",
        headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"},
    )


@app.get("/v1/models")
def openai_models(_: Annotated[dict[str, Any], Depends(service_api_user)]) -> dict[str, Any]:
    return {
        "object": "list",
        "data": [
            {
                "id": "models-router",
                "object": "model",
                "created": 0,
                "owned_by": "models-router",
            }
        ],
    }


@app.post("/v1/chat/completions", response_model=None)
async def openai_chat_completions(
    payload: OpenAIChatCompletionRequest,
    user: Annotated[dict[str, Any], Depends(service_api_user)],
) -> Any:
    if payload.stream:
        run = ChatRun(user_id=user["id"])
        target_messages = await _prepare_chat_run(
            _chat_request_from_openai_messages(payload.messages),
            user,
            run,
        )
        return StreamingResponse(
            _openai_stream_events(run, target_messages, payload.model),
            media_type="text/event-stream",
            headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"},
        )
    routed = await chat(_chat_request_from_openai_messages(payload.messages), user)
    return {
        "id": f"chatcmpl-{uuid.uuid4().hex}",
        "object": "chat.completion",
        "created": int(time.time()),
        "model": payload.model,
        "choices": [
            {
                "index": 0,
                "message": {"role": "assistant", "content": routed["answer"]},
                "finish_reason": "stop",
            }
        ],
        "usage": {
            "prompt_tokens": routed["prompt_tokens"],
            "completion_tokens": routed["completion_tokens"],
            "total_tokens": routed["prompt_tokens"] + routed["completion_tokens"],
        },
    }


async def _openai_stream_events(
    run: ChatRun,
    target_messages: list[dict[str, str]],
    model: str,
) -> AsyncIterator[str]:
    completion_id = f"chatcmpl-{uuid.uuid4().hex}"
    created = int(time.time())

    def chunk(delta: dict[str, Any], finish_reason: str | None = None, usage: dict[str, int] | None = None) -> str:
        payload: dict[str, Any] = {
            "id": completion_id,
            "object": "chat.completion.chunk",
            "created": created,
            "model": model,
            "choices": [{"index": 0, "delta": delta, "finish_reason": finish_reason}],
        }
        if usage is not None:
            payload["usage"] = usage
        return f"data: {json.dumps(payload, ensure_ascii=False)}\n\n"

    answer_parts: list[str] = []
    yield chunk({"role": "assistant"})
    try:
        async for provider_chunk in _stream_invoke(run.selected, target_messages):
            if provider_chunk.content:
                answer_parts.append(provider_chunk.content)
                yield chunk({"content": provider_chunk.content})
            if provider_chunk.usage:
                run.prompt_tokens += provider_chunk.usage.prompt_tokens
                run.completion_tokens += provider_chunk.usage.completion_tokens
                run.total_cost += _cost(run.selected, provider_chunk.usage)
                run.cost_known = run.cost_known and provider_chunk.usage.reported
        answer = "".join(answer_parts).strip()
        if not answer:
            raise ProviderError("Model provider returned an empty streaming response")
        run.total_cost = round(run.total_cost, 8)
        _record_call(
            user_id=run.user_id, redactor_name=run.redactor_name, router_name=run.router_name, target_name=run.selected["name"],
            redacted_message=run.redacted if run.redaction_applied else None, routing_reason=run.routing_reason, prompt_tokens=run.prompt_tokens,
            completion_tokens=run.completion_tokens, total_cost=run.total_cost, cost_known=run.cost_known, status_name="succeeded",
        )
        usage = {
            "prompt_tokens": run.prompt_tokens,
            "completion_tokens": run.completion_tokens,
            "total_tokens": run.prompt_tokens + run.completion_tokens,
        }
        yield chunk({}, "stop", usage)
    except (ProviderError, ValueError) as exc:
        safe_error = str(exc)[:300]
        _record_chat_failure(run, safe_error)
        yield chunk({"content": f"\n[ERROR] {safe_error}"}, "stop")
    except Exception:
        logger.exception("Unexpected OpenAI streaming chat pipeline failure")
        _record_chat_failure(run, "Unexpected pipeline failure")
        yield chunk({"content": "\n[ERROR] Unexpected pipeline failure"}, "stop")
    yield "data: [DONE]\n\n"
