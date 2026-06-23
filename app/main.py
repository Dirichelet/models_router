"""HTTP application for the privacy-aware model router."""

from __future__ import annotations

import hashlib
import hmac
import json
import logging
import re
import sqlite3
from collections import defaultdict, deque
from contextlib import asynccontextmanager
from datetime import UTC, datetime, timedelta
from pathlib import Path
from time import monotonic
from typing import Annotated, Any, Literal
from urllib.parse import urlparse

from fastapi import Cookie, Depends, FastAPI, Header, HTTPException, Request, Response, status
from fastapi.middleware.httpsredirect import HTTPSRedirectMiddleware
from fastapi.middleware.trustedhost import TrustedHostMiddleware
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field, field_validator
from starlette.middleware.base import BaseHTTPMiddleware

from .config import Settings
from .database import Database
from .provider import Completion, ProviderError, Usage, chat_completion
from .security import PasswordHasher, SecretBox, new_token, token_hash


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


class BootstrapCredentials(Credentials):
    bootstrap_token: str = Field(default="", max_length=512)


class PasswordChange(BaseModel):
    current_password: str = Field(min_length=1, max_length=256)
    new_password: str = Field(min_length=12, max_length=256)


class ModelCreate(BaseModel):
    name: str = Field(min_length=1, max_length=80)
    role: Literal["redactor", "router", "target"]
    base_url: str = Field(min_length=8, max_length=500)
    api_key: str = Field(min_length=1, max_length=1000)
    model_name: str = Field(min_length=1, max_length=200)
    input_price_per_million: float = Field(default=0, ge=0, le=1_000_000)
    output_price_per_million: float = Field(default=0, ge=0, le=1_000_000)
    is_active: bool = True

    @field_validator("base_url")
    @classmethod
    def validate_base_url(cls, value: str) -> str:
        parsed = urlparse(value)
        if parsed.scheme not in {"http", "https"} or not parsed.netloc:
            raise ValueError("base_url must be a complete http(s) URL")
        return value.rstrip("/")


class ModelUpdate(BaseModel):
    name: str | None = Field(default=None, min_length=1, max_length=80)
    role: Literal["redactor", "router", "target"] | None = None
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


class RulesUpdate(BaseModel):
    redaction: str = Field(min_length=1, max_length=12_000)
    routing: str = Field(min_length=1, max_length=12_000)


class ChatRequest(BaseModel):
    message: str = Field(min_length=1, max_length=20_000)


@asynccontextmanager
async def lifespan(_: FastAPI):
    database.initialize()
    yield


app = FastAPI(title="Models Router", version="0.1.0", lifespan=lifespan, docs_url=None, redoc_url=None)
app.add_middleware(TrustedHostMiddleware, allowed_hosts=settings.trusted_hosts)
if settings.app_env == "production":
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
        "created_at": row["created_at"],
        "updated_at": row["updated_at"],
    }


def _rules() -> dict[str, str]:
    with database.connection() as connection:
        rows = connection.execute("SELECT name, content FROM rules").fetchall()
    return {row["name"]: row["content"] for row in rows}


def _active_pipeline() -> tuple[sqlite3.Row, sqlite3.Row, list[sqlite3.Row]]:
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
    if not redactor or not router or not targets:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail="Configure one active redactor, one active router, and at least one active target model first",
        )
    return redactor, router, targets


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


@app.post("/api/models", status_code=status.HTTP_201_CREATED)
def create_model(
    model: ModelCreate,
    _: Annotated[dict[str, Any], Depends(csrf_user)],
) -> dict[str, Any]:
    now = utc_text()
    with database.connection() as connection:
        if model.is_active and model.role in {"redactor", "router"}:
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
        if effective_active and effective_role in {"redactor", "router"}:
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


@app.get("/api/calls")
def list_calls(
    _: Annotated[dict[str, Any], Depends(current_user)],
    limit: int = 50,
) -> list[dict[str, Any]]:
    limit = max(1, min(limit, 100))
    with database.connection() as connection:
        rows = connection.execute(
            """
            SELECT id, created_at, kind, redactor_model_name, router_model_name, selected_model_name,
                   redacted_message, routing_reason, prompt_tokens, completion_tokens, total_cost, status, error_message
                   , cost_known
            FROM calls ORDER BY id DESC LIMIT ?
            """,
            (limit,),
        ).fetchall()
    return [dict(row) for row in rows]


@app.delete("/api/calls")
def clear_calls(_: Annotated[dict[str, Any], Depends(csrf_user)]) -> dict[str, int]:
    with database.connection() as connection:
        deleted_count = connection.execute("DELETE FROM calls").rowcount
    return {"deleted_count": deleted_count}


@app.get("/api/stats")
def stats(_: Annotated[dict[str, Any], Depends(current_user)]) -> dict[str, Any]:
    with database.connection() as connection:
        row = connection.execute(
            """
            SELECT COUNT(*) AS total_calls,
                   SUM(CASE WHEN status = 'succeeded' THEN 1 ELSE 0 END) AS successful_calls,
                   COALESCE(SUM(CASE WHEN cost_known = 1 THEN total_cost ELSE 0 END), 0) AS total_cost,
                   SUM(CASE WHEN cost_known = 0 THEN 1 ELSE 0 END) AS unknown_cost_calls
            FROM calls
            """
        ).fetchone()
    return dict(row)


@app.get("/api/evaluation")
def evaluation_signals(_: Annotated[dict[str, Any], Depends(current_user)]) -> dict[str, int]:
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
            FROM calls
            """
        ).fetchone()
    return {key: int(value or 0) for key, value in dict(row).items()}


@app.post("/api/chat")
async def chat(
    payload: ChatRequest,
    user: Annotated[dict[str, Any], Depends(csrf_user)],
) -> dict[str, Any]:
    message = payload.message.strip()
    if not message:
        raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail="Message cannot be empty")
    redactor, router, targets = _active_pipeline()
    rules = _rules()
    redacted: str | None = None
    redaction_verified = False
    selected: sqlite3.Row | None = None
    routing_reason: str | None = None
    prompt_tokens = 0
    completion_tokens = 0
    total_cost = 0.0
    cost_known = True

    try:
        redaction = await _invoke(
            redactor,
            [
                {"role": "system", "content": rules["redaction"]},
                {"role": "user", "content": message},
            ],
            temperature=0,
        )
        redacted = redaction.content
        prompt_tokens += redaction.usage.prompt_tokens
        completion_tokens += redaction.usage.completion_tokens
        total_cost += _cost(redactor, redaction.usage)
        cost_known = cost_known and redaction.usage.reported
        leaked_values = _leaked_sensitive_values(message, redacted)
        if leaked_values:
            raise PrivacyVerificationError(
                "Automated de-identification check blocked sensitive content before routing or target inference"
            )
        redaction_verified = True

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
            "Select exactly one candidate for the redacted user message. Reply only with JSON in this shape: "
            '{"model_id": 123, "reason": "brief explanation"}.\n\n'
            f"Candidates:\n{json.dumps(candidates, ensure_ascii=False)}"
        )
        routing = await _invoke(
            router,
            [{"role": "system", "content": router_system}, {"role": "user", "content": redacted}],
            temperature=0,
        )
        prompt_tokens += routing.usage.prompt_tokens
        completion_tokens += routing.usage.completion_tokens
        total_cost += _cost(router, routing.usage)
        cost_known = cost_known and routing.usage.reported
        selected, routing_reason = _choose_target(routing.content, targets)

        answer = await _invoke(
            selected,
            [
                {
                    "role": "system",
                    "content": "Answer the user helpfully. The supplied user message has already been redacted; never request the original sensitive data.",
                },
                {"role": "user", "content": redacted},
            ],
        )
        prompt_tokens += answer.usage.prompt_tokens
        completion_tokens += answer.usage.completion_tokens
        total_cost += _cost(selected, answer.usage)
        cost_known = cost_known and answer.usage.reported
        total_cost = round(total_cost, 8)
        call_id = _record_call(
            user_id=user["id"], redactor_name=redactor["name"], router_name=router["name"], target_name=selected["name"],
            redacted_message=redacted, routing_reason=routing_reason, prompt_tokens=prompt_tokens,
            completion_tokens=completion_tokens, total_cost=total_cost, cost_known=cost_known, status_name="succeeded",
        )
        return {
            "call_id": call_id,
            "answer": answer.content,
            "redacted_message": redacted,
            "selected_model": selected["name"],
            "routing_reason": routing_reason,
            "prompt_tokens": prompt_tokens,
            "completion_tokens": completion_tokens,
            "total_cost": total_cost,
            "cost_known": cost_known,
        }
    except (ProviderError, ValueError) as exc:
        safe_error = str(exc)[:300]
        _record_call(
            user_id=user["id"], redactor_name=redactor["name"], router_name=router["name"],
            target_name=selected["name"] if selected else None,
            redacted_message=redacted if redaction_verified else None,
            routing_reason=routing_reason, prompt_tokens=prompt_tokens, completion_tokens=completion_tokens,
            total_cost=round(total_cost, 8), cost_known=cost_known, status_name="failed", error_message=safe_error,
        )
        raise HTTPException(status_code=status.HTTP_502_BAD_GATEWAY, detail=safe_error) from exc
    except Exception as exc:  # Keep implementation failures out of the client response and audit payload.
        logger.exception("Unexpected chat pipeline failure")
        _record_call(
            user_id=user["id"], redactor_name=redactor["name"], router_name=router["name"],
            target_name=selected["name"] if selected else None,
            redacted_message=redacted if redaction_verified else None,
            routing_reason=routing_reason, prompt_tokens=prompt_tokens, completion_tokens=completion_tokens,
            total_cost=round(total_cost, 8), cost_known=cost_known, status_name="failed", error_message="Unexpected pipeline failure",
        )
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Unexpected pipeline failure") from exc
