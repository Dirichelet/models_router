"""Application configuration loaded exclusively from environment variables."""

from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path

from cryptography.fernet import Fernet


def _as_bool(value: str | None, default: bool) -> bool:
    if value is None:
        return default
    return value.strip().lower() in {"1", "true", "yes", "on"}


def _optional_file_path(variable: str) -> Path | None:
    raw_path = os.getenv(variable, "").strip()
    if not raw_path:
        return None
    path = Path(raw_path).expanduser()
    if not path.is_file():
        raise RuntimeError(f"{variable} must point to an existing local GGUF model file")
    return path.resolve()


def _optional_model_directory(variable: str) -> Path | None:
    raw_path = os.getenv(variable, "").strip()
    if not raw_path:
        return None
    path = Path(raw_path).expanduser()
    if not path.is_dir():
        raise RuntimeError(f"{variable} must point to an existing local Transformers model directory")
    return path.resolve()


def _score_threshold(variable: str, default: float) -> float:
    value = float(os.getenv(variable, str(default)))
    if not 0 <= value <= 1:
        raise RuntimeError(f"{variable} must be between 0 and 1")
    return value


@dataclass(frozen=True)
class Settings:
    app_env: str
    database_path: Path
    fernet_key: str
    bootstrap_token: str
    cookie_secure: bool
    trusted_hosts: list[str]
    session_hours: int
    max_message_chars: int
    local_redactor_model_path: Path | None
    local_chinese_ner_model_path: Path | None
    local_redactor_device: str
    local_redactor_min_score: float
    local_classifier_model_path: Path | None
    local_gguf_chat_format: str | None
    local_gguf_context_tokens: int
    local_gguf_gpu_layers: int
    local_gguf_threads: int

    @classmethod
    def from_environment(cls) -> "Settings":
        app_env = os.getenv("APP_ENV", "development").strip().lower()
        database_path = Path(os.getenv("DATABASE_PATH", "./data/models_router.db"))
        fernet_key = os.getenv("FERNET_KEY", "").strip()
        if not fernet_key:
            if app_env == "development":
                key_file = database_path.parent / ".dev-fernet.key"
                if key_file.exists():
                    fernet_key = key_file.read_text(encoding="utf-8").strip()
                else:
                    key_file.parent.mkdir(parents=True, exist_ok=True)
                    fernet_key = Fernet.generate_key().decode("utf-8")
                    key_file.write_text(fernet_key, encoding="utf-8")
                    key_file.chmod(0o600)
            else:
                raise RuntimeError(
                    "FERNET_KEY is required. Generate one with: "
                    "python -c \"from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())\""
                )
        bootstrap_token = os.getenv("BOOTSTRAP_TOKEN", "").strip()
        if app_env == "production" and (len(bootstrap_token) < 24 or bootstrap_token.startswith("replace-")):
            raise RuntimeError("A random BOOTSTRAP_TOKEN of at least 24 characters is required in production")

        raw_hosts = os.getenv("TRUSTED_HOSTS", "localhost,127.0.0.1,testserver")
        trusted_hosts = [host.strip() for host in raw_hosts.split(",") if host.strip()]
        if not trusted_hosts:
            raise RuntimeError("TRUSTED_HOSTS must contain at least one host")

        return cls(
            app_env=app_env,
            database_path=database_path,
            fernet_key=fernet_key,
            bootstrap_token=bootstrap_token,
            cookie_secure=_as_bool(os.getenv("COOKIE_SECURE"), app_env == "production"),
            trusted_hosts=trusted_hosts,
            session_hours=int(os.getenv("SESSION_HOURS", "12")),
            max_message_chars=int(os.getenv("MAX_MESSAGE_CHARS", "20000")),
            local_redactor_model_path=_optional_model_directory("LOCAL_REDACTOR_MODEL_PATH"),
            local_chinese_ner_model_path=_optional_model_directory("LOCAL_CHINESE_NER_MODEL_PATH"),
            local_redactor_device=os.getenv("LOCAL_REDACTOR_DEVICE", "cpu").strip().lower(),
            local_redactor_min_score=_score_threshold("LOCAL_REDACTOR_MIN_SCORE", 0.5),
            local_classifier_model_path=_optional_file_path("LOCAL_CLASSIFIER_MODEL_PATH"),
            local_gguf_chat_format=os.getenv("LOCAL_GGUF_CHAT_FORMAT", "").strip() or None,
            local_gguf_context_tokens=int(os.getenv("LOCAL_GGUF_CONTEXT_TOKENS", "4096")),
            local_gguf_gpu_layers=int(os.getenv("LOCAL_GGUF_GPU_LAYERS", "0")),
            local_gguf_threads=int(os.getenv("LOCAL_GGUF_THREADS", "0")),
        )
