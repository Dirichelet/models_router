"""Minimal SQLite persistence layer. The original user message is never persisted."""

from __future__ import annotations

import sqlite3
from contextlib import contextmanager
from pathlib import Path
from typing import Iterator


SCHEMA = """
PRAGMA foreign_keys = ON;

CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT NOT NULL UNIQUE,
    password_hash TEXT NOT NULL,
    created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS sessions (
    token_hash TEXT PRIMARY KEY,
    csrf_hash TEXT NOT NULL,
    user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    expires_at TEXT NOT NULL,
    created_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_sessions_user_id ON sessions(user_id);

CREATE TABLE IF NOT EXISTS models (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL UNIQUE,
    role TEXT NOT NULL CHECK(role IN ('redactor', 'router', 'target')),
    base_url TEXT NOT NULL,
    api_key_encrypted TEXT NOT NULL,
    model_name TEXT NOT NULL,
    input_price_per_million REAL NOT NULL DEFAULT 0 CHECK(input_price_per_million >= 0),
    output_price_per_million REAL NOT NULL DEFAULT 0 CHECK(output_price_per_million >= 0),
    is_active INTEGER NOT NULL DEFAULT 1 CHECK(is_active IN (0, 1)),
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_models_role_active ON models(role, is_active);

CREATE TABLE IF NOT EXISTS rules (
    name TEXT PRIMARY KEY CHECK(name IN ('redaction', 'routing')),
    content TEXT NOT NULL,
    updated_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS calls (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    created_at TEXT NOT NULL,
    user_id INTEGER NOT NULL REFERENCES users(id),
    redactor_model_name TEXT,
    router_model_name TEXT,
    selected_model_name TEXT,
    redacted_message TEXT,
    routing_reason TEXT,
    prompt_tokens INTEGER NOT NULL DEFAULT 0,
    completion_tokens INTEGER NOT NULL DEFAULT 0,
    total_cost REAL NOT NULL DEFAULT 0,
    cost_known INTEGER NOT NULL DEFAULT 1 CHECK(cost_known IN (0, 1)),
    kind TEXT NOT NULL DEFAULT 'chat' CHECK(kind IN ('chat', 'connection_test')),
    status TEXT NOT NULL CHECK(status IN ('succeeded', 'failed')),
    error_message TEXT
);
CREATE INDEX IF NOT EXISTS idx_calls_created_at ON calls(created_at DESC);
"""


class Database:
    def __init__(self, path: Path) -> None:
        self.path = path

    def initialize(self) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        with self.connection() as connection:
            connection.executescript(SCHEMA)
            columns = {row["name"] for row in connection.execute("PRAGMA table_info(calls)")}
            if "cost_known" not in columns:
                connection.execute("ALTER TABLE calls ADD COLUMN cost_known INTEGER NOT NULL DEFAULT 1")
            if "kind" not in columns:
                connection.execute("ALTER TABLE calls ADD COLUMN kind TEXT NOT NULL DEFAULT 'chat'")
            connection.executemany(
                """
                INSERT INTO rules(name, content, updated_at) VALUES (?, ?, datetime('now'))
                ON CONFLICT(name) DO NOTHING
                """,
                (
                    (
                        "redaction",
                        "Replace direct identifiers and sensitive values with consistent placeholders. "
                        "Return only the redacted user message; do not explain the transformation.",
                    ),
                    (
                        "routing",
                        "Select the candidate that can answer accurately at the lowest appropriate cost. "
                        "Consider the redacted request complexity, required reasoning, and configured prices.",
                    ),
                ),
            )

    @contextmanager
    def connection(self) -> Iterator[sqlite3.Connection]:
        connection = sqlite3.connect(self.path, timeout=10, isolation_level="DEFERRED")
        connection.row_factory = sqlite3.Row
        try:
            yield connection
            connection.commit()
        except Exception:
            connection.rollback()
            raise
        finally:
            connection.close()
