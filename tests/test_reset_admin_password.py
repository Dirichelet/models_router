from __future__ import annotations

from pathlib import Path

from app.database import Database
from app.security import PasswordHasher, validate_password_strength
from scripts.reset_admin_password import reset_password


def test_reset_password_invalidates_existing_sessions(tmp_path: Path) -> None:
    database = Database(tmp_path / "router.db")
    database.initialize()
    with database.connection() as connection:
        user_id = connection.execute(
            "INSERT INTO users(username, password_hash, created_at) VALUES (?, ?, ?)",
            ("admin", PasswordHasher.hash("Old-password-2026"), "2026-01-01T00:00:00+00:00"),
        ).lastrowid
        connection.execute(
            "INSERT INTO sessions(token_hash, csrf_hash, user_id, expires_at, created_at) VALUES (?, ?, ?, ?, ?)",
            ("session", "csrf", user_id, "2099-01-01T00:00:00+00:00", "2026-01-01T00:00:00+00:00"),
        )

    assert reset_password(database, "admin", "New-password-2026")
    with database.connection() as connection:
        account = connection.execute("SELECT password_hash FROM users WHERE username = ?", ("admin",)).fetchone()
        assert PasswordHasher.verify("New-password-2026", account["password_hash"])
        assert connection.execute("SELECT COUNT(*) AS count FROM sessions").fetchone()["count"] == 0


def test_password_policy_rejects_weak_recovery_password() -> None:
    assert validate_password_strength("A-safe-password-2026") == "A-safe-password-2026"
    try:
        validate_password_strength("alllowercase12")
    except ValueError as error:
        assert "three character classes" in str(error)
    else:
        raise AssertionError("Expected weak password to be rejected")
