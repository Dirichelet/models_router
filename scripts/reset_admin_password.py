"""Reset one local administrator password without exposing it in shell history.

Run from the repository root:
    uv run python scripts/reset_admin_password.py --username <administrator>
"""

from __future__ import annotations

import argparse
import getpass
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from app.config import Settings  # noqa: E402
from app.database import Database  # noqa: E402
from app.security import PasswordHasher, validate_password_strength  # noqa: E402


def reset_password(database: Database, username: str, password: str) -> bool:
    """Replace a password hash and invalidate every existing browser session."""
    validate_password_strength(password)
    with database.connection() as connection:
        user = connection.execute("SELECT id FROM users WHERE username = ?", (username,)).fetchone()
        if not user:
            return False
        connection.execute("UPDATE users SET password_hash = ? WHERE id = ?", (PasswordHasher.hash(password), user["id"]))
        connection.execute("DELETE FROM sessions WHERE user_id = ?", (user["id"],))
    return True


def main() -> int:
    parser = argparse.ArgumentParser(description="Reset a local Models Router administrator password")
    parser.add_argument("--username", required=True, help="existing administrator username")
    args = parser.parse_args()

    password = getpass.getpass("New password: ")
    confirmation = getpass.getpass("Confirm new password: ")
    if password != confirmation:
        print("Passwords do not match.", file=sys.stderr)
        return 2
    try:
        settings = Settings.from_environment()
        database = Database(settings.database_path)
        database.initialize()
        if not reset_password(database, args.username, password):
            print("No administrator account exists with that username.", file=sys.stderr)
            return 2
    except ValueError as exc:
        print(f"Password was not changed: {exc}", file=sys.stderr)
        return 2
    print("Password reset. Existing browser sessions for this account were signed out.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
