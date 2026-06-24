"""Authentication and secret-at-rest primitives."""

from __future__ import annotations

import base64
import hashlib
import hmac
import secrets

from cryptography.fernet import Fernet, InvalidToken


class PasswordHasher:
    """Use scrypt from the standard library with an encoded, upgradable format."""

    n = 2**14
    r = 8
    p = 1

    @classmethod
    def hash(cls, password: str) -> str:
        salt = secrets.token_bytes(16)
        digest = hashlib.scrypt(
            password.encode("utf-8"), salt=salt, n=cls.n, r=cls.r, p=cls.p
        )
        return "$".join(
            (
                "scrypt",
                str(cls.n),
                str(cls.r),
                str(cls.p),
                base64.urlsafe_b64encode(salt).decode("ascii"),
                base64.urlsafe_b64encode(digest).decode("ascii"),
            )
        )

    @classmethod
    def verify(cls, password: str, encoded: str) -> bool:
        try:
            algorithm, n, r, p, salt, expected = encoded.split("$")
            if algorithm != "scrypt":
                return False
            candidate = hashlib.scrypt(
                password.encode("utf-8"),
                salt=base64.urlsafe_b64decode(salt),
                n=int(n),
                r=int(r),
                p=int(p),
            )
            return hmac.compare_digest(candidate, base64.urlsafe_b64decode(expected))
        except (ValueError, TypeError):
            return False


def validate_password_strength(password: str) -> str:
    """Apply the password policy shared by web and local recovery flows."""
    if not 12 <= len(password) <= 256:
        raise ValueError("Password must contain 12 to 256 characters")
    if len(set(password)) < 4:
        raise ValueError("Password must not be a repeated-character password")
    character_classes = sum(
        (
            any(char.islower() for char in password),
            any(char.isupper() for char in password),
            any(char.isdigit() for char in password),
            any(not char.isalnum() for char in password),
        )
    )
    if len(password) < 16 and character_classes < 3:
        raise ValueError("Passwords shorter than 16 characters must use at least three character classes")
    return password


class SecretBox:
    def __init__(self, key: str) -> None:
        self._fernet = Fernet(key.encode("utf-8"))

    def encrypt(self, value: str) -> str:
        return self._fernet.encrypt(value.encode("utf-8")).decode("utf-8")

    def decrypt(self, value: str) -> str:
        try:
            return self._fernet.decrypt(value.encode("utf-8")).decode("utf-8")
        except InvalidToken as exc:
            raise ValueError("Model API key must be re-entered because FERNET_KEY changed") from exc


def new_token() -> str:
    return secrets.token_urlsafe(32)


def token_hash(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest()
