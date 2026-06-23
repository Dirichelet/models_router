"""Integration tests for the security boundary and the three-stage pipeline."""

from __future__ import annotations

import os
from pathlib import Path

from cryptography.fernet import Fernet
from fastapi.testclient import TestClient


TEST_DATABASE = Path("/tmp/models-router-test.db")
os.environ["APP_ENV"] = "development"
os.environ["COOKIE_SECURE"] = "false"
os.environ["DATABASE_PATH"] = str(TEST_DATABASE)
os.environ["FERNET_KEY"] = Fernet.generate_key().decode()
os.environ["TRUSTED_HOSTS"] = "testserver"

from app import main as application  # noqa: E402
from app.provider import Completion, Usage  # noqa: E402


def client() -> TestClient:
    TEST_DATABASE.unlink(missing_ok=True)
    return TestClient(application.app)


def bootstrap(test_client: TestClient) -> dict[str, str]:
    response = test_client.post("/api/auth/bootstrap", json={"username": "admin", "password": "a-secure-password"})
    assert response.status_code == 201, response.text
    return {"X-CSRF-Token": response.json()["csrf_token"]}


def model_payload(name: str, role: str) -> dict[str, object]:
    return {
        "name": name,
        "role": role,
        "base_url": "https://provider.example/v1/chat/completions",
        "api_key": "test-provider-key",
        "model_name": f"example/{name}",
        "input_price_per_million": 1.0,
        "output_price_per_million": 2.0,
        "is_active": True,
    }


def test_model_changes_require_csrf() -> None:
    with client() as test_client:
        bootstrap(test_client)
        response = test_client.post("/api/models", json=model_payload("redactor", "redactor"))
        assert response.status_code == 403


def test_chat_redacts_before_target_and_records_only_redacted_content(monkeypatch) -> None:
    calls: list[dict[str, object]] = []

    async def fake_completion(**kwargs):
        calls.append(kwargs)
        if len(calls) == 1:
            return Completion("Customer [PERSON] asked about account [ACCOUNT_ID].", Usage(10, 5))
        if len(calls) == 2:
            return Completion('{"model_id": 3, "reason": "Low-cost model is sufficient."}', Usage(20, 10))
        return Completion("Here is the safe answer.", Usage(30, 15))

    monkeypatch.setattr(application, "chat_completion", fake_completion)
    with client() as test_client:
        headers = bootstrap(test_client)
        assert test_client.post("/api/models", headers=headers, json=model_payload("redactor", "redactor")).status_code == 201
        assert test_client.post("/api/models", headers=headers, json=model_payload("router", "router")).status_code == 201
        target = test_client.post("/api/models", headers=headers, json=model_payload("target", "target"))
        assert target.status_code == 201
        assert target.json()["id"] == 3

        original_message = "My name is Alice and my account number is 123456."
        response = test_client.post("/api/chat", headers=headers, json={"message": original_message})
        assert response.status_code == 200, response.text
        payload = response.json()
        assert payload["selected_model"] == "target"
        assert payload["answer"] == "Here is the safe answer."
        assert calls[0]["messages"][1]["content"] == original_message
        assert calls[1]["messages"][1]["content"] == payload["redacted_message"]
        assert calls[2]["messages"][1]["content"] == payload["redacted_message"]

        audit = test_client.get("/api/calls").json()
        assert audit[0]["redacted_message"] == payload["redacted_message"]
        assert original_message not in str(audit)
        assert audit[0]["total_cost"] == 0.00012
