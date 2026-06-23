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
            return Completion('{"model_id": "3", "reason": "Low-cost model is sufficient."}', Usage(20, 10))
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


def test_privacy_guard_stops_a_leaky_redactor_before_routing_or_target(monkeypatch) -> None:
    invoked = 0

    async def leaky_redactor(**_kwargs):
        nonlocal invoked
        invoked += 1
        return Completion("Contact alice@example.com for the answer.", Usage(10, 5))

    monkeypatch.setattr(application, "chat_completion", leaky_redactor)
    with client() as test_client:
        headers = bootstrap(test_client)
        assert test_client.post("/api/models", headers=headers, json=model_payload("redactor", "redactor")).status_code == 201
        assert test_client.post("/api/models", headers=headers, json=model_payload("router", "router")).status_code == 201
        assert test_client.post("/api/models", headers=headers, json=model_payload("target", "target")).status_code == 201

        original_message = "Please contact alice@example.com about my case."
        response = test_client.post("/api/chat", headers=headers, json={"message": original_message})
        assert response.status_code == 502
        assert "de-identification check" in response.json()["detail"]
        assert invoked == 1

        audit = test_client.get("/api/calls").json()
        assert audit[0]["status"] == "failed"
        assert audit[0]["redacted_message"] is None
        assert original_message not in str(audit)


def test_missing_provider_usage_is_not_reported_as_actual_cost(monkeypatch) -> None:
    completions = iter(
        (
            Completion("Question about [PERSON].", Usage(0, 0, reported=False)),
            Completion('{"model_id": 3, "reason": "Suitable."}', Usage(10, 5)),
            Completion("Answer.", Usage(10, 5)),
        )
    )

    async def missing_usage(**_kwargs):
        return next(completions)

    monkeypatch.setattr(application, "chat_completion", missing_usage)
    with client() as test_client:
        headers = bootstrap(test_client)
        for name, role in (("redactor", "redactor"), ("router", "router"), ("target", "target")):
            assert test_client.post("/api/models", headers=headers, json=model_payload(name, role)).status_code == 201
        response = test_client.post("/api/chat", headers=headers, json={"message": "Question for Alice"})
        assert response.status_code == 200, response.text
        assert response.json()["cost_known"] is False

        audit = test_client.get("/api/calls").json()
        assert audit[0]["cost_known"] == 0
        stats = test_client.get("/api/stats").json()
        assert stats["unknown_cost_calls"] == 1


def test_password_change_invalidates_old_sessions_and_reissues_csrf() -> None:
    with client() as test_client:
        headers = bootstrap(test_client)
        response = test_client.put(
            "/api/auth/password",
            headers=headers,
            json={"current_password": "a-secure-password", "new_password": "an-even-better-password"},
        )
        assert response.status_code == 200, response.text
        replacement_headers = {"X-CSRF-Token": response.json()["csrf_token"]}
        assert replacement_headers["X-CSRF-Token"] != headers["X-CSRF-Token"]
        assert test_client.get("/api/auth/me").status_code == 200

        test_client.post("/api/auth/logout", headers=replacement_headers)
        assert test_client.post(
            "/api/auth/login", json={"username": "admin", "password": "a-secure-password"}
        ).status_code == 401
        assert test_client.post(
            "/api/auth/login", json={"username": "admin", "password": "an-even-better-password"}
        ).status_code == 200


def test_model_connection_test_is_audited(monkeypatch) -> None:
    async def test_completion(**kwargs):
        assert kwargs["max_tokens"] == 12
        return Completion("connection-ok", Usage(4, 2))

    monkeypatch.setattr(application, "chat_completion", test_completion)
    with client() as test_client:
        headers = bootstrap(test_client)
        model = test_client.post("/api/models", headers=headers, json=model_payload("target", "target"))
        assert model.status_code == 201
        result = test_client.post(f"/api/models/{model.json()['id']}/test", headers=headers)
        assert result.status_code == 200, result.text
        assert result.json()["response_preview"] == "connection-ok"
        audit = test_client.get("/api/calls").json()
        assert audit[0]["kind"] == "connection_test"
        assert audit[0]["selected_model_name"] == "target"
