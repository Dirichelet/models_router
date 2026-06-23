"""Integration tests for the security boundary and the three-stage pipeline."""

from __future__ import annotations

import os
import asyncio
from dataclasses import replace
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
from app.provider import ProviderError, chat_completion  # noqa: E402
from app.database import DEFAULT_RULES  # noqa: E402


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
        "base_url": "https://provider.example/v1",
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


def test_csrf_token_is_refreshed_after_a_page_reload() -> None:
    with client() as test_client:
        stale_headers = bootstrap(test_client)
        refreshed = test_client.get("/api/auth/csrf")
        assert refreshed.status_code == 200
        fresh_headers = {"X-CSRF-Token": refreshed.json()["csrf_token"]}
        assert fresh_headers["X-CSRF-Token"] != stale_headers["X-CSRF-Token"]
        assert test_client.post("/api/models", headers=stale_headers, json=model_payload("stale", "redactor")).status_code == 403
        assert test_client.post("/api/models", headers=fresh_headers, json=model_payload("fresh", "redactor")).status_code == 201


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
        evaluation = test_client.get("/api/evaluation").json()
        assert evaluation == {
            "chat_calls": 1,
            "successful_chat_calls": 1,
            "privacy_blocks": 0,
            "routing_fallbacks": 0,
            "known_cost_chat_calls": 1,
        }


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
        assert test_client.get("/api/evaluation").json()["privacy_blocks"] == 1


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


def test_bootstrap_token_protects_the_first_public_account(monkeypatch) -> None:
    monkeypatch.setattr(application, "settings", replace(application.settings, bootstrap_token="a-very-long-bootstrap-token-123"))
    with client() as test_client:
        state = test_client.get("/api/auth/state").json()
        assert state["bootstrap_token_required"] is True
        rejected = test_client.post("/api/auth/bootstrap", json={"username": "admin", "password": "a-secure-password"})
        assert rejected.status_code == 403
        accepted = test_client.post(
            "/api/auth/bootstrap",
            json={"username": "admin", "password": "a-secure-password", "bootstrap_token": "a-very-long-bootstrap-token-123"},
        )
        assert accepted.status_code == 201


def test_audit_records_can_be_deleted_from_the_protected_api(monkeypatch) -> None:
    async def test_completion(**_kwargs):
        return Completion("connection-ok", Usage(4, 2))

    monkeypatch.setattr(application, "chat_completion", test_completion)
    with client() as test_client:
        headers = bootstrap(test_client)
        model = test_client.post("/api/models", headers=headers, json=model_payload("target", "target"))
        assert test_client.post(f"/api/models/{model.json()['id']}/test", headers=headers).status_code == 200
        assert len(test_client.get("/api/calls").json()) == 1
        cleared = test_client.delete("/api/calls", headers=headers)
        assert cleared.status_code == 200
        assert cleared.json() == {"deleted_count": 1}
        assert test_client.get("/api/calls").json() == []


def test_short_weak_password_is_rejected_but_long_passphrase_is_accepted() -> None:
    with client() as test_client:
        weak = test_client.post("/api/auth/bootstrap", json={"username": "admin", "password": "onlylowercase"})
        assert weak.status_code == 422
        strong = test_client.post(
            "/api/auth/bootstrap", json={"username": "admin", "password": "correct horse battery staple"}
        )
        assert strong.status_code == 201


def test_invalid_router_choice_falls_back_and_is_exposed_in_evaluation(monkeypatch) -> None:
    completions = iter(
        (
            Completion("Question for [PERSON].", Usage(10, 5)),
            Completion("I cannot choose a model today.", Usage(10, 5)),
            Completion("Fallback answer.", Usage(10, 5)),
        )
    )

    async def invalid_router(**_kwargs):
        return next(completions)

    monkeypatch.setattr(application, "chat_completion", invalid_router)
    with client() as test_client:
        headers = bootstrap(test_client)
        assert test_client.post("/api/models", headers=headers, json=model_payload("redactor", "redactor")).status_code == 201
        assert test_client.post("/api/models", headers=headers, json=model_payload("router", "router")).status_code == 201
        assert test_client.post("/api/models", headers=headers, json=model_payload("target", "target")).status_code == 201
        response = test_client.post("/api/chat", headers=headers, json={"message": "Question for Alice"})
        assert response.status_code == 200
        assert response.json()["routing_reason"].startswith("Router response was invalid")
        evaluation = test_client.get("/api/evaluation").json()
        assert evaluation["routing_fallbacks"] == 1


def test_pipeline_status_reports_missing_and_ready_model_roles() -> None:
    with client() as test_client:
        headers = bootstrap(test_client)
        assert test_client.get("/api/pipeline/status").json() == {
            "redactor": None,
            "router": None,
            "active_targets": 0,
            "ready": False,
        }
        for name, role in (("redactor", "redactor"), ("router", "router"), ("target", "target")):
            assert test_client.post("/api/models", headers=headers, json=model_payload(name, role)).status_code == 201
        status = test_client.get("/api/pipeline/status").json()
        assert status["ready"] is True
        assert status["redactor"] == "redactor"
        assert status["router"] == "router"
        assert status["active_targets"] == 1


def test_audit_records_and_statistics_are_scoped_to_the_current_user() -> None:
    with client() as test_client:
        headers = bootstrap(test_client)
        own_user_id = test_client.get("/api/auth/me").json()["id"]
        with application.database.connection() as connection:
            other_user_id = connection.execute(
                "INSERT INTO users(username, password_hash, created_at) VALUES (?, ?, ?)",
                ("other-user", "not-used-in-this-test", "2026-01-01T00:00:00+00:00"),
            ).lastrowid
        for user_id in (own_user_id, other_user_id):
            application._record_call(
                user_id=user_id,
                redactor_name=None,
                router_name=None,
                target_name="target",
                redacted_message="[PERSON] question",
                routing_reason="test",
                prompt_tokens=1,
                completion_tokens=1,
                total_cost=0.1,
                cost_known=True,
                status_name="succeeded",
            )

        assert len(test_client.get("/api/calls").json()) == 1
        assert test_client.get("/api/stats").json()["total_calls"] == 1
        assert test_client.delete("/api/calls", headers=headers).json() == {"deleted_count": 1}
        with application.database.connection() as connection:
            remaining = connection.execute("SELECT COUNT(*) AS count FROM calls WHERE user_id = ?", (other_user_id,)).fetchone()
        assert remaining["count"] == 1


def test_provider_rate_limit_is_safe_and_includes_retry_guidance(monkeypatch) -> None:
    class Response:
        status_code = 429
        headers = {"retry-after": "20"}

    class Client:
        async def __aenter__(self):
            return self

        async def __aexit__(self, *_args):
            return None

        async def post(self, *_args, **_kwargs):
            return Response()

    captured = {}

    def client_factory(**kwargs):
        captured.update(kwargs)
        return Client()

    monkeypatch.setattr("app.provider.httpx.AsyncClient", client_factory)
    try:
        asyncio.run(
            chat_completion(
                base_url="https://provider.example/v1",
                api_key="not-in-error-message",
                model_name="example/model",
                messages=[{"role": "user", "content": "test"}],
            )
        )
    except ProviderError as error:
        assert error.status_code == 429
        assert str(error) == "Model provider rate limited the request. Retry after 20 seconds."
        assert "not-in-error-message" not in str(error)
    else:
        raise AssertionError("Expected ProviderError")
    assert captured["trust_env"] is False


def test_model_picker_lists_provider_models_without_returning_credentials(monkeypatch) -> None:
    received = {}

    async def fake_models(*, base_url, api_key):
        received.update({"base_url": base_url, "api_key": api_key})
        return ["budget/model", "reasoning/model"]

    monkeypatch.setattr(application, "fetch_provider_models", fake_models)
    with client() as test_client:
        headers = bootstrap(test_client)
        response = test_client.post(
            "/api/provider-models",
            headers=headers,
            json={"base_url": "https://provider.example/v1", "api_key": "temporary-key"},
        )
        assert response.status_code == 200
        assert response.json() == {"models": ["budget/model", "reasoning/model"]}
        assert received == {"base_url": "https://provider.example/v1", "api_key": "temporary-key"}
        compatible_prefix = test_client.post(
            "/api/provider-models",
            headers=headers,
            json={"base_url": "https://openrouter.ai/api/v1", "api_key": "temporary-key"},
        )
        assert compatible_prefix.status_code == 200
        invalid = test_client.post(
            "/api/provider-models",
            headers=headers,
            json={"base_url": "https://provider.example/v1/chat/completions", "api_key": "temporary-key"},
        )
        assert invalid.status_code == 422


def test_saved_model_picker_uses_encrypted_key_and_default_rules_are_detailed(monkeypatch) -> None:
    async def fake_models(*, base_url, api_key):
        assert base_url == "https://provider.example/v1"
        assert api_key == "test-provider-key"
        return ["provider/available-model"]

    monkeypatch.setattr(application, "fetch_provider_models", fake_models)
    with client() as test_client:
        headers = bootstrap(test_client)
        created = test_client.post("/api/models", headers=headers, json=model_payload("target", "target"))
        available = test_client.post(f"/api/models/{created.json()['id']}/available-models", headers=headers)
        assert available.status_code == 200
        assert available.json() == {"models": ["provider/available-model"]}
        defaults = test_client.get("/api/rules/defaults").json()
        assert defaults == DEFAULT_RULES
        assert len(defaults["redaction"]) > 500
        assert len(defaults["routing"]) > 400


def test_multiple_selected_target_models_can_be_created_together() -> None:
    with client() as test_client:
        headers = bootstrap(test_client)
        first = model_payload("target-alpha", "target")
        first["model_name"] = "provider/alpha"
        second = model_payload("target-beta", "target")
        second["model_name"] = "provider/beta"
        response = test_client.post("/api/models/batch", headers=headers, json={"models": [first, second]})
        assert response.status_code == 201, response.text
        assert [model["model_name"] for model in response.json()["models"]] == ["provider/alpha", "provider/beta"]
        assert test_client.get("/api/pipeline/status").json()["active_targets"] == 2
