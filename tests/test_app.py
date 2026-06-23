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
os.environ["HF_HOME"] = "/tmp/models-router-test-huggingface"

from app import main as application  # noqa: E402
from app import redaction as local_redaction  # noqa: E402
from app.provider import Completion, Usage  # noqa: E402
from app.provider import ProviderError, chat_completion  # noqa: E402
from app.database import DEFAULT_RULES  # noqa: E402
from app.config import Settings  # noqa: E402
from app.redaction import KeywordRule, RedactionResult, _replace_keywords, _replace_regex  # noqa: E402
from app.security import SecretBox  # noqa: E402


def client() -> TestClient:
    for path in (TEST_DATABASE, Path(f"{TEST_DATABASE}-shm"), Path(f"{TEST_DATABASE}-wal")):
        path.unlink(missing_ok=True)
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


def enable_local_redaction(monkeypatch, redacted_text: str | None = None) -> list[str]:
    model_path = Path("/tmp/models-router-test-privacy-filter")
    model_path.mkdir(exist_ok=True)
    monkeypatch.setattr(application, "settings", replace(application.settings, local_redactor_model_path=model_path))
    monkeypatch.setattr(application, "local_redactor_runtime_error", lambda: None)
    inputs: list[str] = []

    def fake_local_redact(_options, text, _keyword_rules=()):
        inputs.append(text)
        return RedactionResult(text=redacted_text if redacted_text is not None else text, regex_spans=0, model_spans=1)

    monkeypatch.setattr(application, "local_redact", fake_local_redact)
    return inputs


def test_model_changes_require_csrf() -> None:
    with client() as test_client:
        bootstrap(test_client)
        response = test_client.post("/api/models", json=model_payload("redactor", "redactor"))
        assert response.status_code == 403


def test_provider_redactor_is_rejected_after_csrf_validation() -> None:
    with client() as test_client:
        headers = bootstrap(test_client)
        response = test_client.post("/api/models", headers=headers, json=model_payload("redactor", "redactor"))
        assert response.status_code == 422


def test_csrf_token_is_refreshed_after_a_page_reload() -> None:
    with client() as test_client:
        stale_headers = bootstrap(test_client)
        refreshed = test_client.get("/api/auth/csrf")
        assert refreshed.status_code == 200
        fresh_headers = {"X-CSRF-Token": refreshed.json()["csrf_token"]}
        assert fresh_headers["X-CSRF-Token"] != stale_headers["X-CSRF-Token"]
        assert test_client.post("/api/models", headers=stale_headers, json=model_payload("stale", "redactor")).status_code == 403
        assert test_client.post("/api/models", headers=fresh_headers, json=model_payload("fresh", "router")).status_code == 201


def test_chat_redacts_before_target_and_records_only_redacted_content(monkeypatch) -> None:
    calls: list[dict[str, object]] = []
    local_inputs = enable_local_redaction(monkeypatch, "Customer [PERSON] asked about account [ACCOUNT].")

    async def fake_completion(**kwargs):
        calls.append(kwargs)
        if len(calls) == 1:
            return Completion('{"model_id": "2", "reason": "Low-cost model is sufficient."}', Usage(20, 10))
        return Completion("Here is the safe answer.", Usage(30, 15))

    monkeypatch.setattr(application, "chat_completion", fake_completion)
    with client() as test_client:
        headers = bootstrap(test_client)
        assert test_client.post("/api/models", headers=headers, json=model_payload("router", "router")).status_code == 201
        target = test_client.post("/api/models", headers=headers, json=model_payload("target", "target"))
        assert target.status_code == 201
        assert target.json()["id"] == 2

        original_message = "My name is Alice and my account number is 123456."
        response = test_client.post("/api/chat", headers=headers, json={"message": original_message})
        assert response.status_code == 200, response.text
        payload = response.json()
        assert payload["selected_model"] == "target"
        assert payload["answer"] == "Here is the safe answer."
        assert local_inputs == [original_message]
        assert calls[0]["messages"][1]["content"] == payload["redacted_message"]
        assert calls[1]["messages"][1]["content"] == payload["redacted_message"]

        audit = test_client.get("/api/calls").json()
        assert audit[0]["redacted_message"] == payload["redacted_message"]
        assert original_message not in str(audit)
        assert audit[0]["total_cost"] == 0.0001
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
    enable_local_redaction(monkeypatch, "Contact alice@example.com for the answer.")

    async def leaky_redactor(**_kwargs):
        nonlocal invoked
        invoked += 1
        return Completion("Contact alice@example.com for the answer.", Usage(10, 5))

    monkeypatch.setattr(application, "chat_completion", leaky_redactor)
    with client() as test_client:
        headers = bootstrap(test_client)
        assert test_client.post("/api/models", headers=headers, json=model_payload("router", "router")).status_code == 201
        assert test_client.post("/api/models", headers=headers, json=model_payload("target", "target")).status_code == 201

        original_message = "Please contact alice@example.com about my case."
        response = test_client.post("/api/chat", headers=headers, json={"message": original_message})
        assert response.status_code == 502
        assert "de-identification check" in response.json()["detail"]
        assert invoked == 0

        audit = test_client.get("/api/calls").json()
        assert audit[0]["status"] == "failed"
        assert audit[0]["redacted_message"] is None
        assert original_message not in str(audit)
        assert test_client.get("/api/evaluation").json()["privacy_blocks"] == 1


def test_missing_provider_usage_is_not_reported_as_actual_cost(monkeypatch) -> None:
    completions = iter(
        (
            Completion('{"model_id": 2, "reason": "Suitable."}', Usage(0, 0, reported=False)),
            Completion("Answer.", Usage(10, 5)),
        )
    )

    async def missing_usage(**_kwargs):
        return next(completions)

    monkeypatch.setattr(application, "chat_completion", missing_usage)
    enable_local_redaction(monkeypatch, "Question about [PERSON].")
    with client() as test_client:
        headers = bootstrap(test_client)
        for name, role in (("router", "router"), ("target", "target")):
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
            Completion("I cannot choose a model today.", Usage(10, 5)),
            Completion("Fallback answer.", Usage(10, 5)),
        )
    )

    async def invalid_router(**_kwargs):
        return next(completions)

    monkeypatch.setattr(application, "chat_completion", invalid_router)
    enable_local_redaction(monkeypatch, "Question for [PERSON].")
    with client() as test_client:
        headers = bootstrap(test_client)
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
            "redaction_mode": "disabled",
            "routing_mode": "default",
            "active_targets": 0,
            "available_targets": 0,
            "invalid_credentials": [],
            "invalid_required_credentials": [],
            "invalid_targets": [],
            "local_runtime_error": None,
            "ready": False,
        }
        for name, role in (("router", "router"), ("target", "target")):
            assert test_client.post("/api/models", headers=headers, json=model_payload(name, role)).status_code == 201
        status = test_client.get("/api/pipeline/status").json()
        assert status["ready"] is True
        assert status["redactor"] is None
        assert status["router"] == "router"
        assert status["active_targets"] == 1
        assert status["available_targets"] == 1
        assert status["invalid_credentials"] == []


def test_chat_without_redactor_or_router_uses_default_cost_route_and_never_persists_raw_message(monkeypatch) -> None:
    requests = []

    async def target_completion(**kwargs):
        requests.append(kwargs)
        return Completion("Default-routed answer.", Usage(10, 5))

    monkeypatch.setattr(application, "chat_completion", target_completion)
    with client() as test_client:
        headers = bootstrap(test_client)
        low_cost = model_payload("low-cost", "target")
        low_cost["input_price_per_million"] = 0.1
        low_cost["output_price_per_million"] = 0.1
        high_cost = model_payload("high-cost", "target")
        high_cost["input_price_per_million"] = 10.0
        high_cost["output_price_per_million"] = 10.0
        assert test_client.post("/api/models", headers=headers, json=low_cost).status_code == 201
        assert test_client.post("/api/models", headers=headers, json=high_cost).status_code == 201

        pipeline = test_client.get("/api/pipeline/status").json()
        assert pipeline["ready"] is True
        assert pipeline["redaction_mode"] == "disabled"
        assert pipeline["routing_mode"] == "default"
        response = test_client.post("/api/chat", headers=headers, json={"message": "What time is it?"})
        assert response.status_code == 200, response.text
        assert response.json()["selected_model"] == "low-cost"
        assert response.json()["redaction_applied"] is False
        assert response.json()["redacted_message"] is None
        assert len(requests) == 1
        assert requests[0]["messages"][1]["content"] == "What time is it?"
        audit = test_client.get("/api/calls").json()[0]
        assert audit["redacted_message"] is None
        assert audit["redactor_model_name"] is None
        assert audit["router_model_name"] == "内置难度/费率路由"


def test_local_regex_and_fuzzy_keyword_rules_mask_chinese_sensitive_text() -> None:
    regex_redacted, regex_count = _replace_regex("电话 13800138000，身份证 11010519491231002X，邮箱 alice@example.com")
    assert regex_count == 3
    assert "13800138000" not in regex_redacted
    assert "11010519491231002X" not in regex_redacted
    keyword_redacted, keyword_count = _replace_keywords(
        "项目 天-狼_星 正在上线",
        (KeywordRule(phrase="项目天狼星", replacement="[PROJECT]", fuzzy=True),),
    )
    assert keyword_count == 1
    assert keyword_redacted == "[PROJECT] 正在上线"


def test_local_redactor_uses_only_a_validated_local_path_without_duplicate_local_files_flag(monkeypatch, tmp_path) -> None:
    import transformers
    import transformers.pipelines

    model_directory = tmp_path / "privacy-filter"
    model_directory.mkdir()
    captured = []

    def fake_pipeline(**kwargs):
        captured.append(kwargs)
        return lambda _text: []

    monkeypatch.setattr(transformers, "pipeline", fake_pipeline)
    monkeypatch.setattr(transformers.pipelines, "pipeline", fake_pipeline)
    monkeypatch.setattr(local_redaction, "_pipeline_device", lambda _device: (-1, {"dtype": "float32"}))
    local_redaction.LocalPIIRedactor(
        local_redaction.LocalRedactorOptions(
            privacy_filter_path=model_directory,
            chinese_ner_path=None,
            device="cpu",
            min_score=0.5,
        )
    )
    assert captured[0]["model"] == str(model_directory)
    assert captured[0]["tokenizer"] == str(model_directory)
    assert "local_files_only" not in captured[0]["model_kwargs"]


def test_keyword_rules_are_scoped_to_the_user_and_passed_to_local_redaction(monkeypatch) -> None:
    captured_rules = []
    model_path = Path("/tmp/models-router-test-privacy-filter-keywords")
    model_path.mkdir(exist_ok=True)
    monkeypatch.setattr(application, "settings", replace(application.settings, local_redactor_model_path=model_path))
    monkeypatch.setattr(application, "local_redactor_runtime_error", lambda: None)

    def keyword_redactor(_options, _text, keyword_rules=()):
        captured_rules.extend(keyword_rules)
        return RedactionResult("[PROJECT] 状态", regex_spans=1, model_spans=0)

    async def target_completion(**_kwargs):
        return Completion("Safe answer.", Usage(10, 5))

    monkeypatch.setattr(application, "local_redact", keyword_redactor)
    monkeypatch.setattr(application, "chat_completion", target_completion)
    with client() as test_client:
        headers = bootstrap(test_client)
        assert test_client.post("/api/models", headers=headers, json=model_payload("target", "target")).status_code == 201
        created = test_client.post(
            "/api/keyword-rules",
            headers=headers,
            json={"phrase": "项目天狼星", "replacement": "[PROJECT]", "is_fuzzy": True},
        )
        assert created.status_code == 201, created.text
        assert created.json()["is_fuzzy"] is True
        assert test_client.get("/api/keyword-rules").json()[0]["phrase"] == "项目天狼星"
        response = test_client.post("/api/chat", headers=headers, json={"message": "项目 天-狼_星 状态"})
        assert response.status_code == 200, response.text
        assert captured_rules == [KeywordRule(phrase="项目天狼星", replacement="[PROJECT]", fuzzy=True)]
        assert test_client.get("/api/calls").json()[0]["redacted_message"] == "[PROJECT] 状态"


def test_chat_context_is_sent_to_the_pipeline_without_persisting_raw_turns(monkeypatch) -> None:
    requests = []
    local_inputs = enable_local_redaction(monkeypatch, "[USER]\nPrior [QUESTION]\n\n[ASSISTANT]\nPrior [ANSWER]\n\n[USER]\nCurrent [PERSON] question")
    completions = iter(
        (
            Completion('{"model_id": 2, "reason": "Context requires the configured target."}', Usage(10, 5)),
            Completion("Context-aware answer.", Usage(10, 5)),
        )
    )

    async def pipeline_completion(**kwargs):
        requests.append(kwargs)
        return next(completions)

    monkeypatch.setattr(application, "chat_completion", pipeline_completion)
    with client() as test_client:
        headers = bootstrap(test_client)
        for name, role in (("router", "router"), ("target", "target")):
            assert test_client.post("/api/models", headers=headers, json=model_payload(name, role)).status_code == 201
        response = test_client.post(
            "/api/chat",
            headers=headers,
            json={
                "message": "Current Alice question",
                "context": [
                    {"role": "user", "content": "Previous question"},
                    {"role": "assistant", "content": "Previous answer"},
                ],
            },
        )
        assert response.status_code == 200, response.text
        assert local_inputs == ["[USER]\nPrevious question\n\n[ASSISTANT]\nPrevious answer\n\n[USER]\nCurrent Alice question"]
        assert requests[1]["messages"][1]["content"] == response.json()["redacted_message"]
        assert "Previous question" not in test_client.get("/api/calls").json()[0]["redacted_message"]


def test_development_fernet_key_is_created_once_and_reused(monkeypatch, tmp_path) -> None:
    database_path = tmp_path / "data" / "models_router.db"
    monkeypatch.setenv("APP_ENV", "development")
    monkeypatch.setenv("DATABASE_PATH", str(database_path))
    monkeypatch.delenv("FERNET_KEY", raising=False)
    first = Settings.from_environment()
    second = Settings.from_environment()
    assert first.fernet_key == second.fernet_key
    assert (database_path.parent / ".dev-fernet.key").read_text(encoding="utf-8") == first.fernet_key


def test_local_gguf_paths_are_loaded_only_from_environment(monkeypatch, tmp_path) -> None:
    redactor = tmp_path / "redactor"
    classifier = tmp_path / "classifier.gguf"
    redactor.mkdir()
    classifier.touch()
    monkeypatch.setenv("LOCAL_REDACTOR_MODEL_PATH", str(redactor))
    monkeypatch.setenv("LOCAL_CLASSIFIER_MODEL_PATH", str(classifier))
    settings = Settings.from_environment()
    assert settings.local_redactor_model_path == redactor.resolve()
    assert settings.local_classifier_model_path == classifier.resolve()


def test_cached_privacy_filter_is_used_when_no_redactor_path_is_set(monkeypatch, tmp_path) -> None:
    hub_cache = tmp_path / "hub"
    revision = "test-revision"
    snapshot = hub_cache / "models--openai--privacy-filter" / "snapshots" / revision
    snapshot.mkdir(parents=True)
    reference = hub_cache / "models--openai--privacy-filter" / "refs"
    reference.mkdir(parents=True)
    (reference / "main").write_text(revision, encoding="utf-8")
    monkeypatch.delenv("LOCAL_REDACTOR_MODEL_PATH", raising=False)
    monkeypatch.setenv("HF_HUB_CACHE", str(hub_cache))
    settings = Settings.from_environment()
    assert settings.local_redactor_model_path == snapshot.resolve()


def test_local_redactor_and_classifier_override_web_roles(monkeypatch, tmp_path) -> None:
    redactor = tmp_path / "redactor"
    classifier = tmp_path / "classifier.gguf"
    redactor.mkdir()
    classifier.touch()
    monkeypatch.setattr(
        application,
        "settings",
        replace(
            application.settings,
            local_redactor_model_path=redactor,
            local_classifier_model_path=classifier,
        ),
    )
    monkeypatch.setattr(application, "local_runtime_error", lambda: None)
    monkeypatch.setattr(application, "local_redactor_runtime_error", lambda: None)
    local_requests = []

    local_redactions = []

    def local_redaction(_options, text, _keyword_rules=()):
        local_redactions.append(text)
        return RedactionResult("Question for [PERSON].", regex_spans=0, model_spans=1)

    async def local_completion(options, _messages, **_kwargs):
        local_requests.append(options.path)
        return Completion('{"model_id": 1, "reason": "Local classifier selected it."}', Usage(reported=False))

    monkeypatch.setattr(application, "local_redact", local_redaction)
    async def target_completion(**_kwargs):
        return Completion("Local pipeline answer.", Usage(10, 5))

    monkeypatch.setattr(application, "local_chat_completion", local_completion)
    monkeypatch.setattr(application, "chat_completion", target_completion)
    with client() as test_client:
        headers = bootstrap(test_client)
        assert test_client.post("/api/models", headers=headers, json=model_payload("target", "target")).status_code == 201
        pipeline = test_client.get("/api/pipeline/status").json()
        assert pipeline["redactor"] == "本地 Transformers：redactor"
        assert pipeline["router"] == "本地 GGUF：classifier.gguf"
        assert pipeline["redaction_mode"] == "local"
        assert pipeline["routing_mode"] == "local"
        response = test_client.post("/api/chat", headers=headers, json={"message": "Question for Alice"})
        assert response.status_code == 200, response.text
        assert response.json()["selected_model"] == "target"
        assert response.json()["cost_known"] is True
        assert local_redactions == ["Question for Alice"]
        assert local_requests == [classifier]


def test_models_with_a_changed_fernet_key_are_marked_for_reentry(monkeypatch) -> None:
    with client() as test_client:
        headers = bootstrap(test_client)
        for name, role in (("router", "router"), ("target", "target")):
            assert test_client.post("/api/models", headers=headers, json=model_payload(name, role)).status_code == 201
        monkeypatch.setattr(application, "secret_box", SecretBox(Fernet.generate_key().decode()))
        models = test_client.get("/api/models").json()
        assert all(model["credential_ready"] is False for model in models)
        pipeline = test_client.get("/api/pipeline/status").json()
        assert pipeline["ready"] is False
        assert pipeline["invalid_credentials"] == ["router", "target"]
        assert pipeline["invalid_required_credentials"] == ["router"]
        assert pipeline["invalid_targets"] == ["target"]
        response = test_client.post("/api/chat", headers=headers, json={"message": "Hello"})
        assert response.status_code == 422
        assert "Re-enter the API Key" in response.json()["detail"]


def test_pipeline_skips_target_models_with_unreadable_credentials(monkeypatch) -> None:
    completions = iter(
        (
            Completion('{"model_id": 3, "reason": "Available target."}', Usage(10, 5)),
            Completion("Safe answer.", Usage(10, 5)),
        )
    )

    async def fake_completion(**_kwargs):
        return next(completions)

    monkeypatch.setattr(application, "chat_completion", fake_completion)
    enable_local_redaction(monkeypatch, "Question for [PERSON].")
    with client() as test_client:
        headers = bootstrap(test_client)
        assert test_client.post("/api/models", headers=headers, json=model_payload("router", "router")).status_code == 201
        stale = test_client.post("/api/models", headers=headers, json=model_payload("stale-target", "target"))
        usable = test_client.post("/api/models", headers=headers, json=model_payload("usable-target", "target"))
        assert stale.status_code == 201
        assert usable.status_code == 201
        with application.database.connection() as connection:
            connection.execute("UPDATE models SET api_key_encrypted = ? WHERE id = ?", ("unreadable", stale.json()["id"]))

        pipeline = test_client.get("/api/pipeline/status").json()
        assert pipeline["ready"] is True
        assert pipeline["active_targets"] == 2
        assert pipeline["available_targets"] == 1
        assert pipeline["invalid_required_credentials"] == []
        assert pipeline["invalid_targets"] == ["stale-target"]

        response = test_client.post("/api/chat", headers=headers, json={"message": "Question for Alice"})
        assert response.status_code == 200, response.text
        assert response.json()["selected_model"] == "usable-target"


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


def test_openai_compatible_service_api_routes_agent_messages(monkeypatch) -> None:
    completions = iter(
        (
            Completion('{"model_id": 2, "reason": "Suitable."}', Usage(10, 5)),
            Completion("Agent-compatible answer.", Usage(10, 5)),
        )
    )

    provider_requests = []

    async def fake_completion(**kwargs):
        provider_requests.append(kwargs)
        return next(completions)

    monkeypatch.setattr(application, "chat_completion", fake_completion)
    enable_local_redaction(monkeypatch, "[SYSTEM]\nUse concise answers.\n\n[USER]\nQuestion about [PERSON].\n\n[TOOL]\nLookup result: reference data")
    with client() as test_client:
        csrf = bootstrap(test_client)
        for name, role in (("router", "router"), ("target", "target")):
            assert test_client.post("/api/models", headers=csrf, json=model_payload(name, role)).status_code == 201
        created_key = test_client.post("/api/service-key", headers=csrf)
        assert created_key.status_code == 201
        api_headers = {"Authorization": f"Bearer {created_key.json()['api_key']}"}

        listed = test_client.get("/v1/models", headers=api_headers)
        assert listed.status_code == 200
        assert listed.json()["data"][0]["id"] == "models-router"

        response = test_client.post(
            "/v1/chat/completions",
            headers=api_headers,
            json={
                "model": "models-router",
                "messages": [
                    {"role": "system", "content": "Use concise answers."},
                    {"role": "user", "content": [{"type": "text", "text": "Question about Alice"}]},
                    {"role": "tool", "content": "Lookup result: reference data"},
                ],
            },
        )
        assert response.status_code == 200, response.text
        payload = response.json()
        assert payload["object"] == "chat.completion"
        assert payload["choices"][0]["message"] == {"role": "assistant", "content": "Agent-compatible answer."}
        assert payload["usage"]["total_tokens"] == 30
        assert "[SYSTEM]\nUse concise answers." in provider_requests[0]["messages"][1]["content"]
        assert "[TOOL]\nLookup result: reference data" in provider_requests[0]["messages"][1]["content"]

        streaming = test_client.post(
            "/v1/chat/completions",
            headers=api_headers,
            json={"model": "models-router", "stream": True, "messages": [{"role": "user", "content": "Hello"}]},
        )
        assert streaming.status_code == 400

        revoked = test_client.delete("/api/service-key", headers=csrf)
        assert revoked.json() == {"revoked": True}
        assert test_client.get("/v1/models", headers=api_headers).status_code == 401
