from __future__ import annotations

from pathlib import Path
from urllib.error import HTTPError

from aegis_core.intelligence import IntelligenceService, InterpretationStatus
from aegis_core.intelligence import service
from aegis_core.investigation.agent import InvestigationAgent
from aegis_core.models import Event, EventKind
from aegis_core.storage import EvidenceStore
from aegis_core.triage import InvestigationCase


class FakeProvider:
    name = "fake"

    def __init__(self, response: object) -> None:
        self.response = response
        self.payload = None

    def complete_json(self, **kwargs):
        self.payload = kwargs["payload"]
        return self.response(self.payload) if callable(self.response) else self.response


def _result_with_case(tmp_path: Path, intelligence: IntelligenceService):
    store = EvidenceStore(tmp_path / "evidence.sqlite3")
    event = Event(EventKind.PROCESS, "test", {"action": "start", "pid": 7, "name": "example.exe"}, host_id="test-host")
    store.append_event(event)
    case = InvestigationCase(
        host_id="test-host", severity="high", risk_score=0.7, trigger="TEST-001",
        trigger_event_id=event.event_id, event_ids=(event.event_id,),
        time_window_start=event.observed_at, time_window_end=event.observed_at,
        detection_signals=("test",),
    )
    store.append_case(case)
    return store, event, case, InvestigationAgent(store, intelligence=intelligence).investigate(case.case_id)


def test_llm_interpretation_is_grounded_and_does_not_change_verdict(tmp_path: Path) -> None:
    provider = FakeProvider(lambda payload: {
        "summary": "Observed a new process.", "insights": ["Review its owner."],
        "evidence_event_ids": payload["allowed_event_ids"][:1],
        "uncertainties": ["No network telemetry was supplied."],
    })
    store, _, case, result = _result_with_case(tmp_path, IntelligenceService(provider, model="test-model"))
    try:
        assert result.llm_interpretation.status is InterpretationStatus.COMPLETE
        assert result.llm_interpretation.provider == "fake"
        assert store.get_investigation_result(case.case_id)["llm_interpretation"]["status"] == "COMPLETE"
        assert result.classification.value in {"BENIGN", "SUSPICIOUS", "MALICIOUS", "UNKNOWN"}
        assert provider.payload["deterministic_classification"] == result.classification.value
    finally:
        store.close()


def test_llm_output_cannot_reference_unsupplied_evidence(tmp_path: Path) -> None:
    provider = FakeProvider({"summary": "Unsupported claim.", "insights": [], "evidence_event_ids": ["invented-event"], "uncertainties": []})
    store, _, _, result = _result_with_case(tmp_path, IntelligenceService(provider, model="test-model"))
    try:
        assert result.llm_interpretation.status is InterpretationStatus.INVALID_OUTPUT
        assert result.llm_interpretation.failure_reason
    finally:
        store.close()


def test_disabled_llm_never_calls_a_provider() -> None:
    interpretation = IntelligenceService().interpret(object())
    assert interpretation.status is InterpretationStatus.DISABLED


def test_provider_failure_preserves_sanitized_reason() -> None:
    provider = FakeProvider(lambda _: (_ for _ in ()).throw(RuntimeError("HTTP 401: invalid key")))
    interpretation = IntelligenceService(provider, model="test-model").interpret(object())
    assert interpretation.status is InterpretationStatus.ERROR
    assert interpretation.failure_reason == "RuntimeError: HTTP 401: invalid key"


def test_openai_compatible_http_error_body_is_redacted(monkeypatch) -> None:
    class Body:
        def read(self) -> bytes:
            return b'{"error":{"message":"bad key gsk_secret123","authorization":"Bearer leaked-token"}}'

    def fail(*args, **kwargs):
        raise HTTPError("https://example.test/chat/completions", 403, "Forbidden", {}, Body())

    monkeypatch.setattr(service, "urlopen", fail)
    provider = service.OpenAICompatibleProvider("https://example.test/v1", "secret-key")
    try:
        provider.complete_json(model="openai/gpt-oss-20b", system_prompt="json", payload={}, timeout_seconds=1)
    except RuntimeError as exc:
        message = str(exc)
    else:
        raise AssertionError("expected HTTP error")

    assert "HTTP 403" in message
    assert "bad key" in message
    assert "gsk_secret123" not in message
    assert "leaked-token" not in message


def test_openai_compatible_uses_configured_bearer_token(monkeypatch) -> None:
    captured = {}

    class Response:
        def __enter__(self):
            return self

        def __exit__(self, *args):
            return False

        def read(self) -> bytes:
            return b'{"choices":[{"message":{"content":"{\\"summary\\":\\"ok\\"}"}}]}'

    def succeed(request, **kwargs):
        captured["authorization"] = request.get_header("Authorization")
        captured["user_agent"] = request.get_header("User-agent")
        return Response()

    monkeypatch.setattr(service, "urlopen", succeed)
    service.OpenAICompatibleProvider("https://example.test/v1", "configured-key").complete_json(
        model="model", system_prompt="json", payload={}, timeout_seconds=1
    )
    assert captured["authorization"] == "Bearer configured-key"


    assert captured["user_agent"] == "Aegis-LLM-Client/1.0"


def test_invalid_llm_environment_degrades_to_disabled(monkeypatch) -> None:
    monkeypatch.setenv("AEGIS_LLM_PROVIDER", "openai-compatible")
    monkeypatch.setenv("AEGIS_LLM_BASE_URL", "http://insecure.example")
    monkeypatch.setenv("AEGIS_LLM_API_KEY", "not-a-real-secret")
    monkeypatch.setenv("AEGIS_LLM_MODEL", "model")
    interpretation = IntelligenceService.from_environment(enabled=True).interpret(object())
    assert interpretation.status is InterpretationStatus.DISABLED
    assert "HTTPS" in interpretation.failure_reason


def test_gemini_is_the_default_development_provider(monkeypatch) -> None:
    monkeypatch.delenv("AEGIS_LLM_PROVIDER", raising=False)
    monkeypatch.setenv("GEMINI_API_KEY", "not-a-real-secret")
    service = IntelligenceService.from_environment(enabled=True)
    assert service._provider.name == "gemini"
