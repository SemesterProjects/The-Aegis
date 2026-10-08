from __future__ import annotations

from datetime import timedelta
from pathlib import Path

from aegis_core.engine import MonitoringConfig, MonitoringEngine
from aegis_core.models import Environment, Event, EventKind, utc_now
from aegis_core.detection import DetectionPipeline, ProcessCreationBurstDetector
from aegis_core.investigation.agent import InvestigationAgent
from aegis_core.storage import EvidenceStore
from aegis_core.investigation.result import InvestigationStatus


def test_persisted_case_is_claimed_and_result_is_idempotent(tmp_path: Path) -> None:
    store = EvidenceStore(tmp_path / "evidence.sqlite3")
    try:
        from aegis_core.models import Event, EventKind
        from aegis_core.triage import InvestigationCase

        event = Event(
            EventKind.PROCESS,
            "fixture",
            {"action": "start", "pid": 123, "name": "test-process"},
            host_id="host-test",
        )
        store.append_event(event)
        case = InvestigationCase(
            host_id="host-test",
            severity="high",
            risk_score=0.7,
            trigger="AEGIS-PROC-001",
            trigger_event_id=event.event_id,
            event_ids=(event.event_id,),
            time_window_start=event.observed_at,
            time_window_end=event.observed_at,
            detection_signals=("process_creation_burst",),
            triage_reason="test",
        )
        store.append_case(case)

        first = InvestigationAgent(store).investigate(case.case_id)
        second = InvestigationAgent(store).investigate(case.case_id)

        assert first.case_id == case.case_id
        assert first.status in (InvestigationStatus.COMPLETE, InvestigationStatus.PARTIAL)
        assert second.investigation_id == first.investigation_id
        assert store.get_investigation_result(case.case_id)["case_id"] == case.case_id
        assert store.get_case_by_id(case.case_id)["status"] != "NEW"
    finally:
        store.close()


def test_process_burst_creates_high_case_and_result(tmp_path: Path) -> None:
    data_dir = tmp_path / "data"
    engine = MonitoringEngine(
        MonitoringConfig(Environment.DEVELOPMENT, data_dir, interval_seconds=0.1),
        collectors=[],
        pipeline=DetectionPipeline([ProcessCreationBurstDetector(threshold=3)]),
    )
    engine.start()
    now = utc_now()
    for pid in range(20):
        engine._ingest(Event(
            EventKind.PROCESS,
            "process_lifecycle",
            {"action": "start", "pid": pid, "name": "cmd.exe", "ppid": 1},
            observed_at=now + timedelta(milliseconds=pid),
            host_id="host-test",
        ))
    cases = engine.store.query_cases()
    engine.stop()
    store = EvidenceStore(data_dir / "evidence.sqlite3")
    try:
        high_cases = [case for case in cases if case["severity"] == "high"]
        assert high_cases
        case = high_cases[0]
        assert case["status"] == "NEW"
        result = InvestigationAgent(store).investigate(case["case_id"])
        assert result.case_id == case["case_id"]
        assert result.evidence_ids_used
        assert all(store.get_event_by_id(event_id) for event_id in result.evidence_ids_used)
        assert store.get_investigation_result(case["case_id"]) is not None
    finally:
        store.close()
