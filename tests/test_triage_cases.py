from __future__ import annotations

from pathlib import Path

from aegis_core.detection import DetectionPipeline, FileChangeBurstDetector
from aegis_core.engine import MonitoringConfig, MonitoringEngine
from aegis_core.models import Environment, Event, EventKind
from aegis_core.storage import EvidenceStore
from aegis_core.triage import CaseStatus, InvestigationCase, TriageEngine


class StaticCollector:
    name = "case_fixture"

    def __init__(self, events: list[Event]) -> None:
        self.events = events

    def collect(self, host_id: str):
        return iter(self.events)


def test_high_file_finding_becomes_queryable_investigation_case(tmp_path: Path) -> None:
    events = [Event(EventKind.FILE, "fixture", {
        "action": "modify", "path": str(tmp_path / f"safe-{i}.locked"), "suffix": ".locked"
    }, host_id="host-test") for i in range(3)]
    engine = MonitoringEngine(
        MonitoringConfig(Environment.DEVELOPMENT, tmp_path),
        collectors=[StaticCollector(events)],
        pipeline=DetectionPipeline([FileChangeBurstDetector(threshold=3)]),
    )
    engine.start()
    engine.run_once()
    cases = engine.store.query_cases()
    assert len(cases) == 1
    case = cases[0]
    assert case["status"] == CaseStatus.NEW.value
    assert case["trigger"] == "AEGIS-FILE-001"
    assert set(case["event_ids"]) == {event.event_id for event in events}
    assert engine.store.query_events_for_case(case["case_id"])
    engine.stop()


def test_low_finding_does_not_create_case(tmp_path: Path) -> None:
    engine = MonitoringEngine(MonitoringConfig(Environment.DEVELOPMENT, tmp_path), collectors=[])
    engine.start()
    low_process = Event(EventKind.PROCESS, "fixture", {"action": "start", "pid": 1}, host_id="host-test")
    engine._ingest(low_process)
    assert engine.store.query_cases() == []
    engine.stop()


def test_case_storage_contract_round_trip(tmp_path: Path) -> None:
    store = EvidenceStore(tmp_path / "evidence.sqlite3")
    event = Event(EventKind.NETWORK, "fixture", {"action": "connection_open", "remote_ip": "127.0.0.1"}, host_id="host-test")
    store.append_event(event)
    case = InvestigationCase(
        host_id="host-test", severity="high", risk_score=0.8, trigger="TEST-001",
        trigger_event_id=event.event_id, event_ids=(event.event_id,),
        time_window_start=event.observed_at, time_window_end=event.observed_at,
        detection_signals=("test_signal",), triage_reason="deterministic test case",
    )
    store.append_case(case)
    assert store.get_case_by_id(case.case_id)["case_id"] == case.case_id
    assert store.query_events_for_case(case.case_id)[0]["event_id"] == event.event_id
    store.close()
