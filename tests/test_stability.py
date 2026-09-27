from __future__ import annotations

import json
import subprocess
from datetime import datetime, timezone
from pathlib import Path

from aegis_core.collectors import AuthEventCollector
from aegis_core.engine import MonitoringConfig, MonitoringEngine
from aegis_core.models import Environment, Event, EventKind
from aegis_core.storage import EvidenceStore


def test_run_id_is_persisted_and_isolates_runs(tmp_path: Path) -> None:
    first = MonitoringEngine(
        MonitoringConfig(Environment.DEVELOPMENT, tmp_path / "first"),
        collectors=[],
    )
    first.start()
    first._ingest(Event(EventKind.HEALTH, "test", {"status": "first"}))
    first_run_id = first.config.run_id
    first.stop()

    second = MonitoringEngine(
        MonitoringConfig(Environment.DEVELOPMENT, tmp_path / "second"),
        collectors=[],
    )
    second.start()
    second._ingest(Event(EventKind.HEALTH, "test", {"status": "second"}))
    second_run_id = second.config.run_id
    second.stop()

    assert first_run_id != second_run_id
    first_store = EvidenceStore(tmp_path / "first" / "evidence.sqlite3")
    second_store = EvidenceStore(tmp_path / "second" / "evidence.sqlite3")
    assert {event["run_id"] for event in first_store.query_events()} == {first_run_id}
    assert {event["run_id"] for event in second_store.query_events()} == {second_run_id}
    assert all(event["ingested_at"] for event in first_store.query_events())
    first_store.close()
    second_store.close()


def test_correlation_failure_does_not_drop_event(tmp_path: Path) -> None:
    class BrokenIndex:
        def ingest(self, event: dict) -> None:
            raise RuntimeError("index unavailable")

    engine = MonitoringEngine(
        MonitoringConfig(Environment.DEVELOPMENT, tmp_path),
        collectors=[],
        correlation=BrokenIndex(),  # type: ignore[arg-type]
    )
    engine.start()
    event = Event(EventKind.FILE, "test", {"action": "modify", "path": "x"})
    engine._ingest(event)
    stored = engine.store.query_events(run_id=engine.config.run_id)
    assert any(item["event_id"] == event.event_id for item in stored)
    assert any(item["data"].get("action") == "correlation_error" for item in stored)
    engine.stop()


def test_windows_auth_record_id_cursor_deduplicates(monkeypatch, tmp_path: Path) -> None:
    xml_template = """<Event xmlns=\"http://schemas.microsoft.com/win/2004/08/events/event\"><System><EventID>4625</EventID><EventRecordID>{record}</EventRecordID><TimeCreated SystemTime=\"2026-09-27T06:00:00.000000Z\" /></System><EventData><Data Name=\"TargetUserName\">alice</Data></EventData></Event>"""
    payloads = [xml_template.format(record=10), xml_template.format(record=10), xml_template.format(record=11)]
    calls = iter(payloads)

    def fake_run(*args, **kwargs):
        return subprocess.CompletedProcess(args[0], 0, next(calls), "")

    monkeypatch.setattr(subprocess, "run", fake_run)
    collector = AuthEventCollector(cursor_file=tmp_path / "cursor.json")
    collector._mechanism = "wevtutil"
    first = list(collector._collect_wevtutil("host", lambda action, fields, host, name, mechanism, observed_at=None: Event(
        EventKind.AUTHENTICATION, name, {"action": action, **fields}, observed_at=observed_at or datetime.now(timezone.utc), host_id=host
    )))
    second = list(collector._collect_wevtutil("host", lambda action, fields, host, name, mechanism, observed_at=None: Event(
        EventKind.AUTHENTICATION, name, {"action": action, **fields}, observed_at=observed_at or datetime.now(timezone.utc), host_id=host
    )))
    third = list(collector._collect_wevtutil("host", lambda action, fields, host, name, mechanism, observed_at=None: Event(
        EventKind.AUTHENTICATION, name, {"action": action, **fields}, observed_at=observed_at or datetime.now(timezone.utc), host_id=host
    )))
    assert len(first) == 1
    assert second == []
    assert len(third) == 1
    assert json.loads((tmp_path / "cursor.json").read_text())["event_record_id"] == 11