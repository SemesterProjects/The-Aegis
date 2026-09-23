"""Comprehensive integration tests for the Aegis Core pipeline.

Tests the full observation pipeline:
    Collector → Event → EvidenceStore → DetectionPipeline → Finding
    + Timeline queries
    + CorrelationIndex
    + Storage hash chain integrity

These tests use real OS state (via psutil if available) or carefully
crafted synthetic collectors to exercise the integration seams.
"""
from __future__ import annotations

import pytest
import tempfile
import threading
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Iterable

import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from aegis_core.models import Event, EventKind, Finding, Severity
from aegis_core.storage import EvidenceStore
from aegis_core.detection import (
    DetectionPipeline,
    FileChangeBurstDetector,
    NetworkRateDetector,
    NewProcessWithNetworkDetector,
    AuthFailureBurstDetector,
)
from aegis_core.timeline import Timeline
from aegis_core.correlation import CorrelationIndex
from aegis_core.engine import MonitoringConfig, MonitoringEngine
from aegis_core.models import Environment
from aegis_core.collectors import (
    FilePollingCollector,
    ProcessLifecycleCollector,
    stable_host_id,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

HOST = "test-host"
NOW = datetime.now(timezone.utc)


def utc(seconds_offset: float = 0) -> datetime:
    return NOW + timedelta(seconds=seconds_offset)


def _event(kind: EventKind, data: dict, t: float = 0, source: str = "test") -> Event:
    return Event(kind=kind, source=source, data=data, observed_at=utc(t), host_id=HOST)


def _tmp_store() -> EvidenceStore:
    """Create a temporary in-memory SQLite evidence store."""
    td = tempfile.mkdtemp()
    return EvidenceStore(Path(td) / "test_evidence.sqlite3")


# ---------------------------------------------------------------------------
# EvidenceStore tests
# ---------------------------------------------------------------------------

class TestEvidenceStore:
    def test_append_and_recent(self):
        store = _tmp_store()
        ev = _event(EventKind.PROCESS, {"action": "start", "pid": 1})
        store.append_event(ev)
        events = store.recent_events(utc(-60))
        assert len(events) == 1
        assert events[0]["kind"] == "process"

    def test_chain_valid_empty(self):
        store = _tmp_store()
        assert store.verify_chain() is True

    def test_chain_valid_after_events(self):
        store = _tmp_store()
        for i in range(10):
            store.append_event(_event(EventKind.HEALTH, {"status": "ok", "seq": i}))
        assert store.verify_chain() is True

    def test_idempotent_append(self):
        store = _tmp_store()
        ev = _event(EventKind.PROCESS, {"pid": 99})
        store.append_event(ev)
        store.append_event(ev)  # duplicate
        events = store.recent_events(utc(-60))
        assert len(events) == 1

    def test_query_events_kind_filter(self):
        store = _tmp_store()
        store.append_event(_event(EventKind.PROCESS, {"pid": 1}))
        store.append_event(_event(EventKind.NETWORK, {"action": "connection_snapshot"}))
        store.append_event(_event(EventKind.FILE, {"action": "create", "path": "/tmp/x"}))
        net = store.query_events(kinds=["network"])
        assert len(net) == 1
        assert net[0]["kind"] == "network"

    def test_query_events_time_filter(self):
        store = _tmp_store()
        store.append_event(_event(EventKind.HEALTH, {"status": "old"}, t=-200))
        store.append_event(_event(EventKind.HEALTH, {"status": "new"}, t=0))
        recent = store.query_events(since=utc(-60))
        assert len(recent) == 1
        assert recent[0]["data"]["status"] == "new"

    def test_query_events_action_filter(self):
        store = _tmp_store()
        store.append_event(_event(EventKind.PROCESS, {"action": "start", "pid": 1}))
        store.append_event(_event(EventKind.PROCESS, {"action": "exit", "pid": 2}))
        starts = store.query_events(action="start")
        assert len(starts) == 1
        assert starts[0]["data"]["action"] == "start"

    def test_query_events_pid_filter(self):
        store = _tmp_store()
        store.append_event(_event(EventKind.PROCESS, {"action": "start", "pid": 100}))
        store.append_event(_event(EventKind.PROCESS, {"action": "start", "pid": 200}))
        results = store.query_events(pid=100)
        assert len(results) == 1
        assert results[0]["data"]["pid"] == 100

    def test_count_events(self):
        store = _tmp_store()
        for i in range(5):
            store.append_event(_event(EventKind.NETWORK, {"conn": i}))
        assert store.count_events(kinds=["network"]) == 5
        assert store.count_events(kinds=["process"]) == 0

    def test_get_event_by_id(self):
        store = _tmp_store()
        ev = _event(EventKind.FILE, {"path": "/etc/passwd"})
        store.append_event(ev)
        result = store.get_event_by_id(ev.event_id)
        assert result is not None
        assert result["event_id"] == ev.event_id

    def test_get_event_by_id_not_found(self):
        store = _tmp_store()
        assert store.get_event_by_id("nonexistent-id") is None

    def test_append_and_get_finding(self):
        store = _tmp_store()
        ev = _event(EventKind.FILE, {"path": "/tmp/x"})
        store.append_event(ev)
        finding = Finding(
            rule_id="TEST-001", title="Test Finding",
            severity=Severity.HIGH, confidence=0.9,
            evidence_event_ids=(ev.event_id,),
            explanation="test", recommendation="do nothing",
        )
        store.append_finding(finding)
        findings = store.get_findings()
        assert len(findings) == 1
        assert findings[0]["rule_id"] == "TEST-001"

    def test_findings_since_filter(self):
        store = _tmp_store()
        ev = _event(EventKind.FILE, {"path": "/tmp/y"})
        store.append_event(ev)
        finding = Finding(
            rule_id="TEST-001", title="Old Finding",
            severity=Severity.LOW, confidence=0.5,
            evidence_event_ids=(ev.event_id,),
            explanation="old", recommendation="ignore",
        )
        store.append_finding(finding)
        # Query for findings in the last hour
        results = store.get_findings(since=utc(-3600))
        assert len(results) == 1
        # Query for findings in the future (none)
        results_future = store.get_findings(since=utc(3600))
        assert len(results_future) == 0

    def test_thread_safe(self):
        store = _tmp_store()
        errors = []

        def writer(n: int) -> None:
            try:
                for i in range(n):
                    store.append_event(_event(EventKind.HEALTH, {"thread": threading.current_thread().name, "i": i}))
            except Exception as e:
                errors.append(e)

        threads = [threading.Thread(target=writer, args=(20,)) for _ in range(5)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        assert not errors
        assert store.verify_chain() is True


# ---------------------------------------------------------------------------
# DetectionPipeline tests
# ---------------------------------------------------------------------------

class TestFileChangeBurstDetector:
    def test_no_finding_below_threshold(self):
        det = FileChangeBurstDetector(threshold=25)
        pipeline = DetectionPipeline([det])
        for i in range(24):
            findings = pipeline.evaluate(
                _event(EventKind.FILE, {"action": "modify", "path": f"/tmp/f{i}.txt", "suffix": ".txt"})
            )
            assert len(findings) == 0

    def test_finding_at_threshold(self):
        det = FileChangeBurstDetector(threshold=5, window_seconds=60)
        pipeline = DetectionPipeline([det])
        findings = []
        for i in range(5):
            findings.extend(pipeline.evaluate(
                _event(EventKind.FILE, {"action": "modify", "path": f"/tmp/f{i}.enc", "suffix": ".enc"})
            ))
        assert len(findings) == 1
        assert findings[0].rule_id == "AEGIS-FILE-001"
        assert findings[0].severity is Severity.HIGH

    def test_events_outside_window_not_counted(self):
        det = FileChangeBurstDetector(threshold=3, window_seconds=60)
        pipeline = DetectionPipeline([det])
        # Old events (2 minutes ago)
        for i in range(2):
            pipeline.evaluate(_event(EventKind.FILE,
                {"action": "modify", "path": f"/tmp/f{i}.enc", "suffix": ".enc"}, t=-120))
        # Recent events
        findings = []
        for i in range(3):
            findings.extend(pipeline.evaluate(
                _event(EventKind.FILE, {"action": "modify", "path": f"/tmp/g{i}.enc", "suffix": ".enc"}, t=0)
            ))
        # Should fire at 3 (recent only), not earlier
        assert any(f.rule_id == "AEGIS-FILE-001" for f in findings)


class TestNewProcessWithNetworkDetector:
    def test_fires_on_process_then_network(self):
        det = NewProcessWithNetworkDetector(window_seconds=60)
        pipeline = DetectionPipeline([det])

        proc_event = _event(EventKind.PROCESS, {"action": "start", "pid": 9876, "name": "evil.sh"})
        findings = list(pipeline.evaluate(proc_event))
        assert len(findings) == 0  # no finding yet

        net_event = _event(EventKind.NETWORK, {
            "action": "connection_snapshot", "pid": 9876, "remote_ip": "1.2.3.4"
        }, t=5)
        findings = list(pipeline.evaluate(net_event))
        assert len(findings) == 1
        assert findings[0].rule_id == "AEGIS-PROC-NET-001"

    def test_does_not_fire_for_established_process(self):
        det = NewProcessWithNetworkDetector(window_seconds=60)
        pipeline = DetectionPipeline([det])

        # Network event arrives without a prior process start
        net_event = _event(EventKind.NETWORK, {"action": "connection_snapshot", "pid": 555})
        findings = list(pipeline.evaluate(net_event))
        assert len(findings) == 0

    def test_fires_only_once_per_process(self):
        det = NewProcessWithNetworkDetector(window_seconds=60)
        pipeline = DetectionPipeline([det])

        proc_event = _event(EventKind.PROCESS, {"action": "start", "pid": 1111, "name": "test"})
        pipeline.evaluate(proc_event)

        findings_total = []
        for i in range(5):
            net_event = _event(EventKind.NETWORK, {"action": "connection_snapshot", "pid": 1111}, t=i)
            findings_total.extend(pipeline.evaluate(net_event))

        assert len(findings_total) == 1  # fires exactly once


class TestAuthFailureBurstDetector:
    def test_fires_at_threshold(self):
        det = AuthFailureBurstDetector(threshold=3, window_seconds=60)
        pipeline = DetectionPipeline([det])

        findings = []
        for _ in range(3):
            findings.extend(pipeline.evaluate(
                _event(EventKind.AUTHENTICATION, {"action": "login_failure", "user": "root"})
            ))
        assert len(findings) == 1
        assert findings[0].rule_id == "AEGIS-AUTH-001"
        assert findings[0].severity is Severity.HIGH

    def test_per_user_tracking(self):
        det = AuthFailureBurstDetector(threshold=3, window_seconds=60)
        pipeline = DetectionPipeline([det])

        # 2 failures each for different users — neither should fire
        findings = []
        for user in ("alice", "bob"):
            for _ in range(2):
                findings.extend(pipeline.evaluate(
                    _event(EventKind.AUTHENTICATION, {"action": "login_failure", "user": user})
                ))
        assert len(findings) == 0

    def test_ignores_non_failure_auth(self):
        det = AuthFailureBurstDetector(threshold=2, window_seconds=60)
        pipeline = DetectionPipeline([det])

        for _ in range(5):
            findings = list(pipeline.evaluate(
                _event(EventKind.AUTHENTICATION, {"action": "login_success", "user": "admin"})
            ))
            assert len(findings) == 0


# ---------------------------------------------------------------------------
# Timeline tests
# ---------------------------------------------------------------------------

class TestTimeline:
    def _store_with_events(self):
        store = _tmp_store()
        store.append_event(_event(EventKind.PROCESS, {"action": "start", "pid": 100}, t=-400))
        store.append_event(_event(EventKind.PROCESS, {"action": "start", "pid": 200}, t=-10))
        store.append_event(_event(EventKind.NETWORK, {"action": "connection_snapshot", "pid": 100, "remote_ip": "1.2.3.4"}, t=-5))
        store.append_event(_event(EventKind.FILE, {"action": "modify", "path": "/etc/passwd", "pid": 100}, t=-3))
        store.append_event(_event(EventKind.AUTHENTICATION, {"action": "login_failure", "user": "root"}, t=0))
        return store

    def test_recent_returns_events(self):
        store = self._store_with_events()
        tl = Timeline(store)
        events = tl.recent(seconds=60)
        # Should have process@-10, network@-5, file@-3, auth@0
        kinds = {e["kind"] for e in events}
        assert "network" in kinds
        assert "file" in kinds
        assert "authentication" in kinds

    def test_process_timeline_filters_by_pid(self):
        store = self._store_with_events()
        tl = Timeline(store)
        events = tl.process_timeline(pid=100, window_seconds=500)
        for ev in events:
            assert ev.get("data", {}).get("pid") == 100

    def test_file_timeline_filters_by_path(self):
        store = self._store_with_events()
        tl = Timeline(store)
        events = tl.file_timeline("/etc/passwd", window_seconds=60)
        assert all("/etc/passwd" in e.get("data", {}).get("path", "") for e in events)

    def test_auth_timeline_returns_auth_events(self):
        store = self._store_with_events()
        tl = Timeline(store)
        events = tl.auth_timeline(window_seconds=3600)
        assert all(e["kind"] == "authentication" for e in events)

    def test_summary_counts_by_kind(self):
        store = self._store_with_events()
        tl = Timeline(store)
        summary = tl.summary(window_seconds=500)
        assert summary["total"] >= 5
        assert "process" in summary
        assert "network" in summary


# ---------------------------------------------------------------------------
# CorrelationIndex tests
# ---------------------------------------------------------------------------

class TestCorrelationIndex:
    def _populated_index(self) -> CorrelationIndex:
        idx = CorrelationIndex()
        # Process start
        idx.ingest(_event(EventKind.PROCESS, {"action": "start", "pid": 1000, "ppid": 1, "name": "bash"}).canonical())
        # Child process
        idx.ingest(_event(EventKind.PROCESS, {"action": "start", "pid": 1001, "ppid": 1000, "name": "curl"}).canonical())
        # Network event from child
        idx.ingest(_event(EventKind.NETWORK, {"action": "connection_snapshot", "pid": 1001, "remote_ip": "5.6.7.8", "direction": "outbound"}).canonical())
        # File event from child
        idx.ingest(_event(EventKind.FILE, {"action": "modify", "path": "/tmp/out.txt", "pid": 1001}).canonical())
        return idx

    def test_get_events_for_pid(self):
        idx = self._populated_index()
        events = idx.get_events_for_pid(1001)
        assert len(events) == 3  # start, network, file

    def test_get_process_info(self):
        idx = self._populated_index()
        info = idx.get_process_info(1000)
        assert info is not None
        assert info["name"] == "bash"

    def test_get_network_for_pid(self):
        idx = self._populated_index()
        net = idx.get_network_for_pid(1001)
        assert len(net) == 1
        assert net[0]["data"]["remote_ip"] == "5.6.7.8"

    def test_get_files_for_pid(self):
        idx = self._populated_index()
        files = idx.get_files_for_pid(1001)
        assert len(files) == 1
        assert "/tmp/out.txt" in files[0]["data"]["path"]

    def test_get_child_pids(self):
        idx = self._populated_index()
        children = idx.get_child_pids(1000)
        assert 1001 in children

    def test_process_tree(self):
        idx = self._populated_index()
        tree = idx.get_process_tree(1000)
        assert tree["pid"] == 1000
        assert tree["name"] == "bash"
        assert len(tree["children"]) == 1
        child = tree["children"][0]
        assert child["pid"] == 1001
        assert child["network_events"] == 1

    def test_suspicious_pairs(self):
        idx = self._populated_index()
        pairs = idx.suspicious_process_network_pairs()
        # pid 1001 has outbound network + file modify
        pids = [p["pid"] for p in pairs]
        assert 1001 in pids

    def test_get_events_for_path(self):
        idx = self._populated_index()
        events = idx.get_events_for_path("/tmp")
        assert len(events) == 1

    def test_get_events_for_remote_ip(self):
        idx = self._populated_index()
        events = idx.get_events_for_remote_ip("5.6.7.8")
        assert len(events) == 1

    def test_build_from_store(self):
        store = _tmp_store()
        store.append_event(_event(EventKind.PROCESS, {"action": "start", "pid": 7777, "name": "test"}))
        store.append_event(_event(EventKind.NETWORK, {"action": "connection_snapshot", "pid": 7777, "remote_ip": "9.9.9.9"}))
        idx = CorrelationIndex()
        idx.build_from_store(store)
        assert len(idx.get_events_for_pid(7777)) == 2

    def test_stats(self):
        idx = self._populated_index()
        stats = idx.stats()
        assert stats["tracked_pids"] >= 2
        assert stats["tracked_paths"] >= 1
        assert stats["tracked_remote_ips"] >= 1


# ---------------------------------------------------------------------------
# MonitoringEngine integration tests
# ---------------------------------------------------------------------------

class _DummyCollector:
    """Collector that yields a fixed set of events. No real OS calls."""
    def __init__(self, events: list[Event], name: str = "dummy"):
        self.name = name
        self._events = events
        self.call_count = 0

    def collect(self, host_id: str) -> Iterable[Event]:
        self.call_count += 1
        return iter(self._events)


class TestMonitoringEngine:
    def _config(self, tmp_path: Path) -> MonitoringConfig:
        return MonitoringConfig(
            environment=Environment.DEVELOPMENT,
            data_directory=tmp_path,
            interval_seconds=1.0,
        )

    def test_start_emits_health_event(self, tmp_path: Path):
        config = self._config(tmp_path)
        engine = MonitoringEngine(config, collectors=[_DummyCollector([])])
        engine.start()
        events = engine.store.recent_events(utc(-60))
        health_events = [e for e in events if e.get("kind") == "health"]
        assert len(health_events) >= 1
        assert any(e.get("data", {}).get("status") == "started" for e in health_events)
        engine.stop()

    def test_run_once_ingests_collector_events(self, tmp_path: Path):
        events_to_yield = [
            _event(EventKind.PROCESS, {"action": "start", "pid": 42, "name": "test"}),
        ]
        collector = _DummyCollector(events_to_yield)
        config = self._config(tmp_path)
        engine = MonitoringEngine(config, collectors=[collector])
        engine.start()
        engine.run_once()
        all_events = engine.store.query_events(kinds=["process"])
        assert len(all_events) >= 1
        engine.stop()

    def test_chain_valid_after_run(self, tmp_path: Path):
        config = self._config(tmp_path)
        engine = MonitoringEngine(config, collectors=[_DummyCollector([])])
        engine.start()
        engine.run_once()
        engine.stop()
        # Chain verification: open a new store on the same file
        store2 = EvidenceStore(tmp_path / "evidence.sqlite3")
        assert store2.verify_chain() is True
        store2.close()

    def test_collector_failure_does_not_crash_engine(self, tmp_path: Path):
        class FailingCollector:
            name = "failing"
            def collect(self, host_id: str) -> Iterable[Event]:
                raise RuntimeError("simulated failure")

        config = self._config(tmp_path)
        engine = MonitoringEngine(config, collectors=[FailingCollector()])
        engine.start()
        # Should not raise
        engine.run_once()
        # A HEALTH error event should have been emitted
        health = engine.store.query_events(kinds=["health"])
        error_events = [e for e in health if e.get("data", {}).get("status") == "error"]
        assert len(error_events) >= 1
        engine.stop()

    def test_detection_pipeline_fires(self, tmp_path: Path):
        """A burst of file changes should trigger FileChangeBurstDetector."""
        file_events = [
            _event(EventKind.FILE, {"action": "modify", "path": f"/tmp/f{i}.enc", "suffix": ".enc"})
            for i in range(30)
        ]
        collector = _DummyCollector(file_events)
        pipeline = DetectionPipeline([FileChangeBurstDetector(threshold=5)])
        config = self._config(tmp_path)
        engine = MonitoringEngine(config, collectors=[collector], pipeline=pipeline)
        engine.start()
        findings = engine.run_once()
        assert len(findings) >= 1
        assert any(f.rule_id == "AEGIS-FILE-001" for f in findings)
        engine.stop()

    def test_stop_closes_cleanly(self, tmp_path: Path):
        config = self._config(tmp_path)
        engine = MonitoringEngine(config, collectors=[_DummyCollector([])])
        engine.start()
        engine.run_once()
        engine.stop()
        # Verify chain is still valid after close
        store2 = EvidenceStore(tmp_path / "evidence.sqlite3")
        assert store2.verify_chain() is True
        store2.close()

    def test_status_reports_collectors(self, tmp_path: Path):
        config = self._config(tmp_path)
        collector = _DummyCollector([], name="my_collector")
        engine = MonitoringEngine(config, collectors=[collector])
        engine.start()
        status = engine.status()
        names = [c["collector"] for c in status["collectors"]]
        assert "my_collector" in names
        engine.stop()


# ---------------------------------------------------------------------------
# ProcessLifecycleCollector real-OS test
# ---------------------------------------------------------------------------

class TestProcessLifecycleCollector:
    def test_collects_real_processes(self):
        """Test that ProcessLifecycleCollector returns real process data."""
        col = ProcessLifecycleCollector()
        if not col.is_available:
            pytest.skip("no psutil and no /proc available")

        # First run: initializes snapshot, may emit snapshots
        events1 = list(col.collect(HOST))
        # All events should be valid Event objects
        assert all(isinstance(e, Event) for e in events1)
        assert all(e.kind is EventKind.PROCESS for e in events1)

        # Events should have pid
        if events1:
            assert any("pid" in e.data for e in events1)

    def test_mechanism_detected(self):
        col = ProcessLifecycleCollector()
        mech = col._get_mechanism()
        assert mech in ("psutil", "proc_fs", "unavailable")

    def test_start_events_have_action(self):
        col = ProcessLifecycleCollector()
        if not col.is_available:
            pytest.skip("no psutil or /proc")

        # Prime the snapshot
        list(col.collect(HOST))
        # Second run will produce start/exit diffs (empty snapshot initially)
        events = list(col.collect(HOST))
        for ev in events:
            assert "action" in ev.data
            assert ev.data["action"] in ("start", "exit", "snapshot")
