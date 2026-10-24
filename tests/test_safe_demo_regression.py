"""Regression tests for the safe end-to-end monitoring pipeline.

Covers:
- First-cycle baseline behavior (ProcessLifecycleCollector & FilePollingCollector)
- Subsequent process/file event collection after baseline establishment
- Empty directory baseline handling without event swallowing
- Watched-root isolation (ignoring files outside watched roots and Aegis internal files)
- Event persistence and cryptographic hash-chain integrity
- Triage scoring, threshold gating, and InvestigationCase creation
- ResponseAgent non-destructive dry-run guarantee
- End-to-end execution of scripts/safe_e2e_demo.py
"""
from __future__ import annotations

import subprocess
import sys
import tempfile
from pathlib import Path

import pytest

from aegis_core.collectors import FilePollingCollector, ProcessLifecycleCollector
from aegis_core.detection import DetectionPipeline, FileChangeBurstDetector
from aegis_core.engine import MonitoringConfig, MonitoringEngine
from aegis_core.models import Environment, EventKind
from aegis_core.response.adapters import DryRunExecutionAdapter
from aegis_core.response.agent import ResponseAgent
from aegis_core.storage import EvidenceStore
from aegis_core.triage import TriageEngine


class TestCollectorBaselinesAndLifecycle:
    def test_file_polling_empty_directory_baseline_and_subsequent_events(self, tmp_path: Path):
        """Regression test: Empty directory at cycle 0 must establish baseline,

        and subsequent file creation at cycle 1 must be captured.
        """
        collector = FilePollingCollector(roots=(tmp_path,))

        # Cycle 0: Baseline cycle on empty directory -> must yield 0 events
        cycle0_events = list(collector.collect("test-host"))
        assert len(cycle0_events) == 0
        assert collector._baseline_established is True

        # Cycle 1: Create a file -> must yield 'create' event
        test_file = tmp_path / "hello.txt"
        test_file.write_text("initial content", encoding="utf-8")
        cycle1_events = list(collector.collect("test-host"))
        assert len(cycle1_events) == 1
        assert cycle1_events[0].kind is EventKind.FILE
        assert cycle1_events[0].data["action"] == "create"
        assert cycle1_events[0].data["path"] == str(test_file)

        # Cycle 2: Modify the file -> must yield 'modify' event
        test_file.write_text("updated content with more bytes", encoding="utf-8")
        cycle2_events = list(collector.collect("test-host"))
        assert len(cycle2_events) == 1
        assert cycle2_events[0].data["action"] == "modify"

        # Cycle 3: Delete the file -> must yield 'delete' event
        test_file.unlink()
        cycle3_events = list(collector.collect("test-host"))
        assert len(cycle3_events) == 1
        assert cycle3_events[0].data["action"] == "delete"

    def test_watched_root_isolation(self, tmp_path: Path):
        """Files created outside the explicit watched root must NOT be collected."""
        watched_dir = tmp_path / "watched"
        unwatched_dir = tmp_path / "unwatched"
        watched_dir.mkdir()
        unwatched_dir.mkdir()

        collector = FilePollingCollector(roots=(watched_dir,))
        list(collector.collect("test-host"))  # baseline

        # File in unwatched directory
        (unwatched_dir / "ignored.txt").write_text("ignore me", encoding="utf-8")
        # File in watched directory
        (watched_dir / "captured.txt").write_text("capture me", encoding="utf-8")

        events = list(collector.collect("test-host"))
        assert len(events) == 1
        assert events[0].data["path"] == str(watched_dir / "captured.txt")

    def test_aegis_internal_files_excluded_from_file_collection(self, tmp_path: Path):
        """Database and runtime status files must not generate file events."""
        collector = FilePollingCollector(roots=(tmp_path,))
        list(collector.collect("test-host"))  # baseline

        # Write internal SQLite / status files
        (tmp_path / "evidence.sqlite3").write_text("sqlite", encoding="utf-8")
        (tmp_path / "evidence.sqlite3-wal").write_text("wal", encoding="utf-8")
        (tmp_path / "evidence.sqlite3-shm").write_text("shm", encoding="utf-8")
        (tmp_path / "monitor-status.json").write_text("{}", encoding="utf-8")

        events = list(collector.collect("test-host"))
        assert len(events) == 0

    def test_process_lifecycle_baseline_suppresses_preexisting(self):
        """Cycle 0 of ProcessLifecycleCollector must establish baseline without emitting."""
        collector = ProcessLifecycleCollector()
        if not collector.is_available:
            pytest.skip("psutil or /proc unavailable")

        events_cycle0 = list(collector.collect("test-host"))
        assert len(events_cycle0) == 0
        assert collector._cycle_count == 1


class TestTriageAndResponseRegression:
    def test_triage_incident_creation_and_threshold(self, tmp_path: Path):
        """TriageEngine scores high severity finding with file burst above threshold."""
        store = EvidenceStore(tmp_path / "evidence.sqlite3")
        try:
            triage = TriageEngine(case_threshold=0.50)

            # High severity finding + burst rule gives 0.35 + 0.20 = 0.55
            finding = {
                "rule_id": "AEGIS-FILE-001",
                "severity": "high",
                "confidence": 0.85,
                "evidence_event_ids": ["ev-1", "ev-2"],
                "explanation": "File change burst detected.",
            }
            events = [
                {"event_id": "ev-1", "kind": "file", "observed_at": "2026-10-24T00:00:00+00:00", "data": {"action": "create"}},
                {"event_id": "ev-2", "kind": "file", "observed_at": "2026-10-24T00:00:01+00:00", "data": {"action": "modify"}},
            ]

            assert triage.should_create_case(finding, events) is True
            case = triage.create_case(finding, events, host_id="test-host")
            assert case.severity in ("medium", "high")
            assert case.risk_score >= 0.50
            store.append_case(case)

            cases = store.query_cases()
            assert len(cases) == 1
            assert cases[0]["case_id"] == case.case_id
        finally:
            store.close()

    def test_response_agent_dry_run_safety(self, tmp_path: Path):
        """ResponseAgent with DryRunExecutionAdapter must only simulate actions."""
        store = EvidenceStore(tmp_path / "evidence.sqlite3")
        try:
            # Seed an investigation case
            triage = TriageEngine(case_threshold=0.40)
            finding = {
                "rule_id": "AEGIS-FILE-001",
                "severity": "high",
                "confidence": 0.85,
                "evidence_event_ids": ["ev-1"],
                "explanation": "File change burst.",
            }
            events = [
                {"event_id": "ev-1", "kind": "file", "observed_at": "2026-10-24T00:00:00+00:00", "data": {"action": "create"}},
            ]
            case = triage.create_case(finding, events, host_id="test-host")
            store.append_case(case)

            from aegis_core.investigation.agent import InvestigationAgent
            inv = InvestigationAgent(store)
            inv.investigate(case.case_id)

            adapter = DryRunExecutionAdapter()
            agent = ResponseAgent(store, adapter=adapter)
            plan = agent.plan(case.case_id)
            assert plan.status.value in ("PLANNING", "PENDING_APPROVAL")

            executed = agent.execute_eligible_actions(case.case_id, live=False)
            for action in executed:
                assert action.execution_result is not None
                assert action.execution_result.simulated is True
        finally:
            store.close()


class TestSafeDemoEndToEnd:
    def test_safe_demo_runs_successfully(self, tmp_path: Path):
        """End-to-end invocation of scripts/safe_e2e_demo.py."""
        demo_script = Path(__file__).resolve().parents[1] / "scripts" / "safe_e2e_demo.py"
        assert demo_script.exists()

        result = subprocess.run(
            [sys.executable, str(demo_script), "--root", str(tmp_path)],
            capture_output=True,
            text=True,
            timeout=180,
        )
        assert result.returncode == 0, f"Demo failed with stderr: {result.stderr}\nstdout: {result.stdout}"
        assert '"chain_valid": true' in result.stdout
        assert '"case_count": 1' in result.stdout or '"case_count": 2' in result.stdout
        assert '"dry_run_only": true' in result.stdout
