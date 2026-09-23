from __future__ import annotations

from datetime import timedelta
from pathlib import Path
import tempfile
import time
import unittest

from aegis_core.collectors import FilePollingCollector
from aegis_core.detection import DetectionPipeline, FileChangeBurstDetector
from aegis_core.engine import MonitoringConfig, MonitoringEngine
from aegis_core.models import Environment, Event, EventKind
from aegis_core.storage import EvidenceStore
from aegis_core.versioning import FileVersionVault


class CoreTests(unittest.TestCase):
    def test_evidence_chain_detects_tampering(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            store = EvidenceStore(Path(temporary) / "evidence.sqlite3")
            store.append_event(Event(EventKind.HEALTH, "test", {"status": "ok"}))
            self.assertTrue(store.verify_chain())
            store._connection.execute("UPDATE events SET payload='tampered' WHERE sequence=1")
            store._connection.commit()
            self.assertFalse(store.verify_chain())
            store.close()

    def test_file_burst_is_explainable(self) -> None:
        detector = FileChangeBurstDetector(window_seconds=60, threshold=2)
        first = Event(EventKind.FILE, "test", {"operation": "modified", "path": "a.txt", "suffix": ".locked"})
        second = Event(EventKind.FILE, "test", {"operation": "modified", "path": "b.txt", "suffix": ".locked"})
        self.assertEqual(tuple(detector.evaluate(first)), ())
        findings = tuple(detector.evaluate(second))
        self.assertEqual(findings[0].rule_id, "AEGIS-FILE-001")
        self.assertEqual(len(findings[0].evidence_event_ids), 2)

    def test_version_restore_requires_approver(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = root / "document.txt"
            source.write_text("before", encoding="utf-8")
            vault = FileVersionVault(root / "vault")
            version = vault.capture(source)
            assert version is not None
            source.write_text("after", encoding="utf-8")
            with self.assertRaises(PermissionError):
                vault.restore(version.version_id, approved_by="")
            vault.restore(version.version_id, approved_by="security@example.test")
            self.assertEqual(source.read_text(encoding="utf-8"), "before")
            vault.close()

    def test_file_collector_reports_change_after_baseline(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            document = root / "note.txt"
            document.write_text("first", encoding="utf-8")
            collector = FilePollingCollector((root,))
            self.assertEqual(list(collector.collect("test")), [])
            document.write_text("second version", encoding="utf-8")
            events = list(collector.collect("test"))
            self.assertEqual(events[0].kind, EventKind.FILE)
            self.assertEqual(events[0].data["operation"], "modified")

    def test_runtime_emits_heartbeat_and_recovers_from_a_collector_failure(self) -> None:
        class FlakyCollector:
            name = "flaky"
            def __init__(self) -> None:
                self.calls = 0
            def collect(self, host_id: str):
                self.calls += 1
                if self.calls == 1:
                    raise RuntimeError("temporary failure")
                yield Event(EventKind.PROCESS, self.name, {"pid": 123, "name": "recovered"}, host_id=host_id)

        with tempfile.TemporaryDirectory() as temporary:
            collector = FlakyCollector()
            engine = MonitoringEngine(MonitoringConfig(Environment.PRODUCTION, Path(temporary),
                interval_seconds=0.01, health_interval_seconds=0.01, max_collector_backoff_seconds=0.01),
                collectors=[collector])
            engine.start()
            engine.run_once()
            first_status = engine.status()
            self.assertEqual(first_status["collectors"][0]["failures"], 1)
            time.sleep(0.02)
            engine.run_once()
            recovered_status = engine.status()
            self.assertEqual(collector.calls, 2)
            self.assertEqual(recovered_status["collectors"][0]["failures"], 0)
            engine.close()

    def test_bounded_runner_collects_immediately_and_stops(self) -> None:
        class CountingCollector:
            name = "counter"
            def __init__(self) -> None:
                self.calls = 0
            def collect(self, host_id: str):
                self.calls += 1
                yield Event(EventKind.HEALTH, self.name, {"cycle": self.calls}, host_id=host_id)

        with tempfile.TemporaryDirectory() as temporary:
            collector = CountingCollector()
            engine = MonitoringEngine(MonitoringConfig(Environment.DEVELOPMENT, Path(temporary),
                interval_seconds=0.02, health_interval_seconds=0.02, max_collector_backoff_seconds=0.02),
                collectors=[collector])
            engine.run_for(0.07)
            self.assertGreaterEqual(collector.calls, 2)
            self.assertTrue(engine.status()["stopped"])
            # Evidence store remains usable for post-run statistics
            total = engine.store.count_events()
            self.assertGreaterEqual(total, 2)
            self.assertTrue(engine.store.verify_chain())
            self.assertFalse(engine.store.is_closed)
            # Exactly one close during final cleanup
            engine.close()
            self.assertTrue(engine.store.is_closed)

    def test_cli_bounded_run_lifecycle_queries_store_before_close(self) -> None:
        import io
        from unittest.mock import patch
        from aegis_core.__main__ import main

        with tempfile.TemporaryDirectory() as temporary:
            args = ["aegis_core", "--data-dir", temporary, "--interval-seconds", "0.02", "--run-seconds", "0.06", "--no-network"]
            with patch("sys.argv", args), patch("sys.stdout", new_callable=io.StringIO) as mock_stdout:
                ret = main()
                self.assertEqual(ret, 0)
                output = mock_stdout.getvalue()
                self.assertIn("bounded monitoring run completed", output)
                self.assertIn("chain_valid=True", output)
                self.assertIn("events=", output)


if __name__ == "__main__":
    unittest.main()
