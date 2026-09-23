"""Comprehensive unit and integration test suite for Milestone 4.

Verifies:
1. Network event -> canonical Event conversion
2. ConnectionEvent mapping (ESTABLISHED, SYN_SENT, CLOSE, LISTEN)
3. TrafficEvent mapping (counters and interval deltas)
4. DnsEvent mapping (queries, responses, addresses)
5. ProcessNetworkEvent mapping (process-socket attribution)
6. Event persistence and SQLite hash-chain integrity
7. NetworkRateDetector evaluation of canonical network events
8. Collector failure isolation and exponential backoff
9. Collector recovery behavior
10. End-to-end monitoring pipeline (Process + File + Network + Detection + EvidenceStore)
"""
from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path
import sqlite3
import tempfile
import unittest

from aegis_core.collectors import (
    Collector,
    FilePollingCollector,
    NetworkCollector,
    ProcessSnapshotCollector,
)
from aegis_core.detection import DetectionPipeline, NetworkRateDetector
from aegis_core.engine import MonitoringConfig, MonitoringEngine
from aegis_core.models import Environment, Event, EventKind, Severity
from aegis_core.network import NetworkBridge
from aegis_core.storage import EvidenceStore
from network_monitor.core.events import (
    ConnectionDirection,
    ConnectionEvent,
    ConnectionState,
    DnsEvent,
    ProcessNetworkEvent,
    Protocol,
    TrafficEvent,
)


class BridgeAndIntegrationTests(unittest.TestCase):
    def test_connection_event_mapping(self) -> None:
        """Verify ConnectionEvent maps to EventKind.NETWORK and preserves attributes."""
        # 1. ESTABLISHED connection -> connection_open
        conn_open = ConnectionEvent(
            adapter="TestAdapter",
            collector="test_collector",
            protocol=Protocol.TCP,
            direction=ConnectionDirection.OUTBOUND,
            local_ip="192.168.1.50",
            local_port=54321,
            remote_ip="93.184.216.34",
            remote_port=443,
            state=ConnectionState.ESTABLISHED,
            pid=1234,
            process_name="curl",
            executable_path="/usr/bin/curl",
            user="testuser",
            connection_id="conn-1234",
        )
        canonical = NetworkBridge.connection_event_to_canonical(conn_open, host_id="host-abc")
        self.assertEqual(canonical.kind, EventKind.NETWORK)
        self.assertEqual(canonical.host_id, "host-abc")
        self.assertEqual(canonical.source, "network_monitor.TestAdapter.test_collector")
        self.assertEqual(canonical.event_id, conn_open.event_id)
        self.assertEqual(canonical.data["action"], "connection_open")
        self.assertEqual(canonical.data["protocol"], "tcp")
        self.assertEqual(canonical.data["direction"], "outbound")
        self.assertEqual(canonical.data["state"], "ESTABLISHED")
        self.assertEqual(canonical.data["local_ip"], "192.168.1.50")
        self.assertEqual(canonical.data["local_port"], 54321)
        self.assertEqual(canonical.data["remote_ip"], "93.184.216.34")
        self.assertEqual(canonical.data["remote_port"], 443)
        self.assertEqual(canonical.data["pid"], 1234)
        self.assertEqual(canonical.data["process"], "curl")
        self.assertEqual(canonical.data["connection_id"], "conn-1234")
        self.assertTrue(canonical.digest())

        # 2. CLOSE connection -> connection_close
        conn_close = ConnectionEvent(
            adapter="TestAdapter",
            collector="test_collector",
            state=ConnectionState.CLOSE,
            pid=1234,
        )
        canonical_close = NetworkBridge.connection_event_to_canonical(conn_close)
        self.assertEqual(canonical_close.data["action"], "connection_close")

        # 3. LISTEN connection -> listen
        conn_listen = ConnectionEvent(
            adapter="TestAdapter",
            collector="test_collector",
            state=ConnectionState.LISTEN,
            local_port=8080,
        )
        canonical_listen = NetworkBridge.connection_event_to_canonical(conn_listen)
        self.assertEqual(canonical_listen.data["action"], "listen")

    def test_traffic_event_mapping(self) -> None:
        """Verify TrafficEvent maps to EventKind.NETWORK with counters and deltas."""
        traffic = TrafficEvent(
            adapter="WindowsAdapter",
            collector="traffic",
            interface="eth0",
            bytes_sent=10240,
            bytes_received=20480,
            packets_sent=100,
            packets_received=200,
            errors_in=0,
            errors_out=1,
            drops_in=0,
            drops_out=0,
            delta_bytes_sent=512,
            delta_bytes_received=1024,
            delta_packets_sent=5,
            delta_packets_received=10,
        )
        canonical = NetworkBridge.traffic_event_to_canonical(traffic, host_id="win-host")
        self.assertEqual(canonical.kind, EventKind.NETWORK)
        self.assertEqual(canonical.source, "network_monitor.WindowsAdapter.traffic")
        self.assertEqual(canonical.data["action"], "traffic_update")
        self.assertEqual(canonical.data["interface"], "eth0")
        self.assertEqual(canonical.data["bytes_sent"], 10240)
        self.assertEqual(canonical.data["bytes_received"], 20480)
        self.assertEqual(canonical.data["delta_bytes_sent"], 512)
        self.assertEqual(canonical.data["delta_bytes_received"], 1024)

    def test_dns_event_mapping(self) -> None:
        """Verify DnsEvent maps to EventKind.NETWORK for queries and responses."""
        # Query
        query = DnsEvent(
            adapter="LinuxAdapter",
            collector="dns",
            source_ip="192.168.1.10",
            destination_ip="8.8.8.8",
            query_name="example.com",
            query_type="A",
            is_response=False,
            pid=5555,
            process_name="dig",
        )
        canonical_q = NetworkBridge.dns_event_to_canonical(query, host_id="linux-host")
        self.assertEqual(canonical_q.kind, EventKind.NETWORK)
        self.assertEqual(canonical_q.data["action"], "dns_query")
        self.assertEqual(canonical_q.data["query_name"], "example.com")
        self.assertEqual(canonical_q.data["query_type"], "A")
        self.assertEqual(canonical_q.data["pid"], 5555)

        # Response
        response = DnsEvent(
            adapter="LinuxAdapter",
            collector="dns",
            source_ip="8.8.8.8",
            destination_ip="192.168.1.10",
            query_name="example.com",
            query_type="A",
            is_response=True,
            response_code="NOERROR",
            response_addresses=["93.184.216.34"],
        )
        canonical_r = NetworkBridge.dns_event_to_canonical(response, host_id="linux-host")
        self.assertEqual(canonical_r.data["action"], "dns_response")
        self.assertEqual(canonical_r.data["response_code"], "NOERROR")
        self.assertEqual(canonical_r.data["response_addresses"], ["93.184.216.34"])

    def test_process_network_event_mapping(self) -> None:
        """Verify ProcessNetworkEvent maps process and socket correlation."""
        pne = ProcessNetworkEvent(
            adapter="LinuxAdapter",
            collector="process_network",
            pid=7777,
            process_name="nginx",
            executable_path="/usr/sbin/nginx",
            user="www-data",
            process_status="running",
            connection_id="conn-7777",
            local_ip="0.0.0.0",
            local_port=80,
            remote_ip=None,
            remote_port=None,
            protocol=Protocol.TCP,
        )
        canonical = NetworkBridge.process_network_event_to_canonical(pne, host_id="srv-1")
        self.assertEqual(canonical.kind, EventKind.NETWORK)
        self.assertEqual(canonical.data["action"], "process_network_association")
        self.assertEqual(canonical.data["pid"], 7777)
        self.assertEqual(canonical.data["process"], "nginx")
        self.assertEqual(canonical.data["executable_path"], "/usr/sbin/nginx")
        self.assertEqual(canonical.data["user"], "www-data")
        self.assertEqual(canonical.data["local_port"], 80)
        self.assertEqual(canonical.data["protocol"], "tcp")

    def test_to_canonical_dispatcher(self) -> None:
        """Verify the generic to_canonical method routes correctly and rejects unknowns."""
        conn = ConnectionEvent(state=ConnectionState.ESTABLISHED)
        traffic = TrafficEvent(interface="eth0")
        dns = DnsEvent(query_name="test.org")
        pne = ProcessNetworkEvent(pid=1)

        self.assertEqual(NetworkBridge.to_canonical(conn).kind, EventKind.NETWORK)
        self.assertEqual(NetworkBridge.to_canonical(traffic).kind, EventKind.NETWORK)
        self.assertEqual(NetworkBridge.to_canonical(dns).kind, EventKind.NETWORK)
        self.assertEqual(NetworkBridge.to_canonical(pne).kind, EventKind.NETWORK)

        with self.assertRaises(TypeError):
            NetworkBridge.to_canonical("invalid_event_type")

    def test_network_events_persist_to_evidence_store(self) -> None:
        """Verify converted network events are stored and pass hash chain verification."""
        with tempfile.TemporaryDirectory() as tmpdir:
            db_path = Path(tmpdir) / "evidence.sqlite3"
            store = EvidenceStore(db_path)

            conn = ConnectionEvent(state=ConnectionState.ESTABLISHED, pid=42, process_name="agent")
            traffic = TrafficEvent(interface="eth0", bytes_sent=100)

            event1 = NetworkBridge.connection_event_to_canonical(conn, host_id="test-host")
            event2 = NetworkBridge.traffic_event_to_canonical(traffic, host_id="test-host")

            store.append_event(event1)
            store.append_event(event2)

            self.assertTrue(store.verify_chain())

            # Read back
            since = datetime(2000, 1, 1, tzinfo=timezone.utc)
            recent = store.recent_events(since)
            self.assertEqual(len(recent), 2)
            self.assertEqual(recent[0]["kind"], "network")
            self.assertEqual(recent[1]["kind"], "network")

            # Verify tampering is caught
            conn_db = sqlite3.connect(db_path)
            try:
                conn_db.execute("UPDATE events SET payload = ? WHERE sequence = 1", ('{"tampered": true}',))
                conn_db.commit()
            finally:
                conn_db.close()

            self.assertFalse(store.verify_chain())
            store.close()

    def test_network_rate_detector_receives_network_events(self) -> None:
        """Verify NetworkRateDetector triggers findings from live canonical network events."""
        detector = NetworkRateDetector(window_seconds=60, threshold=5)
        pipeline = DetectionPipeline(detectors=(detector,))

        # Feed 4 events: below threshold, no finding
        findings = []
        for i in range(4):
            conn = ConnectionEvent(
                state=ConnectionState.ESTABLISHED,
                pid=9999,
                process_name="scanner",
                remote_ip=f"10.0.0.{i}",
                remote_port=80,
            )
            event = NetworkBridge.connection_event_to_canonical(conn, host_id="target-host")
            findings.extend(pipeline.evaluate(event))

        self.assertEqual(len(findings), 0)

        # 5th event: threshold met, finding triggered!
        conn_5 = ConnectionEvent(
            state=ConnectionState.ESTABLISHED,
            pid=9999,
            process_name="scanner",
            remote_ip="10.0.0.5",
            remote_port=80,
        )
        event_5 = NetworkBridge.connection_event_to_canonical(conn_5, host_id="target-host")
        findings_5 = pipeline.evaluate(event_5)

        self.assertEqual(len(findings_5), 1)
        finding = findings_5[0]
        self.assertEqual(finding.rule_id, "AEGIS-NET-001")
        self.assertEqual(finding.severity, Severity.MEDIUM)
        self.assertEqual(len(finding.evidence_event_ids), 5)
        self.assertIn("9999", finding.explanation)

    def test_collector_isolation_and_recovery(self) -> None:
        """Verify a collector failure triggers backoff without crashing engine, and recovers."""
        class FlakyCollector:
            name = "flaky_collector"
            def __init__(self) -> None:
                self.should_fail = True

            def collect(self, host_id: str):
                if self.should_fail:
                    raise RuntimeError("Simulated network interface dropped")
                yield Event(EventKind.NETWORK, self.name, {"action": "recovered"}, host_id=host_id)

        flaky = FlakyCollector()

        with tempfile.TemporaryDirectory() as tmpdir:
            config = MonitoringConfig(
                environment=Environment.DEVELOPMENT,
                data_directory=Path(tmpdir),
                interval_seconds=0.01,
            )
            engine = MonitoringEngine(config, collectors=(flaky,))
            engine.start()

            # Cycle 1: fails
            engine.run_once()
            status = engine.status()
            col_info = status["collectors"][0]
            self.assertEqual(col_info["failures"], 1)
            self.assertEqual(col_info["last_error_type"], "RuntimeError")
            self.assertTrue(col_info["backing_off"])

            # Verify error health event recorded
            self.assertTrue(engine.store.verify_chain())

            # Cycle 2: flaky recovers
            flaky.should_fail = False
            # Clear backoff for test progression
            engine._collector_runtime[flaky.name].next_attempt_at = None
            engine.run_once()

            status2 = engine.status()
            col_info2 = status2["collectors"][0]
            self.assertEqual(col_info2["failures"], 0)
            self.assertFalse(col_info2["backing_off"])
            self.assertIsNotNone(col_info2["last_success_at"])

            engine.close()

    def test_end_to_end_monitoring_pipeline(self) -> None:
        """End-to-end integration test with Process, File, and Network collectors."""
        with tempfile.TemporaryDirectory() as tmpdir:
            tmp_path = Path(tmpdir)
            watch_dir = tmp_path / "watched"
            watch_dir.mkdir()
            data_dir = tmp_path / "aegis_data"

            # Create test file to watch
            monitored_file = watch_dir / "target.txt"
            monitored_file.write_text("initial content", encoding="utf-8")

            config = MonitoringConfig(
                environment=Environment.DEVELOPMENT,
                data_directory=data_dir,
                interval_seconds=0.05,
            )

            collectors = (
                ProcessSnapshotCollector(),
                FilePollingCollector(roots=(watch_dir,)),
                NetworkCollector(),
            )

            engine = MonitoringEngine(config, collectors=collectors)
            engine.start()

            # Run cycle 1: establishes baseline
            engine.run_once()

            # Modify monitored file
            monitored_file.write_text("modified content for detection", encoding="utf-8")

            # Run cycle 2: should pick up file modification, process snapshots, and network telemetry
            engine.run_once()

            # Verify evidence store
            self.assertTrue(engine.store.verify_chain())

            # Check recent events to verify multiple kinds of telemetry are present
            since = datetime(2000, 1, 1, tzinfo=timezone.utc)
            events = engine.store.recent_events(since)

            kinds = {e["kind"] for e in events}
            self.assertIn("health", kinds)
            self.assertIn("process", kinds)
            self.assertIn("file", kinds)
            self.assertIn("network", kinds)

            # Check engine status
            status = engine.status()
            self.assertEqual(status["collector_count"], 3)
            self.assertTrue(status["evidence_chain_valid"])

            engine.close()
            self.assertTrue(status["started"])


if __name__ == "__main__":
    unittest.main()
