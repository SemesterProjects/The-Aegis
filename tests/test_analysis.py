"""Tests for the deterministic Telemetry Context & Analysis layer.

Covers:
  - Process event analysis (real fields extracted, missing fields safe)
  - File event analysis (create / modify / delete, size delta)
  - Network event analysis (connection, traffic, dns, process-network)
  - Authentication event analysis
  - Correlator rules (process+network, file+nearby, auth+auth)
  - Correlator non-correlation (unrelated events must not be linked)
  - Evidence traceability (no fabricated event IDs)
  - Formatter output (non-empty, contains real values)
  - CLI --analyze flag (end-to-end)
"""
from __future__ import annotations

import io
import tempfile
from datetime import datetime, timezone
from pathlib import Path
from unittest.mock import patch
import unittest

from aegis_core.analysis import (
    analyze_event,
    Correlator,
    format_analysis,
    format_analyses,
    ChangeDescription,
    EventAnalysis,
    _UNAVAILABLE,
)
from aegis_core.models import Event, EventKind
from aegis_core.storage import EvidenceStore

_UTC = timezone.utc


def _ts(year: int = 2026, hour: int = 12) -> datetime:
    return datetime(year, 1, 1, hour, 0, 0, tzinfo=_UTC)


# ---------------------------------------------------------------------------
# Helper event factories
# ---------------------------------------------------------------------------

def _proc_event(pid: int = 1234, name: str = "python3", exe: str = "/usr/bin/python3",
                user: str = "aegis", host: str = "host-abc", started: float | None = None) -> Event:
    data: dict = {"pid": pid, "name": name, "exe": exe, "user": user}
    if started is not None:
        data["started"] = started
    return Event(EventKind.PROCESS, "process_snapshot", data, host_id=host, observed_at=_ts())


def _file_event(operation: str, path: str = "/tmp/test.txt", size: int | None = None,
                prev_size: int | None = None, host: str = "host-abc") -> Event:
    data: dict = {"path": path, "operation": operation, "suffix": Path(path).suffix}
    if size is not None:
        data["size"] = size
    if prev_size is not None:
        data["previous_size"] = prev_size
    return Event(EventKind.FILE, "file_polling", data, host_id=host, observed_at=_ts())


def _net_connection_event(action: str = "connection_open", pid: int = 1234,
                          process: str = "curl", local_ip: str = "10.0.0.1",
                          remote_ip: str = "93.184.216.34", remote_port: int = 443,
                          direction: str = "outbound", protocol: str = "tcp",
                          host: str = "host-abc") -> Event:
    data = {
        "action": action, "pid": pid, "process": process,
        "local_ip": local_ip, "local_port": 54321,
        "remote_ip": remote_ip, "remote_port": remote_port,
        "direction": direction, "protocol": protocol, "state": "ESTABLISHED",
    }
    return Event(EventKind.NETWORK, "network_monitor", data, host_id=host, observed_at=_ts())


def _auth_event(action: str = "login_failure", user: str = "admin",
                source: str = "192.168.1.1", host: str = "host-abc") -> Event:
    data = {"action": action, "user": user, "source_ip": source}
    return Event(EventKind.AUTHENTICATION, "auth_collector", data, host_id=host, observed_at=_ts())


# ===========================================================================
# Process analysis tests
# ===========================================================================

class TestProcessAnalysis(unittest.TestCase):

    def test_actual_fields_extracted(self) -> None:
        ev = _proc_event(pid=9999, name="nginx", exe="/usr/sbin/nginx", user="www-data")
        a = analyze_event(ev)
        self.assertEqual(a.event_kind, "process")
        self.assertEqual(a.subject["pid"], 9999)
        self.assertEqual(a.subject["process_name"], "nginx")
        self.assertEqual(a.subject["executable"], "/usr/sbin/nginx")
        self.assertEqual(a.subject["user"], "www-data")

    def test_missing_ppid_is_unavailable(self) -> None:
        ev = _proc_event()
        a = analyze_event(ev)
        # ProcessSnapshotCollector never supplies ppid
        self.assertEqual(a.subject["parent_pid"], _UNAVAILABLE)

    def test_started_timestamp_converted_from_epoch(self) -> None:
        epoch = 1_700_000_000.0
        ev = _proc_event(started=epoch)
        a = analyze_event(ev)
        self.assertNotEqual(a.subject["started_at"], _UNAVAILABLE)
        self.assertIn("2023", a.subject["started_at"])  # epoch 1.7B is late 2023

    def test_missing_exe_is_unavailable(self) -> None:
        ev = Event(EventKind.PROCESS, "process_snapshot", {"pid": 42, "name": "sh"}, host_id="h1", observed_at=_ts())
        a = analyze_event(ev)
        self.assertEqual(a.subject["executable"], _UNAVAILABLE)

    def test_summary_contains_process_name(self) -> None:
        ev = _proc_event(name="sshd")
        a = analyze_event(ev)
        self.assertIn("sshd", a.summary)

    def test_no_unsupported_claim(self) -> None:
        ev = _proc_event(name="unusual_proc_xyz")
        a = analyze_event(ev)
        # The analysis reason must NOT make threat verdicts —
        # the process name legitimately appears in the summary.
        for bad in ("malicious", "suspicious", "threat", "attack"):
            self.assertNotIn(bad, a.reason.lower())
        # Summary should contain the actual process name (faithful reporting)
        self.assertIn("unusual_proc_xyz", a.summary)

    def test_evidence_references_real_event_id(self) -> None:
        ev = _proc_event()
        a = analyze_event(ev)
        self.assertEqual(len(a.evidence), 1)
        self.assertEqual(a.evidence[0].event_id, ev.event_id)

    def test_host_id_preserved(self) -> None:
        ev = _proc_event(host="my-special-host")
        a = analyze_event(ev)
        self.assertEqual(a.host_id, "my-special-host")


# ===========================================================================
# File analysis tests
# ===========================================================================

class TestFileAnalysis(unittest.TestCase):

    def test_modify_with_size_delta(self) -> None:
        ev = _file_event("modified", size=75, prev_size=52)
        a = analyze_event(ev)
        self.assertEqual(a.subject["operation"], "MODIFIED")
        self.assertEqual(len(a.changes), 1)
        ch = a.changes[0]
        self.assertEqual(ch.delta, 23)
        self.assertIn("52 bytes", str(ch))
        self.assertIn("75 bytes", str(ch))
        self.assertIn("+23", str(ch))

    def test_create_reports_new_size(self) -> None:
        ev = _file_event("created", size=100)
        a = analyze_event(ev)
        self.assertEqual(a.subject["operation"], "CREATED")
        self.assertEqual(len(a.changes), 1)
        self.assertIn("100 bytes", str(a.changes[0]))

    def test_delete_reports_previous_size(self) -> None:
        ev = _file_event("deleted", prev_size=200)
        a = analyze_event(ev)
        self.assertEqual(a.subject["operation"], "DELETED")
        self.assertEqual(len(a.changes), 1)
        self.assertIn("200 bytes", str(a.changes[0]))

    def test_path_decomposed(self) -> None:
        ev = _file_event("created", path="/home/purva/docs/report.pdf", size=10)
        a = analyze_event(ev)
        self.assertEqual(a.location["filename"], "report.pdf")
        self.assertIn("report.pdf", a.summary)

    def test_no_process_attribution(self) -> None:
        ev = _file_event("modified", size=10, prev_size=5)
        a = analyze_event(ev)
        # actor dict must be empty — file collector has no process attribution
        self.assertEqual(a.actor, {})

    def test_explanation_generated(self) -> None:
        ev = _file_event("modified", size=10, prev_size=5)
        a = analyze_event(ev)
        self.assertNotEqual(a.reason, _UNAVAILABLE)
        self.assertGreater(len(a.reason), 10)

    def test_evidence_event_id_real(self) -> None:
        ev = _file_event("created", size=1)
        a = analyze_event(ev)
        self.assertEqual(a.evidence[0].event_id, ev.event_id)


# ===========================================================================
# Network analysis tests
# ===========================================================================

class TestNetworkAnalysis(unittest.TestCase):

    def test_connection_fields_extracted(self) -> None:
        ev = _net_connection_event(pid=5555, process="wget", remote_ip="1.2.3.4", remote_port=80,
                                   direction="outbound", protocol="tcp")
        a = analyze_event(ev)
        self.assertEqual(a.event_kind, "network")
        self.assertEqual(a.actor["pid"], 5555)
        self.assertEqual(a.actor["process"], "wget")
        self.assertEqual(a.location["direction"], "OUTBOUND")
        self.assertEqual(a.location["protocol"], "tcp")
        self.assertIn("1.2.3.4:80", a.location["remote_endpoint"])

    def test_no_malice_claim(self) -> None:
        ev = _net_connection_event()
        a = analyze_event(ev)
        for bad in ("malicious", "malware", "attack", "threat"):
            self.assertNotIn(bad, a.reason.lower())

    def test_connection_change_description(self) -> None:
        ev = _net_connection_event(action="connection_open")
        a = analyze_event(ev)
        self.assertTrue(any("connection" in str(ch).lower() for ch in a.changes))

    def test_traffic_event_analyzed(self) -> None:
        ev = Event(EventKind.NETWORK, "network_monitor", {
            "action": "traffic_update", "interface": "eth0",
            "delta_bytes_sent": 512, "delta_bytes_received": 1024,
        }, host_id="host-abc", observed_at=_ts())
        a = analyze_event(ev)
        self.assertIn("eth0", a.summary)
        self.assertEqual(len(a.changes), 2)

    def test_dns_query_analyzed(self) -> None:
        ev = Event(EventKind.NETWORK, "network_monitor", {
            "action": "dns_query", "query_name": "example.com", "query_type": "A",
            "pid": 9000, "process_name": "dig",
        }, host_id="host-abc", observed_at=_ts())
        a = analyze_event(ev)
        self.assertIn("example.com", a.summary)
        self.assertEqual(a.actor["pid"], 9000)

    def test_process_network_association_analyzed(self) -> None:
        ev = Event(EventKind.NETWORK, "network_monitor", {
            "action": "process_network_association",
            "pid": 7777, "process": "nginx", "executable_path": "/usr/sbin/nginx",
            "user": "www-data", "local_port": 80, "protocol": "tcp",
        }, host_id="host-abc", observed_at=_ts())
        a = analyze_event(ev)
        self.assertEqual(a.subject["pid"], 7777)
        self.assertEqual(a.subject["user"], "www-data")
        self.assertIn("nginx", a.summary)

    def test_missing_remote_endpoint_is_unavailable(self) -> None:
        ev = Event(EventKind.NETWORK, "network_monitor", {
            "action": "connection_open", "local_ip": "0.0.0.0", "local_port": 8080,
        }, host_id="host-abc", observed_at=_ts())
        a = analyze_event(ev)
        self.assertEqual(a.location["remote_endpoint"], _UNAVAILABLE)


# ===========================================================================
# Authentication analysis tests
# ===========================================================================

class TestAuthAnalysis(unittest.TestCase):

    def test_login_failure_represented(self) -> None:
        ev = _auth_event(action="login_failure", user="root", source="10.0.0.99")
        a = analyze_event(ev)
        self.assertEqual(a.event_kind, "authentication")
        self.assertEqual(a.subject["user"], "root")
        self.assertEqual(a.location["source"], "10.0.0.99")
        self.assertIn("login_failure", a.summary)

    def test_login_success_represented(self) -> None:
        ev = _auth_event(action="login_success", user="purva")
        a = analyze_event(ev)
        self.assertIn("purva", a.summary)

    def test_change_description_present(self) -> None:
        ev = _auth_event()
        a = analyze_event(ev)
        self.assertGreater(len(a.changes), 0)

    def test_evidence_id_real(self) -> None:
        ev = _auth_event()
        a = analyze_event(ev)
        self.assertEqual(a.evidence[0].event_id, ev.event_id)


# ===========================================================================
# Correlator tests
# ===========================================================================

class TestCorrelator(unittest.TestCase):

    def test_process_plus_network_same_pid_correlated(self) -> None:
        proc = _proc_event(pid=4821, host="host-abc")
        net = _net_connection_event(pid=4821, host="host-abc")
        a_proc = analyze_event(proc)
        a_net = analyze_event(net)
        correlated = Correlator(correlation_window_seconds=30).correlate([a_proc, a_net])
        # Process analysis should reference the network event
        proc_result = next(a for a in correlated if a.event_kind == "process")
        net_result = next(a for a in correlated if a.event_kind == "network")
        self.assertIn(net.event_id, proc_result.related_event_ids)
        self.assertIn(proc.event_id, net_result.related_event_ids)

    def test_different_pid_not_correlated(self) -> None:
        proc = _proc_event(pid=100, host="host-abc")
        net = _net_connection_event(pid=999, host="host-abc")
        correlated = Correlator(correlation_window_seconds=30).correlate(
            [analyze_event(proc), analyze_event(net)]
        )
        proc_result = next(a for a in correlated if a.event_kind == "process")
        self.assertNotIn(net.event_id, proc_result.related_event_ids)

    def test_different_host_not_correlated(self) -> None:
        proc = _proc_event(pid=1, host="host-A")
        net = _net_connection_event(pid=1, host="host-B")
        correlated = Correlator(correlation_window_seconds=30).correlate(
            [analyze_event(proc), analyze_event(net)]
        )
        proc_result = next(a for a in correlated if a.event_kind == "process")
        self.assertEqual(proc_result.related_event_ids, [])

    def test_file_event_correlates_with_nearby_events(self) -> None:
        file_ev = _file_event("created", host="host-abc")
        proc_ev = _proc_event(host="host-abc")
        a_file = analyze_event(file_ev)
        a_proc = analyze_event(proc_ev)
        correlated = Correlator(correlation_window_seconds=60).correlate([a_file, a_proc])
        file_result = next(a for a in correlated if a.event_kind == "file")
        self.assertIn(proc_ev.event_id, file_result.related_event_ids)

    def test_auth_same_user_correlated(self) -> None:
        auth1 = _auth_event(action="login_failure", user="root", host="host-abc")
        auth2 = _auth_event(action="login_failure", user="root", host="host-abc")
        a1 = analyze_event(auth1)
        a2 = analyze_event(auth2)
        correlated = Correlator(correlation_window_seconds=60).correlate([a1, a2])
        self.assertIn(auth2.event_id, correlated[0].related_event_ids)

    def test_auth_different_user_not_correlated(self) -> None:
        auth1 = _auth_event(action="login_failure", user="alice", host="host-abc")
        auth2 = _auth_event(action="login_failure", user="bob", host="host-abc")
        correlated = Correlator(correlation_window_seconds=60).correlate(
            [analyze_event(auth1), analyze_event(auth2)]
        )
        self.assertEqual(correlated[0].related_event_ids, [])

    def test_outside_window_not_correlated(self) -> None:
        proc = Event(EventKind.PROCESS, "process_snapshot", {"pid": 1, "name": "sh"},
                     host_id="host-abc",
                     observed_at=datetime(2026, 1, 1, 12, 0, 0, tzinfo=_UTC))
        net = Event(EventKind.NETWORK, "network_monitor",
                    {"action": "connection_open", "pid": 1},
                    host_id="host-abc",
                    observed_at=datetime(2026, 1, 1, 13, 0, 0, tzinfo=_UTC))  # 1 hour later
        correlated = Correlator(correlation_window_seconds=30).correlate(
            [analyze_event(proc), analyze_event(net)]
        )
        self.assertEqual(correlated[0].related_event_ids, [])


# ===========================================================================
# Evidence traceability tests
# ===========================================================================

class TestEvidenceTraceability(unittest.TestCase):

    def test_referenced_event_id_matches_source_event(self) -> None:
        ev = _proc_event()
        a = analyze_event(ev)
        self.assertEqual(a.event_id, ev.event_id)
        for ref in a.evidence:
            self.assertEqual(ref.event_id, ev.event_id)

    def test_analysis_persisted_event_id_in_store(self) -> None:
        """Verify event_id in the analysis matches what is actually in the store."""
        with tempfile.TemporaryDirectory() as tmpdir:
            store = EvidenceStore(Path(tmpdir) / "ev.sqlite3")
            ev = _proc_event()
            store.append_event(ev)
            since = datetime(2000, 1, 1, tzinfo=_UTC)
            rows = store.recent_events(since)
            stored_ids = {row["event_id"] for row in rows}
            a = analyze_event(ev)
            self.assertIn(a.event_id, stored_ids)
            self.assertIn(a.evidence[0].event_id, stored_ids)
            store.close()

    def test_no_fabricated_event_id_in_correlation(self) -> None:
        """All event IDs in related_event_ids must belong to input events."""
        events = [
            _proc_event(pid=42, host="host-abc"),
            _net_connection_event(pid=42, host="host-abc"),
        ]
        real_ids = {e.event_id for e in events}
        analyses = [analyze_event(e) for e in events]
        correlated = Correlator(correlation_window_seconds=60).correlate(analyses)
        for a in correlated:
            for rid in a.related_event_ids:
                self.assertIn(rid, real_ids, f"Fabricated event_id {rid} found in related_event_ids")


# ===========================================================================
# Formatter tests
# ===========================================================================

class TestFormatter(unittest.TestCase):

    def test_process_box_contains_real_values(self) -> None:
        ev = _proc_event(pid=9999, name="bash", user="aegis")
        a = analyze_event(ev)
        rendered = format_analysis(a)
        self.assertIn("PROCESS", rendered)
        self.assertIn("9999", rendered)
        self.assertIn("bash", rendered)
        self.assertIn("aegis", rendered)
        self.assertIn("EVIDENCE", rendered)
        self.assertIn("WHY", rendered)

    def test_file_box_contains_operation_and_path(self) -> None:
        ev = _file_event("modified", path="/var/log/syslog", size=200, prev_size=150)
        a = analyze_event(ev)
        rendered = format_analysis(a)
        self.assertIn("FILE", rendered)
        self.assertIn("MODIFIED", rendered)
        self.assertIn("CHANGE", rendered)
        self.assertIn("+50", rendered)

    def test_network_box_contains_endpoint(self) -> None:
        ev = _net_connection_event(remote_ip="8.8.8.8", remote_port=53)
        a = analyze_event(ev)
        rendered = format_analysis(a)
        self.assertIn("8.8.8.8:53", rendered)
        self.assertIn("NETWORK", rendered)

    def test_auth_box_contains_user(self) -> None:
        ev = _auth_event(user="admin")
        a = analyze_event(ev)
        rendered = format_analysis(a)
        self.assertIn("admin", rendered)
        self.assertIn("AUTHENTICATION", rendered)

    def test_related_events_shown_in_box(self) -> None:
        proc = _proc_event(pid=1, host="host-abc")
        net = _net_connection_event(pid=1, host="host-abc")
        correlated = Correlator(30).correlate([analyze_event(proc), analyze_event(net)])
        proc_analysis = next(a for a in correlated if a.event_kind == "process")
        rendered = format_analysis(proc_analysis)
        self.assertIn("RELATED EVENTS", rendered)

    def test_format_analyses_joins_multiple(self) -> None:
        events = [_proc_event(), _file_event("created", size=10)]
        analyses = [analyze_event(e) for e in events]
        rendered = format_analyses(analyses)
        self.assertIn("PROCESS", rendered)
        self.assertIn("FILE", rendered)


# ===========================================================================
# CLI --analyze flag test
# ===========================================================================

class TestCLIAnalyze(unittest.TestCase):

    def test_analyze_no_store_returns_error(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            args = ["aegis_core", "--data-dir", tmpdir, "--analyze"]
            with patch("sys.argv", args), patch("sys.stdout", new_callable=io.StringIO) as out:
                from aegis_core.__main__ import main
                ret = main()
                self.assertEqual(ret, 1)
                self.assertIn("ERROR", out.getvalue())

    def test_analyze_with_store_returns_zero(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            # Pre-populate store with one event
            store = EvidenceStore(Path(tmpdir) / "evidence.sqlite3")
            store.append_event(_proc_event())
            store.close()
            args = ["aegis_core", "--data-dir", tmpdir, "--analyze"]
            with patch("sys.argv", args), patch("sys.stdout", new_callable=io.StringIO) as out:
                from aegis_core.__main__ import main
                ret = main()
                self.assertEqual(ret, 0)
                output = out.getvalue()
                self.assertIn("AEGIS TELEMETRY ANALYSIS", output)
                self.assertIn("PROCESS", output)


if __name__ == "__main__":
    unittest.main()
