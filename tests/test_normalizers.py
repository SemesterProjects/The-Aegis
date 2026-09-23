"""Comprehensive unit tests for aegis_core normalizers.

Tests every normalization function with realistic inputs and verifies:
- Output is a valid aegis_core.Event
- All enum values are extracted (no raw Enum objects in data)
- None fields are absent from data dict (not present as None)
- Timestamps are UTC-aware
- Required fields are present
"""
from __future__ import annotations

import pytest
from datetime import datetime, timezone
from unittest.mock import MagicMock

import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from aegis_core.models import Event, EventKind
from aegis_core.normalizers import (
    normalize_connection_event,
    normalize_traffic_event,
    normalize_dns_event,
    normalize_process_network_event,
    normalize_process_start,
    normalize_process_exit,
    normalize_process_snapshot,
    normalize_file_event,
    normalize_auth_event,
    normalize_collector_error,
    normalize_capability_status,
)

HOST_ID = "test-host-abc123"
COLLECTOR = "test_collector"
NOW = datetime(2026, 9, 1, 12, 0, 0, tzinfo=timezone.utc)


class _FakeEnum:
    """Simulates a Enum-like object (has .value)."""
    def __init__(self, value: str):
        self.value = value
    def __str__(self):
        return f"FakeEnum({self.value})"


# ---------------------------------------------------------------------------
# Connection event tests
# ---------------------------------------------------------------------------

class TestNormalizeConnectionEvent:
    def _make_conn(self, **overrides):
        conn = MagicMock()
        conn.protocol = _FakeEnum("tcp")
        conn.direction = _FakeEnum("outbound")
        conn.local_ip = "192.168.1.5"
        conn.local_port = 54321
        conn.remote_ip = "8.8.8.8"
        conn.remote_port = 443
        conn.state = _FakeEnum("ESTABLISHED")
        conn.pid = 1234
        conn.process_name = "python"
        conn.executable_path = "/usr/bin/python3"
        conn.user = "alice"
        conn.connection_id = "conn-001"
        conn.collector = "linux_connections"
        conn.timestamp = NOW
        for k, v in overrides.items():
            setattr(conn, k, v)
        return conn

    def test_returns_event(self):
        event = normalize_connection_event(self._make_conn(), HOST_ID)
        assert isinstance(event, Event)
        assert event.kind is EventKind.NETWORK

    def test_enum_values_extracted(self):
        event = normalize_connection_event(self._make_conn(), HOST_ID)
        assert event.data["protocol"] == "tcp"
        assert event.data["direction"] == "outbound"
        assert event.data["state"] == "ESTABLISHED"

    def test_timestamp_utc_aware(self):
        event = normalize_connection_event(self._make_conn(), HOST_ID)
        assert event.observed_at.tzinfo is not None

    def test_none_fields_absent(self):
        conn = self._make_conn(user=None, executable_path=None)
        event = normalize_connection_event(conn, HOST_ID)
        assert "user" not in event.data
        assert "executable_path" not in event.data

    def test_action_is_connection_snapshot(self):
        event = normalize_connection_event(self._make_conn(), HOST_ID)
        assert event.data["action"] == "connection_snapshot"

    def test_host_id_and_source(self):
        event = normalize_connection_event(self._make_conn(), HOST_ID, "my_bridge")
        assert event.host_id == HOST_ID
        assert event.source == "my_bridge"

    def test_pid_preserved_as_int(self):
        event = normalize_connection_event(self._make_conn(pid=9999), HOST_ID)
        assert event.data["pid"] == 9999

    def test_naive_timestamp_gets_utc(self):
        naive_dt = datetime(2026, 1, 1, 0, 0, 0)  # no tzinfo
        event = normalize_connection_event(self._make_conn(timestamp=naive_dt), HOST_ID)
        assert event.observed_at.tzinfo is not None

    def test_no_timestamp_defaults_to_now(self):
        event = normalize_connection_event(self._make_conn(timestamp=None), HOST_ID)
        assert event.observed_at.tzinfo is not None


# ---------------------------------------------------------------------------
# Traffic event tests
# ---------------------------------------------------------------------------

class TestNormalizeTrafficEvent:
    def _make_traffic(self):
        t = MagicMock()
        t.interface = "eth0"
        t.bytes_sent = 1024
        t.bytes_received = 2048
        t.packets_sent = 10
        t.packets_received = 20
        t.delta_bytes_sent = 100
        t.delta_bytes_received = 200
        t.delta_packets_sent = 1
        t.delta_packets_received = 2
        t.errors_in = 0
        t.errors_out = 0
        t.drops_in = 0
        t.drops_out = 0
        t.collector = "linux_traffic"
        t.timestamp = NOW
        return t

    def test_action_is_traffic_stats(self):
        event = normalize_traffic_event(self._make_traffic(), HOST_ID)
        assert event.data["action"] == "traffic_stats"

    def test_interface_name_preserved(self):
        event = normalize_traffic_event(self._make_traffic(), HOST_ID)
        assert event.data["interface"] == "eth0"

    def test_delta_fields_present(self):
        event = normalize_traffic_event(self._make_traffic(), HOST_ID)
        assert "delta_bytes_sent" in event.data
        assert "delta_bytes_received" in event.data


# ---------------------------------------------------------------------------
# DNS event tests
# ---------------------------------------------------------------------------

class TestNormalizeDnsEvent:
    def _make_dns(self, is_response=False):
        d = MagicMock()
        d.query_name = "example.com"
        d.query_type = "A"
        d.query_id = 1234
        d.is_response = is_response
        d.response_code = "NOERROR"
        d.response_addresses = ["93.184.216.34"] if is_response else []
        d.source_ip = "192.168.1.5"
        d.destination_ip = "8.8.8.8"
        d.pid = 5678
        d.process_name = "resolver"
        d.collector = "linux_dns"
        d.timestamp = NOW
        return d

    def test_query_action(self):
        event = normalize_dns_event(self._make_dns(is_response=False), HOST_ID)
        assert event.data["action"] == "dns_query"

    def test_response_action(self):
        event = normalize_dns_event(self._make_dns(is_response=True), HOST_ID)
        assert event.data["action"] == "dns_response"

    def test_response_addresses_present_for_response(self):
        event = normalize_dns_event(self._make_dns(is_response=True), HOST_ID)
        assert "response_addresses" in event.data
        assert "93.184.216.34" in event.data["response_addresses"]

    def test_empty_response_addresses_absent(self):
        event = normalize_dns_event(self._make_dns(is_response=False), HOST_ID)
        assert "response_addresses" not in event.data


# ---------------------------------------------------------------------------
# Process normalization tests
# ---------------------------------------------------------------------------

class TestProcessNormalizers:
    def _info(self, **overrides):
        info = {
            "name": "python3",
            "ppid": 1,
            "exe": "/usr/bin/python3",
            "cmdline": ["python3", "script.py"],
            "user": "alice",
            "create_time": 1700000000.0,
            "status": "running",
            "num_threads": 4,
        }
        info.update(overrides)
        return info

    def test_process_start_action(self):
        event = normalize_process_start(1234, self._info(), HOST_ID, COLLECTOR, "psutil")
        assert event.data["action"] == "start"
        assert event.data["pid"] == 1234
        assert event.kind is EventKind.PROCESS

    def test_cmdline_list_joined(self):
        event = normalize_process_start(1234, self._info(), HOST_ID, COLLECTOR, "psutil")
        assert event.data["cmdline"] == "python3 script.py"

    def test_process_exit_action(self):
        event = normalize_process_exit(1234, self._info(), HOST_ID, COLLECTOR, "psutil")
        assert event.data["action"] == "exit"

    def test_process_snapshot_action(self):
        event = normalize_process_snapshot(1234, self._info(), HOST_ID, COLLECTOR, "psutil")
        assert event.data["action"] == "snapshot"
        assert event.data.get("status") == "running"

    def test_none_exe_absent(self):
        event = normalize_process_start(1234, self._info(exe=None), HOST_ID, COLLECTOR, "psutil")
        assert "exe" not in event.data

    def test_mechanism_recorded(self):
        event = normalize_process_start(1234, self._info(), HOST_ID, COLLECTOR, "proc_fs")
        assert event.data["collection_mechanism"] == "proc_fs"


# ---------------------------------------------------------------------------
# File normalization tests
# ---------------------------------------------------------------------------

class TestNormalizeFileEvent:
    def test_create_action(self):
        event = normalize_file_event("create", "/tmp/test.txt", HOST_ID, COLLECTOR, "inotify")
        assert event.data["action"] == "create"
        assert event.kind is EventKind.FILE

    def test_path_components_extracted(self):
        event = normalize_file_event("modify", "/home/alice/doc.pdf", HOST_ID, COLLECTOR, "watchdog")
        assert event.data["path"] == "/home/alice/doc.pdf"
        assert event.data["name"] == "doc.pdf"
        assert event.data["suffix"] == ".pdf"
        import os
        expected_parent = "\\home\\alice" if os.name == "nt" else "/home/alice"
        assert event.data["parent"] == expected_parent

    def test_rename_with_dest_path(self):
        extra = {"dest_path": "/tmp/test_renamed.txt"}
        event = normalize_file_event("rename", "/tmp/test.txt", HOST_ID, COLLECTOR, "watchdog", extra=extra)
        assert event.data["dest_path"] == "/tmp/test_renamed.txt"

    def test_no_suffix_file(self):
        event = normalize_file_event("delete", "/etc/hosts", HOST_ID, COLLECTOR, "polling")
        assert "suffix" not in event.data  # empty string -> None -> compact removes it

    def test_observed_at_preserved(self):
        event = normalize_file_event("create", "/tmp/x", HOST_ID, COLLECTOR, "inotify", observed_at=NOW)
        assert event.observed_at == NOW


# ---------------------------------------------------------------------------
# Auth normalization tests
# ---------------------------------------------------------------------------

class TestNormalizeAuthEvent:
    def test_login_success(self):
        fields = {"user": "alice", "pid": 1234, "auth_mechanism": "sshd", "message": "Accepted key"}
        event = normalize_auth_event("login_success", fields, HOST_ID, COLLECTOR, "journalctl")
        assert event.kind is EventKind.AUTHENTICATION
        assert event.data["action"] == "login_success"
        assert event.data["user"] == "alice"

    def test_login_failure(self):
        fields = {"user": "root", "pid": None, "auth_mechanism": "sshd"}
        event = normalize_auth_event("login_failure", fields, HOST_ID, COLLECTOR, "journalctl")
        assert event.data["action"] == "login_failure"
        assert "pid" not in event.data  # None -> absent

    def test_mechanism_recorded(self):
        event = normalize_auth_event("privilege_change", {"user": "bob"}, HOST_ID, COLLECTOR, "wevtutil")
        assert event.data["collection_mechanism"] == "wevtutil"

    def test_observed_at_preserved(self):
        event = normalize_auth_event("session_start", {}, HOST_ID, COLLECTOR, "journalctl", observed_at=NOW)
        assert event.observed_at == NOW


# ---------------------------------------------------------------------------
# Health normalization tests
# ---------------------------------------------------------------------------

class TestHealthNormalizers:
    def test_collector_error(self):
        event = normalize_collector_error("network_bridge", "OSError", "permission denied", HOST_ID)
        assert event.kind is EventKind.HEALTH
        assert event.data["action"] == "collector_error"
        assert event.data["collector"] == "network_bridge"
        assert "permission denied" in event.data["error_message"]

    def test_long_error_message_truncated(self):
        long_msg = "x" * 1000
        event = normalize_collector_error("test", "Error", long_msg, HOST_ID)
        assert len(event.data["error_message"]) <= 500

    def test_capability_status(self):
        event = normalize_capability_status("auth_events", "PERMISSION_DENIED", "requires root", HOST_ID, "journalctl")
        assert event.data["status"] == "PERMISSION_DENIED"
        assert event.data["reason"] == "requires root"
        assert event.data["mechanism"] == "journalctl"
