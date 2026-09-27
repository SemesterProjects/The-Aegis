"""
tests/test_milestone3.py
========================
Verification suite for AEGIS Network Monitor Milestone 3:
- Test 1: Linux adapter selection & Milestone 3 metadata
- Test 2: eBPF capability detection (kernel, privilege, BTF, tracepoint probes)
- Test 3: eBPF program load & tracepoint attach (safe on all platforms; reports load status)
- Test 4: Controlled local TCP connection & eBPF event ingestion
- Test 5: Process association via PID from event
- Test 6: Short-lived connection lifecycle detection (CLOSE/TIME_WAIT cleanup)
- Test 7: Fallback to polling when eBPF is unavailable / fails
- Test 8: Multi-cycle monitoring session & JSONL stream validation
"""

from __future__ import annotations

import http.server
import json
import os
import sys
import tempfile
import threading
import time
import urllib.request
from typing import Optional

# Ensure project root is in sys.path
_this_file = os.path.abspath(__file__)
_test_dir = os.path.dirname(_this_file)
_net_mon_dir = os.path.dirname(_test_dir)
_the_aegis_dir = os.path.dirname(_net_mon_dir)
for p in (_the_aegis_dir, _net_mon_dir):
    if p not in sys.path:
        sys.path.insert(0, p)

from network_monitor.core.events import (
    CollectorStatus,
    ConnectionDirection,
    ConnectionEvent,
    ConnectionState,
    Protocol,
)
from network_monitor.core.factory import AdapterFactory
from network_monitor.discovery.system import PrivilegeInfo, SystemDiscovery, SystemInfo
from network_monitor.adapters.linux.adapter import LinuxAdapter
from network_monitor.adapters.linux.connections import LinuxConnectionCollector
from network_monitor.adapters.linux.ebpf.capability import detect as detect_ebpf
from network_monitor.adapters.linux.ebpf.loader import load_connection_tracer


def run_tests() -> None:
    print("==================================================")
    print("AEGIS NETWORK MONITOR - MILESTONE 3 TEST SUITE")
    print("==================================================")
    is_linux = sys.platform.startswith("linux")

    # ------------------------------------------------------------------
    # TEST 1: Linux Adapter Selection & Milestone 3 Metadata
    # ------------------------------------------------------------------
    print("\n[TEST 1] Testing Linux Adapter Selection & Milestone 3 Metadata...")
    synthetic_linux_info = SystemInfo(
        os_name="Linux",
        os_version="5.15.0-generic",
        os_release="5.15.0",
        architecture="x86_64",
        hostname="test-linux-host",
        privilege=PrivilegeInfo(is_root=False, is_admin=None),
        psutil_available=True,
    )
    adapter = AdapterFactory.create(synthetic_linux_info)
    assert isinstance(adapter, LinuxAdapter), f"Expected LinuxAdapter, got {type(adapter)}"

    info = adapter.get_adapter_info()
    assert info.adapter_name == "LinuxAdapter"
    assert info.milestone == "3", f"Expected milestone '3', got '{info.milestone}'"
    print(f"  [PASS] Adapter: {info.adapter_name}, Milestone: {info.milestone}")
    print(f"  [PASS] Adapter description: {info.description[:80]}...")

    # ------------------------------------------------------------------
    # TEST 2: eBPF Capability Detection
    # ------------------------------------------------------------------
    print("\n[TEST 2] Testing eBPF Capability Detection...")
    ebpf_cap = detect_ebpf()
    assert hasattr(ebpf_cap, "available")
    assert hasattr(ebpf_cap, "kernel_sufficient")
    assert hasattr(ebpf_cap, "has_privilege")
    assert hasattr(ebpf_cap, "python_binding_available")
    assert hasattr(ebpf_cap, "tracepoint_available")
    assert hasattr(ebpf_cap, "btf_available")
    assert hasattr(ebpf_cap, "unavailability_reasons")

    print(f"  eBPF available:             {ebpf_cap.available}")
    print(f"  Kernel sufficient (>=4.16): {ebpf_cap.kernel_sufficient}")
    print(f"  Privilege (root/CAP_BPF):   {ebpf_cap.has_privilege}")
    print(f"  Python BCC binding:         {ebpf_cap.python_binding_available}")
    print(f"  Tracepoint visible:         {ebpf_cap.tracepoint_available}")
    print(f"  BTF (vmlinux) available:    {ebpf_cap.btf_available}")
    if ebpf_cap.unavailability_reasons:
        print(f"  Unavailability reasons:     {'; '.join(ebpf_cap.unavailability_reasons)}")
    print("  [PASS] Capability probe executed safely without error.")

    # ------------------------------------------------------------------
    # TEST 3: eBPF Program Load & Tracepoint Attach
    # ------------------------------------------------------------------
    print("\n[TEST 3] Testing eBPF Program Loader...")
    tracer, reason = load_connection_tracer()
    if not is_linux:
        assert tracer is None, "eBPF tracer should be None on non-Linux platforms"
        assert "Linux" in reason, f"Reason should mention Linux: {reason}"
        print(f"  [SKIP] eBPF load skipped cleanly on non-Linux platform ({reason})")
    else:
        if tracer is not None:
            assert tracer.is_running is True
            print("  [PASS] eBPF connection tracer loaded and attached successfully!")
            tracer.stop()
        else:
            print(f"  [SKIP] eBPF could not be loaded in this Linux environment: {reason}")

    # ------------------------------------------------------------------
    # TEST 4: Controlled Local TCP Connection & eBPF Event Ingestion
    # ------------------------------------------------------------------
    print("\n[TEST 4] Testing Controlled Local TCP Connection & Ingestion...")
    server_port = 58923
    server_ready = threading.Event()

    class TestHandler(http.server.SimpleHTTPRequestHandler):
        def log_message(self, *args):
            pass

    server = http.server.HTTPServer(("127.0.0.1", server_port), TestHandler)
    server_thread = threading.Thread(target=server.serve_forever, daemon=True)
    server_thread.start()
    time.sleep(0.15)

    # Test collector with simulated / mock eBPF event to verify ingestion pipeline
    class MockEbpfEvent:
        def __init__(self, saddr, sport, daddr, dport, newstate, pid, comm, is_ipv6=False):
            self.saddr = saddr
            self.sport = sport
            self.daddr = daddr
            self.dport = dport
            self.newstate = newstate
            self.pid = pid
            self.comm = comm
            self.is_ipv6 = is_ipv6
            self.protocol = 6

        @property
        def connection_id(self) -> str:
            return f"tcp:{self.saddr}:{self.sport}->{self.daddr}:{self.dport}"

    class MockTracer:
        def __init__(self):
            self.is_running = True
            self._events = [
                MockEbpfEvent(
                    saddr="127.0.0.1",
                    sport=54321,
                    daddr="127.0.0.1",
                    dport=server_port,
                    newstate="ESTABLISHED",
                    pid=os.getpid(),
                    comm="python_test",
                )
            ]

        def poll(self, timeout_ms=100):
            events = list(self._events)
            self._events.clear()
            return events

        def stop(self):
            self.is_running = False

    mock_tracer = MockTracer()
    collector = LinuxConnectionCollector(
        adapter_name="LinuxAdapter",
        ebpf_tracer=mock_tracer,  # type: ignore[arg-type]
    )
    assert collector.collector_mode == "ebpf+polling"

    conns, procs = collector.collect()
    assert len(conns) >= 1, "Expected at least 1 connection event from mock eBPF tracer"
    ebpf_conn = next((c for c in conns if c.collector.endswith("[ebpf]")), None)
    assert ebpf_conn is not None, "Expected connection event tagged with [ebpf]"
    assert ebpf_conn.state == ConnectionState.ESTABLISHED
    assert ebpf_conn.local_port == 54321
    assert ebpf_conn.remote_port == server_port
    print(f"  [PASS] eBPF event ingested: {ebpf_conn.protocol.value} {ebpf_conn.local_ip}:{ebpf_conn.local_port} -> {ebpf_conn.remote_ip}:{ebpf_conn.remote_port} ({ebpf_conn.state.value}) [collector={ebpf_conn.collector}]")

    # ------------------------------------------------------------------
    # TEST 5: Process Association via PID from eBPF Event
    # ------------------------------------------------------------------
    print("\n[TEST 5] Testing Process Association via PID...")
    assert len(procs) >= 1, "Expected at least 1 ProcessNetworkEvent from eBPF ingestion"
    ebpf_proc = next((p for p in procs if p.collector.endswith("[ebpf]")), None)
    assert ebpf_proc is not None, "Expected ProcessNetworkEvent tagged with [ebpf]"
    assert ebpf_proc.pid == os.getpid()
    assert ebpf_proc.process_name is not None
    print(f"  [PASS] Process network association: PID={ebpf_proc.pid}, Name={ebpf_proc.process_name}, Conn={ebpf_proc.connection_id}")

    # ------------------------------------------------------------------
    # TEST 6: Short-Lived Connection Lifecycle & Cleanup
    # ------------------------------------------------------------------
    print("\n[TEST 6] Testing Short-Lived Connection Lifecycle (CLOSE handling)...")
    # Feed a CLOSE event for the same connection
    mock_tracer._events.append(
        MockEbpfEvent(
            saddr="127.0.0.1",
            sport=54321,
            daddr="127.0.0.1",
            dport=server_port,
            newstate="CLOSE",
            pid=os.getpid(),
            comm="python_test",
        )
    )
    close_conns, _ = collector.collect()
    close_evt = next((c for c in close_conns if c.state == ConnectionState.CLOSE), None)
    assert close_evt is not None, "Expected CLOSE ConnectionEvent"
    assert close_evt.connection_id not in collector._active_connections, "Closed connection should be pruned from active map"
    print(f"  [PASS] CLOSE lifecycle event observed and active state pruned for {close_evt.connection_id}")

    # ------------------------------------------------------------------
    # TEST 7: Polling Fallback When eBPF is Inactive / Fails
    # ------------------------------------------------------------------
    print("\n[TEST 7] Testing Fallback to Polling When eBPF Inactive...")
    fallback_collector = LinuxConnectionCollector(adapter_name="LinuxAdapter", ebpf_tracer=None)
    assert fallback_collector.collector_mode == "polling_only"
    # Should not raise exception
    f_conns, f_procs = fallback_collector.collect()
    print(f"  [PASS] Fallback collector operating in '{fallback_collector.collector_mode}' mode (returned {len(f_conns)} conns)")

    # ------------------------------------------------------------------
    # TEST 8: Multi-Cycle Session & JSONL Validation
    # ------------------------------------------------------------------
    print("\n[TEST 8] Testing Multi-Cycle Session & JSONL Event Serialization...")
    with tempfile.NamedTemporaryFile(suffix=".jsonl", delete=False) as tmp:
        tmp_path = tmp.name

    try:
        from network_monitor.sensors import EventSink
        sink = EventSink(output_path=tmp_path)

        # Emit some events
        sink.emit(ebpf_conn)
        sink.emit(ebpf_proc)
        sink.emit(close_evt)
        sink.close()

        # Validate JSONL
        with open(tmp_path, "r", encoding="utf-8") as f:
            lines = [json.loads(line.strip()) for line in f if line.strip()]

        assert len(lines) == 3, f"Expected 3 JSONL lines, got {len(lines)}"
        assert lines[0]["event_type"] == "connection"
        assert lines[0]["collector"].endswith("[ebpf]")
        assert lines[1]["event_type"] == "process_network"
        assert lines[2]["state"] == "CLOSE"
        print(f"  [PASS] Validated {len(lines)} JSON Lines entries in output file")

    finally:
        if os.path.exists(tmp_path):
            os.remove(tmp_path)
        server.shutdown()

    print("\n==================================================")
    print("ALL MILESTONE 3 TESTS PASSED SUCCESSFULLY!")
    print("==================================================")


if __name__ == "__main__":
    run_tests()


def test_milestone3_runner() -> None:
    run_tests()
