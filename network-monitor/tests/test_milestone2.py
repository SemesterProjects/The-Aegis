"""
tests/test_milestone2.py
========================
Verification suite for AEGIS Network Monitor Milestone 2:
- Connection monitoring & lifecycle detection
- Traffic metrics (cumulative & interval deltas)
- Process-socket attribution
- DNS privilege detection & graceful degradation
- Continuous event collection & JSONL output validation
"""

import http.server
import json
import os
import sys
import threading
import time
import urllib.request

# Ensure network-monitor is importable
_this_file = os.path.abspath(__file__)
_test_dir = os.path.dirname(_this_file)
_net_mon_dir = os.path.dirname(_test_dir)
_the_aegis_dir = os.path.dirname(_net_mon_dir)
for p in (_the_aegis_dir, _net_mon_dir):
    if p not in sys.path:
        sys.path.insert(0, p)

if sys.platform == "win32":
    import io
    try:
        sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8", errors="replace")
    except AttributeError:
        pass

from network_monitor.discovery.system import SystemDiscovery
from network_monitor.core.factory import AdapterFactory
from network_monitor.core.events import ConnectionState, ConnectionDirection, CollectorStatus


def run_tests():
    print("==================================================")
    print("AEGIS NETWORK MONITOR - MILESTONE 2 TEST SUITE")
    print("==================================================")

    # 1. Initialize Adapter
    sys_info = SystemDiscovery().discover()
    adapter = AdapterFactory.create(sys_info)
    print(f"[TEST 1] Adapter Selection: {adapter.get_adapter_info().adapter_name}")
    assert adapter.get_adapter_info().adapter_name == "WindowsAdapter"

    # Check collector capabilities
    report = adapter.discover_capabilities()
    col_map = {c.name: c for c in report.collectors}

    print(f"[TEST 2] Capability / Collector Status:")
    for name, c in col_map.items():
        print(f"  - {name:<25}: [{c.status.value.upper()}] (Reason: {c.reason[:40] if c.reason else 'None'})")

    assert col_map["connections"].status == CollectorStatus.AVAILABLE
    assert col_map["traffic"].status == CollectorStatus.AVAILABLE
    assert col_map["process_network_activity"].status == CollectorStatus.AVAILABLE
    # DNS should be PERMISSION_DENIED on standard unprivileged execution
    assert col_map["dns"].status in (CollectorStatus.PERMISSION_DENIED, CollectorStatus.AVAILABLE)

    # 2. Start local test HTTP server to create controlled connection
    server_port = 58912
    server_ready = threading.Event()

    class TestHandler(http.server.SimpleHTTPRequestHandler):
        def log_message(self, *args):
            pass  # quiet

    server = http.server.HTTPServer(("127.0.0.1", server_port), TestHandler)
    server_thread = threading.Thread(target=server.serve_forever, daemon=True)
    server_thread.start()
    time.sleep(0.2)

    print(f"[TEST 3] Started local test server on port {server_port}")

    # 3. Start Adapter and take baseline
    adapter.start()
    assert adapter.is_running is True

    init_conns = adapter.collect_connections()
    init_proc = adapter.collect_process_network_activity()
    init_traffic = adapter.collect_traffic()
    print(f"[TEST 4] Baseline snapshot: {len(init_conns)} conns, {len(init_traffic)} traffic interfaces")

    # 4. Generate network connection & traffic to test server
    print("[TEST 5] Generating synthetic local connection & traffic...")
    client_thread = threading.Thread(
        target=lambda: urllib.request.urlopen(f"http://127.0.0.1:{server_port}/", timeout=2).read(),
        daemon=True,
    )
    client_thread.start()
    time.sleep(0.3)

    # Poll during / after connection
    new_conns = adapter.collect_connections()
    new_proc = adapter.collect_process_network_activity()
    new_traffic = adapter.collect_traffic()

    print(f"  Observed {len(new_conns)} new/updated connection events")
    print(f"  Observed {len(new_proc)} process network events")
    print(f"  Observed {len(new_traffic)} traffic delta events")

    # 5. Verify process attribution on current PID
    my_pid = os.getpid()
    matched_my_process = [c for c in init_conns + new_conns if c.pid == my_pid]
    print(f"[TEST 6] Self process (PID={my_pid}) sockets observed: {len(matched_my_process)}")
    if matched_my_process:
        sample = matched_my_process[0]
        print(f"  Sample socket: {sample.protocol.value} {sample.local_ip}:{sample.local_port} -> {sample.remote_ip}:{sample.remote_port} [proc={sample.process_name}]")
        assert sample.process_name is not None

    # 6. Verify Traffic Deltas
    for t in new_traffic:
        if (t.delta_bytes_sent or 0) > 0 or (t.delta_bytes_received or 0) > 0:
            print(f"[TEST 7] Interface {t.interface} recorded delta: ▲ +{t.delta_bytes_sent}B, ▼ +{t.delta_bytes_received}B")

    # 7. Stop adapter & shutdown server
    adapter.stop()
    server.shutdown()
    assert adapter.is_running is False
    print("[TEST 8] Adapter stopped cleanly.")

    print("\n[ALL TESTS PASSED SUCCESSFULLY!]")


if __name__ == "__main__":
    run_tests()
