"""
sensors.py
==========
AEGIS Network Monitor - Main Entry Point (Milestone 2)

Continuous security-relevant network telemetry collection pipeline:

    System Discovery
           ↓
    Capability Discovery
           ↓
    Adapter Selection
           ↓
    Start Available Collectors
           ↓
    Continuous Network Telemetry Collection
           ↓
    Normalized Events (Console + network_events.jsonl)
"""

from __future__ import annotations

import argparse
import io
import os
import signal
import sys
import textwrap
import time
from datetime import datetime, timezone
from typing import Optional

# Ensure project root is in sys.path for direct python sensors.py execution
_this_dir = os.path.dirname(os.path.abspath(__file__))
_parent_dir = os.path.dirname(_this_dir)
for _p in (_this_dir, _parent_dir):
    if _p not in sys.path:
        sys.path.insert(0, _p)

# Windows console encoding safeguard
if sys.platform == "win32" and "PYTEST_CURRENT_TEST" not in os.environ:
    try:
        sys.stdout = io.TextIOWrapper(
            sys.stdout.buffer, encoding="utf-8", errors="replace"
        )
        sys.stderr = io.TextIOWrapper(
            sys.stderr.buffer, encoding="utf-8", errors="replace"
        )
    except AttributeError:
        pass


# ---------------------------------------------------------------------------
# Visual Formatting Helpers
# ---------------------------------------------------------------------------

_SEPARATOR = "=" * 64
_THIN_SEP  = "-" * 64


def _header(title: str) -> None:
    print(_SEPARATOR)
    print(f"  {title}")
    print(_SEPARATOR)


def _section(title: str) -> None:
    print()
    print(f"  {title}")
    print(_THIN_SEP)


def _row(label: str, value: object, width: int = 24) -> None:
    print(f"  {label:<{width}} {value}")


def _bool_badge(value: bool) -> str:
    return "AVAILABLE" if value else "UNAVAILABLE"


def _note(text: str, indent: int = 4) -> None:
    prefix = " " * indent + "• "
    wrapped = textwrap.wrap(text, width=72 - indent)
    for i, line in enumerate(wrapped):
        if i == 0:
            print(f"{prefix}{line}")
        else:
            print(f"{' ' * (indent + 2)}{line}")


def _format_bytes(num_bytes: int) -> str:
    if num_bytes < 1024:
        return f"{num_bytes} B"
    elif num_bytes < 1024 * 1024:
        return f"{num_bytes / 1024:.1f} KB"
    elif num_bytes < 1024 * 1024 * 1024:
        return f"{num_bytes / (1024 * 1024):.1f} MB"
    return f"{num_bytes / (1024 * 1024 * 1024):.2f} GB"


# ---------------------------------------------------------------------------
# Event Sink Pipeline
# ---------------------------------------------------------------------------

class EventSink:
    """
    Consumes normalized network events and writes them to console and JSONL.
    """

    def __init__(self, output_path: Optional[str] = "network_events.jsonl") -> None:
        self.output_path = output_path
        self._file = None
        self.event_counts: dict[str, int] = {
            "connection": 0,
            "traffic": 0,
            "dns": 0,
            "process_network": 0,
        }

        if self.output_path:
            # Open file in append mode with UTF-8 encoding
            self._file = open(self.output_path, "a", encoding="utf-8")

    def emit(self, event) -> None:
        """Process a single normalized event."""
        etype = event.event_type.value
        self.event_counts[etype] = self.event_counts.get(etype, 0) + 1

        # Write to JSON Lines output if enabled
        if self._file:
            self._file.write(event.to_json() + "\n")
            self._file.flush()

        # Render formatted console line
        self._render_console(event)

    def _render_console(self, event) -> None:
        ts = event.timestamp.strftime("%H:%M:%S")
        etype = event.event_type.value
        source_tag = "[eBPF]" if "[ebpf]" in getattr(event, "collector", "").lower() else "[POLL]"

        if etype == "connection":
            proto = event.protocol.value.upper()
            direction = event.direction.value.upper()
            state = event.state.value
            l_addr = f"{event.local_ip or '*'}:{event.local_port or '*'}"
            r_addr = f"{event.remote_ip or '*'}:{event.remote_port or '*'}"

            proc_str = ""
            if event.pid:
                name = event.process_name or "pid"
                proc_str = f" [{name}:{event.pid}]"

            arrow = "->" if direction == "OUTBOUND" else ("<-" if direction == "INBOUND" else "<->")
            print(f"  [{ts}] {source_tag} [CONN:{proto}] {direction:<8} {l_addr} {arrow} {r_addr} ({state}){proc_str}")

        elif etype == "traffic":
            iface = event.interface
            d_up = _format_bytes(event.delta_bytes_sent or 0)
            d_down = _format_bytes(event.delta_bytes_received or 0)
            tot_up = _format_bytes(event.bytes_sent or 0)
            tot_down = _format_bytes(event.bytes_received or 0)
            print(f"  [{ts}] [POLL]   [TRAFFIC] {iface:<20} ▲ +{d_up:<8} ▼ +{d_down:<8} (tot: {tot_up} / {tot_down})")

        elif etype == "dns":
            qname = event.query_name or "(unknown)"
            qtype = event.query_type or "A"
            kind = "RESP" if event.is_response else "QUERY"
            tx = f"ID:{event.query_id}" if event.query_id is not None else ""
            print(f"  [{ts}] [POLL]   [DNS]     {kind:<5} {qtype:<4} {qname:<30} {tx}")

        elif etype == "process_network":
            pname = event.process_name or "process"
            pid = event.pid
            status = event.process_status or "active"
            conn = event.connection_id or ""
            print(f"  [{ts}] {source_tag} [PROC]    PID {pid:<6} {pname:<20} ({status}) -> {conn}")

    def close(self) -> None:
        if self._file:
            try:
                self._file.close()
            except Exception:
                pass
            self._file = None


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main() -> int:
    parser = argparse.ArgumentParser(
        description="AEGIS Network Monitor - Continuous Network Telemetry Collection"
    )
    parser.add_argument(
        "--duration",
        type=float,
        default=None,
        help="Monitoring duration in seconds (default: run continuously until Ctrl+C)",
    )
    parser.add_argument(
        "--interval",
        type=float,
        default=1.0,
        help="Polling interval in seconds (default: 1.0)",
    )
    parser.add_argument(
        "--output",
        type=str,
        default="network_events.jsonl",
        help="Output JSON Lines file (default: network_events.jsonl)",
    )
    parser.add_argument(
        "--oneshot",
        action="store_true",
        help="Take a single poll snapshot and exit",
    )
    parser.add_argument(
        "--monitor",
        action="store_true",
        help="Run continuous network monitoring (Milestone 3 mode)",
    )
    args = parser.parse_args()

    now = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

    _header("AEGIS NETWORK MONITOR")
    print(f"  Milestone 3 — Continuous Network Telemetry Collection (eBPF + Polling)")
    print(f"  Timestamp: {now}")
    print()

    # ------------------------------------------------------------------
    # Step 1: System Discovery
    # ------------------------------------------------------------------
    _section("Step 1 — System Discovery")

    try:
        from network_monitor.discovery.system import SystemDiscovery
        discovery = SystemDiscovery()
        system_info = discovery.discover()
    except Exception as exc:
        print(f"  [FATAL] System discovery failed: {exc}", file=sys.stderr)
        return 1

    _row("Operating System",   system_info.os_name)
    _row("OS Version",         system_info.os_version)
    _row("OS Release",         system_info.os_release)
    _row("Architecture",       system_info.architecture)
    _row("Hostname",           system_info.hostname)
    _row("psutil available",   _bool_badge(system_info.psutil_available))

    priv = system_info.privilege
    if priv.is_admin is not None:
        _row("Admin (Windows)", _bool_badge(priv.is_admin))
    if priv.is_root is not None:
        _row("Root (Unix)", _bool_badge(priv.is_root))

    # ------------------------------------------------------------------
    # Step 2: Adapter Selection
    # ------------------------------------------------------------------
    _section("Step 2 — Adapter Selection")

    try:
        from network_monitor.core.factory import AdapterFactory
        adapter = AdapterFactory.create(system_info)
    except Exception as exc:
        print(f"  [FATAL] Adapter creation failed: {exc}", file=sys.stderr)
        return 1

    info = adapter.get_adapter_info()
    _row("Selected Adapter",  info.adapter_name)
    _row("Adapter Milestone", info.milestone)
    print()
    print("  Description:")
    _note(info.description)

    # ------------------------------------------------------------------
    # Step 3: Capability Discovery & Collector Status
    # ------------------------------------------------------------------
    _section("Step 3 — Capability Discovery & Collector Status")

    report = adapter.discover_capabilities()

    print(f"  Collectors registered in {report.adapter_name}:")
    print()
    for col in report.collectors:
        status_val = col.status.value.upper()
        # Display badge style
        badge = f"[{status_val}]"
        print(f"    {col.name:<28} {badge}")
        if col.reason:
            for line in textwrap.wrap(col.reason, width=64):
                print(f"      -> {line}")

    if "ebpf_loaded" in report.capabilities:
        print()
        if report.capabilities["ebpf_loaded"]:
            print("  eBPF Connection Tracer:  ACTIVE    (tracepoint: sock:inet_sock_set_state)")
        else:
            reason = getattr(adapter, "_ebpf_load_reason", "") or "Prerequisites not met"
            print(f"  eBPF Connection Tracer:  INACTIVE  Reason: {reason}, Fallback: polling")

    # ------------------------------------------------------------------
    # Step 4: Start Network Monitoring
    # ------------------------------------------------------------------
    _section("Step 4 — Continuous Network Monitoring")

    event_sink = EventSink(output_path=args.output)
    if args.output:
        print(f"  Writing JSON Lines events to: {os.path.abspath(args.output)}")
    print(f"  Polling interval: {args.interval}s")
    if args.duration:
        print(f"  Running for duration: {args.duration}s")
    else:
        print(f"  Press Ctrl+C to stop monitoring.")
    print(_THIN_SEP)

    # Start the adapter
    adapter.start()

    stop_requested = False

    def _sig_handler(sig, frame):
        nonlocal stop_requested
        stop_requested = True

    signal.signal(signal.SIGINT, _sig_handler)

    start_time = time.time()
    poll_count = 0

    try:
        while not stop_requested:
            poll_count += 1

            # 1. Connection Monitoring
            try:
                conns = adapter.collect_connections()
                for c in conns:
                    event_sink.emit(c)
            except Exception as exc:
                print(f"  [WARN] Connections poll error: {exc}", file=sys.stderr)

            # 2. Process Associations
            try:
                proc_events = adapter.collect_process_network_activity()
                for p in proc_events:
                    event_sink.emit(p)
            except Exception as exc:
                print(f"  [WARN] Process activity poll error: {exc}", file=sys.stderr)

            # 3. Traffic Monitoring
            try:
                traffic = adapter.collect_traffic()
                for t in traffic:
                    event_sink.emit(t)
            except Exception as exc:
                print(f"  [WARN] Traffic poll error: {exc}", file=sys.stderr)

            # 4. DNS Monitoring
            try:
                dns_events = adapter.collect_dns()
                for d in dns_events:
                    event_sink.emit(d)
            except Exception as exc:
                print(f"  [WARN] DNS poll error: {exc}", file=sys.stderr)

            if args.oneshot:
                break

            if args.duration is not None and (time.time() - start_time) >= args.duration:
                break

            time.sleep(args.interval)

    except KeyboardInterrupt:
        pass
    finally:
        adapter.stop()
        event_sink.close()

    elapsed = round(time.time() - start_time, 2)

    # ------------------------------------------------------------------
    # Summary
    # ------------------------------------------------------------------
    print()
    print(_SEPARATOR)
    print("  MONITORING SESSION SUMMARY")
    print(_SEPARATOR)
    _row("Elapsed Time", f"{elapsed}s")
    _row("Poll Cycles", poll_count)
    _row("Connection Events", event_sink.event_counts.get("connection", 0))
    _row("Traffic Events", event_sink.event_counts.get("traffic", 0))
    _row("DNS Events", event_sink.event_counts.get("dns", 0))
    _row("Process Net Events", event_sink.event_counts.get("process_network", 0))
    tot_events = sum(event_sink.event_counts.values())
    _row("Total Events Emitted", tot_events)
    if args.output:
        _row("Saved Event Stream", os.path.abspath(args.output))
    print(_SEPARATOR)

    return 0


if __name__ == "__main__":
    sys.exit(main())
