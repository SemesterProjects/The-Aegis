"""
adapters/linux/connections.py
=============================
Linux Connection Collector for AEGIS Network Monitor.

Collects connection telemetry on Linux hosts via:
  - PRIMARY (Milestone 3): eBPF ``sock:inet_sock_set_state`` tracepoint events
    when a live ``EbpfConnectionTracer`` is provided.
  - SECONDARY: psutil snapshot diffing or /proc/net/{tcp,udp} parsing as the
    polling baseline (always active; catches UDP and long-lived connections).

Deduplication
-------------
When both eBPF and polling are active, they may observe the same TCP socket.
Deduplication prevents double-reporting:
  1. eBPF events are collected first each cycle and their ``connection_id`` keys
     are added to a per-cycle ``_ebpf_seen`` set.
  2. The polling pass checks ``_ebpf_seen`` and skips any connection already
     reported by eBPF this cycle.
  3. The set is cleared at the start of each ``collect()`` call.
  4. eBPF events have precedence — they carry kernel timestamps and PID/comm
     from the in-kernel context (higher accuracy than user-space lookup).

Collector Mode
--------------
  "ebpf+polling"  — eBPF tracer is active; polling covers UDP and fallback.
  "polling_only"  — No eBPF tracer; behaviour is identical to Milestone 2.

Limitations
-----------
- Polling-based baseline: Connections created and destroyed within polling
  intervals (< 1s) cannot be captured by polling alone.  eBPF fills this gap.
- Process attribution from eBPF comes from the in-kernel ``comm`` field
  (15-char truncated process name).  Full exe path and username still require
  the /proc/{pid} lookup on the Python side.
- UDP and ICMP are not traced by the sock:inet_sock_set_state tracepoint and
  are always handled by the polling collector.
"""

from __future__ import annotations

import os
import socket
import time
from typing import Any, Optional, TYPE_CHECKING

from network_monitor.core.events import (
    ConnectionDirection,
    ConnectionEvent,
    ConnectionState,
    ProcessNetworkEvent,
    Protocol,
)

if TYPE_CHECKING:
    from network_monitor.adapters.linux.ebpf.connection_tracer import EbpfConnectionTracer

try:
    import psutil
    _PSUTIL_AVAILABLE = True
except ImportError:
    psutil = None  # type: ignore[assignment]
    _PSUTIL_AVAILABLE = False


class LinuxConnectionCollector:
    """
    Continuous connection collector for Linux.

    Supports:
    - eBPF kernel-level TCP state tracing (Milestone 3, optional)
    - psutil snapshot diffing with /proc/net/ filesystem fallback (Milestone 2)

    When an ``EbpfConnectionTracer`` is provided, it is polled first each
    cycle; its events take precedence and are deduplicated against the polling
    pass.
    """

    COLLECTOR_NAME = "linux_connections"

    def __init__(
        self,
        adapter_name: str = "LinuxAdapter",
        ebpf_tracer: Optional["EbpfConnectionTracer"] = None,
    ) -> None:
        self.adapter_name = adapter_name
        self._ebpf_tracer = ebpf_tracer
        self._active_connections: dict[str, ConnectionEvent] = {}
        self._listening_ports: set[int] = set()
        self._process_cache: dict[int, dict[str, Any]] = {}
        self._cache_expiry: dict[int, float] = {}
        # Per-cycle set of connection_ids already reported by eBPF
        self._ebpf_seen: set[str] = set()

    @property
    def is_available(self) -> bool:
        return _PSUTIL_AVAILABLE or os.path.exists("/proc/net/tcp")

    @property
    def collector_mode(self) -> str:
        """Return the current collection mode identifier."""
        if self._ebpf_tracer is not None and self._ebpf_tracer.is_running:
            return "ebpf+polling"
        return "polling_only"

    def attach_tracer(self, tracer: "EbpfConnectionTracer") -> None:
        """
        Attach an eBPF tracer post-construction.

        Called by ``LinuxAdapter`` after the tracer is loaded to enable eBPF
        collection without requiring a new collector instance.
        """
        self._ebpf_tracer = tracer

    def collect(self) -> tuple[list[ConnectionEvent], list[ProcessNetworkEvent]]:
        """
        Collect connection events for one monitoring cycle.

        Returns
        -------
        (connection_events, process_events)
            ``connection_events`` — list of ``ConnectionEvent`` instances for
            this cycle (new, state-changed, and closed connections).
            ``process_events`` — list of ``ProcessNetworkEvent`` for new
            connections that have an associated PID.
        """
        connection_events: list[ConnectionEvent] = []
        process_events: list[ProcessNetworkEvent] = []

        # Clear per-cycle deduplication set
        self._ebpf_seen = set()

        # ------------------------------------------------------------------
        # Phase 1: eBPF events (kernel-level, highest fidelity)
        # ------------------------------------------------------------------
        if self._ebpf_tracer is not None and self._ebpf_tracer.is_running:
            ebpf_conns, ebpf_procs = self._collect_ebpf_events()
            connection_events.extend(ebpf_conns)
            process_events.extend(ebpf_procs)

        # ------------------------------------------------------------------
        # Phase 2: Polling-based collection (covers UDP + missed TCP)
        # ------------------------------------------------------------------
        if self.is_available:
            poll_conns, poll_procs = self._collect_polling_events()
            connection_events.extend(poll_conns)
            process_events.extend(poll_procs)

        return connection_events, process_events

    # ------------------------------------------------------------------
    # eBPF collection (Phase 1)
    # ------------------------------------------------------------------

    def _collect_ebpf_events(
        self,
    ) -> tuple[list[ConnectionEvent], list[ProcessNetworkEvent]]:
        """
        Poll the eBPF perf buffer and convert kernel events to normalized events.
        """
        connection_events: list[ConnectionEvent] = []
        process_events: list[ProcessNetworkEvent] = []

        assert self._ebpf_tracer is not None

        for kernel_evt in self._ebpf_tracer.poll(timeout_ms=100):
            state = ConnectionState.from_string(kernel_evt.newstate)
            proto = Protocol.TCP6 if kernel_evt.is_ipv6 else Protocol.TCP
            conn_key = kernel_evt.connection_id

            # Track in active connections map
            direction = self._determine_direction(
                kernel_evt.saddr,
                kernel_evt.sport,
                kernel_evt.daddr,
                kernel_evt.dport,
                state,
            )

            # Process info — comm from kernel, full info via /proc
            pid = kernel_evt.pid
            proc_info = self._get_process_info(pid) if pid > 0 else {}
            # Prefer /proc name if available; kernel comm is truncated at 15 chars
            process_name = proc_info.get("name") or (kernel_evt.comm or None)

            event = ConnectionEvent(
                adapter=self.adapter_name,
                collector=f"{self.COLLECTOR_NAME}[ebpf]",
                protocol=proto,
                direction=direction,
                local_ip=kernel_evt.saddr,
                local_port=kernel_evt.sport,
                remote_ip=kernel_evt.daddr,
                remote_port=kernel_evt.dport,
                state=state,
                pid=pid if pid > 0 else None,
                process_name=process_name,
                executable_path=proc_info.get("exe"),
                user=proc_info.get("user"),
                connection_id=conn_key,
            )

            prev = self._active_connections.get(conn_key)
            if prev is None or prev.state != state:
                self._active_connections[conn_key] = event
                connection_events.append(event)

                # Emit process event on first observe
                if prev is None and pid > 0:
                    proc_event = ProcessNetworkEvent(
                        adapter=self.adapter_name,
                        collector=f"{self.COLLECTOR_NAME}[ebpf]",
                        pid=pid,
                        process_name=process_name,
                        executable_path=proc_info.get("exe"),
                        user=proc_info.get("user"),
                        process_status=proc_info.get("status"),
                        connection_id=conn_key,
                        local_ip=kernel_evt.saddr,
                        local_port=kernel_evt.sport,
                        remote_ip=kernel_evt.daddr,
                        remote_port=kernel_evt.dport,
                        protocol=proto,
                    )
                    process_events.append(proc_event)

            # Remove from active map on CLOSE / TIME_WAIT / FIN_WAIT_2
            if state in (ConnectionState.CLOSE, ConnectionState.TIME_WAIT):
                self._active_connections.pop(conn_key, None)

            # Mark as seen by eBPF this cycle (suppresses polling duplicate)
            self._ebpf_seen.add(conn_key)

        return connection_events, process_events

    # ------------------------------------------------------------------
    # Polling collection (Phase 2)
    # ------------------------------------------------------------------

    def _collect_polling_events(
        self,
    ) -> tuple[list[ConnectionEvent], list[ProcessNetworkEvent]]:
        """
        Snapshot-based connection collection via psutil or /proc/net.

        Connections already reported by eBPF this cycle (tracked in
        ``self._ebpf_seen``) are skipped to avoid double-reporting.
        """
        raw_conns = self._get_raw_connections()
        if not raw_conns:
            return [], []

        connection_events: list[ConnectionEvent] = []
        process_events: list[ProcessNetworkEvent] = []

        # Discover listening ports
        current_listeners: set[int] = set()
        for c in raw_conns:
            if c.get("state") == ConnectionState.LISTEN and c.get("local_port"):
                current_listeners.add(c["local_port"])
        self._listening_ports = current_listeners

        current_seen_keys: set[str] = set()

        for c in raw_conns:
            proto = c["protocol"]
            l_ip = c.get("local_ip")
            l_port = c.get("local_port")
            r_ip = c.get("remote_ip")
            r_port = c.get("remote_port")
            state = c.get("state", ConnectionState.NONE)
            pid = c.get("pid")

            conn_key = (
                f"{proto.value}:{l_ip or '*'}:{l_port or '*'}"
                f"-{r_ip or '*'}:{r_port or '*'}"
            )
            current_seen_keys.add(conn_key)

            # Skip connections already emitted by eBPF this cycle
            if conn_key in self._ebpf_seen:
                continue

            direction = self._determine_direction(l_ip, l_port, r_ip, r_port, state)
            proc_info = self._get_process_info(pid) if pid else {}

            event = ConnectionEvent(
                adapter=self.adapter_name,
                collector=self.COLLECTOR_NAME,
                protocol=proto,
                direction=direction,
                local_ip=l_ip,
                local_port=l_port,
                remote_ip=r_ip,
                remote_port=r_port,
                state=state,
                pid=pid,
                process_name=proc_info.get("name"),
                executable_path=proc_info.get("exe"),
                user=proc_info.get("user"),
                connection_id=conn_key,
            )

            prev_event = self._active_connections.get(conn_key)
            if prev_event is None:
                self._active_connections[conn_key] = event
                connection_events.append(event)

                if pid is not None and pid > 0:
                    proc_event = ProcessNetworkEvent(
                        adapter=self.adapter_name,
                        collector=self.COLLECTOR_NAME,
                        pid=pid,
                        process_name=proc_info.get("name"),
                        executable_path=proc_info.get("exe"),
                        user=proc_info.get("user"),
                        process_status=proc_info.get("status"),
                        connection_id=conn_key,
                        local_ip=l_ip,
                        local_port=l_port,
                        remote_ip=r_ip,
                        remote_port=r_port,
                        protocol=proto,
                    )
                    process_events.append(proc_event)

            elif prev_event.state != state:
                self._active_connections[conn_key] = event
                connection_events.append(event)

        # Detect connections closed since last poll
        # Only consider connections NOT in ebpf_seen (eBPF handles its own closes)
        closed_keys = (
            set(self._active_connections.keys())
            - current_seen_keys
            - self._ebpf_seen
        )
        for key in closed_keys:
            closed = self._active_connections.pop(key)
            close_event = ConnectionEvent(
                adapter=self.adapter_name,
                collector=self.COLLECTOR_NAME,
                protocol=closed.protocol,
                direction=closed.direction,
                local_ip=closed.local_ip,
                local_port=closed.local_port,
                remote_ip=closed.remote_ip,
                remote_port=closed.remote_port,
                state=ConnectionState.CLOSE,
                pid=closed.pid,
                process_name=closed.process_name,
                executable_path=closed.executable_path,
                user=closed.user,
                connection_id=closed.connection_id,
            )
            connection_events.append(close_event)

        return connection_events, process_events

    # ------------------------------------------------------------------
    # Raw connection data sources
    # ------------------------------------------------------------------

    def _get_raw_connections(self) -> list[dict[str, Any]]:
        """Collect connections via psutil or /proc fallback."""
        if _PSUTIL_AVAILABLE:
            try:
                records: list[dict[str, Any]] = []
                for c in psutil.net_connections(kind="inet"):
                    proto = Protocol.TCP if c.type == socket.SOCK_STREAM else Protocol.UDP
                    records.append({
                        "protocol": proto,
                        "local_ip": c.laddr.ip if c.laddr else None,
                        "local_port": c.laddr.port if c.laddr else None,
                        "remote_ip": c.raddr.ip if c.raddr else None,
                        "remote_port": c.raddr.port if c.raddr else None,
                        "state": ConnectionState.from_string(c.status) if c.status else ConnectionState.NONE,
                        "pid": c.pid,
                    })
                return records
            except Exception:
                pass

        # Fallback to /proc/net/tcp
        return self._parse_proc_net()

    def _parse_proc_net(self) -> list[dict[str, Any]]:
        """Parse Linux /proc/net/tcp and /proc/net/udp."""
        results: list[dict[str, Any]] = []
        state_map = {
            "01": ConnectionState.ESTABLISHED,
            "02": ConnectionState.SYN_SENT,
            "03": ConnectionState.SYN_RECEIVED,
            "04": ConnectionState.FIN_WAIT_1,
            "05": ConnectionState.FIN_WAIT_2,
            "06": ConnectionState.TIME_WAIT,
            "07": ConnectionState.CLOSE,
            "08": ConnectionState.CLOSE_WAIT,
            "09": ConnectionState.LAST_ACK,
            "0A": ConnectionState.LISTEN,
            "0B": ConnectionState.CLOSING,
        }

        for path, proto in [("/proc/net/tcp", Protocol.TCP), ("/proc/net/udp", Protocol.UDP)]:
            if not os.path.exists(path):
                continue
            try:
                with open(path, "r") as f:
                    lines = f.readlines()
                for line in lines[1:]:
                    parts = line.strip().split()
                    if len(parts) < 10:
                        continue
                    l_hex, r_hex, st_hex = parts[1], parts[2], parts[3]
                    l_ip, l_port = self._decode_hex_endpoint(l_hex)
                    r_ip, r_port = self._decode_hex_endpoint(r_hex)
                    state = state_map.get(st_hex, ConnectionState.UNKNOWN)
                    results.append({
                        "protocol": proto,
                        "local_ip": l_ip,
                        "local_port": l_port,
                        "remote_ip": r_ip,
                        "remote_port": r_port,
                        "state": state,
                        "pid": None,
                    })
            except Exception:
                continue

        return results

    @staticmethod
    def _decode_hex_endpoint(endpoint_hex: str) -> tuple[Optional[str], Optional[int]]:
        try:
            ip_hex, port_hex = endpoint_hex.split(":")
            port = int(port_hex, 16)
            # IP in /proc is little-endian 32-bit hex
            ip_bytes = bytes.fromhex(ip_hex)[::-1]
            ip = socket.inet_ntoa(ip_bytes)
            return ip, port
        except Exception:
            return None, None

    def _determine_direction(
        self,
        local_ip: Optional[str],
        local_port: Optional[int],
        remote_ip: Optional[str],
        remote_port: Optional[int],
        state: ConnectionState,
    ) -> ConnectionDirection:
        if state == ConnectionState.LISTEN:
            return ConnectionDirection.INBOUND

        is_local_loopback = (local_ip in ("127.0.0.1", "::1", "localhost"))
        is_remote_loopback = (remote_ip in ("127.0.0.1", "::1", "localhost"))
        if is_local_loopback and is_remote_loopback:
            return ConnectionDirection.LOCAL

        if not remote_ip or not remote_port:
            return ConnectionDirection.UNKNOWN

        if local_port in self._listening_ports:
            return ConnectionDirection.INBOUND

        if local_port and local_port >= 1024 and remote_port < 1024:
            return ConnectionDirection.OUTBOUND

        if remote_port in (80, 443, 8080, 8443, 53, 22, 21, 25):
            return ConnectionDirection.OUTBOUND

        return ConnectionDirection.UNKNOWN

    def _get_process_info(self, pid: int) -> dict[str, Any]:
        if pid <= 0:
            return {}

        now = time.time()
        if pid in self._process_cache and now < self._cache_expiry.get(pid, 0):
            return self._process_cache[pid]

        if _PSUTIL_AVAILABLE:
            try:
                proc = psutil.Process(pid)
                name = proc.name()
                try:
                    exe = proc.exe()
                except Exception:
                    exe = None
                try:
                    user = proc.username()
                except Exception:
                    user = None
                try:
                    status = proc.status()
                except Exception:
                    status = None
                info = {"name": name, "exe": exe, "user": user, "status": status}
                self._process_cache[pid] = info
                self._cache_expiry[pid] = now + 60.0
                return info
            except Exception:
                return {}

        # Fallback reading /proc/{pid}/comm
        comm_path = f"/proc/{pid}/comm"
        if os.path.exists(comm_path):
            try:
                with open(comm_path, "r") as f:
                    name = f.read().strip()
                exe = None
                exe_link = f"/proc/{pid}/exe"
                if os.path.exists(exe_link):
                    try:
                        exe = os.readlink(exe_link)
                    except Exception:
                        pass
                info = {"name": name, "exe": exe, "user": None, "status": "running"}
                self._process_cache[pid] = info
                self._cache_expiry[pid] = now + 60.0
                return info
            except Exception:
                return {}

        return {}
