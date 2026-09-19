"""
adapters/windows/connections.py
===============================
Windows Connection Collector for AEGIS Network Monitor.

Collects network connection telemetry via psutil and IP Helper APIs, associates
sockets with running processes, determines connection direction, and tracks
connection lifecycle (new connections, state transitions, closed connections)
via snapshot diffing.

Limitations:
------------
- Polling baseline: Connections that are initiated and terminated entirely between
  polling intervals (e.g. short-lived ephemeral HTTP/DNS sockets) cannot be observed.
- Process attribution: Certain system-owned sockets or protected processes may deny
  access (psutil.AccessDenied); in such cases, process details remain null.
"""

from __future__ import annotations

import time
from typing import Any, Optional

from network_monitor.core.events import (
    ConnectionDirection,
    ConnectionEvent,
    ConnectionState,
    ProcessNetworkEvent,
    Protocol,
)

try:
    import psutil
    _PSUTIL_AVAILABLE = True
except ImportError:
    psutil = None  # type: ignore[assignment]
    _PSUTIL_AVAILABLE = False


class WindowsConnectionCollector:
    """
    Continuous connection collector for Windows.

    Uses snapshot comparison to detect newly established connections, state
    transitions, and closed/terminated connections.
    """

    COLLECTOR_NAME = "windows_connections"

    def __init__(self, adapter_name: str = "WindowsAdapter") -> None:
        self.adapter_name = adapter_name
        self._active_connections: dict[str, ConnectionEvent] = {}
        self._listening_ports: set[int] = set()
        self._process_cache: dict[int, dict[str, Any]] = {}
        self._cache_expiry: dict[int, float] = {}
        self._first_snapshot = True

    @property
    def is_available(self) -> bool:
        return _PSUTIL_AVAILABLE

    def collect(self) -> tuple[list[ConnectionEvent], list[ProcessNetworkEvent]]:
        """
        Perform a connection snapshot poll and return newly generated events.

        Returns:
            Tuple of (connection_events, process_network_events)
        """
        if not _PSUTIL_AVAILABLE:
            return [], []

        connection_events: list[ConnectionEvent] = []
        process_events: list[ProcessNetworkEvent] = []

        try:
            raw_conns = psutil.net_connections(kind="inet")
        except (psutil.AccessDenied, PermissionError, OSError):
            return [], []

        # Step 1: Discover all current listening ports on this host
        current_listeners: set[int] = set()
        for c in raw_conns:
            if c.status == "LISTEN" and c.laddr:
                current_listeners.add(c.laddr.port)
        self._listening_ports = current_listeners

        # Step 2: Process current connections
        current_seen_keys: set[str] = set()

        for c in raw_conns:
            proto = self._map_protocol(c.type)
            l_ip = c.laddr.ip if c.laddr else None
            l_port = c.laddr.port if c.laddr else None
            r_ip = c.raddr.ip if c.raddr else None
            r_port = c.raddr.port if c.raddr else None
            state = ConnectionState.from_string(c.status) if c.status else ConnectionState.NONE

            conn_key = self._generate_connection_id(proto, l_ip, l_port, r_ip, r_port)
            current_seen_keys.add(conn_key)

            # Determine direction
            direction = self._determine_direction(l_ip, l_port, r_ip, r_port, state)

            # Retrieve process metadata
            proc_info = self._get_process_info(c.pid) if c.pid is not None else {}

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
                pid=c.pid,
                process_name=proc_info.get("name"),
                executable_path=proc_info.get("exe"),
                user=proc_info.get("user"),
                connection_id=conn_key,
            )

            # Check for lifecycle events
            prev_event = self._active_connections.get(conn_key)

            if prev_event is None:
                # Brand new connection observed
                self._active_connections[conn_key] = event
                connection_events.append(event)

                # Emit dedicated process network event if associated with a process
                if c.pid is not None and c.pid > 0:
                    proc_event = ProcessNetworkEvent(
                        adapter=self.adapter_name,
                        collector=self.COLLECTOR_NAME,
                        pid=c.pid,
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
                # Connection state transition (e.g. SYN_SENT -> ESTABLISHED)
                self._active_connections[conn_key] = event
                connection_events.append(event)

        # Step 3: Detect closed connections (present previously but missing in current tick)
        closed_keys = set(self._active_connections.keys()) - current_seen_keys
        for key in closed_keys:
            closed_conn = self._active_connections.pop(key)
            # Emit closed lifecycle event
            close_event = ConnectionEvent(
                adapter=self.adapter_name,
                collector=self.COLLECTOR_NAME,
                protocol=closed_conn.protocol,
                direction=closed_conn.direction,
                local_ip=closed_conn.local_ip,
                local_port=closed_conn.local_port,
                remote_ip=closed_conn.remote_ip,
                remote_port=closed_conn.remote_port,
                state=ConnectionState.CLOSE,
                pid=closed_conn.pid,
                process_name=closed_conn.process_name,
                executable_path=closed_conn.executable_path,
                user=closed_conn.user,
                connection_id=closed_conn.connection_id,
            )
            connection_events.append(close_event)

        self._first_snapshot = False
        return connection_events, process_events

    # ------------------------------------------------------------------
    # Helper methods
    # ------------------------------------------------------------------

    @staticmethod
    def _generate_connection_id(
        proto: Protocol,
        l_ip: Optional[str],
        l_port: Optional[int],
        r_ip: Optional[str],
        r_port: Optional[int],
    ) -> str:
        return f"{proto.value}:{l_ip or '*'}:{l_port or '*'}-{r_ip or '*'}:{r_port or '*'}"

    @staticmethod
    def _map_protocol(socket_type: Any) -> Protocol:
        import socket
        if socket_type == socket.SOCK_STREAM:
            return Protocol.TCP
        elif socket_type == socket.SOCK_DGRAM:
            return Protocol.UDP
        return Protocol.UNKNOWN

    def _determine_direction(
        self,
        local_ip: Optional[str],
        local_port: Optional[int],
        remote_ip: Optional[str],
        remote_port: Optional[int],
        state: ConnectionState,
    ) -> ConnectionDirection:
        """
        Deduce connection direction based on socket endpoints and listening status.
        Never guess if indeterminate.
        """
        if state == ConnectionState.LISTEN:
            return ConnectionDirection.INBOUND

        # Loopback check
        is_local_loopback = (local_ip in ("127.0.0.1", "::1", "localhost"))
        is_remote_loopback = (remote_ip in ("127.0.0.1", "::1", "localhost"))

        if is_local_loopback and is_remote_loopback:
            return ConnectionDirection.LOCAL

        if not remote_ip or not remote_port:
            return ConnectionDirection.UNKNOWN

        # If local port matches an established local listening server port
        if local_port in self._listening_ports:
            return ConnectionDirection.INBOUND

        # If local port is an ephemeral client port (> 1024 or Windows dynamic range 49152+)
        # and remote port is a well-known server port (< 1024 or known service ports)
        if local_port and local_port >= 1024 and remote_port < 1024:
            return ConnectionDirection.OUTBOUND

        if remote_port in (80, 443, 8080, 8443, 53, 22, 21, 25, 123):
            return ConnectionDirection.OUTBOUND

        return ConnectionDirection.UNKNOWN

    def _get_process_info(self, pid: int) -> dict[str, Any]:
        """
        Safely look up process metadata with caching.
        Handles AccessDenied, NoSuchProcess, and PID 4 (System) gracefully.
        """
        if pid <= 0:
            return {}

        now = time.time()
        if pid in self._process_cache and now < self._cache_expiry.get(pid, 0):
            return self._process_cache[pid]

        if pid == 4:
            info = {"name": "System", "exe": None, "user": "SYSTEM", "status": "running"}
            self._process_cache[pid] = info
            self._cache_expiry[pid] = now + 300.0
            return info

        try:
            proc = psutil.Process(pid)
            name = proc.name()
            try:
                exe = proc.exe()
            except (psutil.AccessDenied, PermissionError):
                exe = None
            try:
                user = proc.username()
            except (psutil.AccessDenied, PermissionError):
                user = None
            try:
                status = proc.status()
            except (psutil.AccessDenied, PermissionError):
                status = None

            info = {
                "name": name,
                "exe": exe,
                "user": user,
                "status": status,
            }
            self._process_cache[pid] = info
            self._cache_expiry[pid] = now + 60.0  # cache 60 seconds
            return info
        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess, PermissionError):
            return {}
