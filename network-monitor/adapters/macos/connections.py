"""
adapters/macos/connections.py
=============================
macOS Connection Collector for AEGIS Network Monitor.

Collects network socket connections on macOS via psutil, associates sockets with
processes, infers connection direction, and tracks connection lifecycle via snapshot diffing.

Limitations:
------------
- Baseline polling: Connections established and closed between polling intervals will not be observed.
- Network Extension: Apple Network Extension requires native app entitlements and cannot be
  instantiated from ordinary Python processes.
"""

from __future__ import annotations

import socket
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


class MacOSConnectionCollector:
    """
    Continuous connection collector for macOS.
    """

    COLLECTOR_NAME = "macos_connections"

    def __init__(self, adapter_name: str = "MacOSAdapter") -> None:
        self.adapter_name = adapter_name
        self._active_connections: dict[str, ConnectionEvent] = {}
        self._listening_ports: set[int] = set()
        self._process_cache: dict[int, dict[str, Any]] = {}
        self._cache_expiry: dict[int, float] = {}

    @property
    def is_available(self) -> bool:
        return _PSUTIL_AVAILABLE

    def collect(self) -> tuple[list[ConnectionEvent], list[ProcessNetworkEvent]]:
        if not _PSUTIL_AVAILABLE:
            return [], []

        connection_events: list[ConnectionEvent] = []
        process_events: list[ProcessNetworkEvent] = []

        try:
            raw_conns = psutil.net_connections(kind="inet")
        except Exception:
            return [], []

        # Find listening ports
        current_listeners: set[int] = set()
        for c in raw_conns:
            if c.status == "LISTEN" and c.laddr:
                current_listeners.add(c.laddr.port)
        self._listening_ports = current_listeners

        current_seen_keys: set[str] = set()

        for c in raw_conns:
            proto = Protocol.TCP if c.type == socket.SOCK_STREAM else Protocol.UDP
            l_ip = c.laddr.ip if c.laddr else None
            l_port = c.laddr.port if c.laddr else None
            r_ip = c.raddr.ip if c.raddr else None
            r_port = c.raddr.port if c.raddr else None
            state = ConnectionState.from_string(c.status) if c.status else ConnectionState.NONE
            pid = c.pid

            conn_key = f"{proto.value}:{l_ip or '*'}:{l_port or '*'}-{r_ip or '*'}:{r_port or '*'}"
            current_seen_keys.add(conn_key)

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

        closed_keys = set(self._active_connections.keys()) - current_seen_keys
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
        if pid <= 0 or not _PSUTIL_AVAILABLE:
            return {}

        now = time.time()
        if pid in self._process_cache and now < self._cache_expiry.get(pid, 0):
            return self._process_cache[pid]

        try:
            proc = psutil.Process(pid)
            info = {
                "name": proc.name(),
                "exe": proc.exe() if hasattr(proc, "exe") else None,
                "user": proc.username() if hasattr(proc, "username") else None,
                "status": proc.status() if hasattr(proc, "status") else None,
            }
            self._process_cache[pid] = info
            self._cache_expiry[pid] = now + 60.0
            return info
        except Exception:
            return {}
