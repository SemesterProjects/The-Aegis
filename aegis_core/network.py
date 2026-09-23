"""Network to Core bridge and NetworkCollector for AEGIS Monitoring Engine.

Translates OS-independent network telemetry events (ConnectionEvent,
TrafficEvent, DnsEvent, ProcessNetworkEvent) into the canonical Event model,
preserving provenance, timestamps, process metadata, and network attributes.
"""
from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Iterable, Optional, TYPE_CHECKING

from .models import Event, EventKind

if TYPE_CHECKING:
    from network_monitor.core.adapter import NetworkAdapter
    from network_monitor.core.events import (
        ConnectionEvent,
        DnsEvent,
        ProcessNetworkEvent,
        TrafficEvent,
    )


def _ensure_utc(dt: datetime) -> datetime:
    if dt.tzinfo is None:
        return dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc)


def _get_enum_val(val: Any) -> Any:
    if hasattr(val, "value"):
        return val.value
    return val


def _resolve_connection_action(state_val: str) -> str:
    """Map ConnectionState to canonical action understood by detectors like NetworkRateDetector."""
    state_upper = state_val.upper()
    if state_upper in {"ESTABLISHED", "SYN_SENT", "SYN_RECEIVED"}:
        return "connection_open"
    elif state_upper in {"CLOSE", "TIME_WAIT", "FIN_WAIT_1", "FIN_WAIT_2", "CLOSE_WAIT", "LAST_ACK", "CLOSING"}:
        return "connection_close"
    elif state_upper == "LISTEN":
        return "listen"
    return "connection_snapshot"


class NetworkBridge:
    """Translates raw network_monitor events into canonical aegis_core.models.Event instances."""

    @staticmethod
    def connection_event_to_canonical(event: "ConnectionEvent", host_id: str = "unknown") -> Event:
        state_str = str(_get_enum_val(event.state) or "UNKNOWN")
        action = _resolve_connection_action(state_str)
        source = f"network_monitor.{event.adapter}.{event.collector}" if event.adapter != "unknown" else "network_monitor.connections"

        data: dict[str, Any] = {
            "action": action,
            "protocol": _get_enum_val(event.protocol),
            "direction": _get_enum_val(event.direction),
            "state": state_str,
            "local_ip": event.local_ip,
            "local_port": event.local_port,
            "remote_ip": event.remote_ip,
            "remote_port": event.remote_port,
            "pid": event.pid,
            "process": event.process_name or event.executable_path,
            "process_name": event.process_name,
            "executable_path": event.executable_path,
            "user": event.user,
            "connection_id": event.connection_id,
            "adapter": event.adapter,
            "collector": event.collector,
        }

        return Event(
            kind=EventKind.NETWORK,
            source=source,
            data=data,
            observed_at=_ensure_utc(event.timestamp),
            event_id=event.event_id,
            host_id=host_id,
        )

    @staticmethod
    def traffic_event_to_canonical(event: "TrafficEvent", host_id: str = "unknown") -> Event:
        source = f"network_monitor.{event.adapter}.{event.collector}" if event.adapter != "unknown" else "network_monitor.traffic"

        data: dict[str, Any] = {
            "action": "traffic_update",
            "interface": event.interface,
            "bytes_sent": event.bytes_sent,
            "bytes_received": event.bytes_received,
            "packets_sent": event.packets_sent,
            "packets_received": event.packets_received,
            "errors_in": event.errors_in,
            "errors_out": event.errors_out,
            "drops_in": event.drops_in,
            "drops_out": event.drops_out,
            "delta_bytes_sent": event.delta_bytes_sent,
            "delta_bytes_received": event.delta_bytes_received,
            "delta_packets_sent": event.delta_packets_sent,
            "delta_packets_received": event.delta_packets_received,
            "adapter": event.adapter,
            "collector": event.collector,
        }

        return Event(
            kind=EventKind.NETWORK,
            source=source,
            data=data,
            observed_at=_ensure_utc(event.timestamp),
            event_id=event.event_id,
            host_id=host_id,
        )

    @staticmethod
    def dns_event_to_canonical(event: "DnsEvent", host_id: str = "unknown") -> Event:
        action = "dns_response" if event.is_response else "dns_query"
        source = f"network_monitor.{event.adapter}.{event.collector}" if event.adapter != "unknown" else "network_monitor.dns"

        data: dict[str, Any] = {
            "action": action,
            "source_ip": event.source_ip,
            "destination_ip": event.destination_ip,
            "protocol": _get_enum_val(event.protocol),
            "query_name": event.query_name,
            "query_type": event.query_type,
            "query_id": event.query_id,
            "is_response": event.is_response,
            "response_code": event.response_code,
            "response_addresses": list(event.response_addresses or []),
            "pid": event.pid,
            "process": event.process_name,
            "process_name": event.process_name,
            "adapter": event.adapter,
            "collector": event.collector,
        }

        return Event(
            kind=EventKind.NETWORK,
            source=source,
            data=data,
            observed_at=_ensure_utc(event.timestamp),
            event_id=event.event_id,
            host_id=host_id,
        )

    @staticmethod
    def process_network_event_to_canonical(event: "ProcessNetworkEvent", host_id: str = "unknown") -> Event:
        source = f"network_monitor.{event.adapter}.{event.collector}" if event.adapter != "unknown" else "network_monitor.process_network"

        data: dict[str, Any] = {
            "action": "process_network_association",
            "pid": event.pid,
            "process": event.process_name or event.executable_path,
            "process_name": event.process_name,
            "executable_path": event.executable_path,
            "user": event.user,
            "process_status": event.process_status,
            "connection_id": event.connection_id,
            "local_ip": event.local_ip,
            "local_port": event.local_port,
            "remote_ip": event.remote_ip,
            "remote_port": event.remote_port,
            "protocol": _get_enum_val(event.protocol),
            "adapter": event.adapter,
            "collector": event.collector,
        }

        return Event(
            kind=EventKind.NETWORK,
            source=source,
            data=data,
            observed_at=_ensure_utc(event.timestamp),
            event_id=event.event_id,
            host_id=host_id,
        )

    @classmethod
    def to_canonical(cls, raw_event: Any, host_id: str = "unknown") -> Event:
        """Route any supported network_monitor event to its canonical converter."""
        # Use class name checking to avoid hard dependency on specific subclasses if mocked
        type_name = type(raw_event).__name__
        if type_name == "ConnectionEvent":
            return cls.connection_event_to_canonical(raw_event, host_id=host_id)
        elif type_name == "TrafficEvent":
            return cls.traffic_event_to_canonical(raw_event, host_id=host_id)
        elif type_name == "DnsEvent":
            return cls.dns_event_to_canonical(raw_event, host_id=host_id)
        elif type_name == "ProcessNetworkEvent":
            return cls.process_network_event_to_canonical(raw_event, host_id=host_id)
        else:
            raise TypeError(f"Unsupported network event type for conversion: {type_name}")


@dataclass
class NetworkCollector:
    """Aegis collector that polls the OS NetworkAdapter and emits canonical network Events.

    Satisfies the aegis_core.collectors.Collector protocol.
    """
    name: str = "network_monitor"
    adapter: Optional["NetworkAdapter"] = None

    def __post_init__(self) -> None:
        if self.adapter is None:
            self._init_adapter()

    def _init_adapter(self) -> None:
        from network_monitor.discovery.system import SystemDiscovery
        from network_monitor.core.factory import AdapterFactory
        sys_info = SystemDiscovery().discover()
        self.adapter = AdapterFactory.create(sys_info)

    def collect(self, host_id: str) -> Iterable[Event]:
        """Collect network events across all active sub-collectors in the adapter."""
        if self.adapter is None:
            self._init_adapter()

        assert self.adapter is not None

        if not self.adapter.is_running:
            self.adapter.start()

        from network_monitor.core.adapter import CollectorNotImplementedError

        # 1. Connection Monitoring
        try:
            conns = self.adapter.collect_connections()
            for c in conns:
                yield NetworkBridge.connection_event_to_canonical(c, host_id=host_id)
        except CollectorNotImplementedError:
            pass

        # 2. Process Associations
        try:
            proc_events = self.adapter.collect_process_network_activity()
            for p in proc_events:
                yield NetworkBridge.process_network_event_to_canonical(p, host_id=host_id)
        except CollectorNotImplementedError:
            pass

        # 3. Traffic Monitoring
        try:
            traffic_events = self.adapter.collect_traffic()
            for t in traffic_events:
                yield NetworkBridge.traffic_event_to_canonical(t, host_id=host_id)
        except CollectorNotImplementedError:
            pass

        # 4. DNS Monitoring
        try:
            dns_events = self.adapter.collect_dns()
            for d in dns_events:
                yield NetworkBridge.dns_event_to_canonical(d, host_id=host_id)
        except CollectorNotImplementedError:
            pass

    def stop(self) -> None:
        if self.adapter is not None and self.adapter.is_running:
            self.adapter.stop()
