"""
core/events.py
==============
Normalized Network Monitor event structures.

These dataclasses represent the Network Monitor's internal telemetry language.
They are OS-independent and do NOT implement or integrate with the AEGIS
Universal Event Model (UEM) or Core. That integration is out of scope for
this module.

All timestamps are timezone-aware UTC datetimes.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Optional
import json


# ---------------------------------------------------------------------------
# Enumerations
# ---------------------------------------------------------------------------


class EventType(str, Enum):
    """Top-level category for each network event."""

    CONNECTION = "connection"
    TRAFFIC = "traffic"
    DNS = "dns"
    PROCESS_NETWORK = "process_network"


class ConnectionState(str, Enum):
    """Lifecycle state of a TCP/UDP connection as reported by the OS."""

    ESTABLISHED = "ESTABLISHED"
    SYN_SENT = "SYN_SENT"
    SYN_RECEIVED = "SYN_RECEIVED"
    FIN_WAIT_1 = "FIN_WAIT_1"
    FIN_WAIT_2 = "FIN_WAIT_2"
    TIME_WAIT = "TIME_WAIT"
    CLOSE = "CLOSE"
    CLOSE_WAIT = "CLOSE_WAIT"
    LAST_ACK = "LAST_ACK"
    LISTEN = "LISTEN"
    CLOSING = "CLOSING"
    NONE = "NONE"
    UNKNOWN = "UNKNOWN"

    @classmethod
    def from_string(cls, raw: str) -> "ConnectionState":
        """Parse a raw OS state string, falling back to UNKNOWN."""
        normalised = raw.upper().replace("-", "_").strip()
        return cls._value2member_map_.get(normalised, cls.UNKNOWN)  # type: ignore[return-value]


class ConnectionDirection(str, Enum):
    """Observed direction of the connection relative to the local host."""

    INBOUND = "inbound"
    OUTBOUND = "outbound"
    LOCAL = "local"       # both endpoints are local
    UNKNOWN = "unknown"


class Protocol(str, Enum):
    """Transport-layer protocol."""

    TCP = "tcp"
    UDP = "udp"
    TCP6 = "tcp6"
    UDP6 = "udp6"
    ICMP = "icmp"
    UNKNOWN = "unknown"

    @classmethod
    def from_string(cls, raw: str) -> "Protocol":
        normalised = raw.lower().strip()
        return cls._value2member_map_.get(normalised, cls.UNKNOWN)  # type: ignore[return-value]


# ---------------------------------------------------------------------------
# Helper
# ---------------------------------------------------------------------------


def _utcnow() -> datetime:
    """Return a timezone-aware UTC datetime for the current moment."""
    return datetime.now(timezone.utc)


def _new_event_id() -> str:
    """Return a unique event identifier."""
    return str(uuid.uuid4())


def _serialize_value(val: Any) -> Any:
    """Helper to convert dataclass field values to JSON-serializable types."""
    if isinstance(val, Enum):
        return val.value
    if isinstance(val, datetime):
        return val.isoformat()
    if isinstance(val, list):
        return [_serialize_value(item) for item in val]
    if isinstance(val, dict):
        return {k: _serialize_value(v) for k, v in val.items()}
    return val


class _BaseEvent:
    """Base mixin providing to_dict and to_json serialization for events."""

    def to_dict(self) -> dict[str, Any]:
        """Return a dictionary representation with Enums and datetimes serialized."""
        from dataclasses import fields
        result: dict[str, Any] = {}
        for f in fields(self):
            val = getattr(self, f.name)
            result[f.name] = _serialize_value(val)
        return result

    def to_json(self) -> str:
        """Return a compact JSON string representation."""
        return json.dumps(self.to_dict(), ensure_ascii=False)


# ---------------------------------------------------------------------------
# Event Dataclasses
# ---------------------------------------------------------------------------


@dataclass
class ConnectionEvent(_BaseEvent):
    """
    A single observed network connection.

    Represents a point-in-time snapshot of a connection's state.  The Network
    Monitor emits these continuously; consumers can correlate them over time
    using ``connection_id`` and ``process_id``.

    Fields marked Optional[...] may be ``None`` when the OS does not expose
    that information or when the required privilege level is absent.
    """

    # --- Identity & timing ---
    event_id: str = field(default_factory=_new_event_id)
    event_type: EventType = field(default=EventType.CONNECTION, init=False)
    timestamp: datetime = field(default_factory=_utcnow)

    # --- Source ---
    adapter: str = "unknown"          # adapter that produced this event
    collector: str = "unknown"        # specific collector within the adapter

    # --- Transport ---
    protocol: Protocol = Protocol.UNKNOWN
    direction: ConnectionDirection = ConnectionDirection.UNKNOWN

    # --- Addressing ---
    local_ip: Optional[str] = None
    local_port: Optional[int] = None
    remote_ip: Optional[str] = None
    remote_port: Optional[int] = None

    # --- State ---
    state: ConnectionState = ConnectionState.UNKNOWN

    # --- Process association (OS-permitting) ---
    pid: Optional[int] = None
    process_name: Optional[str] = None
    executable_path: Optional[str] = None
    user: Optional[str] = None

    # --- Correlation ---
    connection_id: Optional[str] = None   # stable ID across lifecycle events

    def __post_init__(self) -> None:
        # Ensure timestamp is always timezone-aware UTC.
        if self.timestamp.tzinfo is None:
            self.timestamp = self.timestamp.replace(tzinfo=timezone.utc)


@dataclass
class TrafficEvent(_BaseEvent):
    """
    Network interface traffic statistics at a point in time.

    These are counters collected from the OS network stack (e.g. via psutil
    or /proc/net/dev on Linux).  The values are cumulative since boot or
    since the interface was last reset, paired with interval deltas.
    """

    # --- Identity & timing ---
    event_id: str = field(default_factory=_new_event_id)
    event_type: EventType = field(default=EventType.TRAFFIC, init=False)
    timestamp: datetime = field(default_factory=_utcnow)

    # --- Source ---
    adapter: str = "unknown"
    collector: str = "unknown"

    # --- Interface ---
    interface: str = "unknown"

    # --- Cumulative counters ---
    bytes_sent: Optional[int] = None
    bytes_received: Optional[int] = None
    packets_sent: Optional[int] = None
    packets_received: Optional[int] = None
    errors_in: Optional[int] = None
    errors_out: Optional[int] = None
    drops_in: Optional[int] = None
    drops_out: Optional[int] = None

    # --- Interval deltas ---
    delta_bytes_sent: Optional[int] = None
    delta_bytes_received: Optional[int] = None
    delta_packets_sent: Optional[int] = None
    delta_packets_received: Optional[int] = None

    def __post_init__(self) -> None:
        if self.timestamp.tzinfo is None:
            self.timestamp = self.timestamp.replace(tzinfo=timezone.utc)


@dataclass
class DnsEvent(_BaseEvent):
    """
    An observed DNS transaction.

    Note: DNS activity is only observable when a supported mechanism is
    available (e.g. eBPF on Linux, or passive inspection of DNS port traffic
    where permitted).  When not available the collector will be absent and
    no events of this type will be emitted.
    """

    # --- Identity & timing ---
    event_id: str = field(default_factory=_new_event_id)
    event_type: EventType = field(default=EventType.DNS, init=False)
    timestamp: datetime = field(default_factory=_utcnow)

    # --- Source ---
    adapter: str = "unknown"
    collector: str = "unknown"

    # --- Network ---
    source_ip: Optional[str] = None
    destination_ip: Optional[str] = None
    protocol: Protocol = Protocol.UDP   # DNS over UDP by default

    # --- Query ---
    query_name: Optional[str] = None
    query_type: Optional[str] = None    # e.g. "A", "AAAA", "CNAME", "MX"
    query_id: Optional[int] = None
    is_response: Optional[bool] = None

    # --- Response (if observed) ---
    response_code: Optional[str] = None    # e.g. "NOERROR", "NXDOMAIN"
    response_addresses: Optional[list[str]] = field(default=None)

    # --- Process association (OS-permitting) ---
    pid: Optional[int] = None
    process_name: Optional[str] = None

    def __post_init__(self) -> None:
        if self.timestamp.tzinfo is None:
            self.timestamp = self.timestamp.replace(tzinfo=timezone.utc)
        if self.response_addresses is None:
            self.response_addresses = []


@dataclass
class ProcessNetworkEvent(_BaseEvent):
    """
    Associates a process with observed network activity.

    Emitted when the OS allows process-level attribution of network
    connections (requires sufficient privilege on most platforms).
    """

    # --- Identity & timing ---
    event_id: str = field(default_factory=_new_event_id)
    event_type: EventType = field(default=EventType.PROCESS_NETWORK, init=False)
    timestamp: datetime = field(default_factory=_utcnow)

    # --- Source ---
    adapter: str = "unknown"
    collector: str = "unknown"

    # --- Process ---
    pid: int = -1
    process_name: Optional[str] = None
    executable_path: Optional[str] = None
    user: Optional[str] = None
    process_status: Optional[str] = None

    # --- Associated connection reference ---
    connection_id: Optional[str] = None    # links to ConnectionEvent.connection_id
    local_ip: Optional[str] = None
    local_port: Optional[int] = None
    remote_ip: Optional[str] = None
    remote_port: Optional[int] = None
    protocol: Protocol = Protocol.UNKNOWN

    def __post_init__(self) -> None:
        if self.timestamp.tzinfo is None:
            self.timestamp = self.timestamp.replace(tzinfo=timezone.utc)


# ---------------------------------------------------------------------------
# Capability / Status types used by adapters
# ---------------------------------------------------------------------------


class CollectorStatus(str, Enum):
    """
    Lifecycle status of an individual collector within an adapter.

    Adapters report the status of each collector so consumers can reason
    about the completeness of the telemetry they receive.
    """

    AVAILABLE = "available"           # collector is running and producing data
    NOT_IMPLEMENTED = "not_implemented"  # placeholder; will be built in a future milestone
    UNAVAILABLE = "unavailable"       # capability detected as absent on this system
    PERMISSION_DENIED = "permission_denied"  # capability exists but lacks required privilege
    ERROR = "error"                   # collector attempted to start but encountered an error


@dataclass
class CollectorInfo:
    """Describes a single collector's identity and current status."""

    name: str
    status: CollectorStatus
    reason: Optional[str] = None      # human-readable explanation for non-AVAILABLE statuses
