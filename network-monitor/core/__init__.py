"""
core/__init__.py
================
Public re-exports for the AEGIS Network Monitor core package.

Import from here to avoid coupling consumers to internal module paths.
"""

from network_monitor.core.adapter import (
    AdapterInfo,
    AdapterNotRunningError,
    CapabilityReport,
    CollectorNotImplementedError,
    NetworkAdapter,
)
from network_monitor.core.events import (
    CollectorInfo,
    CollectorStatus,
    ConnectionDirection,
    ConnectionEvent,
    ConnectionState,
    DnsEvent,
    EventType,
    ProcessNetworkEvent,
    Protocol,
    TrafficEvent,
)
from network_monitor.core.factory import AdapterFactory, UnsupportedOSError

__all__ = [
    # Adapter base
    "NetworkAdapter",
    "AdapterInfo",
    "CapabilityReport",
    "CollectorNotImplementedError",
    "AdapterNotRunningError",
    # Events
    "EventType",
    "ConnectionState",
    "ConnectionDirection",
    "Protocol",
    "ConnectionEvent",
    "TrafficEvent",
    "DnsEvent",
    "ProcessNetworkEvent",
    "CollectorStatus",
    "CollectorInfo",
    # Factory
    "AdapterFactory",
    "UnsupportedOSError",
]
