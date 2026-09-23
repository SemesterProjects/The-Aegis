"""Aegis Core: safe, cross-platform monitoring primitives."""

from .correlation import CorrelationIndex
from .engine import MonitoringConfig, MonitoringEngine
from .models import Environment, Event, EventKind, Finding, Severity
from .normalizers import (
    normalize_auth_event,
    normalize_connection_event,
    normalize_dns_event,
    normalize_file_event,
    normalize_process_exit,
    normalize_process_network_event,
    normalize_process_snapshot,
    normalize_process_start,
    normalize_traffic_event,
)
from .storage import EvidenceStore
from .timeline import Timeline

__all__ = [
    # Models
    "Environment", "Event", "EventKind", "Finding", "Severity",
    # Engine
    "MonitoringConfig", "MonitoringEngine",
    # Storage
    "EvidenceStore",
    # Query layers
    "Timeline", "CorrelationIndex",
    # Normalization
    "normalize_connection_event", "normalize_traffic_event",
    "normalize_dns_event", "normalize_process_network_event",
    "normalize_process_start", "normalize_process_exit",
    "normalize_process_snapshot", "normalize_file_event",
    "normalize_auth_event",
]
