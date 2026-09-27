"""Aegis Core: safe, cross-platform monitoring primitives."""

from .engine import MonitoringEngine
from .models import Environment, Event, EventKind, Severity
from .network import NetworkBridge, NetworkCollector
from .analysis import (
    analyze_event,
    Correlator,
    format_analysis,
    format_analyses,
    EventAnalysis,
    ChangeDescription,
    EvidenceRef,
)

__all__ = [
    "ChangeDescription",
    "Correlator",
    "Environment",
    "Event",
    "EventAnalysis",
    "EventKind",
    "EvidenceRef",
    "MonitoringEngine",
    "NetworkBridge",
    "NetworkCollector",
    "Severity",
    "analyze_event",
    "format_analysis",
    "format_analyses",
]
