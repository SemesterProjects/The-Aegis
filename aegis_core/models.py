"""Canonical, serialisable telemetry and finding models.

OS adapters may add attributes, but the Core never accepts unvalidated raw
objects.  This prevents platform-specific data from leaking into detection
logic and gives every conclusion a traceable source event.
"""
from __future__ import annotations

from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from enum import Enum
import hashlib
import json
import uuid
from typing import Any, Mapping


class EventKind(str, Enum):
    PROCESS = "process"
    NETWORK = "network"
    FILE = "file"
    AUTHENTICATION = "authentication"
    CONFIGURATION = "configuration"
    HEALTH = "health"


class Severity(str, Enum):
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class Environment(str, Enum):
    DEVELOPMENT = "development"
    PRODUCTION = "production"


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


def _normalise(value: Any) -> Any:
    if isinstance(value, Enum):
        return value.value
    if isinstance(value, datetime):
        return value.astimezone(timezone.utc).isoformat()
    if isinstance(value, Mapping):
        return {str(k): _normalise(v) for k, v in value.items()}
    if isinstance(value, (list, tuple)):
        return [_normalise(v) for v in value]
    return value


@dataclass(frozen=True, slots=True)
class Event:
    """A validated observation with provenance; data must contain no secrets."""
    kind: EventKind
    source: str
    data: Mapping[str, Any]
    observed_at: datetime = field(default_factory=utc_now)
    event_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    host_id: str = "unknown"
    schema_version: int = 1

    def __post_init__(self) -> None:
        if not self.source.strip():
            raise ValueError("event source is required")
        if self.observed_at.tzinfo is None:
            raise ValueError("observed_at must be timezone-aware")
        # Persist a concrete copy so callers cannot mutate an event post-ingest.
        object.__setattr__(self, "data", dict(self.data))

    def canonical(self) -> dict[str, Any]:
        return _normalise(asdict(self))

    def digest(self) -> str:
        encoded = json.dumps(self.canonical(), sort_keys=True, separators=(",", ":")).encode()
        return hashlib.sha256(encoded).hexdigest()


@dataclass(frozen=True, slots=True)
class Finding:
    rule_id: str
    title: str
    severity: Severity
    confidence: float
    evidence_event_ids: tuple[str, ...]
    explanation: str
    recommendation: str
    created_at: datetime = field(default_factory=utc_now)
    finding_id: str = field(default_factory=lambda: str(uuid.uuid4()))

    def __post_init__(self) -> None:
        if not 0.0 <= self.confidence <= 1.0:
            raise ValueError("confidence must be between 0 and 1")
        if not self.evidence_event_ids:
            raise ValueError("a finding requires evidence")

    def canonical(self) -> dict[str, Any]:
        return _normalise(asdict(self))
