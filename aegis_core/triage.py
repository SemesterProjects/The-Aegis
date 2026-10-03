"""Persistent, explainable investigation case models and triage boundary."""
from __future__ import annotations

from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from enum import Enum
import json
import uuid
from typing import Any, Iterable


class CaseStatus(str, Enum):
    NEW = "NEW"
    QUEUED = "QUEUED"
    INVESTIGATING = "INVESTIGATING"
    BENIGN = "BENIGN"
    SUSPICIOUS = "SUSPICIOUS"
    MALICIOUS = "MALICIOUS"
    CLOSED = "CLOSED"
    ERROR = "ERROR"


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _json(value: Any) -> Any:
    if isinstance(value, Enum):
        return value.value
    if isinstance(value, datetime):
        return value.astimezone(timezone.utc).isoformat()
    if isinstance(value, tuple):
        return [_json(item) for item in value]
    if isinstance(value, list):
        return [_json(item) for item in value]
    if isinstance(value, dict):
        return {str(key): _json(item) for key, item in value.items()}
    return value


@dataclass(frozen=True, slots=True)
class InvestigationCase:
    """Stable handoff object consumed by the future Investigation Agent."""
    host_id: str
    severity: str
    risk_score: float
    trigger: str
    trigger_event_id: str
    event_ids: tuple[str, ...]
    time_window_start: datetime
    time_window_end: datetime
    detection_signals: tuple[str, ...]
    hostname: str | None = None
    os: str | None = None
    related_processes: tuple[dict[str, Any], ...] = ()
    related_files: tuple[dict[str, Any], ...] = ()
    related_network_activity: tuple[dict[str, Any], ...] = ()
    user_context: dict[str, Any] | None = None
    parent_process: dict[str, Any] | None = None
    child_processes: tuple[dict[str, Any], ...] = ()
    initial_assessment: str = ""
    triage_reason: str = ""
    source: str = "aegis-triage"
    schema_version: int = 1
    status: CaseStatus = CaseStatus.NEW
    case_id: str = field(default_factory=lambda: f"INC-{uuid.uuid4().hex[:12].upper()}")
    created_at: datetime = field(default_factory=_now)
    updated_at: datetime = field(default_factory=_now)

    def __post_init__(self) -> None:
        if not self.event_ids:
            raise ValueError("an investigation case requires event references")
        if not 0.0 <= self.risk_score <= 1.0:
            raise ValueError("risk_score must be between 0 and 1")
        if self.time_window_start.tzinfo is None or self.time_window_end.tzinfo is None:
            raise ValueError("case time window must be timezone-aware")
        if self.time_window_end < self.time_window_start:
            raise ValueError("case time window is inverted")

    def canonical(self) -> dict[str, Any]:
        return _json(asdict(self))


class TriageEngine:
    """Deterministic first-stage triage; it never claims final maliciousness."""

    SIGNAL_WEIGHTS = {
        "high_severity_finding": 0.35,
        "process_file_network_correlation": 0.30,
        "suspicious_process_network_chain": 0.20,
        "file_change_burst": 0.20,
        "authentication_failure_burst": 0.20,
        "unusual_network_rate": 0.15,
    }

    def __init__(self, case_threshold: float = 0.50) -> None:
        if not 0.0 <= case_threshold <= 1.0:
            raise ValueError("case_threshold must be between 0 and 1")
        self.case_threshold = case_threshold

    def score_findings(self, findings: Iterable[dict[str, Any]], events: Iterable[dict[str, Any]]) -> tuple[float, tuple[str, ...], str]:
        findings_list = list(findings)
        events_list = list(events)
        signals: list[str] = []
        score = 0.0
        for finding in findings_list:
            rule_id = str(finding.get("rule_id", ""))
            severity = str(finding.get("severity", "")).lower()
            if severity in {"high", "critical"}:
                signals.append("high_severity_finding")
                score += self.SIGNAL_WEIGHTS["high_severity_finding"]
            if "FILE" in rule_id:
                signals.append("file_change_burst")
                score += self.SIGNAL_WEIGHTS["file_change_burst"]
            elif "AUTH" in rule_id:
                signals.append("authentication_failure_burst")
                score += self.SIGNAL_WEIGHTS["authentication_failure_burst"]
            elif "NET" in rule_id:
                signals.append("suspicious_process_network_chain" if "PROC" in rule_id else "unusual_network_rate")
                score += self.SIGNAL_WEIGHTS[signals[-1]]
        kinds = {str(event.get("kind")) for event in events_list}
        if {"file", "network"}.issubset(kinds) and any(event.get("data", {}).get("pid") is not None for event in events_list):
            signals.append("process_file_network_correlation")
            score += self.SIGNAL_WEIGHTS["process_file_network_correlation"]
        unique_signals = tuple(dict.fromkeys(signals))
        score = min(1.0, score)
        reason = "Triage signals: " + (", ".join(unique_signals) if unique_signals else "no deterministic signal")
        return score, unique_signals, reason

    @staticmethod
    def severity_for(score: float) -> str:
        if score >= 0.85:
            return "critical"
        if score >= 0.60:
            return "high"
        if score >= 0.30:
            return "medium"
        return "low"

    def create_case(self, finding: dict[str, Any], events: list[dict[str, Any]], host_id: str, hostname: str | None = None, os_name: str | None = None) -> InvestigationCase:
        score, signals, reason = self.score_findings([finding], events)
        observed = [datetime.fromisoformat(str(event["observed_at"])) for event in events]
        event_ids = tuple(str(event["event_id"]) for event in events)
        process_events = tuple(event.get("data", {}) for event in events if event.get("kind") == "process")
        file_events = tuple(event.get("data", {}) for event in events if event.get("kind") == "file")
        network_events = tuple(event.get("data", {}) for event in events if event.get("kind") == "network")
        trigger_ids = tuple(finding.get("evidence_event_ids", ()))
        return InvestigationCase(
            host_id=host_id,
            hostname=hostname,
            os=os_name,
            severity=self.severity_for(score),
            risk_score=score,
            trigger=str(finding.get("rule_id", "triage")),
            trigger_event_id=trigger_ids[0] if trigger_ids else event_ids[0],
            event_ids=event_ids,
            time_window_start=min(observed),
            time_window_end=max(observed),
            detection_signals=signals,
            related_processes=process_events,
            related_files=file_events,
            related_network_activity=network_events,
            initial_assessment="Suspicious activity requires investigation; this is not a final malware classification.",
            triage_reason=reason + ". " + str(finding.get("explanation", "")),
        )

    def should_create_case(self, finding: dict[str, Any], events: list[dict[str, Any]]) -> bool:
        """Use the documented transparent threshold; low findings stay queryable."""
        score, _, _ = self.score_findings([finding], events)
        return score >= self.case_threshold
