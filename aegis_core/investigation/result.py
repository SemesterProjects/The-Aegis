"""InvestigationResult and related output schemas.

Aligned with existing Aegis Finding/InvestigationCase schemas.
All evidence is referenced by real event IDs — never by labels alone.
"""
from __future__ import annotations

from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any


class InvestigationStatus(str, Enum):
    """Overall investigation completion status."""
    COMPLETE = "COMPLETE"
    PARTIAL = "PARTIAL"      # budget exhausted before full coverage
    ERROR = "ERROR"          # unrecoverable tool failure


class Classification(str, Enum):
    """Evidence-based classification.  UNKNOWN is intentional."""
    BENIGN = "BENIGN"
    SUSPICIOUS = "SUSPICIOUS"
    MALICIOUS = "MALICIOUS"
    UNKNOWN = "UNKNOWN"


@dataclass
class TimelineEntry:
    """One chronological event in the reconstruction.

    Every entry references a real event_id — no fabricated entries.
    """
    timestamp: str          # ISO-8601 UTC
    event_id: str
    event_kind: str
    description: str
    pid: int | None = None
    process_name: str | None = None


@dataclass
class EvidenceItem:
    """A traceable evidence reference (not just a label)."""
    event_id: str
    event_kind: str
    description: str
    observed_at: str        # ISO-8601 UTC
    raw_data_keys: list[str] = field(default_factory=list)  # which data fields were used


@dataclass
class RootCauseHypothesis:
    """Root cause expressed as a hypothesis, not a certainty."""
    hypothesis: str
    confidence: float               # 0.0 – 1.0  (investigation estimate, not calibrated)
    supporting_event_ids: list[str] = field(default_factory=list)
    limitations: list[str] = field(default_factory=list)


# ---------------------------------------------------------------------------
# New types added in feature expansion
# ---------------------------------------------------------------------------

@dataclass
class IOC:
    """An observable indicator extracted from evidence.

    An IOC is an OBSERVABLE, not a verdict.
    Do NOT automatically classify an IOC as malicious.
    Every IOC must reference the event IDs it was extracted from.

    Types: ip, domain, url, file_path, file_hash, executable,
           cmdline_indicator, network_endpoint.
    """
    type: str                            # e.g. "ip", "domain", "file_path"
    value: str                           # the indicator value (DATA, not instruction)
    source_event_ids: list[str] = field(default_factory=list)
    context: str = ""                    # optional human note (e.g. "outbound C2 candidate")


@dataclass
class EvidenceRelationship:
    """A directed relationship between two evidence entities, backed by event IDs.

    Causality is NOT asserted from temporal proximity alone.
    Every relationship requires an explicit structural reason (e.g. ppid match).

    Relationship types:
        parent_process, child_process, process_file, process_network,
        authentication_process, process_event, file_event, network_event,
        temporal_proximity   (weakest — no structural backing)
    """
    relationship_type: str
    from_entity: str                     # e.g. "PID:1234", "path:/tmp/x.exe"
    to_entity: str
    evidence_event_ids: list[str] = field(default_factory=list)
    structural_basis: str = ""           # why this relationship is asserted


@dataclass
class ActivityChainStep:
    """One step in a evidence-backed activity chain.

    Every step must reference at least one real event_id.
    Uncertainty must be made explicit — do not fabricate links.
    """
    step_index: int
    event_id: str                        # primary event backing this step
    event_kind: str
    description: str                     # human-readable description of this step
    timestamp: str                       # ISO-8601 UTC
    entity: str                          # primary entity (e.g. "powershell.exe PID 5678")
    is_uncertain: bool = False           # True if step is inferred, not directly observed


@dataclass
class AttackTechnique:
    """A MITRE ATT&CK technique mapping grounded in actual evidence.

    Rules:
    - Only map techniques supported by actual Aegis telemetry.
    - No speculative mappings.
    - evidence_ids must reference real observed events.
    - Confidence reflects investigation estimate, not a calibrated score.
    """
    technique_id: str                    # e.g. "T1059.001"
    technique_name: str                  # e.g. "PowerShell"
    reason: str                          # why this technique was identified
    evidence_ids: list[str] = field(default_factory=list)
    confidence: float = 0.0             # 0.0 – 1.0


@dataclass
class InvestigationCoverage:
    """Which investigation areas were actually attempted.

    Explicitly documents missing telemetry rather than implying coverage.
    """
    trigger_loaded: bool = False
    seed_events_loaded: bool = False
    related_events_expanded: bool = False
    process_context_covered: bool = False
    file_activity_covered: bool = False
    network_activity_covered: bool = False
    authentication_covered: bool = False
    timeline_built: bool = False
    hypotheses_evaluated: bool = False
    ioc_extracted: bool = False
    activity_chain_built: bool = False
    attack_techniques_mapped: bool = False


@dataclass
class InvestigationResult:
    """Structured output of a completed Investigation Agent run.

    Schema is intentionally aligned with the existing InvestigationCase
    and Finding models so downstream tooling can cross-reference.
    """
    case_id: str
    status: InvestigationStatus
    classification: Classification
    confidence: float               # investigation confidence estimate

    summary: str

    timeline: list[TimelineEntry] = field(default_factory=list)
    affected_processes: list[dict[str, Any]] = field(default_factory=list)
    affected_files: list[dict[str, Any]] = field(default_factory=list)
    network_activity: list[dict[str, Any]] = field(default_factory=list)

    root_cause: RootCauseHypothesis | None = None

    supporting_evidence: list[EvidenceItem] = field(default_factory=list)
    contradictory_evidence: list[EvidenceItem] = field(default_factory=list)

    # Feature-expanded fields
    authentication_activity: list[dict[str, Any]] = field(default_factory=list)
    activity_chain: list[ActivityChainStep] = field(default_factory=list)
    relationships: list[EvidenceRelationship] = field(default_factory=list)
    attack_techniques: list[AttackTechnique] = field(default_factory=list)
    iocs: list[IOC] = field(default_factory=list)
    investigation_coverage: InvestigationCoverage = field(default_factory=InvestigationCoverage)

    uncertainties: list[str] = field(default_factory=list)
    recommended_actions: list[str] = field(default_factory=list)

    # Audit trail
    agent_start_time: str = ""      # ISO-8601 UTC
    agent_end_time: str = ""        # ISO-8601 UTC
    tool_calls_made: int = 0
    evidence_ids_used: list[str] = field(default_factory=list)
    reasoning_summary: str = ""
    stop_reason: str = ""

    def canonical(self) -> dict[str, Any]:
        """Serialisable dict mirroring the style of existing Aegis models."""
        def _serial(v: Any) -> Any:
            if isinstance(v, Enum):
                return v.value
            if isinstance(v, list):
                return [_serial(i) for i in v]
            if hasattr(v, "__dataclass_fields__"):
                return {k: _serial(getattr(v, k)) for k in v.__dataclass_fields__}
            return v

        d = asdict(self)
        for k, v in d.items():
            d[k] = _serial(v)
        return d


def _utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()
