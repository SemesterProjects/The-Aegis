"""InvestigationState — mutable working memory for the Investigation Agent.

Collects hypotheses, evidence, tool call log, and intermediate findings
as the agent progresses through the adaptive investigation loop.

All evidence is referenced by real event_id strings.
Hypothesis support is weighed against contradictory evidence.

Changes vs. previous version
-----------------------------
- Added StopReason enum (machine-readable stopping conditions).
- Added InvestigationAction dataclass (explicit action record with reason).
- Added EvidenceCoverage tracker (which evidence dimensions are done).
- Added max_context_size to InvestigationBudget and enforcement in add_events().
- Added is_evidence_sufficient() for evidence-based early stopping.
- Added pending_pids / pending_paths for newly discovered entity tracking.
- ToolCall now carries reason + gap_description fields.
"""
from __future__ import annotations

import json as _json
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any

from .result import EvidenceItem, TimelineEntry


# ---------------------------------------------------------------------------
# StopReason — machine-readable stopping conditions
# ---------------------------------------------------------------------------

class StopReason(str, Enum):
    """Why the investigation loop stopped."""
    SUFFICIENT_EVIDENCE = "sufficient_evidence"
    NO_RELEVANT_EVIDENCE = "no_relevant_evidence"
    MAX_TOOL_CALLS = "max_tool_calls"
    MAX_TIME = "max_time"
    MAX_EVIDENCE_EXPANSION = "max_evidence_expansion"
    MAX_CONTEXT_SIZE = "max_context_size"
    TELEMETRY_UNAVAILABLE = "telemetry_unavailable"
    ERROR = "error"
    LOOP_COMPLETE = "loop_complete"


# ---------------------------------------------------------------------------
# InvestigationAction — explicit record of what the agent chose to do and why
# ---------------------------------------------------------------------------

@dataclass
class InvestigationAction:
    """One investigation action the agent decided to take.

    Every action must document WHY it was selected (evidence gap reasoning).
    This makes adaptive tool selection explicit and auditable.

    Attributes:
        tool_name: The InvestigationTools method to call.
        reason: Human-readable explanation of WHY this tool was chosen.
        arguments: Dict of arguments to pass to the tool.
        gap_description: The evidence gap this action addresses.
        priority: Lower = higher priority (used for ordering candidates).
    """
    tool_name: str
    reason: str
    arguments: dict[str, Any]
    gap_description: str
    priority: int = 10

    def dedup_key(self) -> str:
        """Stable deduplication key — tool + sorted arguments."""
        arg_repr = ",".join(
            f"{k}={v}" for k, v in sorted(self.arguments.items(), key=lambda x: str(x[0]))
        )
        return f"{self.tool_name}:{arg_repr}"


# ---------------------------------------------------------------------------
# ToolCall — audit record for a single investigation tool invocation
# ---------------------------------------------------------------------------

@dataclass
class ToolCall:
    """Audit record for a single investigation tool invocation."""
    tool_name: str
    arguments: dict[str, Any]
    result_summary: str
    event_ids_returned: list[str]
    reason: str = ""
    gap_description: str = ""
    timestamp: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    error: str | None = None

    @property
    def success(self) -> bool:
        return self.error is None


# ---------------------------------------------------------------------------
# Hypothesis
# ---------------------------------------------------------------------------

@dataclass
class Hypothesis:
    """One competing explanation under investigation.

    Agents must actively collect evidence for AND against each hypothesis.
    """
    label: str
    description: str
    supporting_event_ids: list[str] = field(default_factory=list)
    contradicting_event_ids: list[str] = field(default_factory=list)
    confidence: float = 0.5

    def update(
        self,
        supporting: list[str] | None = None,
        contradicting: list[str] | None = None,
        confidence_delta: float = 0.0,
    ) -> None:
        if supporting:
            self.supporting_event_ids.extend(supporting)
        if contradicting:
            self.contradicting_event_ids.extend(contradicting)
        self.confidence = max(0.0, min(1.0, self.confidence + confidence_delta))


# ---------------------------------------------------------------------------
# EvidenceCoverage — tracks which investigation dimensions are done
# ---------------------------------------------------------------------------

@dataclass
class EvidenceCoverage:
    """Tracks which investigation dimensions have been addressed."""
    trigger_loaded: bool = False
    trigger_analyzed: bool = False
    seed_events_loaded: bool = False
    related_events_expanded: bool = False
    process_context_covered: bool = False
    file_activity_covered: bool = False
    network_activity_covered: bool = False
    authentication_covered: bool = False
    timeline_built: bool = False
    hypotheses_evaluated: bool = False
    contradictory_evidence_searched: bool = False
    ioc_extracted: bool = False
    activity_chain_built: bool = False
    attack_techniques_mapped: bool = False

    def is_sufficient_for_classification(
        self,
        has_process_events: bool,
        has_file_events: bool,
        has_network_events: bool,
        has_auth_events: bool = False,
    ) -> bool:
        """Return True only when all relevant evidence dimensions are covered.

        Relevant means the dimension has events present in working memory.
        A dimension is not required if no events of that kind exist.
        """
        if not (self.trigger_loaded and self.seed_events_loaded):
            return False
        if not self.related_events_expanded:
            return False
        if has_process_events and not self.process_context_covered:
            return False
        if has_file_events and not self.file_activity_covered:
            return False
        if has_network_events and not self.network_activity_covered:
            return False
        if has_auth_events and not self.authentication_covered:
            return False
        if not self.timeline_built:
            return False
        if not self.hypotheses_evaluated:
            return False
        return True


# ---------------------------------------------------------------------------
# InvestigationState
# ---------------------------------------------------------------------------

class InvestigationState:
    """Mutable working memory for one adaptive investigation run.

    Thread-safety: NOT intended for concurrent access within one run.
    """

    def __init__(self, case_id: str, budget: "InvestigationBudget") -> None:
        self.case_id = case_id
        self.budget = budget
        self.start_time = datetime.now(timezone.utc)

        # Evidence collected so far (keyed by event_id)
        self.known_events: dict[str, dict[str, Any]] = {}

        # Entities already queried to prevent redundant tool calls
        self.queried_entities: set[str] = set()

        # Actions that have been executed (dedup_key -> True)
        self.executed_actions: set[str] = set()

        # Active hypotheses
        self.hypotheses: list[Hypothesis] = []

        # Supporting and contradictory evidence lists
        self.supporting_evidence: list[EvidenceItem] = []
        self.contradictory_evidence: list[EvidenceItem] = []

        # Chronological timeline
        self.timeline: list[TimelineEntry] = []

        # Tool call audit log (includes action reasons)
        self.tool_calls: list[ToolCall] = []

        # Processes, files, network entities seen
        self.affected_pids: set[int] = set()
        self.affected_files: list[dict[str, Any]] = []
        self.network_activity: list[dict[str, Any]] = []
        self.affected_processes: list[dict[str, Any]] = []

        # Authentication activity observed
        self.authentication_activity: list[dict[str, Any]] = []

        # Newly discovered entities pending investigation
        self.pending_pids: set[int] = set()
        self.pending_paths: set[str] = set()
        self.pending_users: set[str] = set()  # usernames seen in auth events

        # Uncertainty notes
        self.uncertainties: list[str] = []

        # Recommended actions (read-only, never executed)
        self.recommended_actions: list[str] = []

        # Evidence dimension coverage tracker
        self.coverage: EvidenceCoverage = EvidenceCoverage()

        # Stop reason (set when loop terminates)
        self.stop_reason: StopReason | None = None

        # Approximate context size in bytes
        self._context_bytes: int = 0

    # ------------------------------------------------------------------
    # Budget checks
    # ------------------------------------------------------------------

    def can_call_tool(self) -> bool:
        return self.budget.can_call_tool(len(self.tool_calls))

    def elapsed_seconds(self) -> float:
        return (datetime.now(timezone.utc) - self.start_time).total_seconds()

    def within_time_budget(self) -> bool:
        return self.elapsed_seconds() < self.budget.max_investigation_time_seconds

    def within_context_budget(self) -> bool:
        return self._context_bytes < self.budget.max_context_size

    def can_expand(self) -> bool:
        return (
            self.can_call_tool()
            and self.within_time_budget()
            and len(self.known_events) < self.budget.max_evidence_expansion
            and self.within_context_budget()
        )

    # ------------------------------------------------------------------
    # Event collection
    # ------------------------------------------------------------------

    def add_events(self, events: list[dict[str, Any]]) -> list[str]:
        """Absorb a batch of canonical events; return their event_ids.

        Enforces max_context_size: stops adding when budget is exceeded.
        Auto-discovers new PIDs and file paths as pending investigation candidates.
        """
        new_ids = []
        for ev in events:
            eid = str(ev.get("event_id", ""))
            if not eid or eid in self.known_events:
                continue

            # Measure context cost
            ev_bytes = len(_json.dumps(ev))
            if self._context_bytes + ev_bytes > self.budget.max_context_size:
                self.stop_reason = StopReason.MAX_CONTEXT_SIZE
                if not any("Context size budget" in u for u in self.uncertainties):
                    self.uncertainties.append(
                        f"Context size budget reached "
                        f"({self.budget.max_context_size} bytes); "
                        "some events were not loaded into working memory."
                    )
                break

            self.known_events[eid] = ev
            self._context_bytes += ev_bytes
            new_ids.append(eid)

            # Auto-discover new PIDs
            pid_raw = ev.get("data", {}).get("pid")
            if pid_raw is not None:
                try:
                    pid = int(pid_raw)
                    if pid not in self.affected_pids:
                        self.pending_pids.add(pid)
                except (TypeError, ValueError):
                    pass

            # Auto-discover file paths
            if ev.get("kind") == "file":
                path = str(ev.get("data", {}).get("path", "") or "")
                if path and path not in self.pending_paths:
                    self.pending_paths.add(path)

        return new_ids

    def already_queried(self, entity_key: str) -> bool:
        return entity_key in self.queried_entities

    def mark_queried(self, entity_key: str) -> None:
        self.queried_entities.add(entity_key)

    def already_executed(self, action: InvestigationAction) -> bool:
        """Return True if an identical action has already been executed."""
        return action.dedup_key() in self.executed_actions

    def mark_executed(self, action: InvestigationAction) -> None:
        self.executed_actions.add(action.dedup_key())

    # ------------------------------------------------------------------
    # Tool call logging
    # ------------------------------------------------------------------

    def record_tool_call(
        self,
        tool_name: str,
        arguments: dict[str, Any],
        result_summary: str,
        event_ids: list[str],
        reason: str = "",
        gap_description: str = "",
        error: str | None = None,
    ) -> None:
        self.tool_calls.append(ToolCall(
            tool_name=tool_name,
            arguments=arguments,
            result_summary=result_summary,
            event_ids_returned=event_ids,
            reason=reason,
            gap_description=gap_description,
            error=error,
        ))

    # ------------------------------------------------------------------
    # Evidence management
    # ------------------------------------------------------------------

    def add_supporting(self, item: EvidenceItem) -> None:
        if not any(e.event_id == item.event_id for e in self.supporting_evidence):
            self.supporting_evidence.append(item)

    def add_contradictory(self, item: EvidenceItem) -> None:
        if not any(e.event_id == item.event_id for e in self.contradictory_evidence):
            self.contradictory_evidence.append(item)

    def add_timeline_entry(self, entry: TimelineEntry) -> None:
        """Insert timeline entry maintaining chronological order."""
        self.timeline.append(entry)
        self.timeline.sort(key=lambda e: e.timestamp)

    # ------------------------------------------------------------------
    # Evidence sufficiency
    # ------------------------------------------------------------------

    def has_process_events(self) -> bool:
        return any(ev.get("kind") == "process" for ev in self.known_events.values())

    def has_file_events(self) -> bool:
        return any(ev.get("kind") == "file" for ev in self.known_events.values())

    def has_network_events(self) -> bool:
        return any(ev.get("kind") == "network" for ev in self.known_events.values())

    def has_auth_events(self) -> bool:
        return any(ev.get("kind") == "authentication" for ev in self.known_events.values())

    def is_evidence_sufficient(self) -> bool:
        """Return True when all relevant evidence dimensions are covered.

        This checks structural coverage, not just confidence level.
        The loop should only stop early when all present evidence dimensions
        have been investigated, the timeline built, and hypotheses evaluated.
        """
        return self.coverage.is_sufficient_for_classification(
            has_process_events=self.has_process_events(),
            has_file_events=self.has_file_events(),
            has_network_events=self.has_network_events(),
            has_auth_events=self.has_auth_events(),
        )

    # ------------------------------------------------------------------
    # Summaries
    # ------------------------------------------------------------------

    def all_evidence_ids(self) -> list[str]:
        return list(self.known_events.keys())

    def tool_call_count(self) -> int:
        return len(self.tool_calls)

    def context_bytes(self) -> int:
        return self._context_bytes


# ---------------------------------------------------------------------------
# InvestigationBudget
# ---------------------------------------------------------------------------

@dataclass
class InvestigationBudget:
    """Configurable safeguards preventing runaway investigation loops.

    Attributes:
        max_tool_calls: Maximum number of tool invocations per run.
        max_investigation_time_seconds: Wall-clock time limit in seconds.
        max_evidence_expansion: Maximum number of events in working memory.
        max_context_size: Maximum total bytes of JSON-serialised event data
            in working memory.  Measured as sum of json.dumps() of each event
            dict in known_events.  Prevents memory exhaustion from large events.
    """
    max_tool_calls: int = 30
    max_investigation_time_seconds: float = 120.0
    max_evidence_expansion: int = 500
    max_context_size: int = 1_000_000  # 1 MB default

    def can_call_tool(self, current_count: int) -> bool:
        return current_count < self.max_tool_calls

    @classmethod
    def default(cls) -> "InvestigationBudget":
        return cls()

    @classmethod
    def tight(cls) -> "InvestigationBudget":
        """For tests / demos where speed matters."""
        return cls(max_tool_calls=10, max_investigation_time_seconds=30.0)
