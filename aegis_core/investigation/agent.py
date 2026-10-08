"""InvestigationAgent — adaptive, evidence-driven, read-only investigation loop.

Architecture (Phase 2 — Adaptive Loop)
----------------------------------------
InvestigationCase  (from existing Aegis triage pipeline)
    |
InvestigationAgent.investigate(case_id)
    |
    +-- Phase 1: Bootstrap
    |     get_case()
    |     get_events()  (seed)
    |     initialize_hypotheses()
    |     analyze_event(trigger_event)
    |
    +-- Phase 2: Adaptive Loop
    |     while not (sufficient | budget_exhausted):
    |         observe_state()           -- what do we know?
    |         identify_evidence_gaps()  -- what is missing?
    |         choose_next_action()      -- select best tool for the gap
    |         execute_action()          -- call the tool
    |         update_state()            -- absorb new events/entities
    |         check_sufficiency()       -- are we done?
    |
    +-- Phase 3: Finalize
          build_timeline()
          evaluate_hypotheses()
          classify()
          root_cause()
          recommend_actions()
          -> InvestigationResult

Design Principles (unchanged)
-------------------------------
1. Evidence-first: every conclusion references real event_ids.
2. Read-only: no system modification, no remediation.
3. Budget-bounded: max_tool_calls, time, evidence expansion, context_size.
4. Contradiction-aware: actively searches for weakening evidence.
5. UNKNOWN is valid — never force a definitive classification.
6. Graceful degradation: tool failure -> PARTIAL, not crash.
7. Prompt-injection safe: telemetry is DATA, never executed as instructions.
8. Adaptive: next action depends on current investigation state.
9. Duplicate-free: identical tool calls are not repeated.
10. Entity discovery: newly seen PIDs/paths are queued for investigation.

WHAT THIS AGENT DOES NOT DO:
  - kill_process
  - delete_file
  - quarantine_file
  - block_network
  - isolate_host
  - execute arbitrary shell commands
  - perform remediation of any kind
"""
from __future__ import annotations

import logging
from datetime import datetime, timezone
from typing import Any

from ..storage import EvidenceStore
from .result import (
    ActivityChainStep,
    AttackTechnique,
    Classification,
    EvidenceItem,
    EvidenceRelationship,
    IOC,
    InvestigationCoverage,
    InvestigationResult,
    InvestigationStatus,
    RootCauseHypothesis,
    TimelineEntry,
)
from .state import (
    EvidenceCoverage,
    Hypothesis,
    InvestigationAction,
    InvestigationBudget,
    InvestigationState,
    StopReason,
)
from .tools import InvestigationTools

logger = logging.getLogger(__name__)

_UNAVAILABLE = "UNAVAILABLE"

# Priority constants for action ordering (lower = higher priority)
_PRIORITY_TRIGGER_ANALYSIS = 1
_PRIORITY_RELATED_EVENTS = 2
_PRIORITY_PROCESS = 3
_PRIORITY_FILE = 4
_PRIORITY_NETWORK = 5
_PRIORITY_AUTH = 5        # same tier as network — complements it
_PRIORITY_SUSPICIOUS_PAIRS = 6
_PRIORITY_NEWLY_DISCOVERED = 7
_PRIORITY_TIMELINE = 8
_PRIORITY_HYPOTHESES = 9


class InvestigationAgent:
    """Adaptive, evidence-driven investigation agent.

    This agent consumes an existing Aegis InvestigationCase (produced by
    TriageEngine) and expands outward from the trigger event using structured,
    read-only tools.  Tool selection is ADAPTIVE: each tool call is chosen
    based on the current investigation state and identified evidence gaps.

    It does NOT require an LLM. All selection logic is rule-based and
    evidence-grounded. If an LLM integration is added in future, it must
    be layered on top; the agent's evidence collection and classification
    must remain deterministic and testable.
    """

    def __init__(
        self,
        store: EvidenceStore,
        budget: InvestigationBudget | None = None,
    ) -> None:
        self._store = store
        self._tools = InvestigationTools(store)
        self._budget = budget or InvestigationBudget.default()
        self.last_state: InvestigationState | None = None

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def investigate(self, case_id: str) -> InvestigationResult:
        """Run the full adaptive investigation loop for a case.

        Returns InvestigationResult regardless of outcome
        (COMPLETE, PARTIAL, or ERROR).
        """
        persisted = self._store.get_investigation_result(case_id)
        if persisted is not None:
            logger.info("Investigation result already exists; returning case_id=%s", case_id)
            return InvestigationResult.from_canonical(persisted)

        case = self._store.get_case_by_id(case_id)
        if case is None:
            state = InvestigationState(case_id, self._budget)
            result = self._make_error_result(state, f"Case {case_id!r} not found")
            self._store.append_investigation_result(result)
            return result

        claimed = self._store.claim_case(case_id)
        if claimed is None:
            result = self._make_error_result(
                InvestigationState(case_id, self._budget),
                f"Case {case_id!r} is already claimed or is not NEW",
            )
            logger.warning("Investigation case claim failed: case_id=%s", case_id)
            return result

        logger.info("Investigation case received: case_id=%s", case_id)
        logger.info("Investigation started: case_id=%s status=INVESTIGATING", case_id)
        state = InvestigationState(case_id, self._budget)
        start_iso = datetime.now(timezone.utc).isoformat()

        try:
            result = self._run_loop(state)
        except Exception as exc:
            logger.warning("Investigation %s failed: %s", case_id, exc)
            result = self._make_error_result(state, str(exc))
            state.stop_reason = StopReason.ERROR

        result.agent_start_time = start_iso
        result.agent_end_time = datetime.now(timezone.utc).isoformat()
        result.tool_calls_made = state.tool_call_count()
        result.evidence_ids_used = state.all_evidence_ids()
        self._store.append_investigation_result(result)
        final_case_status = {
            InvestigationStatus.ERROR: "ERROR",
            Classification.BENIGN: "BENIGN",
            Classification.MALICIOUS: "MALICIOUS",
            Classification.SUSPICIOUS: "SUSPICIOUS",
            Classification.UNKNOWN: "SUSPICIOUS",
        }.get(result.status if result.status is InvestigationStatus.ERROR else result.classification, "SUSPICIOUS")
        self._store.update_case_status(case_id, final_case_status)
        logger.info(
            "Investigation completed: case_id=%s status=%s result_persisted=true",
            case_id, result.status.value,
        )
        self.last_state = state
        return result

    # ------------------------------------------------------------------
    # Main loop
    # ------------------------------------------------------------------

    def _run_loop(self, state: InvestigationState) -> InvestigationResult:
        """Adaptive investigation loop.

        Phase 1: Bootstrap (load case, seed events, analyze trigger).
        Phase 2: Adaptive loop (observe -> gap -> action -> execute -> assess).
        Phase 3: Finalize (timeline, evaluate, classify, result).
        """
        case_id = state.case_id

        # ---------------------------------------------------------------
        # Phase 1: Bootstrap
        # ---------------------------------------------------------------
        case = self._bootstrap_load_case(state, case_id)
        if case is None:
            state.stop_reason = StopReason.ERROR
            return self._make_error_result(state, f"Case {case_id!r} not found")

        self._bootstrap_seed_events(state, case_id, case)
        self._bootstrap_hypotheses(state, case)
        self._bootstrap_analyze_trigger(state, case)

        # Check if telemetry is marked unavailable for this case
        signals = [str(s).lower() for s in case.get("detection_signals", [])]
        status_val = str(case.get("status", "")).lower()
        triage_reason = str(case.get("triage_reason", "")).lower()
        trigger_rule = str(case.get("trigger", "")).lower()
        if (
            "telemetry_unavailable" in signals
            or "telemetry unavailable" in signals
            or "telemetry_unavailable" in status_val
            or "telemetry unavailable" in status_val
            or "telemetry_unavailable" in triage_reason
            or "telemetry unavailable" in triage_reason
            or "telemetry_unavailable" in trigger_rule
            or "telemetry unavailable" in trigger_rule
        ):
            state.stop_reason = StopReason.TELEMETRY_UNAVAILABLE
            state.uncertainties.append(
                "Host telemetry is unavailable; investigation cannot collect evidence."
            )

        # ---------------------------------------------------------------
        # Phase 2: Adaptive loop
        # ---------------------------------------------------------------
        loop_iterations = 0
        max_iterations = self._budget.max_tool_calls + 5  # safety ceiling

        while state.stop_reason is None and loop_iterations < max_iterations:
            loop_iterations += 1

            # Check all budget limits
            if not state.can_call_tool():
                state.stop_reason = StopReason.MAX_TOOL_CALLS
                break
            if not state.within_time_budget():
                state.stop_reason = StopReason.MAX_TIME
                break
            if not state.within_context_budget():
                state.stop_reason = StopReason.MAX_CONTEXT_SIZE
                break
            if len(state.known_events) >= self._budget.max_evidence_expansion:
                state.stop_reason = StopReason.MAX_EVIDENCE_EXPANSION
                break

            # Check evidence sufficiency (structural coverage, not just confidence)
            if state.is_evidence_sufficient():
                state.stop_reason = StopReason.SUFFICIENT_EVIDENCE
                logger.debug("Investigation %s: sufficient evidence at iteration %d",
                             case_id, loop_iterations)
                break

            # Identify next action based on current state
            action = self._choose_next_action(state, case)
            if action is None:
                # No more useful actions identified
                if len(state.known_events) == 0:
                    state.stop_reason = StopReason.NO_RELEVANT_EVIDENCE
                    state.uncertainties.append(
                        "No relevant events were found in the evidence store for this case."
                    )
                else:
                    state.stop_reason = StopReason.LOOP_COMPLETE
                break

            # Guard: do not repeat identical actions
            if state.already_executed(action):
                logger.debug("Skipping duplicate action: %s", action.dedup_key())
                # Mark this gap as covered to prevent infinite loop
                self._mark_gap_covered(state, action)
                continue

            # Execute action
            state.mark_executed(action)
            self._execute_action(state, case, action)

        # ---------------------------------------------------------------
        # Phase 3: Finalize (always runs regardless of stop reason)
        # ---------------------------------------------------------------
        self._finalize_timeline(state)
        self._finalize_evaluate_hypotheses(state, case)
        self._finalize_auth(state, case)

        classification, confidence = self._classify(state, case)
        root_cause = self._build_root_cause(state, case, classification)
        self._build_recommendations(state, case, classification)

        # Build new feature outputs
        relationships = self._build_relationships(state)
        activity_chain = self._build_activity_chain(state)
        state.coverage.activity_chain_built = True
        iocs = self._extract_iocs(state)
        state.coverage.ioc_extracted = True
        attack_techniques = self._map_attack_techniques(state, case)
        state.coverage.attack_techniques_mapped = True
        coverage = self._build_coverage(state)

        # Compose status
        if state.stop_reason in (StopReason.SUFFICIENT_EVIDENCE, StopReason.LOOP_COMPLETE):
            status = InvestigationStatus.COMPLETE
        elif state.stop_reason == StopReason.ERROR:
            status = InvestigationStatus.ERROR
        else:
            status = InvestigationStatus.PARTIAL

        return InvestigationResult(
            case_id=case_id,
            status=status,
            classification=classification,
            confidence=confidence,
            summary=self._make_summary(state, case, classification, confidence),
            timeline=list(state.timeline),
            affected_processes=state.affected_processes,
            affected_files=state.affected_files,
            network_activity=state.network_activity,
            root_cause=root_cause,
            supporting_evidence=state.supporting_evidence,
            contradictory_evidence=state.contradictory_evidence,
            authentication_activity=state.authentication_activity,
            activity_chain=activity_chain,
            relationships=relationships,
            attack_techniques=attack_techniques,
            iocs=iocs,
            investigation_coverage=coverage,
            uncertainties=state.uncertainties,
            recommended_actions=state.recommended_actions,
            reasoning_summary=self._make_reasoning(state),
            stop_reason=state.stop_reason.value if state.stop_reason else "",
        )

    # ------------------------------------------------------------------
    # Phase 1: Bootstrap
    # ------------------------------------------------------------------

    def _bootstrap_load_case(
        self, state: InvestigationState, case_id: str
    ) -> dict[str, Any] | None:
        case = self._tools.get_case(case_id)
        state.record_tool_call(
            tool_name="get_case",
            arguments={"case_id": case_id},
            result_summary="found" if case else "not_found",
            event_ids=[],
            reason="Load the InvestigationCase that triggered this investigation",
            gap_description="case_not_loaded",
            error=None if case else "Case not found",
        )
        if case:
            state.coverage.trigger_loaded = True
        return case

    def _bootstrap_seed_events(
        self, state: InvestigationState, case_id: str, case: dict[str, Any]
    ) -> None:
        events = self._tools.get_events(case_id)
        new_ids = state.add_events(events)
        state.record_tool_call(
            tool_name="get_events",
            arguments={"case_id": case_id},
            result_summary=f"seeded {len(new_ids)} events",
            event_ids=new_ids,
            reason="Seed all events associated with this case into working memory",
            gap_description="seed_events_not_loaded",
        )
        state.coverage.seed_events_loaded = True

        # Classify each seed event as initial supporting evidence
        trigger_id = str(case.get("trigger_event_id", ""))
        for ev in events:
            eid = str(ev.get("event_id", ""))
            kind = str(ev.get("kind", ""))
            data = ev.get("data", {})
            ts = str(ev.get("observed_at", ""))
            summary = self._describe_event(ev)
            item = EvidenceItem(
                event_id=eid,
                event_kind=kind,
                description=summary,
                observed_at=ts,
                raw_data_keys=list(data.keys()),
            )
            state.add_supporting(item)

    def _bootstrap_hypotheses(
        self, state: InvestigationState, case: dict[str, Any]
    ) -> None:
        risk = float(case.get("risk_score", 0.5))
        state.hypotheses = [
            Hypothesis(
                label="H_BENIGN",
                description="Activity is legitimate administrative or user-initiated behavior",
                confidence=max(0.1, 0.5 - risk * 0.4),
            ),
            Hypothesis(
                label="H_SUSPICIOUS",
                description="Activity is abnormal and warrants investigation but is not confirmed malicious",
                confidence=risk * 0.6,
            ),
            Hypothesis(
                label="H_MALICIOUS",
                description="Activity reflects deliberate malicious action",
                confidence=0.0,  # requires corroborating evidence
            ),
        ]

    def _bootstrap_analyze_trigger(
        self, state: InvestigationState, case: dict[str, Any]
    ) -> None:
        """Analyze the trigger event using analyze_event() to seed interpretation."""
        if not state.can_call_tool():
            return
        trigger_id = str(case.get("trigger_event_id", ""))
        if not trigger_id or state.already_queried(f"analyze:{trigger_id}"):
            return
        state.mark_queried(f"analyze:{trigger_id}")

        analysis = self._tools.analyze_event(trigger_id)
        state.record_tool_call(
            tool_name="analyze_event",
            arguments={"event_id": trigger_id},
            result_summary="analyzed" if analysis and "error" not in analysis else "failed",
            event_ids=[trigger_id] if analysis else [],
            reason="Analyze trigger event to understand the initial detection context",
            gap_description="trigger_not_analyzed",
        )

        if analysis and "error" not in analysis:
            state.coverage.trigger_analyzed = True
            # Enrich the supporting evidence description for the trigger
            for item in state.supporting_evidence:
                if item.event_id == trigger_id:
                    item.description = (
                        f"{item.description} | Analysis: {analysis.get('summary', '')}"
                    )[:400]
                    break
        elif analysis and "error" in analysis:
            state.uncertainties.append(
                f"Trigger event analysis failed: {analysis['error'][:100]}"
            )

    # ------------------------------------------------------------------
    # Phase 2: Adaptive loop — observe, gap-detect, action-select
    # ------------------------------------------------------------------

    def _choose_next_action(
        self, state: InvestigationState, case: dict[str, Any]
    ) -> InvestigationAction | None:
        """Identify the highest-priority evidence gap and return an action.

        This is the core of the adaptive loop. Each candidate action has:
          - A specific evidence gap it addresses.
          - A reason grounded in the current investigation state.
          - A priority (lower = more important).

        Returns None if no further useful action can be identified.
        """
        candidates: list[InvestigationAction] = []

        # Gap 1: Related events not yet expanded
        if not state.coverage.related_events_expanded:
            candidates.append(self._action_expand_related(state))

        # Gap 2: Process context for known PIDs
        if state.can_expand():
            candidates.extend(self._actions_for_process_gaps(state, case))

        # Gap 3: File activity for known paths
        if state.can_expand():
            candidates.extend(self._actions_for_file_gaps(state))

        # Gap 4: Network activity for known PIDs
        if state.can_expand():
            candidates.extend(self._actions_for_network_gaps(state))

        # Gap 4.5: Authentication activity (if auth events present or not yet checked)
        if state.can_expand():
            candidates.extend(self._actions_for_auth_gaps(state, case))

        # Gap 5: Suspicious process-network pair check
        if (state.can_call_tool() and
                not state.already_queried("suspicious_pairs")):
            candidates.append(InvestigationAction(
                tool_name="get_suspicious_process_network_pairs",
                reason="Check for processes with concurrent file-write and outbound network activity",
                arguments={},
                gap_description="suspicious_process_network_pairs_not_checked",
                priority=_PRIORITY_SUSPICIOUS_PAIRS,
            ))

        # Gap 6: Newly discovered pending PIDs
        if state.can_expand():
            candidates.extend(self._actions_for_pending_pids(state))

        # Gap 7: Newly discovered pending paths
        if state.can_expand():
            candidates.extend(self._actions_for_pending_paths(state))

        # Gap 8: Analyze newly discovered important events
        if state.can_call_tool():
            candidates.extend(self._actions_for_event_analysis(state))

        # Gap 9: Timeline not built
        if (not state.coverage.timeline_built and
                state.can_call_tool() and
                len(state.known_events) > 0):
            candidates.append(InvestigationAction(
                tool_name="build_timeline",
                reason="Construct chronological timeline from all collected events",
                arguments={"event_count": len(state.known_events)},
                gap_description="timeline_not_built",
                priority=_PRIORITY_TIMELINE,
            ))

        # Filter already-executed actions
        candidates = [c for c in candidates if not state.already_executed(c)]

        if not candidates:
            return None

        # Sort by priority (ascending = highest priority first)
        candidates.sort(key=lambda a: a.priority)
        return candidates[0]

    def _action_expand_related(self, state: InvestigationState) -> InvestigationAction:
        seed_ids = list(state.known_events.keys())[:10]
        return InvestigationAction(
            tool_name="get_related_events",
            reason=(
                "Expand evidence outward from seed events to discover "
                "temporally related activity on the same host"
            ),
            arguments={"event_ids": seed_ids, "window_seconds": 120.0},
            gap_description="related_events_not_expanded",
            priority=_PRIORITY_RELATED_EVENTS,
        )

    def _actions_for_process_gaps(
        self, state: InvestigationState, case: dict[str, Any]
    ) -> list[InvestigationAction]:
        actions = []
        # Collect PIDs from known events + case
        pids: set[int] = set()
        for ev in state.known_events.values():
            pid_raw = ev.get("data", {}).get("pid")
            if pid_raw is not None:
                try:
                    pids.add(int(pid_raw))
                except (TypeError, ValueError):
                    pass
        for proc in case.get("related_processes", []):
            pid_raw = proc.get("pid")
            if pid_raw is not None:
                try:
                    pids.add(int(pid_raw))
                except (TypeError, ValueError):
                    pass

        for pid in sorted(pids)[:8]:
            if not state.already_queried(f"proc_info:{pid}"):
                actions.append(InvestigationAction(
                    tool_name="get_process_info",
                    reason=(
                        f"PID {pid} appears in case events but process metadata "
                        f"(name/exe/user/ppid) has not been retrieved"
                    ),
                    arguments={"pid": pid},
                    gap_description=f"process_metadata_missing:{pid}",
                    priority=_PRIORITY_PROCESS,
                ))
            if not state.already_queried(f"proc_tree:{pid}"):
                actions.append(InvestigationAction(
                    tool_name="get_process_tree",
                    reason=(
                        f"PID {pid} ancestry and children are unknown; "
                        f"parent-child relationships may reveal attack chain"
                    ),
                    arguments={"pid": pid, "max_depth": 3},
                    gap_description=f"process_tree_missing:{pid}",
                    priority=_PRIORITY_PROCESS + 1,
                ))
        return actions

    def _actions_for_file_gaps(self, state: InvestigationState) -> list[InvestigationAction]:
        actions = []
        for path in list(state.pending_paths)[:8]:
            entity_key = f"file:{path}"
            if state.already_queried(entity_key):
                continue
            actions.append(InvestigationAction(
                tool_name="get_file_activity",
                reason=(
                    f"File path '{path[:80]}' was discovered in process events "
                    f"but its full activity history has not been retrieved"
                ),
                arguments={"path": path},
                gap_description=f"file_activity_missing:{path[:80]}",
                priority=_PRIORITY_FILE,
            ))
        return actions

    def _actions_for_network_gaps(self, state: InvestigationState) -> list[InvestigationAction]:
        actions = []
        # Find PIDs with network events not yet investigated
        pids_with_net: set[int] = set()
        for ev in state.known_events.values():
            if ev.get("kind") == "network":
                pid_raw = ev.get("data", {}).get("pid")
                if pid_raw is not None:
                    try:
                        pids_with_net.add(int(pid_raw))
                    except (TypeError, ValueError):
                        pass
        for pid in sorted(pids_with_net)[:6]:
            entity_key = f"network_pid:{pid}"
            if state.already_queried(entity_key):
                continue
            actions.append(InvestigationAction(
                tool_name="get_network_for_pid",
                reason=(
                    f"Network events for PID {pid} exist but full network "
                    f"activity has not been retrieved from the correlation index"
                ),
                arguments={"pid": pid},
                gap_description=f"network_activity_missing:{pid}",
                priority=_PRIORITY_NETWORK,
            ))
        return actions

    def _actions_for_auth_gaps(
        self, state: InvestigationState, case: dict[str, Any]
    ) -> list[InvestigationAction]:
        """Authentication investigation gap actions.

        Fires once per investigation run if:
        - auth events are already in working memory (discovered via get_related_events), OR
        - no auth query has been attempted yet (we may be missing auth telemetry entirely).
        Returns empty list if auth has already been covered.
        """
        if state.coverage.authentication_covered:
            return []
        if state.already_queried("auth_activity"):
            return []

        # Build time bounds from known events
        times = [
            ev.get("observed_at", "")
            for ev in state.known_events.values()
            if ev.get("observed_at")
        ]
        reason = (
            "Authentication events in the investigation time window have not been retrieved. "
            "Auth activity may reveal user context or a credential abuse chain."
        )
        return [InvestigationAction(
            tool_name="get_auth_activity",
            reason=reason,
            arguments={},
            gap_description="authentication_activity_not_investigated",
            priority=_PRIORITY_AUTH,
        )]

    def _actions_for_pending_pids(self, state: InvestigationState) -> list[InvestigationAction]:
        """Actions for newly discovered PIDs not yet investigated."""
        actions = []
        uninvestigated = state.pending_pids - state.affected_pids
        for pid in sorted(uninvestigated)[:4]:
            entity_key = f"process:{pid}"
            if state.already_queried(entity_key):
                state.affected_pids.add(pid)
                continue
            actions.append(InvestigationAction(
                tool_name="get_events_for_pid",
                reason=(
                    f"PID {pid} was discovered in related events but "
                    f"its full event history has not been retrieved"
                ),
                arguments={"pid": pid},
                gap_description=f"new_pid_events_missing:{pid}",
                priority=_PRIORITY_NEWLY_DISCOVERED,
            ))
        return actions

    def _actions_for_pending_paths(self, state: InvestigationState) -> list[InvestigationAction]:
        """Actions for newly discovered file paths not yet investigated."""
        # Delegates to file gaps — pending paths are picked up there
        return []

    def _actions_for_event_analysis(
        self, state: InvestigationState
    ) -> list[InvestigationAction]:
        """Identify important events that have not been analyzed yet."""
        actions = []
        # Analyze network events (outbound connections) that are in supporting evidence
        for ev in list(state.known_events.values())[:20]:
            eid = str(ev.get("event_id", ""))
            if not eid:
                continue
            key = f"analyze:{eid}"
            if state.already_queried(key):
                continue
            kind = ev.get("kind", "")
            # Only analyze network connection events beyond the trigger
            if kind == "network":
                action_field = ev.get("data", {}).get("action", "")
                if action_field == "connection_open":
                    actions.append(InvestigationAction(
                        tool_name="analyze_event",
                        reason=(
                            f"Network connection event {eid[:8]}.. has not been "
                            f"analyzed; may reveal process-to-IP associations"
                        ),
                        arguments={"event_id": eid},
                        gap_description=f"event_not_analyzed:{eid[:8]}",
                        priority=_PRIORITY_NEWLY_DISCOVERED + 1,
                    ))
        return actions[:2]  # bound to 2 extra analyses per iteration

    # ------------------------------------------------------------------
    # Execute a chosen action
    # ------------------------------------------------------------------

    def _execute_action(
        self,
        state: InvestigationState,
        case: dict[str, Any],
        action: InvestigationAction,
    ) -> None:
        """Dispatch an InvestigationAction to the appropriate tool method."""
        logger.debug("Investigation %s: executing %s (%s)",
                     state.case_id, action.tool_name, action.reason[:60])

        tool = action.tool_name
        args = action.arguments

        try:
            if tool == "get_related_events":
                self._exec_get_related_events(state, action)

            elif tool == "get_process_info":
                self._exec_get_process_info(state, action)

            elif tool == "get_process_tree":
                self._exec_get_process_tree(state, action)

            elif tool == "get_events_for_pid":
                self._exec_get_events_for_pid(state, action)

            elif tool == "get_file_activity":
                self._exec_get_file_activity(state, action)

            elif tool == "get_network_for_pid":
                self._exec_get_network_for_pid(state, action)

            elif tool == "get_suspicious_process_network_pairs":
                self._exec_get_suspicious_pairs(state, action, case)

            elif tool == "build_timeline":
                self._exec_build_timeline(state, action)

            elif tool == "analyze_event":
                self._exec_analyze_event(state, action)

            elif tool == "get_auth_activity":
                self._exec_get_auth_activity(state, action, case)

            else:
                logger.warning("Unknown tool name in action: %s", tool)

        except Exception as exc:
            logger.warning("Tool %s failed: %s", tool, exc)
            state.record_tool_call(
                tool_name=tool,
                arguments=args,
                result_summary="error",
                event_ids=[],
                reason=action.reason,
                gap_description=action.gap_description,
                error=str(exc)[:200],
            )
            state.uncertainties.append(
                f"Tool {tool} failed: {str(exc)[:100]}"
            )
            # Mark gap as covered to avoid infinite retry
            self._mark_gap_covered(state, action)

    def _exec_get_related_events(
        self, state: InvestigationState, action: InvestigationAction
    ) -> None:
        seed_ids = action.arguments.get("event_ids", list(state.known_events.keys())[:10])
        window = action.arguments.get("window_seconds", 120.0)
        related = self._tools.get_related_events(seed_ids, window_seconds=window)
        new_ids = state.add_events(related)
        state.record_tool_call(
            tool_name="get_related_events",
            arguments=action.arguments,
            result_summary=f"found {len(new_ids)} related events",
            event_ids=new_ids,
            reason=action.reason,
            gap_description=action.gap_description,
        )
        state.coverage.related_events_expanded = True

    def _exec_get_process_info(
        self, state: InvestigationState, action: InvestigationAction
    ) -> None:
        pid = int(action.arguments["pid"])
        entity_key = f"proc_info:{pid}"
        state.mark_queried(entity_key)
        state.affected_pids.add(pid)
        state.pending_pids.discard(pid)

        info = self._tools.get_process_info(pid)
        state.record_tool_call(
            tool_name="get_process_info",
            arguments=action.arguments,
            result_summary="found" if info else "not_found",
            event_ids=[],
            reason=action.reason,
            gap_description=action.gap_description,
        )
        if info:
            state.affected_processes.append({"pid": pid, **info})
        state.coverage.process_context_covered = True

    def _exec_get_process_tree(
        self, state: InvestigationState, action: InvestigationAction
    ) -> None:
        pid = int(action.arguments["pid"])
        state.mark_queried(f"proc_tree:{pid}")
        state.affected_pids.add(pid)
        max_depth = int(action.arguments.get("max_depth", 3))
        tree = self._tools.get_process_tree(pid, max_depth=max_depth)
        state.record_tool_call(
            tool_name="get_process_tree",
            arguments=action.arguments,
            result_summary=f"children={len(tree.get('children', []))}",
            event_ids=[],
            reason=action.reason,
            gap_description=action.gap_description,
        )
        state.coverage.process_context_covered = True
        # Discover child PIDs for potential investigation
        for child in tree.get("children", []):
            child_pid = child.get("pid")
            if child_pid is not None:
                try:
                    cpid = int(child_pid)
                    if cpid not in state.affected_pids:
                        state.pending_pids.add(cpid)
                        logger.debug(
                            "Discovered child PID %d from tree of PID %d", cpid, pid
                        )
                except (TypeError, ValueError):
                    pass

    def _exec_get_events_for_pid(
        self, state: InvestigationState, action: InvestigationAction
    ) -> None:
        pid = int(action.arguments["pid"])
        state.mark_queried(f"process:{pid}")
        state.affected_pids.add(pid)
        state.pending_pids.discard(pid)

        pid_events = self._tools.get_events_for_pid(pid)
        new_ids = state.add_events(pid_events)
        state.record_tool_call(
            tool_name="get_events_for_pid",
            arguments=action.arguments,
            result_summary=f"found {len(new_ids)} new events for PID {pid}",
            event_ids=new_ids,
            reason=action.reason,
            gap_description=action.gap_description,
        )

    def _exec_get_file_activity(
        self, state: InvestigationState, action: InvestigationAction
    ) -> None:
        path = str(action.arguments["path"])
        entity_key = f"file:{path}"
        state.mark_queried(entity_key)
        state.pending_paths.discard(path)

        file_events = self._tools.get_file_activity(path)
        new_ids = state.add_events(file_events)
        state.record_tool_call(
            tool_name="get_file_activity",
            arguments=action.arguments,
            result_summary=f"found {len(file_events)} file events for path",
            event_ids=new_ids,
            reason=action.reason,
            gap_description=action.gap_description,
        )
        if file_events:
            actions_seen = {
                e.get("data", {}).get("action") or e.get("data", {}).get("operation")
                for e in file_events
            }
            state.affected_files.append({
                "path": path,
                "event_count": len(file_events),
                "actions": [a for a in actions_seen if a],
                "event_ids": [e.get("event_id") for e in file_events],
            })
        state.coverage.file_activity_covered = True

    def _exec_get_network_for_pid(
        self, state: InvestigationState, action: InvestigationAction
    ) -> None:
        pid = int(action.arguments["pid"])
        entity_key = f"network_pid:{pid}"
        state.mark_queried(entity_key)

        net_events = self._tools.get_network_for_pid(pid)
        new_ids = state.add_events(net_events)
        state.record_tool_call(
            tool_name="get_network_activity",
            arguments=action.arguments,
            result_summary=f"found {len(net_events)} network events for PID {pid}",
            event_ids=new_ids,
            reason=action.reason,
            gap_description=action.gap_description,
        )
        for ev in net_events:
            data = ev.get("data", {})
            state.network_activity.append({
                "event_id": ev.get("event_id"),
                "pid": pid,
                "remote_ip": data.get("remote_ip", _UNAVAILABLE),
                "remote_port": data.get("remote_port", _UNAVAILABLE),
                "direction": data.get("direction", _UNAVAILABLE),
                "protocol": data.get("protocol", _UNAVAILABLE),
                "observed_at": ev.get("observed_at"),
            })
        state.coverage.network_activity_covered = True

    def _exec_get_suspicious_pairs(
        self,
        state: InvestigationState,
        action: InvestigationAction,
        case: dict[str, Any],
    ) -> None:
        state.mark_queried("suspicious_pairs")
        pairs = self._tools.get_suspicious_process_network_pairs()
        state.record_tool_call(
            tool_name="get_suspicious_process_network_pairs",
            arguments={},
            result_summary=f"found {len(pairs)} suspicious pairs",
            event_ids=[],
            reason=action.reason,
            gap_description=action.gap_description,
        )
        for pair in pairs:
            pid = pair.get("pid")
            if pid and pid in state.affected_pids:
                for eid in (
                    pair.get("evidence", {}).get("network_sample", []) +
                    pair.get("evidence", {}).get("file_sample", [])
                ):
                    ev = state.known_events.get(eid)
                    if ev:
                        state.add_supporting(EvidenceItem(
                            event_id=eid,
                            event_kind=str(ev.get("kind", "unknown")),
                            description=(
                                f"PID {pid} has both file-write and "
                                f"outbound network activity"
                            ),
                            observed_at=str(ev.get("observed_at", "")),
                            raw_data_keys=list(ev.get("data", {}).keys()),
                        ))

    def _exec_build_timeline(
        self, state: InvestigationState, action: InvestigationAction
    ) -> None:
        all_ids = list(state.known_events.keys())
        entries_raw = self._tools.build_timeline(all_ids)
        state.record_tool_call(
            tool_name="build_timeline",
            arguments={"event_count": len(all_ids)},
            result_summary=f"built {len(entries_raw)} timeline entries",
            event_ids=[],
            reason=action.reason,
            gap_description=action.gap_description,
        )
        state.timeline.clear()
        for e in entries_raw:
            state.timeline.append(TimelineEntry(
                timestamp=e["timestamp"],
                event_id=e["event_id"],
                event_kind=e["event_kind"],
                description=e["description"],
                pid=e.get("pid"),
                process_name=e.get("process_name"),
            ))
        state.timeline.sort(key=lambda x: x.timestamp)
        state.coverage.timeline_built = True

    def _exec_analyze_event(
        self, state: InvestigationState, action: InvestigationAction
    ) -> None:
        event_id = str(action.arguments["event_id"])
        state.mark_queried(f"analyze:{event_id}")

        analysis = self._tools.analyze_event(event_id)
        state.record_tool_call(
            tool_name="analyze_event",
            arguments=action.arguments,
            result_summary=(
                "analyzed" if analysis and "error" not in analysis else "failed"
            ),
            event_ids=[event_id] if analysis else [],
            reason=action.reason,
            gap_description=action.gap_description,
        )
        if analysis and "error" in analysis:
            state.uncertainties.append(
                f"Event analysis failed for {event_id[:8]}: {analysis['error'][:80]}"
            )

    def _exec_get_auth_activity(
        self,
        state: InvestigationState,
        action: InvestigationAction,
        case: dict[str, Any],
    ) -> None:
        """Execute authentication activity investigation.

        Retrieves authentication events within the investigation time window.
        Absorbs auth events into working memory, tracks involved users,
        and adds to state.authentication_activity for result export.

        Authentication telemetry may not be available on all platforms.
        Missing telemetry is recorded as an explicit uncertainty.
        """
        state.mark_queried("auth_activity")

        # Derive time window from known events (best effort)
        from datetime import timedelta
        times = []
        for ev in state.known_events.values():
            raw_ts = ev.get("observed_at", "")
            if raw_ts:
                try:
                    times.append(datetime.fromisoformat(str(raw_ts)))
                except (ValueError, TypeError):
                    pass

        since = (min(times) - timedelta(seconds=60)) if times else None
        until = (max(times) + timedelta(seconds=60)) if times else None

        auth_events = self._tools.get_auth_activity(since=since, until=until)
        new_ids = state.add_events(auth_events)
        state.record_tool_call(
            tool_name="get_auth_activity",
            arguments=action.arguments,
            result_summary=(
                f"found {len(auth_events)} auth events"
                if auth_events
                else "no authentication telemetry in window"
            ),
            event_ids=new_ids,
            reason=action.reason,
            gap_description=action.gap_description,
        )

        if not auth_events:
            state.uncertainties.append(
                "No authentication telemetry found in investigation time window. "
                "Authentication activity coverage is unavailable."
            )
            state.coverage.authentication_covered = True
            return

        # Process each auth event
        for ev in auth_events:
            data = ev.get("data", {})
            eid = str(ev.get("event_id", ""))
            action_field = str(data.get("action", "unknown"))
            user = str(data.get("user", "unknown"))
            ts = str(ev.get("observed_at", ""))

            # Track user for cross-reference with process events
            if user and user != "unknown":
                state.pending_users.add(user)

            # Build structured auth record (all fields are DATA)
            auth_record: dict[str, Any] = {
                "event_id": eid,
                "timestamp": ts,
                "action": action_field,
                "user": user,
                "source_ip": str(data.get("source_ip", _UNAVAILABLE))[:64],
                "auth_mechanism": str(data.get("auth_mechanism", _UNAVAILABLE))[:64],
                "result": "success" if "success" in action_field.lower() else (
                    "failure" if "failure" in action_field.lower() or "fail" in action_field.lower()
                    else "unknown"
                ),
            }
            state.authentication_activity.append(auth_record)

            # Add to supporting or contradictory evidence based on action
            item = EvidenceItem(
                event_id=eid,
                event_kind="authentication",
                description=f"Auth {action_field} for user {user!r}",
                observed_at=ts,
                raw_data_keys=list(data.keys()),
            )
            if "failure" in action_field.lower() or "fail" in action_field.lower():
                state.add_contradictory(item)
            else:
                state.add_supporting(item)

        state.coverage.authentication_covered = True

    def _finalize_auth(
        self, state: InvestigationState, case: dict[str, Any]
    ) -> None:
        """Ensure auth coverage is recorded even if the loop didn't call get_auth_activity.

        If we never reached the auth gap (e.g. budget exhausted early),
        record an explicit uncertainty noting auth was not investigated.
        """
        if not state.coverage.authentication_covered:
            state.uncertainties.append(
                "Authentication activity was not investigated "
                "(tool budget exhausted before auth gap was reached)."
            )
            state.coverage.authentication_covered = True

    # ------------------------------------------------------------------
    # Mark coverage to prevent looping on covered gaps
    # ------------------------------------------------------------------

    def _mark_gap_covered(
        self, state: InvestigationState, action: InvestigationAction
    ) -> None:
        """Mark the coverage dimension addressed by this action as done."""
        tool = action.tool_name
        if tool == "get_related_events":
            state.coverage.related_events_expanded = True
        elif tool == "get_process_info":
            state.mark_queried(f"proc_info:{action.arguments.get('pid', '')}")
            state.coverage.process_context_covered = True
        elif tool == "get_process_tree":
            state.mark_queried(f"proc_tree:{action.arguments.get('pid', '')}")
            state.coverage.process_context_covered = True
        elif tool == "get_events_for_pid":
            state.coverage.process_context_covered = True
        elif tool == "get_file_activity":
            state.coverage.file_activity_covered = True
        elif tool in ("get_network_for_pid", "get_network_activity"):
            state.coverage.network_activity_covered = True
        elif tool == "build_timeline":
            state.coverage.timeline_built = True
        elif tool == "analyze_event":
            state.mark_queried(
                f"analyze:{action.arguments.get('event_id', '')}"
            )
        elif tool == "get_suspicious_process_network_pairs":
            state.mark_queried("suspicious_pairs")
        elif tool == "get_auth_activity":
            state.mark_queried("auth_activity")
            state.coverage.authentication_covered = True

    # ------------------------------------------------------------------
    # Phase 3: Finalize
    # ------------------------------------------------------------------

    def _finalize_timeline(self, state: InvestigationState) -> None:
        """Build/rebuild timeline if not already done."""
        if state.coverage.timeline_built:
            return
        if not state.can_call_tool():
            state.uncertainties.append(
                "Timeline construction skipped: tool budget exhausted"
            )
            return
        all_ids = list(state.known_events.keys())
        if not all_ids:
            return
        entries_raw = self._tools.build_timeline(all_ids)
        state.record_tool_call(
            tool_name="build_timeline",
            arguments={"event_count": len(all_ids)},
            result_summary=f"built {len(entries_raw)} timeline entries (finalize)",
            event_ids=[],
            reason="Build timeline during finalization phase",
            gap_description="timeline_not_built",
        )
        state.timeline.clear()
        for e in entries_raw:
            state.timeline.append(TimelineEntry(
                timestamp=e["timestamp"],
                event_id=e["event_id"],
                event_kind=e["event_kind"],
                description=e["description"],
                pid=e.get("pid"),
                process_name=e.get("process_name"),
            ))
        state.timeline.sort(key=lambda x: x.timestamp)
        state.coverage.timeline_built = True

    def _finalize_evaluate_hypotheses(
        self, state: InvestigationState, case: dict[str, Any]
    ) -> None:
        """Update hypothesis confidences based on all collected evidence."""
        signals = set(case.get("detection_signals", []))
        risk = float(case.get("risk_score", 0.5))
        net_count = sum(1 for ev in state.known_events.values() if ev.get("kind") == "network")
        file_count = sum(1 for ev in state.known_events.values() if ev.get("kind") == "file")
        proc_count = sum(1 for ev in state.known_events.values() if ev.get("kind") == "process")

        has_file_net_proc = net_count > 0 and file_count > 0 and proc_count > 0
        suspicious_pair_pids = {
            p.get("pid") for p in self._tools.get_suspicious_process_network_pairs()
        }
        overlap_with_case_pids = bool(suspicious_pair_pids & state.affected_pids)

        h_benign, h_suspicious, h_malicious = (
            state.hypotheses[0], state.hypotheses[1], state.hypotheses[2]
        )

        if "high_severity_finding" in signals:
            h_suspicious.update(confidence_delta=+0.15)
            h_benign.update(confidence_delta=-0.10)

        if "process_file_network_correlation" in signals or has_file_net_proc:
            h_suspicious.update(confidence_delta=+0.10)

        if overlap_with_case_pids:
            h_suspicious.update(confidence_delta=+0.10)
            h_malicious.update(confidence_delta=+0.05)
            for eid in list(state.known_events.keys())[:3]:
                ev = state.known_events[eid]
                if ev.get("kind") == "network":
                    state.add_supporting(EvidenceItem(
                        event_id=eid,
                        event_kind="network",
                        description=(
                            "Process with file-write activity also has outbound network connection"
                        ),
                        observed_at=str(ev.get("observed_at", "")),
                        raw_data_keys=list(ev.get("data", {}).keys()),
                    ))

        # Contradictory evidence: high risk + no file/network corroboration
        if risk > 0.6 and not has_file_net_proc:
            state.add_contradictory(EvidenceItem(
                event_id=case.get("trigger_event_id", ""),
                event_kind="process",
                description=(
                    "Risk score is elevated but no corroborating file or network "
                    "telemetry was found in the investigation window"
                ),
                observed_at=str(case.get("created_at", "")),
                raw_data_keys=["risk_score"],
            ))
            h_malicious.update(confidence_delta=-0.10)
            state.uncertainties.append(
                "High risk score but corroborating file/network evidence is absent"
            )

        if file_count == 0:
            state.uncertainties.append(
                "No file telemetry found; file activity cannot be confirmed"
            )
        if net_count == 0:
            state.uncertainties.append(
                "No network telemetry found; network activity cannot be confirmed"
            )

        state.coverage.hypotheses_evaluated = True
        state.coverage.contradictory_evidence_searched = True

    # ------------------------------------------------------------------
    # Classification
    # ------------------------------------------------------------------

    def _classify(
        self, state: InvestigationState, case: dict[str, Any]
    ) -> tuple[Classification, float]:
        h_benign = state.hypotheses[0]
        h_suspicious = state.hypotheses[1]
        h_malicious = state.hypotheses[2]

        n_supporting = len(state.supporting_evidence)
        n_contradictory = len(state.contradictory_evidence)
        total_events = len(state.known_events)
        signals = set(case.get("detection_signals", []))
        risk = float(case.get("risk_score", 0.5))
        completeness = min(1.0, total_events / max(1, 5))

        strong_signals = signals & {
            "high_severity_finding",
            "process_file_network_correlation",
            "suspicious_process_network_chain",
        }

        if total_events == 0:
            classification = Classification.UNKNOWN
            raw_confidence = 0.0
            if not any("No events were found" in u for u in state.uncertainties):
                state.uncertainties.append(
                    "No events were found in evidence store for this case."
                )
        elif h_malicious.confidence > 0.4 and len(strong_signals) >= 2 and n_supporting >= 3:
            classification = Classification.MALICIOUS
            raw_confidence = h_malicious.confidence
        elif (h_suspicious.confidence > h_benign.confidence and
              (len(signals) > 0 or risk > 0.4)):
            classification = Classification.SUSPICIOUS
            raw_confidence = h_suspicious.confidence
        elif h_benign.confidence > 0.6 and n_contradictory == 0:
            classification = Classification.BENIGN
            raw_confidence = h_benign.confidence
        elif total_events < 2:
            classification = Classification.UNKNOWN
            raw_confidence = 0.2
            state.uncertainties.append(
                "Insufficient events collected to make a reliable classification"
            )
        else:
            classification = Classification.UNKNOWN
            raw_confidence = 0.3

        contradiction_penalty = 0.05 * n_contradictory
        confidence = max(0.0, min(1.0, raw_confidence * completeness - contradiction_penalty))
        return classification, round(confidence, 3)

    # ------------------------------------------------------------------
    # Root cause
    # ------------------------------------------------------------------

    def _build_root_cause(
        self,
        state: InvestigationState,
        case: dict[str, Any],
        classification: Classification,
    ) -> RootCauseHypothesis | None:
        if classification == Classification.BENIGN:
            return None

        trigger = str(case.get("trigger", "unknown"))
        signals = list(case.get("detection_signals", []))
        supporting_ids = [
            e.event_id for e in state.supporting_evidence if e.event_id
        ]

        hypothesis_text = (
            f"Detection triggered by rule {trigger!r}. "
            f"Active signals: {', '.join(signals) or 'none'}."
        )

        proc_count = sum(1 for e in state.known_events.values() if e.get("kind") == "process")
        net_count = sum(1 for e in state.known_events.values() if e.get("kind") == "network")
        file_count = sum(1 for e in state.known_events.values() if e.get("kind") == "file")
        behaviors = []
        if proc_count:
            behaviors.append(f"{proc_count} process event(s)")
        if file_count:
            behaviors.append(f"{file_count} file event(s)")
        if net_count:
            behaviors.append(f"{net_count} network event(s)")
        if behaviors:
            hypothesis_text += " Observed behaviors: " + "; ".join(behaviors) + "."

        limitations = list(state.uncertainties)
        if not state.affected_files:
            limitations.append("File telemetry was not available or empty for this case")
        if not state.network_activity:
            limitations.append("Network telemetry was not available or empty for this case")

        root_conf = (
            state.hypotheses[1].confidence if classification == Classification.SUSPICIOUS
            else state.hypotheses[2].confidence if classification == Classification.MALICIOUS
            else 0.3
        )

        return RootCauseHypothesis(
            hypothesis=hypothesis_text,
            confidence=round(max(0.0, min(1.0, root_conf)), 3),
            supporting_event_ids=supporting_ids[:20],
            limitations=limitations,
        )

    # ------------------------------------------------------------------
    # Recommendations
    # ------------------------------------------------------------------

    def _build_recommendations(
        self,
        state: InvestigationState,
        case: dict[str, Any],
        classification: Classification,
    ) -> None:
        """Populate recommended actions. These are RECOMMENDATIONS ONLY.
        The Investigation Agent does NOT execute them.
        """
        actions: list[str] = []

        if classification in (Classification.SUSPICIOUS, Classification.MALICIOUS):
            actions.append(
                "Review the full event timeline and cross-reference with "
                "approved change management records."
            )
            if state.network_activity:
                actions.append(
                    "Have an authorized network administrator review the identified "
                    "outbound connections before any containment action."
                )
            if state.affected_files:
                actions.append(
                    "Have an authorized security analyst review the identified file "
                    "modifications; verify integrity against known-good baseline."
                )
            if classification == Classification.MALICIOUS:
                actions.append(
                    "Escalate to incident response team for containment decision. "
                    "Do not perform containment without approval from authorized responder."
                )

        if classification == Classification.UNKNOWN:
            actions.append(
                "Collect additional telemetry; the current evidence is insufficient "
                "for a definitive classification."
            )

        if state.uncertainties:
            actions.append(
                "Address listed uncertainties before making containment decisions."
            )

        state.recommended_actions = actions

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    def _describe_event(self, ev: dict[str, Any]) -> str:
        """Build a safe, human-readable description from event fields (all DATA)."""
        kind = str(ev.get("kind", "unknown"))
        data = ev.get("data", {})
        if kind == "process":
            name = str(data.get("name") or "unknown")[:100]
            pid = data.get("pid", "?")
            action = str(data.get("action") or data.get("operation") or "activity")
            return f"Process {name!r} (PID {pid}) - {action}"
        if kind == "file":
            path = str(data.get("path", "unknown"))[:200]
            action = str(data.get("action") or data.get("operation") or "activity")
            return f"File {action} - {path}"
        if kind == "network":
            remote = str(data.get("remote_ip", "unknown"))[:50]
            port = data.get("remote_port", "?")
            action = str(data.get("action", "connection"))
            return f"Network {action} -> {remote}:{port}"
        if kind == "authentication":
            user = str(data.get("user", "unknown"))[:100]
            action = str(data.get("action", "auth"))
            return f"Auth {action} - user: {user}"
        return f"Event kind={kind}"

    def _make_summary(
        self,
        state: InvestigationState,
        case: dict[str, Any],
        classification: Classification,
        confidence: float,
    ) -> str:
        host = str(case.get("hostname") or case.get("host_id") or "unknown")
        trigger = str(case.get("trigger", "unknown"))
        n_events = len(state.known_events)
        n_tl = len(state.timeline)
        stop = state.stop_reason.value if state.stop_reason else "unknown"
        return (
            f"Investigation of case {state.case_id} on host {host!r}. "
            f"Trigger: {trigger}. "
            f"Classification: {classification.value} (confidence {confidence:.0%}). "
            f"Evidence: {n_events} event(s) examined; {n_tl} timeline entry(ies). "
            f"Supporting: {len(state.supporting_evidence)}; "
            f"Contradictory: {len(state.contradictory_evidence)}. "
            f"Stop reason: {stop}."
        )

    def _make_reasoning(self, state: InvestigationState) -> str:
        parts = [f"Tool calls: {state.tool_call_count()}"]
        parts.append(f"Events examined: {len(state.known_events)}")
        parts.append(f"Context: {state.context_bytes()} bytes")
        for h in state.hypotheses:
            parts.append(
                f"{h.label}: confidence={h.confidence:.2f} "
                f"(+{len(h.supporting_event_ids)} / -{len(h.contradicting_event_ids)})"
            )
        stop = state.stop_reason.value if state.stop_reason else "unknown"
        parts.append(f"Stop reason: {stop}")
        if state.uncertainties:
            parts.append("Uncertainties: " + "; ".join(state.uncertainties[:3]))
        return " | ".join(parts)

    def _make_error_result(
        self, state: InvestigationState, error_msg: str
    ) -> InvestigationResult:
        return InvestigationResult(
            case_id=state.case_id,
            status=InvestigationStatus.ERROR,
            classification=Classification.UNKNOWN,
            confidence=0.0,
            summary=f"Investigation failed: {error_msg[:200]}",
            uncertainties=[f"Investigation error: {error_msg[:200]}"],
            reasoning_summary=f"Error: {error_msg[:200]}",
            stop_reason=state.stop_reason.value if state.stop_reason else StopReason.ERROR.value,
        )

    # ------------------------------------------------------------------
    # Feature expansion: relationship extraction
    # ------------------------------------------------------------------

    def _build_relationships(self, state):
        """Build structured EvidenceRelationships from collected evidence.

        Only asserts relationships where a structural basis exists.
        Does NOT assert causality from temporal proximity alone.
        """
        relationships = []
        seen = set()

        for eid, ev in state.known_events.items():
            kind = ev.get("kind", "")
            data = ev.get("data", {})
            pid_raw = data.get("pid")
            ppid_raw = data.get("ppid")

            if kind == "process" and pid_raw is not None and ppid_raw is not None:
                try:
                    pid = int(pid_raw)
                    ppid = int(ppid_raw)
                    dedup = f"parent:{ppid}->child:{pid}"
                    if dedup not in seen:
                        seen.add(dedup)
                        relationships.append(EvidenceRelationship(
                            relationship_type="parent_process",
                            from_entity=f"PID:{ppid}",
                            to_entity=f"PID:{pid}",
                            evidence_event_ids=[eid],
                            structural_basis="ppid field matches parent PID in process event",
                        ))
                except (TypeError, ValueError):
                    pass

            if kind == "file" and pid_raw is not None:
                try:
                    pid = int(pid_raw)
                    path = str(data.get("path", ""))[:200]
                    if path:
                        dedup = f"proc:{pid}->file:{path}"
                        if dedup not in seen:
                            seen.add(dedup)
                            relationships.append(EvidenceRelationship(
                                relationship_type="process_file",
                                from_entity=f"PID:{pid}",
                                to_entity=f"path:{path}",
                                evidence_event_ids=[eid],
                                structural_basis="pid field on file event attributes it to this process",
                            ))
                except (TypeError, ValueError):
                    pass

            if kind == "network" and pid_raw is not None:
                try:
                    pid = int(pid_raw)
                    remote_ip = str(data.get("remote_ip", ""))[:64]
                    remote_port = data.get("remote_port", "")
                    dest = f"{remote_ip}:{remote_port}" if remote_ip else ""
                    if dest:
                        dedup = f"proc:{pid}->net:{dest}"
                        if dedup not in seen:
                            seen.add(dedup)
                            relationships.append(EvidenceRelationship(
                                relationship_type="process_network",
                                from_entity=f"PID:{pid}",
                                to_entity=f"endpoint:{dest}",
                                evidence_event_ids=[eid],
                                structural_basis="pid field on network event attributes connection to this process",
                            ))
                except (TypeError, ValueError):
                    pass

            if kind == "authentication":
                user = str(data.get("user", ""))
                if user:
                    for peid, pev in state.known_events.items():
                        if pev.get("kind") != "process":
                            continue
                        pdata = pev.get("data", {})
                        if str(pdata.get("user", "")) == user:
                            ppid_val = pdata.get("pid")
                            try:
                                ppid_int = int(ppid_val) if ppid_val is not None else None
                            except (TypeError, ValueError):
                                ppid_int = None
                            dedup = f"auth:{eid[:8]}->proc:{peid[:8]}"
                            if dedup not in seen and ppid_int is not None:
                                seen.add(dedup)
                                relationships.append(EvidenceRelationship(
                                    relationship_type="authentication_process",
                                    from_entity=f"auth:user={user}",
                                    to_entity=f"PID:{ppid_int}",
                                    evidence_event_ids=[eid, peid],
                                    structural_basis="user field matches between auth and process events",
                                ))

        return relationships[:50]

    # ------------------------------------------------------------------
    # Feature expansion: activity chain
    # ------------------------------------------------------------------

    def _build_activity_chain(self, state):
        """Build an ordered, evidence-backed activity chain from the timeline.

        Each step references a real event_id. Uncertain steps (only
        temporally related, no structural link) are flagged is_uncertain=True.
        """
        if not state.timeline:
            return []

        structural_pairs = set()
        for ev in state.known_events.values():
            data = ev.get("data", {})
            pid_raw = data.get("pid")
            ppid_raw = data.get("ppid")
            if pid_raw is not None and ppid_raw is not None:
                try:
                    structural_pairs.add(f"{int(ppid_raw)}->{int(pid_raw)}")
                except (TypeError, ValueError):
                    pass

        steps = []
        for i, entry in enumerate(state.timeline):
            pid = entry.pid
            proc_name = entry.process_name or "unknown"

            if entry.event_kind == "process":
                entity = f"{proc_name} PID:{pid}" if pid else proc_name
            elif entry.event_kind == "file":
                entity = f"file (PID:{pid})" if pid else "file"
            elif entry.event_kind == "network":
                entity = f"network (PID:{pid})" if pid else "network"
            elif entry.event_kind == "authentication":
                entity = "authentication"
            else:
                entity = entry.event_kind

            is_uncertain = False
            if i > 0 and pid is not None:
                prev = steps[i - 1]
                prev_pid = None
                if "PID:" in prev.entity:
                    try:
                        prev_pid = int(prev.entity.split("PID:")[-1].split()[0])
                    except (ValueError, TypeError):
                        pass
                if prev_pid is not None:
                    is_uncertain = f"{prev_pid}->{pid}" not in structural_pairs

            steps.append(ActivityChainStep(
                step_index=i,
                event_id=entry.event_id,
                event_kind=entry.event_kind,
                description=entry.description,
                timestamp=entry.timestamp,
                entity=entity,
                is_uncertain=is_uncertain,
            ))

        return steps

    # ------------------------------------------------------------------
    # Feature expansion: IOC extraction
    # ------------------------------------------------------------------

    def _extract_iocs(self, state):
        """Extract observable indicators from collected evidence.

        IOCs are OBSERVABLES, not verdicts. Never label as malicious.
        Deduplicates by (type, value) and preserves source event IDs.
        """
        seen = {}

        def _add(ioc_type, value, eid):
            value = str(value).strip()[:512]
            if not value or value == _UNAVAILABLE:
                return
            key = (ioc_type, value)
            if key not in seen:
                seen[key] = []
            if eid and eid not in seen[key]:
                seen[key].append(eid)

        for eid, ev in state.known_events.items():
            kind = ev.get("kind", "")
            data = ev.get("data", {})

            if kind == "network":
                remote_ip = data.get("remote_ip")
                if remote_ip:
                    _add("ip", str(remote_ip), eid)
                remote_port = data.get("remote_port")
                if remote_ip and remote_port:
                    _add("network_endpoint", f"{remote_ip}:{remote_port}", eid)
                query_name = data.get("query_name")
                if query_name:
                    _add("domain", str(query_name), eid)

            elif kind == "file":
                path = data.get("path")
                if path:
                    _add("file_path", str(path), eid)

            elif kind == "process":
                exe = data.get("exe")
                if exe:
                    _add("executable", str(exe), eid)
                name = data.get("name")
                if name:
                    _add("executable", str(name), eid)
                cmdline = data.get("cmdline")
                if cmdline:
                    s = str(cmdline)
                    suspicious_markers = ["-enc", "-encodedcommand", "iex",
                                          "invoke-expression", "downloadstring", "webclient"]
                    if any(m in s.lower() for m in suspicious_markers):
                        _add("cmdline_indicator", s[:256], eid)

        iocs = []
        for (ioc_type, value), source_ids in seen.items():
            iocs.append(IOC(
                type=ioc_type,
                value=value,
                source_event_ids=source_ids[:10],
                context="",
            ))

        return iocs

    # ------------------------------------------------------------------
    # Feature expansion: MITRE ATT&CK mapping
    # ------------------------------------------------------------------

    def _map_attack_techniques(self, state, case):
        """Map observed behaviors to MITRE ATT&CK techniques.

        Evidence-backed only. No speculative mappings.
        Only maps techniques directly supported by Aegis telemetry.
        """
        techniques = []
        signals = set(case.get("detection_signals", []))

        process_events = [(eid, ev) for eid, ev in state.known_events.items() if ev.get("kind") == "process"]
        file_events = [(eid, ev) for eid, ev in state.known_events.items() if ev.get("kind") == "file"]
        network_events = [(eid, ev) for eid, ev in state.known_events.items() if ev.get("kind") == "network"]
        auth_events = [(eid, ev) for eid, ev in state.known_events.items() if ev.get("kind") == "authentication"]

        # T1059.001 PowerShell
        ps_eids = [eid for eid, ev in process_events
                   if "powershell" in str(ev.get("data", {}).get("name", "")).lower()
                   or "powershell" in str(ev.get("data", {}).get("exe", "")).lower()]
        if ps_eids:
            has_enc = any("-enc" in str(state.known_events[eid].get("data", {}).get("cmdline", "")).lower()
                         for eid in ps_eids)
            techniques.append(AttackTechnique(
                technique_id="T1059.001",
                technique_name="Command and Scripting Interpreter: PowerShell",
                reason="PowerShell process execution was directly observed in telemetry.",
                evidence_ids=ps_eids[:5],
                confidence=0.85 if has_enc else 0.70,
            ))

        # T1059.003 cmd.exe
        cmd_eids = [eid for eid, ev in process_events
                    if str(ev.get("data", {}).get("name", "")).lower() in ("cmd.exe", "cmd")]
        if cmd_eids:
            techniques.append(AttackTechnique(
                technique_id="T1059.003",
                technique_name="Command and Scripting Interpreter: Windows Command Shell",
                reason="cmd.exe process execution was directly observed in telemetry.",
                evidence_ids=cmd_eids[:5],
                confidence=0.70,
            ))

        # T1105 Ingress Tool Transfer
        exe_suffixes = (".exe", ".dll", ".bat", ".ps1", ".vbs")
        exe_drop_eids = [eid for eid, ev in file_events
                         if ev.get("data", {}).get("action") in ("create", "write")
                         and str(ev.get("data", {}).get("suffix", "")).lower() in exe_suffixes]
        if exe_drop_eids:
            techniques.append(AttackTechnique(
                technique_id="T1105",
                technique_name="Ingress Tool Transfer",
                reason="Executable or script file creation was observed in telemetry.",
                evidence_ids=exe_drop_eids[:5],
                confidence=0.65,
            ))

        # T1071.001 Web Protocols (port 80/443)
        web_net_eids = [eid for eid, ev in network_events
                        if ev.get("data", {}).get("direction") == "outbound"
                        and ev.get("data", {}).get("remote_port") in (80, 443, "80", "443")]
        if web_net_eids:
            techniques.append(AttackTechnique(
                technique_id="T1071.001",
                technique_name="Application Layer Protocol: Web Protocols",
                reason="Outbound network connection on port 80/443 observed.",
                evidence_ids=web_net_eids[:5],
                confidence=0.55,
            ))

        # T1071 Non-standard outbound port
        nonweb_net_eids = [eid for eid, ev in network_events
                           if ev.get("data", {}).get("direction") == "outbound"
                           and ev.get("data", {}).get("remote_port") not in (80, 443, "80", "443", None)]
        if nonweb_net_eids:
            techniques.append(AttackTechnique(
                technique_id="T1071",
                technique_name="Application Layer Protocol (non-standard port)",
                reason="Outbound connection to non-standard port observed.",
                evidence_ids=nonweb_net_eids[:5],
                confidence=0.60,
            ))

        # T1566 Phishing (Office app spawned child)
        office_apps = {"winword.exe", "excel.exe", "outlook.exe", "powerpnt.exe"}
        office_child_eids = []
        for eid, ev in process_events:
            pdata = ev.get("data", {})
            ppid_raw = pdata.get("ppid")
            if ppid_raw is None:
                continue
            try:
                ppid = int(ppid_raw)
            except (TypeError, ValueError):
                continue
            for peid, pev in process_events:
                if pev.get("data", {}).get("pid") == ppid:
                    parent_name = str(pev.get("data", {}).get("name", "")).lower()
                    if parent_name in office_apps:
                        office_child_eids.append(eid)
                        break
        if office_child_eids:
            techniques.append(AttackTechnique(
                technique_id="T1566",
                technique_name="Phishing (Office document macro execution)",
                reason="Child process spawned by Office application, consistent with macro-triggered execution.",
                evidence_ids=office_child_eids[:5],
                confidence=0.70,
            ))

        # T1110 Brute Force
        auth_fail_eids = [eid for eid, ev in auth_events
                          if "fail" in str(ev.get("data", {}).get("action", "")).lower()]
        if "authentication_failure_burst" in signals or len(auth_fail_eids) >= 3:
            if auth_fail_eids:
                techniques.append(AttackTechnique(
                    technique_id="T1110",
                    technique_name="Brute Force",
                    reason="Multiple authentication failures observed, consistent with brute force.",
                    evidence_ids=auth_fail_eids[:5],
                    confidence=0.75,
                ))

        # T1078 Valid Accounts
        auth_success_eids = [eid for eid, ev in auth_events
                              if "success" in str(ev.get("data", {}).get("action", "")).lower()]
        if auth_success_eids and (process_events or office_child_eids):
            techniques.append(AttackTechnique(
                technique_id="T1078",
                technique_name="Valid Accounts",
                reason="Authentication success observed alongside suspicious process activity.",
                evidence_ids=auth_success_eids[:5],
                confidence=0.55,
            ))

        return techniques

    # ------------------------------------------------------------------
    # Feature expansion: coverage serialization
    # ------------------------------------------------------------------

    def _build_coverage(self, state):
        """Serialize EvidenceCoverage into exported InvestigationCoverage."""
        cov = state.coverage
        return InvestigationCoverage(
            trigger_loaded=cov.trigger_loaded,
            seed_events_loaded=cov.seed_events_loaded,
            related_events_expanded=cov.related_events_expanded,
            process_context_covered=cov.process_context_covered,
            file_activity_covered=cov.file_activity_covered,
            network_activity_covered=cov.network_activity_covered,
            authentication_covered=cov.authentication_covered,
            timeline_built=cov.timeline_built,
            hypotheses_evaluated=cov.hypotheses_evaluated,
            ioc_extracted=cov.ioc_extracted,
            activity_chain_built=cov.activity_chain_built,
            attack_techniques_mapped=cov.attack_techniques_mapped,
        )
