"""ResponseAgent for the AEGIS Autonomous Cyber Defense Platform.

Orchestrates the 6-phase response lifecycle:
Phase A: Input Retrieval and validation
Phase B: Evidence and Risk Assessment
Phase C: Response Planning
Phase D: Policy and Approval Gate
Phase E: Controlled Execution
Phase F: Post-Action Verification & Audit Trail
"""
from __future__ import annotations

import logging
from datetime import datetime, timezone
from typing import Any

from .adapters import DryRunExecutionAdapter, ExecutionAdapter
from .models import (
    ActionStatus,
    ActionType,
    ApprovalRecord,
    ApprovalStatus,
    PlanStatus,
    PolicyDecision,
    ResponseAction,
    ResponsePlan,
    RiskAssessment,
    RiskLevel,
    utc_now_iso,
)
from .playbooks import PlaybookEngine
from .policy import PolicyEvaluator, ResponsePolicyConfig
from .verification import OutcomeVerifier
from ..investigation.result import Classification, InvestigationResult, InvestigationStatus
from ..storage import EvidenceStore

logger = logging.getLogger(__name__)


class ResponseAgent:
    """Production-oriented response agent for AEGIS."""

    def __init__(
        self,
        store: EvidenceStore,
        policy_config: ResponsePolicyConfig | None = None,
        adapter: ExecutionAdapter | None = None,
        verifier: OutcomeVerifier | None = None,
    ) -> None:
        self.store = store
        self.policy_evaluator = PolicyEvaluator(policy_config)
        self.adapter = adapter or DryRunExecutionAdapter()
        self.verifier = verifier or OutcomeVerifier(store)
        self.playbook_engine = PlaybookEngine()

    # ------------------------------------------------------------------
    # Phase A, B, C, D: Planning and Policy Evaluation
    # ------------------------------------------------------------------

    def plan(self, case_id: str) -> ResponsePlan:
        """Retrieve investigation, assess risk, generate plan, and evaluate policy."""
        # 1. Idempotency Check: return existing plan if already generated
        existing_plan_data = self.store.get_response_plan_by_case(case_id)
        if existing_plan_data is not None:
            logger.info("Response plan already exists for case_id=%s; returning existing", case_id)
            return ResponsePlan.from_canonical(existing_plan_data)

        # 2. Input Retrieval and Validation
        case = self.store.get_case_by_id(case_id)
        if case is None:
            return self._make_error_plan(case_id, "unknown", f"Investigation case '{case_id}' not found.")

        result_data = self.store.get_investigation_result(case_id)
        if result_data is None:
            return self._make_error_plan(
                case_id, "unknown", f"No completed investigation result found for case '{case_id}'."
            )

        try:
            investigation = InvestigationResult.from_canonical(result_data)
        except Exception as exc:
            return self._make_error_plan(
                case_id, "unknown", f"Investigation result schema deserialization failed: {exc}"
            )

        # Identifier check
        if investigation.case_id != case_id:
            return self._make_error_plan(
                case_id,
                investigation.investigation_id,
                f"Mismatched case IDs: requested '{case_id}', result has '{investigation.case_id}'.",
            )

        # Terminal status check
        if investigation.status == InvestigationStatus.ERROR:
            return self._make_error_plan(
                case_id,
                investigation.investigation_id,
                "Investigation ended in ERROR status; containment response prohibited.",
            )

        # 3. Risk Assessment & Action Generation (Playbooks)
        risk_assessment, decision, raw_actions, approval_reqs = self.playbook_engine.generate_plan_actions(
            investigation, case
        )

        # Intelligence is already validated by IntelligenceService and persisted
        # with the investigation.  It may give responders context, but it never
        # creates actions, changes the deterministic classification, or bypasses
        # this plan's policy/approval evaluation.
        intelligence_context = self._advisory_intelligence_context(investigation)
        if intelligence_context is not None:
            decision += " A validated LLM interpretation is attached as non-authoritative responder context."

        # 4. Centralized Policy Evaluation
        evaluated_actions: list[ResponseAction] = []
        policy_decisions: list[PolicyDecision] = []
        verification_plan: list[str] = []

        for action in raw_actions:
            decision_eval = self.policy_evaluator.evaluate_action(
                action, investigation, store=self.store, is_live_execution=False
            )
            policy_decisions.append(decision_eval)

            if not decision_eval.allowed:
                # Action denied by policy safety invariants
                action.status = ActionStatus.UNSUPPORTED
                action.reason += f" [POLICY DENIAL: {decision_eval.reason}]"
            else:
                if not self.adapter.can_execute(action):
                    action.status = ActionStatus.UNSUPPORTED
                    action.reason += " [UNSUPPORTED: No capable execution adapter]"
                elif decision_eval.requires_approval:
                    action.status = ActionStatus.PENDING_APPROVAL
                    action.approval_status = ApprovalStatus.PENDING
                else:
                    action.status = ActionStatus.PROPOSED
                    action.approval_status = ApprovalStatus.NOT_REQUIRED

            if action.verification_criteria:
                verification_plan.append(f"Action {action.action_id}: {action.verification_criteria}")

            evaluated_actions.append(action)

        plan = ResponsePlan(
            case_id=case_id,
            investigation_id=investigation.investigation_id,
            risk_assessment=risk_assessment,
            decision=decision,
            actions=evaluated_actions,
            supporting_evidence_ids=list(investigation.evidence_ids_used),
            uncertainties=list(investigation.uncertainties),
            approval_requirements=approval_reqs,
            policy_decisions=policy_decisions,
            verification_plan=verification_plan,
            intelligence_context=intelligence_context,
            status=PlanStatus.PENDING_APPROVAL if any(a.status == ActionStatus.PENDING_APPROVAL for a in evaluated_actions) else PlanStatus.PLANNING,
        )

        # Persist generated plan atomically
        self.store.append_response_plan(plan)
        logger.info(
            "Response plan created: response_id=%s case_id=%s actions_count=%d",
            plan.response_id, plan.case_id, len(plan.actions),
        )
        return plan

    # ------------------------------------------------------------------
    # Approval Workflow
    # ------------------------------------------------------------------

    def approve_action(
        self,
        case_id: str,
        action_id: str,
        approver_id: str,
        rationale: str,
        expires_at: str | None = None,
    ) -> ResponseAction:
        """Record explicit human approval for a pending response action."""
        if not approver_id.strip():
            raise ValueError("Approver identity is required.")
        if not rationale.strip():
            raise ValueError("Approval rationale is required.")

        action = self._get_action_obj(action_id, case_id)
        if action is None:
            raise KeyError(f"Action '{action_id}' not found.")

        if action.status not in (ActionStatus.PENDING_APPROVAL, ActionStatus.PROPOSED, ActionStatus.FAILED):
            raise ValueError(f"Cannot approve action in status {action.status.value}.")

        record = ApprovalRecord(
            approver_id=approver_id,
            status=ApprovalStatus.APPROVED,
            rationale=rationale,
            expires_at=expires_at,
            scope=dict(action.target),
        )
        action.approval_record = record
        action.approval_status = ApprovalStatus.APPROVED
        action.status = ActionStatus.APPROVED
        action.updated_at = utc_now_iso()

        self.store.update_response_action(action)
        logger.info("Action %s approved by %s", action_id, approver_id)
        return action

    def reject_action(
        self,
        case_id: str,
        action_id: str,
        approver_id: str,
        rationale: str,
    ) -> ResponseAction:
        """Record explicit human rejection for a proposed or pending action."""
        if not approver_id.strip():
            raise ValueError("Approver identity is required.")

        action = self._get_action_obj(action_id, case_id)
        if action is None:
            raise KeyError(f"Action '{action_id}' not found.")

        record = ApprovalRecord(
            approver_id=approver_id,
            status=ApprovalStatus.REJECTED,
            rationale=rationale,
            scope=dict(action.target),
        )
        action.approval_record = record
        action.approval_status = ApprovalStatus.REJECTED
        action.status = ActionStatus.REJECTED
        action.updated_at = utc_now_iso()

        self.store.update_response_action(action)
        logger.info("Action %s rejected by %s", action_id, approver_id)
        return action

    # ------------------------------------------------------------------
    # Phase E & F: Execution and Post-Action Verification
    # ------------------------------------------------------------------

    def execute_action(
        self,
        case_id: str,
        action_id: str,
        live: bool = False,
    ) -> ResponseAction:
        """Execute one eligible action through policy gate, adapter handoff, and verification."""
        action = self._get_action_obj(action_id, case_id)
        if action is None:
            raise KeyError(f"Action '{action_id}' not found.")

        # Idempotency Guard: do not repeat executed actions
        if action.status in (ActionStatus.SUCCEEDED, ActionStatus.VERIFIED, ActionStatus.EXECUTING):
            logger.warning("Action %s already executed (status=%s); skipping.", action_id, action.status.value)
            return action

        if action.status in (ActionStatus.REJECTED, ActionStatus.CANCELLED, ActionStatus.UNSUPPORTED):
            logger.warning("Action %s cannot be executed in terminal status=%s.", action_id, action.status.value)
            return action

        # Retrieve investigation for policy re-check at execution time
        result_data = self.store.get_investigation_result(case_id)
        if result_data is None:
            action.status = ActionStatus.FAILED
            action.updated_at = utc_now_iso()
            self.store.update_response_action(action)
            return action

        investigation = InvestigationResult.from_canonical(result_data)

        # Policy Gate Re-Evaluation before Execution
        policy_decision = self.policy_evaluator.evaluate_action(
            action, investigation, store=self.store, is_live_execution=live
        )
        if not policy_decision.allowed:
            action.status = ActionStatus.FAILED
            action.reason += f" [POLICY DENIED: {policy_decision.reason}]"
            action.updated_at = utc_now_iso()
            self.store.update_response_action(action)
            logger.warning("Policy denied execution of action %s: %s", action_id, policy_decision.reason)
            return action

        # Transition: EXECUTING
        action.status = ActionStatus.EXECUTING
        action.updated_at = utc_now_iso()
        self.store.update_response_action(action)

        # Adapter Execution
        try:
            exec_res = self.adapter.execute(action, dry_run=not live)
            action.execution_result = exec_res
            if exec_res.success:
                action.status = ActionStatus.SUCCEEDED
            else:
                action.status = ActionStatus.FAILED
                action.reason += f" [ADAPTER ERROR: {exec_res.error}]"
        except Exception as exc:
            logger.exception("Adapter crashed during execution of action %s", action_id)
            action.status = ActionStatus.FAILED
            action.reason += f" [CRASH: {exc}]"

        # Post-Action Verification (Phase F)
        if action.status == ActionStatus.SUCCEEDED:
            action.status = ActionStatus.VERIFICATION_PENDING
            try:
                ver_res = self.verifier.verify_action(action, is_simulated=exec_res.simulated)
                action.verification_result = ver_res
                if ver_res.verified:
                    action.status = ActionStatus.VERIFIED
                else:
                    action.status = ActionStatus.FAILED
                    action.reason += f" [VERIFICATION FAILED: {ver_res.error or ver_res.details}]"
            except Exception as exc:
                action.status = ActionStatus.FAILED
                action.reason += f" [VERIFICATION ERROR: {exc}]"

        action.updated_at = utc_now_iso()
        self.store.update_response_action(action)
        return action

    def execute_eligible_actions(
        self,
        case_id: str,
        live: bool = False,
    ) -> list[ResponseAction]:
        """Execute all actions that are eligible (non-disruptive or approved)."""
        plan_dict = self.store.get_response_plan_by_case(case_id)
        if plan_dict is None:
            return []

        plan = ResponsePlan.from_canonical(plan_dict)
        executed: list[ResponseAction] = []

        for action in plan.actions:
            # Eligible if PROPOSED (and requires no approval) or APPROVED
            if (action.status == ActionStatus.PROPOSED and not action.requires_approval) or action.status == ActionStatus.APPROVED:
                res = self.execute_action(case_id, action.action_id, live=live)
                executed.append(res)

        return executed

    # ------------------------------------------------------------------
    # Query & Audit Reporting
    # ------------------------------------------------------------------

    def get_plan(self, case_id: str) -> ResponsePlan | None:
        """Fetch the current response plan for a case."""
        data = self.store.get_response_plan_by_case(case_id)
        return ResponsePlan.from_canonical(data) if data else None

    def get_audit_history(self, case_id: str) -> dict[str, Any]:
        """Compile a complete, auditable response history linking case, investigation, and actions."""
        plan_dict = self.store.get_response_plan_by_case(case_id)
        if plan_dict is None:
            return {"case_id": case_id, "status": "NO_RESPONSE_PLAN"}

        actions = self.store.query_response_actions_for_case(case_id)
        inv_dict = self.store.get_investigation_result(case_id) or {}
        case_dict = self.store.get_case_by_id(case_id) or {}

        return {
            "case_id": case_id,
            "investigation_id": inv_dict.get("investigation_id", "unknown"),
            "response_id": plan_dict.get("response_id"),
            "created_at": plan_dict.get("created_at"),
            "updated_at": plan_dict.get("updated_at"),
            "investigation_classification": inv_dict.get("classification"),
            "investigation_confidence": inv_dict.get("confidence"),
            "decision": plan_dict.get("decision"),
            "risk_assessment": plan_dict.get("risk_assessment"),
            "intelligence_context": plan_dict.get("intelligence_context"),
            "policy_decisions": plan_dict.get("policy_decisions"),
            "actions": actions,
            "evidence_chain_valid": self.store.verify_chain(),
        }

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    def _get_action_obj(self, action_id: str, case_id: str | None = None) -> ResponseAction | None:
        if case_id is not None:
            plan = self.store.get_response_plan_by_case(case_id)
            if plan is None:
                return None
            for candidate in plan.get("actions", []):
                if candidate.get("action_id") == action_id:
                    return ResponseAction.from_canonical(candidate)
            return None
        act_dict = self.store.get_response_action(action_id)
        return ResponseAction.from_canonical(act_dict) if act_dict else None

    def _make_error_plan(self, case_id: str, investigation_id: str, reason: str) -> ResponsePlan:
        risk = RiskAssessment(
            classification="UNKNOWN",
            confidence=0.0,
            business_impact="LOW",
            containment_urgency="LOW",
            uncertainties=[reason],
        )
        plan = ResponsePlan(
            case_id=case_id,
            investigation_id=investigation_id,
            risk_assessment=risk,
            decision=f"Response planning aborted: {reason}",
            status=PlanStatus.FAILED,
            uncertainties=[reason],
        )
        logger.warning("Response planning aborted for case %s: %s", case_id, reason)
        return plan

    @staticmethod
    def _advisory_intelligence_context(investigation: InvestigationResult) -> dict[str, Any] | None:
        """Return completed LLM context without granting it response authority."""
        interpretation = investigation.llm_interpretation
        if interpretation is None:
            return None
        try:
            from ..intelligence import InterpretationStatus
            if interpretation.status is not InterpretationStatus.COMPLETE:
                return None
            cited = set(interpretation.evidence_event_ids)
            known = set(investigation.evidence_ids_used)
            if not cited or not cited.issubset(known):
                return None
            return {
                "status": interpretation.status.value,
                "provider": interpretation.provider,
                "model": interpretation.model,
                "summary": interpretation.summary,
                "insights": list(interpretation.insights),
                "uncertainties": list(interpretation.uncertainties),
                "evidence_event_ids": list(interpretation.evidence_event_ids),
                "authority": "ADVISORY_ONLY",
            }
        except (AttributeError, TypeError, ValueError):
            return None
