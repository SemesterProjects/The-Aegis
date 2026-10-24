"""Data models and schemas for the AEGIS Response Agent.

Enforces explicit types, state transitions, evidence grounding, and serialisation
compatible with existing Aegis models.
"""
from __future__ import annotations

from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from enum import Enum
import uuid
from typing import Any, Mapping


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


def utc_now_iso() -> str:
    return utc_now().isoformat()


def _normalise(value: Any) -> Any:
    if isinstance(value, Enum):
        return value.value
    if isinstance(value, datetime):
        return value.astimezone(timezone.utc).isoformat()
    if isinstance(value, Mapping):
        return {str(k): _normalise(v) for k, v in value.items()}
    if isinstance(value, (list, tuple)):
        return [_normalise(v) for v in value]
    if hasattr(value, "__dataclass_fields__"):
        return {k: _normalise(getattr(value, k)) for k in value.__dataclass_fields__}
    return value


class ActionType(str, Enum):
    """Categorized response action types."""
    RECORD_INCIDENT = "RECORD_INCIDENT"
    NOTIFY_RESPONDER = "NOTIFY_RESPONDER"
    REQUEST_ADDITIONAL_TELEMETRY = "REQUEST_ADDITIONAL_TELEMETRY"
    TERMINATE_PROCESS = "TERMINATE_PROCESS"
    QUARANTINE_FILE = "QUARANTINE_FILE"
    BLOCK_NETWORK_IP = "BLOCK_NETWORK_IP"
    ISOLATE_HOST = "ISOLATE_HOST"
    ACCOUNT_REVIEW = "ACCOUNT_REVIEW"


class ActionStatus(str, Enum):
    """Finite lifecycle states for a response action."""
    PROPOSED = "PROPOSED"
    PENDING_APPROVAL = "PENDING_APPROVAL"
    APPROVED = "APPROVED"
    REJECTED = "REJECTED"
    EXECUTING = "EXECUTING"
    SUCCEEDED = "SUCCEEDED"
    FAILED = "FAILED"
    VERIFICATION_PENDING = "VERIFICATION_PENDING"
    VERIFIED = "VERIFIED"
    ROLLED_BACK = "ROLLED_BACK"
    CANCELLED = "CANCELLED"
    UNSUPPORTED = "UNSUPPORTED"


class RiskLevel(str, Enum):
    """Risk and potential operational impact of an action."""
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class ApprovalStatus(str, Enum):
    """Approval gate status for an action."""
    NOT_REQUIRED = "NOT_REQUIRED"
    PENDING = "PENDING"
    APPROVED = "APPROVED"
    REJECTED = "REJECTED"
    EXPIRED = "EXPIRED"
    REVOKED = "REVOKED"


class PlanStatus(str, Enum):
    """Lifecycle status for a response plan."""
    PLANNING = "PLANNING"
    PENDING_APPROVAL = "PENDING_APPROVAL"
    APPROVED = "APPROVED"
    EXECUTING = "EXECUTING"
    COMPLETED = "COMPLETED"
    FAILED = "FAILED"
    CANCELLED = "CANCELLED"


@dataclass(slots=True)
class ApprovalRecord:
    """Explicit human approval decision."""
    approver_id: str
    status: ApprovalStatus
    rationale: str
    granted_at: str = field(default_factory=utc_now_iso)
    expires_at: str | None = None
    approval_id: str = field(default_factory=lambda: f"APP-{uuid.uuid4().hex[:8].upper()}")
    scope: dict[str, Any] = field(default_factory=dict)

    def canonical(self) -> dict[str, Any]:
        return _normalise(asdict(self))

    @classmethod
    def from_canonical(cls, payload: dict[str, Any]) -> ApprovalRecord:
        return cls(
            approver_id=str(payload.get("approver_id", "")),
            status=ApprovalStatus(payload.get("status", ApprovalStatus.PENDING)),
            rationale=str(payload.get("rationale", "")),
            granted_at=str(payload.get("granted_at", "")),
            expires_at=payload.get("expires_at"),
            approval_id=str(payload.get("approval_id", "")),
            scope=dict(payload.get("scope", {})),
        )


@dataclass(slots=True)
class PolicyDecision:
    """Evaluation output from the centralized policy gate."""
    allowed: bool
    requires_approval: bool
    policy_name: str
    reason: str
    violations: list[str] = field(default_factory=list)
    evaluated_at: str = field(default_factory=utc_now_iso)

    def canonical(self) -> dict[str, Any]:
        return _normalise(asdict(self))

    @classmethod
    def from_canonical(cls, payload: dict[str, Any]) -> PolicyDecision:
        return cls(
            allowed=bool(payload.get("allowed", False)),
            requires_approval=bool(payload.get("requires_approval", True)),
            policy_name=str(payload.get("policy_name", "")),
            reason=str(payload.get("reason", "")),
            violations=list(payload.get("violations", [])),
            evaluated_at=str(payload.get("evaluated_at", "")),
        )


@dataclass(slots=True)
class ExecutionResult:
    """Result emitted by an execution adapter."""
    success: bool
    adapter_name: str
    simulated: bool
    executed_at: str = field(default_factory=utc_now_iso)
    output: str = ""
    error: str | None = None
    execution_time_seconds: float = 0.0

    def canonical(self) -> dict[str, Any]:
        return _normalise(asdict(self))

    @classmethod
    def from_canonical(cls, payload: dict[str, Any]) -> ExecutionResult:
        return cls(
            success=bool(payload.get("success", False)),
            adapter_name=str(payload.get("adapter_name", "")),
            simulated=bool(payload.get("simulated", True)),
            executed_at=str(payload.get("executed_at", "")),
            output=str(payload.get("output", "")),
            error=payload.get("error"),
            execution_time_seconds=float(payload.get("execution_time_seconds", 0.0)),
        )


@dataclass(slots=True)
class VerificationResult:
    """Result of independent post-action outcome verification."""
    verified: bool
    method: str
    details: str
    verified_at: str = field(default_factory=utc_now_iso)
    error: str | None = None

    def canonical(self) -> dict[str, Any]:
        return _normalise(asdict(self))

    @classmethod
    def from_canonical(cls, payload: dict[str, Any]) -> VerificationResult:
        return cls(
            verified=bool(payload.get("verified", False)),
            method=str(payload.get("method", "")),
            details=str(payload.get("details", "")),
            verified_at=str(payload.get("verified_at", "")),
            error=payload.get("error"),
        )


@dataclass(slots=True)
class ResponseAction:
    """A granular, policy-governed action item in a response plan."""
    action_type: ActionType
    target: dict[str, Any]
    reason: str
    evidence_ids: list[str]
    risk_level: RiskLevel
    status: ActionStatus = ActionStatus.PROPOSED
    requires_approval: bool = True
    approval_status: ApprovalStatus = ApprovalStatus.PENDING
    action_id: str = field(default_factory=lambda: f"ACT-{uuid.uuid4().hex[:10].upper()}")
    approval_record: ApprovalRecord | None = None
    preconditions: list[str] = field(default_factory=list)
    rollback_or_recovery_plan: str = ""
    verification_criteria: str = ""
    execution_result: ExecutionResult | None = None
    verification_result: VerificationResult | None = None
    created_at: str = field(default_factory=utc_now_iso)
    updated_at: str = field(default_factory=utc_now_iso)

    def canonical(self) -> dict[str, Any]:
        return _normalise(asdict(self))

    @classmethod
    def from_canonical(cls, payload: dict[str, Any]) -> ResponseAction:
        app_rec = payload.get("approval_record")
        exec_res = payload.get("execution_result")
        ver_res = payload.get("verification_result")
        return cls(
            action_id=str(payload.get("action_id", "")),
            action_type=ActionType(payload.get("action_type")),
            target=dict(payload.get("target", {})),
            reason=str(payload.get("reason", "")),
            evidence_ids=list(payload.get("evidence_ids", [])),
            risk_level=RiskLevel(payload.get("risk_level", RiskLevel.MEDIUM)),
            status=ActionStatus(payload.get("status", ActionStatus.PROPOSED)),
            requires_approval=bool(payload.get("requires_approval", True)),
            approval_status=ApprovalStatus(payload.get("approval_status", ApprovalStatus.PENDING)),
            approval_record=ApprovalRecord.from_canonical(app_rec) if app_rec else None,
            preconditions=list(payload.get("preconditions", [])),
            rollback_or_recovery_plan=str(payload.get("rollback_or_recovery_plan", "")),
            verification_criteria=str(payload.get("verification_criteria", "")),
            execution_result=ExecutionResult.from_canonical(exec_res) if exec_res else None,
            verification_result=VerificationResult.from_canonical(ver_res) if ver_res else None,
            created_at=str(payload.get("created_at", "")),
            updated_at=str(payload.get("updated_at", "")),
        )


@dataclass(slots=True)
class RiskAssessment:
    """Synthesized risk and impact assessment."""
    classification: str
    confidence: float
    business_impact: str
    containment_urgency: str
    uncertainties: list[str] = field(default_factory=list)
    contradictory_evidence_count: int = 0

    def canonical(self) -> dict[str, Any]:
        return _normalise(asdict(self))

    @classmethod
    def from_canonical(cls, payload: dict[str, Any]) -> RiskAssessment:
        return cls(
            classification=str(payload.get("classification", "UNKNOWN")),
            confidence=float(payload.get("confidence", 0.0)),
            business_impact=str(payload.get("business_impact", "LOW")),
            containment_urgency=str(payload.get("containment_urgency", "LOW")),
            uncertainties=list(payload.get("uncertainties", [])),
            contradictory_evidence_count=int(payload.get("contradictory_evidence_count", 0)),
        )


@dataclass(slots=True)
class ResponsePlan:
    """Complete, auditable response plan linking investigation to decisions and actions."""
    case_id: str
    investigation_id: str
    risk_assessment: RiskAssessment
    decision: str
    actions: list[ResponseAction] = field(default_factory=list)
    supporting_evidence_ids: list[str] = field(default_factory=list)
    uncertainties: list[str] = field(default_factory=list)
    approval_requirements: list[str] = field(default_factory=list)
    policy_decisions: list[PolicyDecision] = field(default_factory=list)
    verification_plan: list[str] = field(default_factory=list)
    # Optional, validated interpretation retained as advisory context only.
    # It is never an authorization, a policy decision, or executable input.
    intelligence_context: dict[str, Any] | None = None
    status: PlanStatus = PlanStatus.PLANNING
    response_id: str = field(default_factory=lambda: f"RSP-{uuid.uuid4().hex[:10].upper()}")
    created_at: str = field(default_factory=utc_now_iso)
    updated_at: str = field(default_factory=utc_now_iso)

    def canonical(self) -> dict[str, Any]:
        return _normalise(asdict(self))

    @classmethod
    def from_canonical(cls, payload: dict[str, Any]) -> ResponsePlan:
        risk_raw = payload.get("risk_assessment", {})
        actions_raw = payload.get("actions", [])
        decisions_raw = payload.get("policy_decisions", [])
        return cls(
            response_id=str(payload.get("response_id", "")),
            case_id=str(payload.get("case_id", "")),
            investigation_id=str(payload.get("investigation_id", "")),
            created_at=str(payload.get("created_at", "")),
            updated_at=str(payload.get("updated_at", "")),
            status=PlanStatus(payload.get("status", PlanStatus.PLANNING)),
            risk_assessment=RiskAssessment.from_canonical(risk_raw),
            decision=str(payload.get("decision", "")),
            actions=[ResponseAction.from_canonical(a) for a in actions_raw],
            supporting_evidence_ids=list(payload.get("supporting_evidence_ids", [])),
            uncertainties=list(payload.get("uncertainties", [])),
            approval_requirements=list(payload.get("approval_requirements", [])),
            policy_decisions=[PolicyDecision.from_canonical(d) for d in decisions_raw],
            verification_plan=list(payload.get("verification_plan", [])),
            intelligence_context=(
                dict(payload["intelligence_context"])
                if isinstance(payload.get("intelligence_context"), Mapping)
                else None
            ),
        )
