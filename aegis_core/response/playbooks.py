"""Response Playbook Engine for AEGIS.

Maps investigation results (classification, attack techniques, affected processes,
files, and network telemetry) to structured, policy-gated response actions.
"""
from __future__ import annotations

from typing import Any

from .models import (
    ActionStatus,
    ActionType,
    ApprovalStatus,
    ResponseAction,
    RiskAssessment,
    RiskLevel,
)
from ..investigation.result import Classification, InvestigationResult, InvestigationStatus


class PlaybookEngine:
    """Translates an InvestigationResult into a set of proposed response actions."""

    def generate_plan_actions(
        self,
        investigation: InvestigationResult,
        case: dict[str, Any] | None = None,
    ) -> tuple[RiskAssessment, str, list[ResponseAction], list[str]]:
        """Generate risk assessment, high-level decision, and list of proposed actions."""
        classification = investigation.classification
        confidence = investigation.confidence
        uncertainties = list(investigation.uncertainties)
        contradictory_count = len(investigation.contradictory_evidence)

        # 1. Synthesize Risk Assessment
        if classification == Classification.MALICIOUS:
            business_impact = "HIGH" if confidence >= 0.75 else "MEDIUM"
            urgency = "HIGH"
            decision = (
                f"Active threat detected with {confidence:.0%} confidence. "
                "Containment actions proposed subject to human approval."
            )
        elif classification == Classification.SUSPICIOUS:
            business_impact = "MEDIUM"
            urgency = "MEDIUM"
            decision = (
                f"Suspicious activity observed with {confidence:.0%} confidence. "
                "Proportionate monitoring, notification, and selective containment proposed."
            )
        elif classification == Classification.BENIGN:
            business_impact = "LOW"
            urgency = "LOW"
            decision = (
                f"Activity evaluated as BENIGN with {confidence:.0%} confidence. "
                "No containment required; incident recorded for audit."
            )
        else:  # UNKNOWN
            business_impact = "LOW"
            urgency = "LOW"
            decision = (
                "Insufficient evidence for definitive classification. "
                "Proposing telemetry collection and human analyst review."
            )

        risk_assessment = RiskAssessment(
            classification=classification.value,
            confidence=confidence,
            business_impact=business_impact,
            containment_urgency=urgency,
            uncertainties=uncertainties,
            contradictory_evidence_count=contradictory_count,
        )

        actions: list[ResponseAction] = []
        approval_requirements: list[str] = []

        # All scenarios get an incident audit record action (Informational)
        record_action = ResponseAction(
            action_type=ActionType.RECORD_INCIDENT,
            target={"case_id": investigation.case_id, "classification": classification.value},
            reason=f"Record incident response evaluation for {investigation.case_id}.",
            evidence_ids=list(investigation.evidence_ids_used[:5]),
            risk_level=RiskLevel.LOW,
            status=ActionStatus.PROPOSED,
            requires_approval=False,
            approval_status=ApprovalStatus.NOT_REQUIRED,
            verification_criteria="Response record persisted in EvidenceStore.",
        )
        actions.append(record_action)

        # Handle BENIGN
        if classification == Classification.BENIGN:
            # Benign cases require NO containment
            return risk_assessment, decision, actions, approval_requirements

        # Handle UNKNOWN
        if classification == Classification.UNKNOWN:
            telemetry_action = ResponseAction(
                action_type=ActionType.REQUEST_ADDITIONAL_TELEMETRY,
                target={"host_id": case.get("host_id", "unknown") if case else "unknown"},
                reason="Collect additional telemetry to resolve investigation uncertainties.",
                evidence_ids=list(investigation.evidence_ids_used[:3]),
                risk_level=RiskLevel.LOW,
                status=ActionStatus.PROPOSED,
                requires_approval=False,
                approval_status=ApprovalStatus.NOT_REQUIRED,
                verification_criteria="Additional events observed in evidence store.",
            )
            notify_action = ResponseAction(
                action_type=ActionType.NOTIFY_RESPONDER,
                target={"role": "security_analyst", "case_id": investigation.case_id},
                reason="Notify Tier-2 responder for manual review of ambiguous activity.",
                evidence_ids=list(investigation.evidence_ids_used[:3]),
                risk_level=RiskLevel.LOW,
                status=ActionStatus.PROPOSED,
                requires_approval=False,
                approval_status=ApprovalStatus.NOT_REQUIRED,
                verification_criteria="Notification logged and delivered to queue.",
            )
            actions.extend([telemetry_action, notify_action])
            return risk_assessment, decision, actions, approval_requirements

        # Handle SUSPICIOUS & MALICIOUS
        # 1. Notify authorized responder
        notify_action = ResponseAction(
            action_type=ActionType.NOTIFY_RESPONDER,
            target={"role": "incident_responder", "case_id": investigation.case_id},
            reason=f"Alert responder to {classification.value} activity on host.",
            evidence_ids=list(investigation.evidence_ids_used[:5]),
            risk_level=RiskLevel.LOW,
            status=ActionStatus.PROPOSED,
            requires_approval=False,
            approval_status=ApprovalStatus.NOT_REQUIRED,
            verification_criteria="Notification acknowledged or queued.",
        )
        actions.append(notify_action)

        # 2. Process Termination Proposals
        for proc in investigation.affected_processes:
            pid = proc.get("pid")
            name = proc.get("name") or proc.get("exe") or "unknown"
            if pid is not None and isinstance(pid, int):
                # Locate evidence IDs linked to this process
                proc_eids = [
                    t.event_id for t in investigation.timeline if t.pid == pid
                ] or list(investigation.evidence_ids_used[:2])

                action = ResponseAction(
                    action_type=ActionType.TERMINATE_PROCESS,
                    target={"pid": pid, "name": name},
                    reason=f"Terminate process '{name}' (PID {pid}) identified in malicious execution chain.",
                    evidence_ids=proc_eids[:5],
                    risk_level=RiskLevel.HIGH if classification == Classification.MALICIOUS else RiskLevel.MEDIUM,
                    status=ActionStatus.PROPOSED,
                    requires_approval=True,
                    approval_status=ApprovalStatus.PENDING,
                    preconditions=["Process PID must be currently running", "Process must not be a protected OS PID"],
                    rollback_or_recovery_plan="Restart process from verified service or binary if required.",
                    verification_criteria=f"Process PID {pid} is no longer observed in running processes.",
                )
                actions.append(action)
                approval_requirements.append(
                    f"Action {action.action_id} (TERMINATE_PROCESS PID {pid}) requires recorded human approval."
                )

        # 3. File Quarantine Proposals
        for f in investigation.affected_files:
            path = f.get("path")
            if path:
                file_eids = [
                    t.event_id for t in investigation.timeline if "file" in t.event_kind
                ] or list(investigation.evidence_ids_used[:2])

                action = ResponseAction(
                    action_type=ActionType.QUARANTINE_FILE,
                    target={"path": path},
                    reason=f"Quarantine file '{path}' created or modified during suspicious chain.",
                    evidence_ids=file_eids[:5],
                    risk_level=RiskLevel.HIGH if classification == Classification.MALICIOUS else RiskLevel.MEDIUM,
                    status=ActionStatus.PROPOSED,
                    requires_approval=True,
                    approval_status=ApprovalStatus.PENDING,
                    preconditions=["File must exist at specified path", "Path must not be in protected OS directories"],
                    rollback_or_recovery_plan="Restore file from Aegis version vault or quarantine storage.",
                    verification_criteria=f"File at '{path}' no longer exists; vault copy preserved.",
                )
                actions.append(action)
                approval_requirements.append(
                    f"Action {action.action_id} (QUARANTINE_FILE '{path}') requires recorded human approval."
                )

        # 4. Network IP Block Proposals
        for net in investigation.network_activity:
            remote_ip = net.get("remote_ip")
            if remote_ip and remote_ip not in ("127.0.0.1", "::1", "0.0.0.0"):
                net_eids = [
                    t.event_id for t in investigation.timeline if "network" in t.event_kind
                ] or list(investigation.evidence_ids_used[:2])

                action = ResponseAction(
                    action_type=ActionType.BLOCK_NETWORK_IP,
                    target={"ip": str(remote_ip), "port": net.get("remote_port")},
                    reason=f"Block outbound communication to suspicious endpoint {remote_ip}.",
                    evidence_ids=net_eids[:5],
                    risk_level=RiskLevel.HIGH if classification == Classification.MALICIOUS else RiskLevel.MEDIUM,
                    status=ActionStatus.PROPOSED,
                    requires_approval=True,
                    approval_status=ApprovalStatus.PENDING,
                    preconditions=["Target IP is not loopback or local management network"],
                    rollback_or_recovery_plan="Remove firewall rule blocking remote IP.",
                    verification_criteria=f"Outbound connection attempts to {remote_ip} are rejected or dropped.",
                )
                actions.append(action)
                approval_requirements.append(
                    f"Action {action.action_id} (BLOCK_NETWORK_IP {remote_ip}) requires recorded human approval."
                )

        # 5. Account Review Proposal (if authentication activity is implicated)
        if any(t.technique_id in ("T1110", "T1078") for t in investigation.attack_techniques):
            action = ResponseAction(
                action_type=ActionType.ACCOUNT_REVIEW,
                target={"case_id": investigation.case_id},
                reason="Review affected accounts due to observed credential abuse / brute force patterns.",
                evidence_ids=list(investigation.evidence_ids_used[:3]),
                risk_level=RiskLevel.MEDIUM,
                status=ActionStatus.PROPOSED,
                requires_approval=True,
                approval_status=ApprovalStatus.PENDING,
                preconditions=["Valid user account identified in auth telemetry"],
                rollback_or_recovery_plan="Re-enable account or re-issue credentials if benign.",
                verification_criteria="Account security audit logged.",
            )
            actions.append(action)
            approval_requirements.append(
                f"Action {action.action_id} (ACCOUNT_REVIEW) requires recorded responder review."
            )

        return risk_assessment, decision, actions, approval_requirements
