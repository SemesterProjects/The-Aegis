"""Centralized Response Policy and Safety Gate for AEGIS.

Enforces:
- Least privilege & default deny
- Mandatory human approval for disruptive operations
- Dry-run mode by default
- Target scope validation against investigation evidence
- Protection of critical system resources
- Prompt injection immunity (telemetry treated strictly as data)
- Timeouts and safety limits
"""
from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
import ipaddress
from pathlib import Path
from typing import Any, Iterable

from .models import (
    ActionStatus,
    ActionType,
    ApprovalRecord,
    ApprovalStatus,
    PolicyDecision,
    ResponseAction,
    RiskLevel,
    utc_now,
)
from ..investigation.result import Classification, InvestigationResult, InvestigationStatus
from ..storage import EvidenceStore


# Core protected system processes
PROTECTED_PIDS = {0, 4, 1}
PROTECTED_PROCESS_NAMES = {
    "system", "system idle process", "smss.exe", "csrss.exe", "wininit.exe",
    "services.exe", "lsass.exe", "svchost.exe", "init", "systemd", "launchd"
}

# Critical OS paths that must never be quarantined or deleted
PROTECTED_SYSTEM_PATHS = {
    r"c:\windows\system32",
    r"c:\windows\syswow64",
    r"c:\windows\explorer.exe",
    r"/bin",
    r"/sbin",
    r"/usr/bin",
    r"/usr/sbin",
    r"/lib",
    r"/lib64",
}

# Protected loopback / private management addresses
PROTECTED_IPS = {
    "127.0.0.1",
    "::1",
    "0.0.0.0",
}


@dataclass(slots=True)
class ResponsePolicyConfig:
    """Configurable boundaries for response safety."""
    dry_run: bool = True
    allow_containment_on_suspicious: bool = True  # requires explicit approval
    min_confidence_for_containment: float = 0.60
    allowed_action_types: set[ActionType] = field(default_factory=lambda: {
        ActionType.RECORD_INCIDENT,
        ActionType.NOTIFY_RESPONDER,
        ActionType.REQUEST_ADDITIONAL_TELEMETRY,
        ActionType.TERMINATE_PROCESS,
        ActionType.QUARANTINE_FILE,
        ActionType.BLOCK_NETWORK_IP,
        ActionType.ISOLATE_HOST,
        ActionType.ACCOUNT_REVIEW,
    })
    disruptive_action_types: set[ActionType] = field(default_factory=lambda: {
        ActionType.TERMINATE_PROCESS,
        ActionType.QUARANTINE_FILE,
        ActionType.BLOCK_NETWORK_IP,
        ActionType.ISOLATE_HOST,
        ActionType.ACCOUNT_REVIEW,
    })
    max_action_execution_seconds: float = 30.0


class PolicyEvaluator:
    """Evaluates proposed actions against system safety invariants and response policy."""

    def __init__(self, config: ResponsePolicyConfig | None = None) -> None:
        self.config = config or ResponsePolicyConfig()

    def evaluate_action(
        self,
        action: ResponseAction,
        investigation: InvestigationResult,
        store: EvidenceStore | None = None,
        is_live_execution: bool = False,
    ) -> PolicyDecision:
        """Evaluate whether an action is allowed, and whether it requires approval."""
        violations: list[str] = []
        policy_name = "AegisCoreResponsePolicy-v1"

        # 1. Action Type Allowlist (Default Deny)
        if action.action_type not in self.config.allowed_action_types:
            violations.append(f"Action type {action.action_type.value} is not in the allowed action types.")

        # 2. Dry-Run Policy Guard
        if is_live_execution and self.config.dry_run:
            violations.append("Live execution attempted while system policy mandates dry_run=True.")

        # 3. Investigation Status Validation
        if investigation.status == InvestigationStatus.ERROR:
            violations.append(f"Investigation status is ERROR; no response actions may be executed.")
        elif investigation.status == InvestigationStatus.PARTIAL:
            if action.action_type in self.config.disruptive_action_types:
                violations.append(
                    f"Investigation is PARTIAL; disruptive action {action.action_type.value} is forbidden."
                )

        # 4. Classification Constraints
        is_disruptive = action.action_type in self.config.disruptive_action_types
        if investigation.classification == Classification.BENIGN:
            if is_disruptive:
                violations.append(
                    f"Investigation classified as BENIGN; disruptive action {action.action_type.value} is prohibited."
                )
        elif investigation.classification == Classification.UNKNOWN:
            if is_disruptive:
                violations.append(
                    f"Investigation classified as UNKNOWN; disruptive action {action.action_type.value} is prohibited. Human review or additional telemetry required."
                )
        elif investigation.classification == Classification.SUSPICIOUS:
            if is_disruptive and not self.config.allow_containment_on_suspicious:
                violations.append(
                    f"Policy disallows containment on SUSPICIOUS classification without explicit escalation."
                )

        # 5. Confidence Bounds
        if is_disruptive and investigation.confidence < self.config.min_confidence_for_containment:
            violations.append(
                f"Investigation confidence ({investigation.confidence:.2f}) is below minimum required for containment ({self.config.min_confidence_for_containment:.2f})."
            )

        # 6. Evidence Linkage & Integrity
        if not action.evidence_ids:
            violations.append("Action has no supporting evidence references.")
        else:
            # All action evidence IDs must be a subset of the investigation's used evidence
            investigation_eids = set(investigation.evidence_ids_used)
            missing_from_inv = [eid for eid in action.evidence_ids if eid not in investigation_eids]
            if missing_from_inv:
                violations.append(
                    f"Action references evidence IDs not present in investigation: {missing_from_inv[:3]}"
                )

            # If store is provided, verify evidence IDs actually exist in store
            if store is not None:
                for eid in action.evidence_ids:
                    if store.get_event_by_id(eid) is None:
                        violations.append(f"Referenced evidence ID {eid} does not exist in EvidenceStore.")
                        break

        # 7. Target Validation and Scope Constraints
        self._validate_target_safety(action, investigation, violations)

        # 8. Approval Verification (if attempting execution)
        requires_approval = is_disruptive
        if requires_approval and is_live_execution:
            self._verify_approval_for_execution(action, violations)

        allowed = len(violations) == 0
        reason = "All policy constraints satisfied." if allowed else "; ".join(violations)

        return PolicyDecision(
            allowed=allowed,
            requires_approval=requires_approval,
            policy_name=policy_name,
            reason=reason,
            violations=violations,
        )

    def _validate_target_safety(
        self,
        action: ResponseAction,
        investigation: InvestigationResult,
        violations: list[str],
    ) -> None:
        """Validate that targets are well-formed, scoped to the incident, and not protected system assets."""
        target = action.target

        if action.action_type == ActionType.TERMINATE_PROCESS:
            pid = target.get("pid")
            name = str(target.get("name", "")).lower()
            if pid is None or not isinstance(pid, int):
                violations.append("TERMINATE_PROCESS requires a valid integer 'pid' target.")
                return
            if pid in PROTECTED_PIDS or pid <= 0:
                violations.append(f"Attempted termination of protected system PID: {pid}.")
            if name in PROTECTED_PROCESS_NAMES:
                violations.append(f"Attempted termination of protected system process name: {name}.")

            # Scope check: PID must appear in investigation affected_processes or timeline
            inv_pids = {p.get("pid") for p in investigation.affected_processes if "pid" in p}
            inv_pids.update(
                t.pid for t in investigation.timeline if t.pid is not None
            )
            if pid not in inv_pids:
                violations.append(
                    f"Process PID {pid} is not present in investigation affected processes or timeline."
                )

        elif action.action_type == ActionType.QUARANTINE_FILE:
            file_path = str(target.get("path", "")).strip()
            if not file_path:
                violations.append("QUARANTINE_FILE requires a non-empty 'path' target.")
                return
            clean_path = file_path.lower().replace("/", "\\")
            for protected in PROTECTED_SYSTEM_PATHS:
                if clean_path == protected or clean_path.startswith(protected + "\\") or clean_path.startswith(protected + "/"):
                    violations.append(f"Attempted quarantine of protected system file path: {file_path}.")
                    break

            # Scope check: path must be in affected_files or IOCs (slash-normalized)
            inv_paths = {
                str(f.get("path", "")).lower().replace("/", "\\") for f in investigation.affected_files if "path" in f
            }
            inv_paths.update(
                ioc.value.lower().replace("/", "\\") for ioc in investigation.iocs if ioc.type == "file_path"
            )
            if clean_path not in inv_paths and not any(clean_path.endswith(p) or p.endswith(clean_path) for p in inv_paths if p):
                violations.append(
                    f"File path '{file_path}' is not present in investigation affected files or IOCs."
                )

        elif action.action_type == ActionType.BLOCK_NETWORK_IP:
            ip_str = str(target.get("ip", "")).strip()
            if not ip_str:
                violations.append("BLOCK_NETWORK_IP requires an 'ip' target.")
                return
            if ip_str in PROTECTED_IPS:
                violations.append(f"Attempted network block of protected IP address: {ip_str}.")
            try:
                ip_obj = ipaddress.ip_address(ip_str)
                if ip_obj.is_loopback:
                    violations.append(f"Cannot block loopback IP: {ip_str}.")
            except ValueError:
                violations.append(f"Invalid IP address format: {ip_str}.")

            # Scope check: IP must be in network_activity or IOCs
            inv_ips = {str(n.get("remote_ip", "")) for n in investigation.network_activity if "remote_ip" in n}
            inv_ips.update(
                ioc.value for ioc in investigation.iocs if ioc.type in ("ip", "network_endpoint")
            )
            if ip_str not in inv_ips and not any(ip_str in i for i in inv_ips if i):
                violations.append(
                    f"IP address '{ip_str}' is not present in investigation network activity or IOCs."
                )

        elif action.action_type == ActionType.ISOLATE_HOST:
            host_id = str(target.get("host_id", "")).strip()
            if not host_id:
                violations.append("ISOLATE_HOST requires a 'host_id' target.")

    def _verify_approval_for_execution(
        self,
        action: ResponseAction,
        violations: list[str],
    ) -> None:
        """Verify that a disruptive action has a valid, unexpired approval record."""
        record = action.approval_record
        if record is None:
            violations.append(
                f"Action {action.action_id} requires explicit human approval before execution, but none was recorded."
            )
            return

        if record.status != ApprovalStatus.APPROVED:
            violations.append(
                f"Action approval record has invalid status: {record.status.value}."
            )

        if not record.approver_id.strip():
            violations.append("Approval record is missing authorized approver identity.")

        if record.expires_at:
            try:
                exp_dt = datetime.fromisoformat(record.expires_at)
                if utc_now() > exp_dt:
                    violations.append(f"Approval for action {action.action_id} expired at {record.expires_at}.")
            except ValueError:
                violations.append(f"Malformed approval expiration timestamp: {record.expires_at}.")
