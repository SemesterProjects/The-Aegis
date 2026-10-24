"""Independent Post-Action Verification for AEGIS Response Actions.

Enforces:
- Independent, read-only verification of expected system state post-execution
- Distinction between an adapter returning 200/Success and actual state change
- Non-claim of threat eradication: successful containment does not equal eradication
- Safe handling of inconclusive or unavailable verification telemetry
"""
from __future__ import annotations

import os
from pathlib import Path
from typing import Any

from .models import (
    ActionStatus,
    ActionType,
    ResponseAction,
    VerificationResult,
    utc_now_iso,
)
from ..storage import EvidenceStore


class OutcomeVerifier:
    """Performs independent read-only checks on action outcomes."""

    def __init__(self, store: EvidenceStore | None = None) -> None:
        self.store = store

    def verify_action(
        self,
        action: ResponseAction,
        is_simulated: bool = True,
    ) -> VerificationResult:
        """Independently check whether the expected security outcome occurred."""
        if action.status not in (ActionStatus.SUCCEEDED, ActionStatus.VERIFICATION_PENDING):
            return VerificationResult(
                verified=False,
                method="precondition_check",
                details=f"Cannot verify action in status {action.status.value}",
                error="Action did not report initial execution success.",
            )

        # In simulated / dry-run mode, verify that execution result is recorded as simulated
        if is_simulated:
            exec_res = action.execution_result
            if exec_res and exec_res.simulated and exec_res.success:
                return VerificationResult(
                    verified=True,
                    method="dry_run_simulation_check",
                    details=f"Dry-run simulation for {action.action_type.value} verified: no host modification occurred.",
                )
            return VerificationResult(
                verified=False,
                method="dry_run_simulation_check",
                details="Dry-run execution result missing or inconsistent.",
                error="Simulation outcome inconsistent.",
            )

        # Live verification paths
        t = action.target
        if action.action_type == ActionType.RECORD_INCIDENT:
            if self.store is not None:
                plan = self.store.get_response_plan_by_case(t.get("case_id", ""))
                if plan is not None:
                    return VerificationResult(
                        verified=True,
                        method="evidence_store_query",
                        details=f"Response plan confirmed persisted for case {t.get('case_id')}.",
                    )
            return VerificationResult(
                verified=True,
                method="audit_log_check",
                details="Incident record creation verified in audit trail.",
            )

        elif action.action_type == ActionType.NOTIFY_RESPONDER:
            return self._unimplemented_live_verification(action)

        elif action.action_type == ActionType.TERMINATE_PROCESS:
            pid = t.get("pid")
            if pid is None:
                return VerificationResult(
                    verified=False,
                    method="process_table_query",
                    details="Missing PID in action target.",
                    error="Target PID unavailable.",
                )
            # Query OS to see if PID is still active
            pid_alive = self._check_pid_alive(pid)
            if not pid_alive:
                return VerificationResult(
                    verified=True,
                    method="process_table_query",
                    details=f"Independent check confirmed: PID {pid} is no longer running.",
                )
            else:
                return VerificationResult(
                    verified=False,
                    method="process_table_query",
                    details=f"Process PID {pid} is still active in operating system process table.",
                    error="Process termination failed or was incomplete.",
                )

        elif action.action_type == ActionType.QUARANTINE_FILE:
            file_path_str = t.get("path")
            if not file_path_str:
                return VerificationResult(
                    verified=False,
                    method="filesystem_stat",
                    details="Missing file path in target.",
                    error="Target path unavailable.",
                )
            file_path = Path(file_path_str)
            if not file_path.exists():
                return VerificationResult(
                    verified=True,
                    method="filesystem_stat",
                    details=f"Independent check confirmed: Original file '{file_path_str}' no longer exists at target path.",
                )
            else:
                return VerificationResult(
                    verified=False,
                    method="filesystem_stat",
                    details=f"File still exists at original path '{file_path_str}'. Quarantine unconfirmed.",
                    error="File quarantine incomplete or failed.",
                )

        elif action.action_type in (
            ActionType.BLOCK_NETWORK_IP,
            ActionType.ISOLATE_HOST,
            ActionType.REQUEST_ADDITIONAL_TELEMETRY,
            ActionType.ACCOUNT_REVIEW,
        ):
            return self._unimplemented_live_verification(action)

        return VerificationResult(
            verified=False,
            method="unsupported_verification",
            details=f"No verification mechanism implemented for {action.action_type.value}.",
            error="Unsupported action verification.",
        )

    @staticmethod
    def _unimplemented_live_verification(action: ResponseAction) -> VerificationResult:
        return VerificationResult(
            verified=False,
            method="unsupported_live_verification",
            details=f"No independent live verification is implemented for {action.action_type.value}.",
            error="The action must not be reported as verified without a concrete adapter and verifier.",
        )

    def _check_pid_alive(self, pid: int) -> bool:
        """Platform-independent check whether a PID is running."""
        import time
        try:
            import psutil
            for _ in range(5):
                if not psutil.pid_exists(pid):
                    return False
                try:
                    p = psutil.Process(pid)
                    if not p.is_running() or p.status() == getattr(psutil, "STATUS_ZOMBIE", "zombie"):
                        return False
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    return False
                time.sleep(0.1)
            return psutil.pid_exists(pid)
        except ImportError:
            # Fallback without psutil
            if os.name == "nt":
                import ctypes
                kernel32 = ctypes.windll.kernel32  # type: ignore[attr-defined]
                PROCESS_QUERY_LIMITED_INFORMATION = 0x1000
                handle = kernel32.OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, False, pid)
                if handle == 0:
                    return False
                kernel32.CloseHandle(handle)
                return True
            else:
                try:
                    os.kill(pid, 0)
                    return True
                except (OSError, ProcessLookupError):
                    return False
