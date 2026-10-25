"""Execution Adapters for the AEGIS Response Agent.

Provides:
- Base abstract adapter interface
- Safe DryRunExecutionAdapter (default: zero host modification)
- MockExecutionAdapter for deterministic unit tests
- Controlled LocalLabExecutionAdapter for isolated testing
"""
from __future__ import annotations

from abc import ABC, abstractmethod
import os
from pathlib import Path
import shutil
import time

from .models import (
    ActionStatus,
    ActionType,
    ExecutionResult,
    ResponseAction,
    utc_now_iso,
)


class ExecutionAdapter(ABC):
    """Abstract interface for executing approved response actions."""

    @abstractmethod
    def can_execute(self, action: ResponseAction) -> bool:
        """Return True if this adapter supports the given action type."""
        ...

    @abstractmethod
    def execute(self, action: ResponseAction, dry_run: bool = True) -> ExecutionResult:
        """Execute the action, either as a simulation (dry_run=True) or live."""
        ...

    @abstractmethod
    def rollback(self, action: ResponseAction) -> ExecutionResult:
        """Attempt rollback or recovery for an executed action."""
        ...


class DryRunExecutionAdapter(ExecutionAdapter):
    """Safe, non-destructive adapter that simulates all response actions.

    Default production adapter. It never performs real containment on the host.
    """

    SUPPORTED_TYPES = {
        ActionType.RECORD_INCIDENT,
        ActionType.NOTIFY_RESPONDER,
        ActionType.REQUEST_ADDITIONAL_TELEMETRY,
        ActionType.TERMINATE_PROCESS,
        ActionType.QUARANTINE_FILE,
        ActionType.BLOCK_NETWORK_IP,
        ActionType.ISOLATE_HOST,
        ActionType.ACCOUNT_REVIEW,
    }

    def can_execute(self, action: ResponseAction) -> bool:
        return action.action_type in self.SUPPORTED_TYPES

    def execute(self, action: ResponseAction, dry_run: bool = True) -> ExecutionResult:
        start_time = time.monotonic()
        t = action.target

        if action.action_type == ActionType.RECORD_INCIDENT:
            output = f"[DRY-RUN] Incident recorded: case_id={t.get('case_id')} classification={t.get('classification')}"
        elif action.action_type == ActionType.NOTIFY_RESPONDER:
            output = f"[DRY-RUN] Notification dispatched to {t.get('role')} for case {t.get('case_id')}"
        elif action.action_type == ActionType.REQUEST_ADDITIONAL_TELEMETRY:
            output = f"[DRY-RUN] Additional telemetry requested for host {t.get('host_id')}"
        elif action.action_type == ActionType.TERMINATE_PROCESS:
            output = f"[DRY-RUN] Simulated SIGTERM / TerminateProcess for PID {t.get('pid')} ({t.get('name')})"
        elif action.action_type == ActionType.QUARANTINE_FILE:
            output = f"[DRY-RUN] Simulated file quarantine: path='{t.get('path')}' -> vault:quarantine/"
        elif action.action_type == ActionType.BLOCK_NETWORK_IP:
            output = f"[DRY-RUN] Simulated firewall drop rule: remote_ip={t.get('ip')} port={t.get('port')}"
        elif action.action_type == ActionType.ISOLATE_HOST:
            output = f"[DRY-RUN] Simulated network isolation for host {t.get('host_id')}"
        elif action.action_type == ActionType.ACCOUNT_REVIEW:
            output = f"[DRY-RUN] Simulated account security review flag queued for {t.get('case_id')}"
        else:
            return ExecutionResult(
                success=False,
                adapter_name="DryRunExecutionAdapter",
                simulated=True,
                output="",
                error=f"Unsupported action type: {action.action_type.value}",
                execution_time_seconds=time.monotonic() - start_time,
            )

        elapsed = time.monotonic() - start_time
        return ExecutionResult(
            success=True,
            adapter_name="DryRunExecutionAdapter",
            simulated=True,
            output=output,
            execution_time_seconds=elapsed,
        )

    def rollback(self, action: ResponseAction) -> ExecutionResult:
        start_time = time.monotonic()
        return ExecutionResult(
            success=True,
            adapter_name="DryRunExecutionAdapter",
            simulated=True,
            output=f"[DRY-RUN] Simulated rollback for action {action.action_id} ({action.action_type.value})",
            execution_time_seconds=time.monotonic() - start_time,
        )


class MockExecutionAdapter(ExecutionAdapter):
    """Controllable adapter for automated unit and integration tests."""

    def __init__(
        self,
        failing_action_ids: set[str] | None = None,
        unsupported_action_types: set[ActionType] | None = None,
        simulate_timeout: bool = False,
    ) -> None:
        self.failing_action_ids = failing_action_ids or set()
        self.unsupported_action_types = unsupported_action_types or set()
        self.simulate_timeout = simulate_timeout
        self.executed_actions: list[ResponseAction] = []
        self.rolled_back_actions: list[ResponseAction] = []

    def can_execute(self, action: ResponseAction) -> bool:
        return action.action_type not in self.unsupported_action_types

    def execute(self, action: ResponseAction, dry_run: bool = True) -> ExecutionResult:
        self.executed_actions.append(action)
        if not self.can_execute(action):
            return ExecutionResult(
                success=False,
                adapter_name="MockExecutionAdapter",
                simulated=dry_run,
                output="",
                error=f"Action type {action.action_type.value} unsupported by mock adapter.",
            )

        if self.simulate_timeout:
            return ExecutionResult(
                success=False,
                adapter_name="MockExecutionAdapter",
                simulated=dry_run,
                output="",
                error="Adapter execution timed out after 30.0s.",
            )

        if action.action_id in self.failing_action_ids:
            return ExecutionResult(
                success=False,
                adapter_name="MockExecutionAdapter",
                simulated=dry_run,
                output="",
                error=f"Simulated adapter failure for action {action.action_id}.",
            )

        return ExecutionResult(
            success=True,
            adapter_name="MockExecutionAdapter",
            simulated=dry_run,
            output=f"Mock successfully executed {action.action_type.value} target={action.target}",
        )

    def rollback(self, action: ResponseAction) -> ExecutionResult:
        self.rolled_back_actions.append(action)
        return ExecutionResult(
            success=True,
            adapter_name="MockExecutionAdapter",
            simulated=True,
            output=f"Mock successfully rolled back {action.action_id}",
        )


class LocalLabExecutionAdapter(ExecutionAdapter):
    """Strictly bounded execution adapter for isolated lab / sandbox test environments.

    Safety constraints:
    - Only quarantines files located inside the designated sandbox root.
    - Process termination is limited to explicitly registered test PIDs.
    - It does not implement firewall or host-isolation operations.
    """

    def __init__(
        self,
        lab_root: Path,
        *,
        allowed_pids: set[int] | None = None,
        process_identities: dict[int, dict[str, object]] | None = None,
    ) -> None:
        self.lab_root = lab_root.resolve()
        self.allowed_pids = frozenset(allowed_pids or ())
        # A PID alone is not a durable identity. Demos that opt into live
        # termination register creation time and a run marker so a reused PID
        # or an unrelated process fails closed immediately before OS action.
        self.process_identities = {
            int(pid): dict(identity)
            for pid, identity in (process_identities or {}).items()
        }
        self.quarantine_dir = self.lab_root / "quarantine"
        self.quarantine_dir.mkdir(parents=True, exist_ok=True)

    def can_execute(self, action: ResponseAction) -> bool:
        return action.action_type in {ActionType.QUARANTINE_FILE, ActionType.TERMINATE_PROCESS}

    def execute(self, action: ResponseAction, dry_run: bool = True) -> ExecutionResult:
        if dry_run:
            return DryRunExecutionAdapter().execute(action, dry_run=True)

        start_time = time.monotonic()
        if action.action_type == ActionType.QUARANTINE_FILE:
            file_path_str = str(action.target.get("path", ""))
            src_path = Path(file_path_str)
            try:
                # Must be inside lab_root to be manipulated live
                resolved_src = src_path.resolve()
                if not resolved_src.is_relative_to(self.lab_root):
                    return ExecutionResult(
                        success=False,
                        adapter_name="LocalLabExecutionAdapter",
                        simulated=False,
                        error=f"Refusing to touch file outside lab_root: {src_path}",
                    )

                if not resolved_src.exists():
                    return ExecutionResult(
                        success=False,
                        adapter_name="LocalLabExecutionAdapter",
                        simulated=False,
                        error=f"Source file does not exist: {src_path}",
                    )

                dest_path = self.quarantine_dir / f"{resolved_src.name}.quarantine"
                if dest_path.exists():
                    return ExecutionResult(
                        success=False,
                        adapter_name="LocalLabExecutionAdapter",
                        simulated=False,
                        error=f"Refusing to overwrite existing quarantine artifact: {dest_path}",
                    )
                shutil.move(resolved_src, dest_path)
                return ExecutionResult(
                    success=True,
                    adapter_name="LocalLabExecutionAdapter",
                    simulated=False,
                    output=f"File {src_path} quarantined to {dest_path}",
                    execution_time_seconds=time.monotonic() - start_time,
                )
            except Exception as exc:
                return ExecutionResult(
                    success=False,
                    adapter_name="LocalLabExecutionAdapter",
                    simulated=False,
                    error=f"Quarantine failed: {exc}",
                    execution_time_seconds=time.monotonic() - start_time,
                )

        if action.action_type == ActionType.TERMINATE_PROCESS:
            pid = action.target.get("pid")
            try:
                if not isinstance(pid, int) or pid not in self.allowed_pids:
                    return ExecutionResult(
                        success=False,
                        adapter_name="LocalLabExecutionAdapter",
                        simulated=False,
                        error="Refusing process termination: PID is not an explicitly registered lab process.",
                    )
                identity_error = self._verify_process_identity(pid)
                if identity_error is not None:
                    return ExecutionResult(
                        success=False,
                        adapter_name="LocalLabExecutionAdapter",
                        simulated=False,
                        error=identity_error,
                    )
                import subprocess
                if os.name == "nt":
                    result = subprocess.run(
                        ["taskkill", "/F", "/PID", str(pid)],
                        stdout=subprocess.DEVNULL,
                        stderr=subprocess.DEVNULL,
                        check=False,
                    )
                    if result.returncode != 0:
                        return ExecutionResult(
                            success=False,
                            adapter_name="LocalLabExecutionAdapter",
                            simulated=False,
                            error=f"taskkill failed for registered lab PID {pid} (exit {result.returncode}).",
                        )
                else:
                    os.kill(pid, 15)
                time.sleep(0.2)
                return ExecutionResult(
                    success=True,
                    adapter_name="LocalLabExecutionAdapter",
                    simulated=False,
                    output=f"Lab process PID {pid} terminated via OS signal.",
                    execution_time_seconds=time.monotonic() - start_time,
                )
            except Exception as exc:
                return ExecutionResult(
                    success=False,
                    adapter_name="LocalLabExecutionAdapter",
                    simulated=False,
                    error=f"Process termination failed: {exc}",
                    execution_time_seconds=time.monotonic() - start_time,
                )
        return ExecutionResult(
            success=False,
            adapter_name="LocalLabExecutionAdapter",
            simulated=False,
            error=f"No live lab handler exists for {action.action_type.value}.",
            execution_time_seconds=time.monotonic() - start_time,
        )

    def rollback(self, action: ResponseAction) -> ExecutionResult:
        if action.action_type == ActionType.QUARANTINE_FILE:
            file_path_str = str(action.target.get("path", ""))
            src_path = Path(file_path_str)
            quarantined = self.quarantine_dir / f"{src_path.name}.quarantine"
            if quarantined.exists():
                try:
                    shutil.move(quarantined, src_path)
                    return ExecutionResult(
                        success=True,
                        adapter_name="LocalLabExecutionAdapter",
                        simulated=False,
                        output=f"File {src_path} restored from quarantine.",
                    )
                except Exception as exc:
                    return ExecutionResult(
                        success=False,
                        adapter_name="LocalLabExecutionAdapter",
                        simulated=False,
                        error=f"Rollback failed: {exc}",
                    )
        return ExecutionResult(
            success=False,
            adapter_name="LocalLabExecutionAdapter",
            simulated=False,
            error="Rollback not supported for this action type.",
        )

    def _verify_process_identity(self, pid: int) -> str | None:
        """Confirm an optional registered identity just before termination."""
        expected = self.process_identities.get(pid)
        if expected is None:
            return None
        try:
            import psutil
            process = psutil.Process(pid)
            actual_create_time = process.create_time()
            expected_create_time = expected.get("create_time")
            if not isinstance(expected_create_time, (int, float)):
                return "Refusing process termination: registered identity lacks create_time."
            if abs(actual_create_time - float(expected_create_time)) > 0.01:
                return "Refusing process termination: PID creation time no longer matches registered lab process."
            marker = expected.get("marker")
            if not isinstance(marker, str) or not marker:
                return "Refusing process termination: registered identity lacks demo run marker."
            if marker not in " ".join(process.cmdline()):
                return "Refusing process termination: process command line does not match registered demo run marker."
        except ImportError:
            return "Refusing process termination: psutil is required to verify a registered process identity."
        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
            return "Refusing process termination: registered lab process is unavailable for identity verification."
        except Exception as exc:
            return f"Refusing process termination: identity verification failed ({type(exc).__name__})."
        return None
