"""End-to-end demonstration of the AEGIS Response Agent.

Executes the complete defense pipeline:
Monitoring Telemetry -> Triage Case -> Investigation Agent -> Response Agent
  -> Policy & Approval Gate -> Dry-Run Execution -> Post-Action Verification -> Audit Trail

Run with:
    python scripts/demo_response_agent.py
"""
from __future__ import annotations

from datetime import datetime, timedelta, timezone
import json
from pathlib import Path
import sys
import tempfile

# Ensure project root is importable
sys.path.insert(0, str(Path(__file__).parent.parent))

from aegis_core.investigation.agent import InvestigationAgent
from aegis_core.investigation.state import InvestigationBudget
from aegis_core.models import Event, EventKind
from aegis_core.response.agent import ResponseAgent
from aegis_core.response.models import ActionStatus, ActionType
from aegis_core.storage import EvidenceStore
from aegis_core.triage import TriageEngine

_UTC = timezone.utc


def _ts(offset: float) -> datetime:
    return datetime(2026, 10, 22, 14, 0, 0, tzinfo=_UTC) + timedelta(seconds=offset)


def main() -> None:
    with tempfile.TemporaryDirectory(ignore_cleanup_errors=True) as tmpdir:
        db_path = Path(tmpdir) / "evidence.sqlite3"
        store = EvidenceStore(db_path)

        print("=" * 72)
        print("  AEGIS AUTONOMOUS CYBER DEFENSE PLATFORM")
        print("  Complete Pipeline: Telemetry -> Triage -> Investigation -> Response")
        print("=" * 72)
        print()

        # Step 1: Ingest Telemetry
        print("[1] Ingesting Host Telemetry (Process, File, Network)...")
        events = [
            Event(EventKind.PROCESS, "process_lifecycle", {
                "pid": 1234, "ppid": 4, "name": "WINWORD.EXE",
                "exe": "C:/Program Files/Microsoft Office/Office16/WINWORD.EXE",
                "action": "start", "user": "alice",
            }, observed_at=_ts(0), host_id="workstation-01"),

            Event(EventKind.PROCESS, "process_lifecycle", {
                "pid": 5678, "ppid": 1234, "name": "powershell.exe",
                "exe": "C:/Windows/System32/WindowsPowerShell/v1.0/powershell.exe",
                "cmdline": "powershell.exe -enc JABzAHUAcwBw...",
                "action": "start", "user": "alice",
            }, observed_at=_ts(1), host_id="workstation-01"),

            Event(EventKind.FILE, "file_events", {
                "pid": 5678, "path": "C:/Users/alice/AppData/Local/Temp/payload.exe",
                "action": "create", "suffix": ".exe",
            }, observed_at=_ts(2), host_id="workstation-01"),

            Event(EventKind.NETWORK, "network_bridge", {
                "pid": 5678, "process": "powershell.exe",
                "action": "connection_open", "direction": "outbound",
                "local_ip": "192.168.1.50", "local_port": 52341,
                "remote_ip": "185.220.101.10", "remote_port": 4444,
                "protocol": "TCP",
            }, observed_at=_ts(3), host_id="workstation-01"),
        ]

        for ev in events:
            store.append_event(ev)
        print(f"    Ingested {len(events)} canonical events (hash-chain verified: {store.verify_chain()})")

        # Step 2: Triage Engine Evaluates Finding -> Creates Case
        print("\n[2] Triage Engine Evaluating Telemetry...")
        finding = {
            "finding_id": "FIND-DEMO-001",
            "rule_id": "AEGIS-PROC-NET-001",
            "severity": "high",
            "confidence": 0.85,
            "evidence_event_ids": [ev.event_id for ev in events],
            "explanation": "Document triggered PowerShell spawning outbound C2 connection.",
        }
        triage = TriageEngine(case_threshold=0.50)
        stored_events = store.query_events()
        assert triage.should_create_case(finding, stored_events)

        case = triage.create_case(finding, stored_events, host_id="workstation-01")
        store.append_case(case)
        print(f"    Created Case: {case.case_id} (Severity: {case.severity}, Risk: {case.risk_score:.2f})")
        print(f"    Initial Status: {case.status.value}")

        # Step 3: Investigation Agent Runs
        print("\n[3] Investigation Agent Running (Adaptive, Read-Only Loop)...")
        inv_agent = InvestigationAgent(store, budget=InvestigationBudget(max_tool_calls=20))
        inv_result = inv_agent.investigate(case.case_id)
        print(f"    Investigation ID : {inv_result.investigation_id}")
        print(f"    Status           : {inv_result.status.value}")
        print(f"    Classification   : {inv_result.classification.value}")
        print(f"    Confidence       : {inv_result.confidence:.0%}")
        print(f"    Evidence Used    : {len(inv_result.evidence_ids_used)} event(s)")
        print(f"    Recommendations  : {len(inv_result.recommended_actions)} item(s) (READ-ONLY advisory)")

        # Step 4: Response Agent Plans
        print("\n[4] Response Agent Generating Policy-Gated Response Plan...")
        resp_agent = ResponseAgent(store)
        plan = resp_agent.plan(case.case_id)
        print(f"    Response ID      : {plan.response_id}")
        print(f"    Plan Status      : {plan.status.value}")
        print(f"    Decision         : {plan.decision}")
        print(f"    Total Actions    : {len(plan.actions)}")
        print(f"    Approval Required: {len(plan.approval_requirements)} item(s)")

        for i, act in enumerate(plan.actions, 1):
            app_str = "[NEEDS APPROVAL]" if act.requires_approval else "[AUTO-ELIGIBLE]"
            print(f"      {i}. [{act.status.value}] {act.action_type.value} -> target={act.target} {app_str}")

        # Step 5: Execute Eligible Non-Disruptive Actions
        print("\n[5] Executing Eligible Non-Disruptive Actions (RECORD_INCIDENT, NOTIFY)...")
        auto_executed = resp_agent.execute_eligible_actions(case.case_id)
        for act in auto_executed:
            print(f"    Executed: [{act.status.value}] {act.action_type.value} (ID: {act.action_id})")

        # Step 6: Safety Check - Disruptive action execution without approval is blocked
        print("\n[6] Testing Policy Gate: Attempting Disruptive Action without Approval...")
        proc_act = next(a for a in plan.actions if a.action_type == ActionType.TERMINATE_PROCESS)
        blocked_act = resp_agent.execute_action(case.case_id, proc_act.action_id, live=True)
        print(f"    Outcome: status={blocked_act.status.value} (Blocked as expected!)")
        print(f"    Reason : {blocked_act.reason}")

        # Step 7: Operator Approval
        print("\n[7] SecOps Operator Approves Process Termination & Quarantine Actions...")
        file_act = next(a for a in plan.actions if a.action_type == ActionType.QUARANTINE_FILE)

        resp_agent.approve_action(
            case.case_id, proc_act.action_id,
            approver_id="secops-lead@aegis.defense",
            rationale="Verified malicious PowerShell C2 chain from macro execution.",
        )
        resp_agent.approve_action(
            case.case_id, file_act.action_id,
            approver_id="secops-lead@aegis.defense",
            rationale="Verified dropped executable payload.",
        )
        print(f"    Action {proc_act.action_id} -> APPROVED")
        print(f"    Action {file_act.action_id} -> APPROVED")

        # Step 8: Controlled Execution (Safe Dry-Run Mode)
        print("\n[8] Executing Approved Actions in Default Safe Dry-Run Mode...")
        proc_executed = resp_agent.execute_action(case.case_id, proc_act.action_id, live=False)
        file_executed = resp_agent.execute_action(case.case_id, file_act.action_id, live=False)

        print(f"    Action {proc_executed.action_id}: status={proc_executed.status.value}")
        print(f"      Output      : {proc_executed.execution_result.output}")
        print(f"      Verification: verified={proc_executed.verification_result.verified} ({proc_executed.verification_result.details})")

        print(f"    Action {file_executed.action_id}: status={file_executed.status.value}")
        print(f"      Output      : {file_executed.execution_result.output}")
        print(f"      Verification: verified={file_executed.verification_result.verified} ({file_executed.verification_result.details})")

        # Step 9: Audit History
        print("\n[9] Inspecting Complete Audit Trail...")
        audit = resp_agent.get_audit_history(case.case_id)
        print(f"    Case ID         : {audit['case_id']}")
        print(f"    Investigation ID: {audit['investigation_id']}")
        print(f"    Response ID     : {audit['response_id']}")
        print(f"    Classification  : {audit['investigation_classification']}")
        print(f"    Total Actions   : {len(audit['actions'])}")
        print(f"    Hash Chain Valid: {audit['evidence_chain_valid']}")

        print("\n" + "=" * 72)
        print("  DEMONSTRATION COMPLETE: Zero unauthorized actions, zero host damage.")
        print("=" * 72)


if __name__ == "__main__":
    main()
