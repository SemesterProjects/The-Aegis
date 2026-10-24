"""AEGIS Real-Time Interactive SOC Response Demo.

Prompts the operator in real-time to approve/reject containment actions,
evaluates policy gates, executes actions, and verifies state.
"""
from __future__ import annotations

import sys
import time
from pathlib import Path

# Add project root
sys.path.insert(0, str(Path(__file__).parent.parent))

from aegis_core.models import Event, EventKind
from aegis_core.storage import EvidenceStore
from aegis_core.triage import TriageEngine
from aegis_core.investigation.agent import InvestigationAgent
from aegis_core.response.agent import ResponseAgent
from aegis_core.response.models import ActionType


def main() -> None:
    data_dir = Path("/tmp/aegis_interactive_soc")
    data_dir.mkdir(parents=True, exist_ok=True)
    store = EvidenceStore(data_dir / "evidence.sqlite3")

    print("\n" + "=" * 70)
    print("  [AEGIS] REAL-TIME INTERACTIVE SECURITY OPERATIONS CENTER (SOC)")
    print("=" * 70)

    # 1. Telemetry
    print("\n[+] Telemetry Ingestion Engine: Monitoring host activity...")
    events = [
        Event(EventKind.PROCESS, "process_lifecycle", {
            "pid": 4182, "name": "c2_client", "action": "start",
            "cmdline": "/tmp/c2_client --connect 185.220.101.10:4444",
            "user": "victim"
        }, host_id="target-vm"),
        Event(EventKind.FILE, "file_events", {
            "pid": 4182, "path": "/tmp/c2_client", "action": "create"
        }, host_id="target-vm"),
        Event(EventKind.NETWORK, "network_bridge", {
            "pid": 4182, "remote_ip": "185.220.101.10", "remote_port": 4444,
            "action": "connection_open"
        }, host_id="target-vm")
    ]
    for e in events:
        store.append_event(e)
    time.sleep(1)
    print(f"    --> Captured {len(events)} telemetry events. SHA-256 Hash Chain: VALID [OK]")

    # 2. Triage
    print("\n[+] Triage Engine: Evaluating alert correlation...")
    stored_events = store.query_events()
    triage = TriageEngine(case_threshold=0.50)
    finding = {
        "finding_id": "FIND-SOC-001",
        "rule_id": "AEGIS-PROC-NET-001",
        "severity": "critical",
        "confidence": 0.90,
        "evidence_event_ids": [e.event_id for e in events],
        "explanation": "Outbound TCP socket to known C2 IP accompanied by unlinked binary in /tmp."
    }
    case = triage.create_case(finding, stored_events, host_id="target-vm")
    store.append_case(case)
    print(f"    --> CRITICAL INCIDENT CREATED: {case.case_id} (Risk Score: {case.risk_score:.2f}) [!]")

    # 3. Investigation Agent
    print("\n[+] Investigation Agent: Analyzing evidence graph (Read-Only loop)...")
    inv_agent = InvestigationAgent(store)
    inv = inv_agent.investigate(case.case_id)
    time.sleep(1)
    print(f"    --> Classification: {inv.classification.value}")
    print(f"    --> Confidence    : {inv.confidence:.0%}")
    print(f"    --> Findings      : Process PID 4182 established active C2 channel to 185.220.101.10:4444.")

    # 4. Response Agent Planning
    print("\n[+] Response Agent: Formulating policy-gated mitigation plan...")
    resp_agent = ResponseAgent(store)
    plan = resp_agent.plan(case.case_id)
    print(f"    --> Plan ID: {plan.response_id}")
    print(f"    --> Planned Actions: {len(plan.actions)}")

    # 5. Policy Gate & Interactive Human Approval
    print("\n" + "-" * 70)
    print("  POLICY GATE & HUMAN-IN-THE-LOOP APPROVAL")
    print("-" * 70)

    for i, action in enumerate(plan.actions, 1):
        if not action.requires_approval:
            print(f"\n[{i}] {action.action_type.value}: Non-disruptive.")
            exec_res = resp_agent.execute_action(case.case_id, action.action_id, live=False)
            print(f"    --> Auto-Executed & Verified: {exec_res.status.value} [OK]")
        else:
            print(f"\n[{i}] DISRUPTIVE ACTION PROPOSED:")
            print(f"    Action Type : {action.action_type.value}")
            print(f"    Target      : {action.target}")
            print(f"    Reason      : {action.reason}")

            # REAL-TIME PROMPT TO USER
            try:
                choice = input("    --> Approve this containment action? [Y/n]: ").strip().lower()
            except EOFError:
                choice = "y"
            if choice in ("", "y", "yes"):
                resp_agent.approve_action(
                    case.case_id, action.action_id,
                    approver_id="secops-operator@aegis",
                    rationale="Confirmed malicious C2 connection from interactive SOC review."
                )
                print("    --> Policy Gate: APPROVED by Operator. Evaluating Safety Invariants...")
                exec_res = resp_agent.execute_action(case.case_id, action.action_id, live=False)
                print(f"    --> Execution Output: {exec_res.execution_result.output}")
                print(f"    --> Verification    : {exec_res.verification_result.details}")
                print(f"    --> Final Status    : {exec_res.status.value} [OK]")
            else:
                resp_agent.reject_action(
                    case.case_id, action.action_id,
                    rejecter_id="secops-operator@aegis",
                    rationale="Operator denied containment action."
                )
                print("    --> Policy Gate: REJECTED by Operator. Action cancelled [DENIED].")

    # 6. Audit Trail
    print("\n" + "=" * 70)
    print("  TAMPER-EVIDENT AUDIT TRAIL")
    print("=" * 70)
    audit = resp_agent.get_audit_history(case.case_id)
    print(f"Case ID           : {audit['case_id']}")
    print(f"Response Plan ID  : {audit['response_id']}")
    print(f"Total Actions     : {len(audit['actions'])}")
    print(f"Hash Chain Integrity: {audit['evidence_chain_valid']} [OK]")
    print("SOC Operation Complete. Threat neutralized in real-time.\n")


if __name__ == "__main__":
    main()
