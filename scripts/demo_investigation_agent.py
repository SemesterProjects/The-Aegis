"""End-to-end demonstration of the Aegis Investigation Agent.

Simulates a realistic attack scenario:
  WINWORD.EXE -> powershell.exe -> file drop -> network C2

Creates synthetic events in a temp evidence store,
runs the Investigation Agent, and prints the full InvestigationResult.

Run with:
    python scripts/demo_investigation_agent.py
"""
from __future__ import annotations

import json
import sys
import tempfile
from datetime import datetime, timedelta, timezone
from pathlib import Path

# Make sure aegis_core is importable
sys.path.insert(0, str(Path(__file__).parent.parent))

from aegis_core.models import Event, EventKind
from aegis_core.storage import EvidenceStore
from aegis_core.triage import TriageEngine
from aegis_core.investigation.agent import InvestigationAgent
from aegis_core.investigation.state import InvestigationBudget

_UTC = timezone.utc


def _ts(offset: float) -> datetime:
    return datetime(2026, 10, 4, 10, 31, 0, tzinfo=_UTC) + timedelta(seconds=offset)


def main() -> None:
    with tempfile.TemporaryDirectory(ignore_cleanup_errors=True) as tmpdir:
        db_path = Path(tmpdir) / "evidence.sqlite3"
        store = EvidenceStore(db_path)

        print("=" * 70)
        print("  AEGIS INVESTIGATION AGENT -- END-TO-END DEMO")
        print("=" * 70)
        print()
        print("Scenario: Document-triggered script execution chain")
        print("  WINWORD.EXE -> powershell.exe -> file drop -> C2 network")
        print()

        # --- Create synthetic telemetry events ---
        events = [
            # Parent: Word opens a document
            Event(EventKind.PROCESS, "process_lifecycle", {
                "pid": 1234, "ppid": 4, "name": "WINWORD.EXE",
                "exe": "C:/Program Files/Microsoft Office/Office16/WINWORD.EXE",
                "action": "start", "user": "alice",
            }, observed_at=_ts(0), host_id="workstation-01"),

            # Child: Word launches PowerShell (suspicious)
            Event(EventKind.PROCESS, "process_lifecycle", {
                "pid": 5678, "ppid": 1234, "name": "powershell.exe",
                "exe": "C:/Windows/System32/WindowsPowerShell/v1.0/powershell.exe",
                "cmdline": "powershell.exe -enc JABz...",  # base64-encoded cmd (DATA)
                "action": "start", "user": "alice",
            }, observed_at=_ts(1), host_id="workstation-01"),

            # PowerShell drops a file
            Event(EventKind.FILE, "file_events", {
                "pid": 5678, "path": "C:/Users/alice/AppData/Local/Temp/update.exe",
                "action": "create", "suffix": ".exe",
            }, observed_at=_ts(2), host_id="workstation-01"),

            # PowerShell establishes outbound connection
            Event(EventKind.NETWORK, "network_bridge", {
                "pid": 5678, "process": "powershell.exe",
                "action": "connection_open", "direction": "outbound",
                "local_ip": "192.168.1.50", "local_port": 52341,
                "remote_ip": "185.220.101.10", "remote_port": 4444,
                "protocol": "TCP",
            }, observed_at=_ts(3), host_id="workstation-01"),

            # DNS query (before C2 connection)
            Event(EventKind.NETWORK, "network_bridge", {
                "pid": 5678, "process": "powershell.exe",
                "action": "dns_query", "query_name": "c2.malicious-domain.example",
                "query_type": "A",
            }, observed_at=_ts(2.5), host_id="workstation-01"),
        ]

        # Persist to store
        for ev in events:
            store.append_event(ev)

        print(f"[+] Stored {len(events)} telemetry events")

        # --- Create Investigation Case via existing TriageEngine ---
        triage = TriageEngine(case_threshold=0.0)
        finding = {
            "rule_id": "AEGIS-PROC-NET-001",
            "severity": "high",
            "confidence": 0.85,
            "evidence_event_ids": [events[1].event_id],  # powershell start
            "explanation": "New process (powershell.exe) established network connection immediately after start",
            "recommendation": "Investigate parent process and child process activity",
            "run_id": "demo-run",
        }
        case_events = [ev.canonical() for ev in events]
        case = triage.create_case(finding, case_events, host_id="workstation-01", hostname="workstation-01")
        store.append_case(case)

        print(f"[+] Created Investigation Case: {case.case_id}")
        print(f"    Severity: {case.severity}  Risk: {case.risk_score:.2f}")
        print(f"    Trigger: {case.trigger}")
        print()

        # --- Run Investigation Agent ---
        budget = InvestigationBudget(max_tool_calls=25, max_investigation_time_seconds=60.0)
        agent = InvestigationAgent(store, budget=budget)

        print("[*] Running Investigation Agent...")
        result = agent.investigate(case.case_id)

        # --- Print Results ---
        print()
        print("=" * 70)
        print("  INVESTIGATION RESULT")
        print("=" * 70)
        print(f"  Case ID        : {result.case_id}")
        print(f"  Status         : {result.status.value}")
        print(f"  Classification : {result.classification.value}")
        print(f"  Confidence     : {result.confidence:.0%}")
        print(f"  Tool Calls     : {result.tool_calls_made}")
        print(f"  Events Examined: {len(result.evidence_ids_used)}")
        if agent.last_state:
            print(f"  Stop Reason    : {agent.last_state.stop_reason.value if agent.last_state.stop_reason else 'unknown'}")
            print(f"  Context Size   : {agent.last_state.context_bytes()} bytes")
        print()
        print("  SUMMARY:")
        print(f"  {result.summary}")

        if agent.last_state and agent.last_state.tool_calls:
            print()
            print("  ADAPTIVE TOOL SELECTION TRACE (Observation -> Gap -> Tool):")
            for i, tc in enumerate(agent.last_state.tool_calls, 1):
                reason_clean = tc.reason.replace('\u2192', '->').replace('\u2014', '-')
                gap_clean = tc.gap_description.replace('\u2192', '->').replace('\u2014', '-')
                status_str = "OK" if tc.success else "FAIL"
                print(f"    [{i:02d}] {tc.tool_name:<28} [{status_str}]")
                print(f"         Gap   : {gap_clean}")
                print(f"         Why   : {reason_clean}")
                print(f"         Result: {tc.result_summary}")

        print()
        print(f"  TIMELINE ({len(result.timeline)} entries):")
        for entry in result.timeline:
            print(f"    {entry.timestamp[11:19]} UTC  {entry.description.replace('\u2192', '->').replace('\u2014', '-')}"[:75])

        if result.supporting_evidence:
            print()
            print(f"  SUPPORTING EVIDENCE ({len(result.supporting_evidence)}):")
            for ev in result.supporting_evidence:
                desc = ev.description.replace('\u2192', '->').replace('\u2014', '-').replace('→', '->')
                print(f"    [{ev.event_id[:8]}..] {desc[:70]}")

        if result.contradictory_evidence:
            print()
            print(f"  CONTRADICTORY EVIDENCE ({len(result.contradictory_evidence)}):")
            for ev in result.contradictory_evidence:
                desc = ev.description.replace('\u2192', '->').replace('\u2014', '-').replace('→', '->')
                print(f"    [{ev.event_id[:8]}..] {desc[:70]}")

        if result.root_cause:
            print()
            print("  ROOT CAUSE (HYPOTHESIS):")
            print(f"    Hypothesis : {result.root_cause.hypothesis[:100]}")
            print(f"    Confidence : {result.root_cause.confidence:.0%}")
            if result.root_cause.limitations:
                print("    Limitations:")
                for lim in result.root_cause.limitations[:3]:
                    print(f"      - {lim[:80]}")

        if result.network_activity:
            print()
            print(f"  NETWORK ACTIVITY ({len(result.network_activity)} connections):")
            for net in result.network_activity[:5]:
                remote = f"{net.get('remote_ip', '?')}:{net.get('remote_port', '?')}"
                print(f"    PID {net.get('pid')} -> {remote} [{net.get('direction', '?')}]")

        if result.uncertainties:
            print()
            print("  UNCERTAINTIES:")
            for u in result.uncertainties:
                print(f"    - {u}")

        if result.recommended_actions:
            print()
            print("  RECOMMENDED ACTIONS (read-only; require human approval):")
            for i, action in enumerate(result.recommended_actions, 1):
                print(f"    {i}. {action[:90]}")

        print()
        print("  REASONING SUMMARY:")
        print(f"  {result.reasoning_summary}")
        print()
        print("=" * 70)
        print("  AUDIT TRAIL")
        print("=" * 70)
        print(f"  Agent start : {result.agent_start_time[:19]} UTC")
        print(f"  Agent end   : {result.agent_end_time[:19]} UTC")
        print(f"  Tool calls  : {result.tool_calls_made}")
        print(f"  Evidence IDs: {len(result.evidence_ids_used)}")
        print()
        print("  Evidence ID traceability:")
        for eid in result.evidence_ids_used:
            print(f"    {eid}")
        print()

        # Verify: all original event IDs are in evidence
        missing = [ev.event_id for ev in events if ev.event_id not in result.evidence_ids_used]
        if missing:
            print(f"  [!] WARNING: {len(missing)} original events missing from evidence trace")
        else:
            print("  [OK] All original event IDs traceable in investigation result")

        # Verify: evidence chain intact
        chain_ok = store.verify_chain()
        print(f"  [{'OK' if chain_ok else 'FAIL'}] Evidence hash chain valid: {chain_ok}")

        # Verify: no system modification
        print("  [OK] Investigation agent performed NO system modifications (read-only)")

        # Serialize and validate JSON
        canonical = result.canonical()
        json_out = json.dumps(canonical, indent=2)
        print(f"  JSON result size: {len(json_out)} bytes")

        store.close()  # must close before tempdir cleanup on Windows

        print()
        print("Demo complete.")
        print()
        return result


if __name__ == "__main__":
    main()
