"""Controlled, real telemetry-to-response process-burst demonstration.

This exercises the existing monitoring engine, its default process-burst
detector, triage, investigation, response policy, approval, and audit layers.
It never inserts findings or cases. Live termination is disabled by default.
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path
import socketserver
import subprocess
import sys
import threading
import time
import uuid

REPOSITORY_ROOT = Path(__file__).resolve().parents[1]
if str(REPOSITORY_ROOT) not in sys.path:
    sys.path.insert(0, str(REPOSITORY_ROOT))

# On Windows a venv launcher can be a short-lived parent of the actual Python
# interpreter. Use the base executable so Popen's PID is the PID psutil sees.
CHILD_PYTHON = getattr(sys, "_base_executable", sys.executable)

from aegis_core.engine import MonitoringConfig, MonitoringEngine
from aegis_core.investigation.agent import InvestigationAgent
from aegis_core.investigation.state import InvestigationBudget
from aegis_core.models import Environment
from aegis_core.response.adapters import LocalLabExecutionAdapter
from aegis_core.response.agent import ResponseAgent
from aegis_core.response.models import ActionType
from aegis_core.response.policy import ResponsePolicyConfig


class _QuietLoopbackHandler(socketserver.BaseRequestHandler):
    def handle(self) -> None:
        self.request.recv(256)


_CHILD_CODE = """
from pathlib import Path
import socket
import sys
import time
marker, file_path, port, hold_seconds = sys.argv[1:]
Path(file_path).write_text(marker, encoding='utf-8')
with socket.create_connection(('127.0.0.1', int(port)), timeout=5) as conn:
    conn.sendall(marker.encode('utf-8'))
time.sleep(float(hold_seconds))
"""


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="AEGIS controlled process-burst end-to-end demo")
    parser.add_argument("--root", type=Path, required=True, help="dedicated, non-production demo directory")
    parser.add_argument("--count", type=int, default=10, help="number of demo children (10..20)")
    parser.add_argument("--interval", type=float, default=0.08, help="seconds between child starts")
    parser.add_argument("--hold-seconds", type=float, default=30.0, help="how long children remain alive")
    parser.add_argument("--live-terminate", action="store_true", help="opt in to approved termination of this run's children")
    parser.add_argument("--approver-id", help="recorded operator identity required with --live-terminate")
    return parser


def _identity_for(pid: int, marker: str) -> dict[str, object]:
    import psutil
    return {"create_time": psutil.Process(pid).create_time(), "marker": marker}


def _wait_for_collector(engine: MonitoringEngine, cycles: int = 3) -> None:
    for _ in range(cycles):
        time.sleep(0.45)
        engine.run_once()


def main() -> int:
    args = _parser().parse_args()
    if not 10 <= args.count <= 20 or args.interval < 0 or args.hold_seconds < 8:
        _parser().error("--count must be 10..20, --interval non-negative, and --hold-seconds at least 8")

    root = args.root.resolve()
    watch = root / "watch"
    data = root / "data"
    watch.mkdir(parents=True, exist_ok=True)
    data.mkdir(parents=True, exist_ok=True)
    run_id = f"aegis-demo-{uuid.uuid4().hex[:12]}"
    if args.live_terminate:
        if not args.approver_id:
            _parser().error("--approver-id is required with --live-terminate")
        print(f"LIVE termination requested for run {run_id}.")
        try:
            confirmation = input("Type that exact run ID to authorize only its demo-owned processes: ").strip()
        except EOFError:
            confirmation = ""
        if confirmation != run_id:
            print(json.dumps({"run_id": run_id, "live_termination": "NOT_AUTHORIZED", "reason": "Exact run-ID confirmation was not provided."}))
            return 2

    engine = MonitoringEngine.build_from_capability(
        MonitoringConfig(Environment.DEVELOPMENT, data, interval_seconds=0.2, health_interval_seconds=0.5),
        watch_roots=(watch,), enable_auth=False,
    )
    children: list[subprocess.Popen[bytes]] = []
    identities: dict[int, dict[str, object]] = {}
    result: dict[str, object] = {"run_id": run_id, "live_termination": args.live_terminate}
    server = socketserver.ThreadingTCPServer(("127.0.0.1", 0), _QuietLoopbackHandler)
    server.daemon_threads = True
    server.allow_reuse_address = True
    server_thread = threading.Thread(target=server.serve_forever, daemon=True)

    try:
        engine.start()
        engine.run_once()  # lifecycle baseline before any child starts
        server_thread.start()
        for index in range(args.count):
            child_marker = f"{run_id}-child-{index:02d}"
            child = subprocess.Popen(
                [CHILD_PYTHON, "-c", _CHILD_CODE, child_marker, str(watch / f"{child_marker}.txt"), str(server.server_address[1]), str(args.hold_seconds)],
                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, cwd=root,
            )
            children.append(child)
            identities[child.pid] = _identity_for(child.pid, child_marker)
            time.sleep(args.interval)

        _wait_for_collector(engine)
        findings = engine.store.get_findings()
        cases = engine.store.query_cases()
        process_events = engine.store.query_events(kinds=["process"])
        process_starts = [event for event in process_events if event.get("data", {}).get("action") == "start"]
        owned_pids = set(identities)
        qualifying_cases = [
            case for case in cases
            if case.get("trigger") == "AEGIS-PROC-001"
            and any(int(event.get("data", {}).get("pid", -1)) in owned_pids for event in process_events if event.get("event_id") in case.get("event_ids", []))
        ]
        if not qualifying_cases:
            result.update({"process_starts": len(process_starts), "findings": len(findings), "cases": len(cases), "error": "No qualifying persisted process-burst case was created by the monitoring pipeline."})
            print(json.dumps(result, indent=2, sort_keys=True))
            return 1

        case_id = qualifying_cases[-1]["case_id"]
        # Network snapshots can include unrelated host connections.  This
        # bounded demo budget permits the existing read-only investigator to
        # finish its normal coverage work without changing detection or policy.
        investigation = InvestigationAgent(
            engine.store,
            budget=InvestigationBudget(
                max_tool_calls=100,
                max_investigation_time_seconds=60.0,
                max_evidence_expansion=2_000,
                max_context_size=5_000_000,
            ),
        ).investigate(case_id)
        adapter = LocalLabExecutionAdapter(root, allowed_pids=owned_pids, process_identities=identities)
        response = ResponseAgent(engine.store, policy_config=ResponsePolicyConfig(dry_run=not args.live_terminate), adapter=adapter)
        plan = response.plan(case_id)
        termination_actions = [
            action for action in plan.actions
            if action.action_type is ActionType.TERMINATE_PROCESS and action.target.get("pid") in owned_pids
        ]
        result.update({
            "process_starts": len(process_starts), "findings": len(findings), "case_id": case_id,
            "investigation_status": investigation.status.value, "classification": investigation.classification.value,
            "confidence": investigation.confidence, "evidence_ids_used": len(investigation.evidence_ids_used),
            "response_id": plan.response_id, "termination_actions": len(termination_actions),
        })
        if not termination_actions:
            result["error"] = "No response termination targets were both investigation-scoped and demo-owned."
            print(json.dumps(result, indent=2, sort_keys=True))
            return 1

        if args.live_terminate:
            executed = []
            for action in termination_actions:
                response.approve_action(
                    case_id, action.action_id, approver_id=args.approver_id,
                    rationale=f"Demo operator approved exact demo-owned process target for run {run_id}.",
                )
                outcome = response.execute_action(case_id, action.action_id, live=True)
                executed.append({
                    "action_id": outcome.action_id, "pid": outcome.target.get("pid"),
                    "status": outcome.status.value,
                    "verified": bool(outcome.verification_result and outcome.verification_result.verified),
                    "approval_scope": outcome.approval_record.scope if outcome.approval_record else None,
                })
            result["executed_terminations"] = executed
            if not executed or not all(item["verified"] for item in executed):
                result["error"] = "One or more approved demo-owned process terminations were not independently verified."
                print(json.dumps(result, indent=2, sort_keys=True))
                return 1

        audit = response.get_audit_history(case_id)
        persisted_plan = response.get_plan(case_id)
        persisted_termination_actions = [
            action for action in (persisted_plan.actions if persisted_plan else [])
            if action.action_type is ActionType.TERMINATE_PROCESS and action.target.get("pid") in owned_pids
        ]
        # The durable audit remains in EvidenceStore. Keep console/result JSON
        # readable by displaying the trace summary rather than every unrelated
        # host-network response proposal discovered during investigation.
        result["audit"] = {
            "case_id": audit["case_id"],
            "response_id": audit["response_id"],
            "evidence_chain_valid": audit["evidence_chain_valid"],
            "termination_action_statuses": [
                {"action_id": action.action_id, "pid": action.target.get("pid"), "status": action.status.value}
                for action in persisted_termination_actions
            ],
        }
        result["chain_valid"] = engine.store.verify_chain()
        (root / "demo-result.json").write_text(json.dumps(result, indent=2, sort_keys=True, default=str), encoding="utf-8")
        print(json.dumps(result, indent=2, sort_keys=True, default=str))
        return 0 if result["chain_valid"] else 1
    finally:
        for child in children:
            if child.poll() is None:
                child.terminate()
        for child in children:
            try:
                child.wait(timeout=3)
            except subprocess.TimeoutExpired:
                child.kill()
        server.shutdown()
        server.server_close()
        if not getattr(engine, "_closed", True):
            try:
                engine.run_once()  # capture remaining exits before shutdown
            finally:
                engine.stop()


if __name__ == "__main__":
    raise SystemExit(main())
