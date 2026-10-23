"""Safe command-line runner; service installation is intentionally external."""
from __future__ import annotations

import argparse
import sys
from datetime import datetime
from pathlib import Path

from .capabilities import discover_capabilities
from .collectors import FilePollingCollector, ProcessSnapshotCollector
from .engine import MonitoringConfig, MonitoringEngine
from .models import Environment, Event, EventKind
from .storage import EvidenceStore


def _build_engine(args: argparse.Namespace) -> MonitoringEngine:
    config = MonitoringConfig(Environment(args.environment), args.data_dir,
                              interval_seconds=args.interval_seconds)
    return MonitoringEngine.build_from_capability(
        config=config, watch_roots=args.watch, enable_auth=not args.no_auth,
    )


def monitor_command(argv: list[str]) -> int:
    """Operational CLI: a foreground process plus durable stop/status files."""
    parser = argparse.ArgumentParser(prog="aegis monitor")
    parser.add_argument("action", choices=("start", "test", "stop", "status"))
    parser.add_argument("--data-dir", type=Path, default=Path("./aegis-data"))
    parser.add_argument("--environment", choices=[item.value for item in Environment], default="production")
    parser.add_argument("--watch", type=Path, action="append", default=[])
    parser.add_argument("--interval-seconds", type=float, default=2.0)
    parser.add_argument("--seconds", type=float, default=10.0)
    parser.add_argument("--no-auth", action="store_true")
    args = parser.parse_args(argv)

    if args.action == "status":
        status = MonitoringEngine.read_runtime_status(args.data_dir)
        if status is None:
            print("Aegis Monitoring: NO STATUS (not started in this data directory)")
            return 1
        print(json_dumps(status))
        return 0
    if args.action == "stop":
        MonitoringEngine.request_stop(args.data_dir)
        print(f"Stop requested: {args.data_dir / 'monitor-stop.request'}")
        return 0

    engine = _build_engine(args)
    try:
        if args.action == "test":
            engine.run_for(args.seconds)
            print(f"Aegis monitoring test complete; events={engine.status()['event_count']}")
        else:
            print("Aegis monitoring started in foreground. Use `aegis monitor stop --data-dir ...` from another terminal, or Ctrl+C.")
            engine.run_forever()
    except KeyboardInterrupt:
        engine.stop()
    return 0


def json_dumps(value: object) -> str:
    import json
    return json.dumps(value, indent=2, sort_keys=True, default=str)


def analyze_stored_events(data_directory: Path) -> int:
    """Render deterministic explanations for the canonical evidence store."""
    database = data_directory / "evidence.sqlite3"
    if not database.exists():
        print(f"ERROR: evidence store not found: {database}")
        return 1

    from .analysis import Correlator, analyze_event, format_analyses
    from .storage import EvidenceStore

    store = EvidenceStore(database)
    try:
        canonical_events = store.query_events()
        events = [
            Event(
                kind=EventKind(item["kind"]),
                source=item["source"],
                data=item.get("data", {}),
                observed_at=datetime.fromisoformat(item["observed_at"]),
                event_id=item["event_id"],
                host_id=item.get("host_id", "unknown"),
                schema_version=item.get("schema_version", 1),
                run_id=item.get("run_id", "unknown"),
                ingested_at=datetime.fromisoformat(item["ingested_at"])
                if item.get("ingested_at") else datetime.fromisoformat(item["observed_at"]),
            )
            for item in canonical_events
        ]
        analyses = Correlator().correlate([analyze_event(event) for event in events])
        print("=== AEGIS TELEMETRY ANALYSIS ===")
        if analyses:
            print(format_analyses(analyses))
        else:
            print("No canonical events found.")
        return 0
    finally:
        store.close()


def print_capability_report(watch_roots: list[Path]) -> None:
    """Print a human-readable capability report and exit."""
    from .collectors import (
        AuthEventCollector,
        FileEventCollector,
        NetworkBridgeCollector,
        ProcessLifecycleCollector,
    )

    caps = discover_capabilities()
    print("=== AEGIS CORE CAPABILITY REPORT ===")
    print(f"OS:        {caps.os_name} {caps.release} ({caps.machine})")
    print(f"Elevated:  {caps.is_elevated}")
    print(f"Features:  {', '.join(sorted(caps.features)) or 'none'}")
    if caps.limitations:
        print(f"Limits:    {'; '.join(caps.limitations)}")

    print("\nCOLLECTORS:")

    # Process lifecycle
    proc_col = ProcessLifecycleCollector()
    if proc_col.is_available:
        mech = proc_col._get_mechanism()
        print(f"  process_lifecycle : AVAILABLE   (mechanism: {mech})")
    else:
        print("  process_lifecycle : UNAVAILABLE (no psutil, no /proc)")

    # File events
    roots = tuple(watch_roots) if watch_roots else (Path("."),)
    file_col = FileEventCollector(roots=roots)
    file_col.initialize()
    if file_col.is_available:
        print(f"  file_events       : AVAILABLE   (mechanism: {file_col._mechanism})")
    else:
        print("  file_events       : UNAVAILABLE (no valid roots)")

    # Network bridge
    net_col = NetworkBridgeCollector()
    net_col.initialize()
    if net_col.is_available:
        adapter_name = type(net_col._adapter).__name__
        print(f"  network_bridge    : AVAILABLE   (adapter: {adapter_name})")
    else:
        print(f"  network_bridge    : UNAVAILABLE ({net_col._init_error})")
    file_col.close()
    net_col.close()

    # Auth events
    auth_col = AuthEventCollector()
    auth_col.initialize()
    if auth_col.is_available:
        print(f"  auth_events       : AVAILABLE   (mechanism: {auth_col._mechanism})")
    else:
        reason = auth_col._status_reason or "unsupported OS"
        print(f"  auth_events       : UNAVAILABLE ({reason})")


def investigate_command(argv: list[str]) -> int:
    """Run the Investigation Agent on one persisted InvestigationCase."""
    parser = argparse.ArgumentParser(prog="aegis investigate")
    parser.add_argument("case_id", nargs="?", help="InvestigationCase ID (e.g. INC-ABCD1234)")
    parser.add_argument("operation", nargs="?", choices=("run", "pending"))
    parser.add_argument("--case-id", dest="case_id_option")
    parser.add_argument("--data-dir", type=Path, default=Path("./aegis-data"))
    parser.add_argument("--max-tool-calls", type=int, default=30)
    parser.add_argument("--max-seconds", type=float, default=120.0)
    parser.add_argument("--json", action="store_true", help="output result as JSON")
    args = parser.parse_args(argv)
    case_id = args.case_id_option or args.case_id
    if args.case_id == "run":
        case_id = args.case_id_option
    if args.case_id == "pending" or args.operation == "pending":
        return investigate_pending(args.data_dir, args.max_tool_calls, args.max_seconds, args.json)
    if not case_id:
        parser.error("provide a case ID or use `pending`")

    database = args.data_dir / "evidence.sqlite3"
    if not database.exists():
        print(f"ERROR: evidence store not found: {database}")
        return 1

    from .investigation.agent import InvestigationAgent
    from .investigation.state import InvestigationBudget
    from .storage import EvidenceStore

    store = EvidenceStore(database)
    try:
        budget = InvestigationBudget(
            max_tool_calls=args.max_tool_calls,
            max_investigation_time_seconds=args.max_seconds,
        )
        agent = InvestigationAgent(store, budget=budget)
        result = agent.investigate(case_id)
        if args.json:
            print(json_dumps(result.canonical()))
        else:
            _print_result_summary(result)
        return 0 if result.status.value != "ERROR" else 1
    finally:
        store.close()


def investigate_pending(
    data_dir: Path, max_tool_calls: int, max_seconds: float, as_json: bool,
) -> int:
    """Process all currently NEW cases, one at a time."""
    database = data_dir / "evidence.sqlite3"
    if not database.exists():
        print(f"ERROR: evidence store not found: {database}")
        return 1
    from .investigation.agent import InvestigationAgent
    from .investigation.state import InvestigationBudget
    from .storage import EvidenceStore

    store = EvidenceStore(database)
    try:
        cases = store.query_cases(status="NEW")
        exit_code = 0
        for case in cases:
            result = InvestigationAgent(
                store,
                budget=InvestigationBudget(
                    max_tool_calls=max_tool_calls,
                    max_investigation_time_seconds=max_seconds,
                ),
            ).investigate(case["case_id"])
            if as_json:
                print(json_dumps(result.canonical()))
            else:
                _print_result_summary(result)
            if result.status.value == "ERROR":
                exit_code = 1
        return exit_code
    finally:
        store.close()


def _print_result_summary(result: object) -> None:
    """Human-readable investigation result summary."""
    from .investigation.result import InvestigationResult
    r = result  # type: InvestigationResult  # type: ignore[assignment]
    print("=" * 64)
    print(f"  AEGIS INVESTIGATION RESULT")
    print("=" * 64)
    print(f"  Case ID        : {r.case_id}")
    print(f"  Status         : {r.status.value}")
    print(f"  Classification : {r.classification.value}")
    print(f"  Confidence     : {r.confidence:.0%}")
    print(f"  Tool calls     : {r.tool_calls_made}")
    print(f"  Evidence used  : {len(r.evidence_ids_used)} event(s)")
    print("-" * 64)
    print(f"  Summary:")
    print(f"    {r.summary}")
    def _safe_txt(txt: str) -> str:
        return str(txt).replace("\u2192", "->").replace("\u2014", "-")

    if r.timeline:
        print("-" * 64)
        print(f"  Timeline ({len(r.timeline)} entries):")
        for entry in r.timeline[:15]:
            print(f"    {entry.timestamp[:19]}  {_safe_txt(entry.description)[:80]}")
        if len(r.timeline) > 15:
            print(f"    ... and {len(r.timeline) - 15} more")
    if r.supporting_evidence:
        print("-" * 64)
        print(f"  Supporting evidence ({len(r.supporting_evidence)}):")
        for ev in r.supporting_evidence[:5]:
            print(f"    [{ev.event_id[:8]}] {_safe_txt(ev.description)[:70]}")
    if r.contradictory_evidence:
        print("-" * 64)
        print(f"  Contradictory evidence ({len(r.contradictory_evidence)}):")
        for ev in r.contradictory_evidence[:3]:
            print(f"    [{ev.event_id[:8]}] {_safe_txt(ev.description)[:70]}")
    if r.uncertainties:
        print("-" * 64)
        print(f"  Uncertainties:")
        for u in r.uncertainties:
            print(f"    - {_safe_txt(u)}")
    if r.recommended_actions:
        print("-" * 64)
        print(f"  Recommended Actions (READ-ONLY - requires human approval):")
        for i, action in enumerate(r.recommended_actions, 1):
            print(f"    {i}. {_safe_txt(action)}")
    print("=" * 64)




def respond_command(argv: list[str]) -> int:
    """Run response planning, approval, execution, or audit inspection."""
    parser = argparse.ArgumentParser(prog="aegis respond")
    subparsers = parser.add_subparsers(dest="action", required=True)

    plan_parser = subparsers.add_parser("plan", help="Generate response plan for a case")
    plan_parser.add_argument("--case-id", required=True, help="InvestigationCase ID (e.g. INC-...)")
    plan_parser.add_argument("--data-dir", type=Path, default=Path("./aegis-data"))
    plan_parser.add_argument("--json", action="store_true")

    show_parser = subparsers.add_parser("show", help="Display existing response plan")
    show_parser.add_argument("--case-id", required=True, help="InvestigationCase ID")
    show_parser.add_argument("--data-dir", type=Path, default=Path("./aegis-data"))
    show_parser.add_argument("--json", action="store_true")

    approve_parser = subparsers.add_parser("approve", help="Approve an action")
    approve_parser.add_argument("--case-id", required=True)
    approve_parser.add_argument("--action-id", required=True)
    approve_parser.add_argument("--approver", required=True, help="Approver identity")
    approve_parser.add_argument("--rationale", default="Authorized by security responder", help="Approval rationale")
    approve_parser.add_argument("--data-dir", type=Path, default=Path("./aegis-data"))

    reject_parser = subparsers.add_parser("reject", help="Reject an action")
    reject_parser.add_argument("--case-id", required=True)
    reject_parser.add_argument("--action-id", required=True)
    reject_parser.add_argument("--approver", required=True)
    reject_parser.add_argument("--rationale", default="Rejected by security responder")
    reject_parser.add_argument("--data-dir", type=Path, default=Path("./aegis-data"))

    execute_parser = subparsers.add_parser("execute", help="Execute approved/eligible actions")
    execute_parser.add_argument("--case-id", required=True)
    execute_parser.add_argument("--action-id", help="Optional specific action ID")
    execute_parser.add_argument("--live", action="store_true", help="Attempt live execution (default: dry-run)")
    execute_parser.add_argument("--data-dir", type=Path, default=Path("./aegis-data"))
    execute_parser.add_argument("--json", action="store_true")

    audit_parser = subparsers.add_parser("audit", help="Inspect response audit history")
    audit_parser.add_argument("--case-id", required=True)
    audit_parser.add_argument("--data-dir", type=Path, default=Path("./aegis-data"))
    audit_parser.add_argument("--json", action="store_true")

    args = parser.parse_args(argv)
    database = args.data_dir / "evidence.sqlite3"
    if not database.exists():
        print(f"ERROR: evidence store not found: {database}")
        return 1

    from .response.agent import ResponseAgent
    from .storage import EvidenceStore

    store = EvidenceStore(database)
    try:
        agent = ResponseAgent(store)
        if args.action == "plan":
            plan = agent.plan(args.case_id)
            if args.json:
                print(json_dumps(plan.canonical()))
            else:
                _print_plan_summary(plan)
            return 0 if plan.status.value != "FAILED" else 1

        elif args.action == "show":
            plan = agent.get_plan(args.case_id)
            if plan is None:
                print(f"No response plan exists for case '{args.case_id}'")
                return 1
            if args.json:
                print(json_dumps(plan.canonical()))
            else:
                _print_plan_summary(plan)
            return 0

        elif args.action == "approve":
            try:
                action = agent.approve_action(
                    args.case_id, args.action_id, args.approver, args.rationale
                )
                print(f"Action {action.action_id} approved. Status: {action.status.value}")
                return 0
            except Exception as exc:
                print(f"Approval failed: {exc}")
                return 1

        elif args.action == "reject":
            try:
                action = agent.reject_action(
                    args.case_id, args.action_id, args.approver, args.rationale
                )
                print(f"Action {action.action_id} rejected. Status: {action.status.value}")
                return 0
            except Exception as exc:
                print(f"Rejection failed: {exc}")
                return 1

        elif args.action == "execute":
            if args.action_id:
                action = agent.execute_action(args.case_id, args.action_id, live=args.live)
                if args.json:
                    print(json_dumps(action.canonical()))
                else:
                    print(f"Executed action {action.action_id}: status={action.status.value}")
                    if action.execution_result:
                        print(f"  Result: {action.execution_result.output}")
                    if action.verification_result:
                        print(f"  Verification: verified={action.verification_result.verified} ({action.verification_result.details})")
            else:
                actions = agent.execute_eligible_actions(args.case_id, live=args.live)
                if args.json:
                    print(json_dumps([a.canonical() for a in actions]))
                else:
                    print(f"Executed {len(actions)} eligible action(s) for case {args.case_id}")
                    for a in actions:
                        print(f"  [{a.status.value}] {a.action_type.value} -> {a.action_id}")
            return 0

        elif args.action == "audit":
            audit = agent.get_audit_history(args.case_id)
            print(json_dumps(audit))
            return 0

        return 0
    finally:
        store.close()


def _print_plan_summary(plan: Any) -> None:
    p = plan
    print("=" * 64)
    print("  AEGIS RESPONSE PLAN")
    print("=" * 64)
    print(f"  Response ID     : {p.response_id}")
    print(f"  Case ID         : {p.case_id}")
    print(f"  Investigation ID: {p.investigation_id}")
    print(f"  Plan Status     : {p.status.value}")
    print(f"  Risk Level      : {p.risk_assessment.business_impact} impact, {p.risk_assessment.containment_urgency} urgency")
    print(f"  Classification  : {p.risk_assessment.classification} ({p.risk_assessment.confidence:.0%})")
    print("-" * 64)
    print(f"  Decision:")
    print(f"    {p.decision}")
    if p.actions:
        print("-" * 64)
        print(f"  Proposed Actions ({len(p.actions)}):")
        for i, a in enumerate(p.actions, 1):
            app_req = "[REQUIRES APPROVAL]" if a.requires_approval else "[NO APPROVAL REQ]"
            print(f"    {i}. [{a.status.value}] {a.action_type.value} -> {a.target} {app_req}")
            print(f"       Action ID: {a.action_id} | Risk: {a.risk_level.value}")
            print(f"       Reason   : {a.reason}")
            if a.execution_result:
                sim_str = " (SIMULATED)" if a.execution_result.simulated else " (LIVE)"
                print(f"       Executed : success={a.execution_result.success}{sim_str} output={a.execution_result.output}")
            if a.verification_result:
                print(f"       Verified : {a.verification_result.verified} via {a.verification_result.method}")
    if p.uncertainties:
        print("-" * 64)
        print(f"  Uncertainties:")
        for u in p.uncertainties:
            print(f"    - {u}")
    print("=" * 64)


def main() -> int:
    if len(sys.argv) > 1 and sys.argv[1] == "monitor":
        return monitor_command(sys.argv[2:])
    if len(sys.argv) > 1 and sys.argv[1] == "investigate":
        return investigate_command(sys.argv[2:])
    if len(sys.argv) > 1 and sys.argv[1] in ("respond", "response"):
        return respond_command(sys.argv[2:])
    parser = argparse.ArgumentParser(description="Run one safe Aegis monitoring collection cycle")
    parser.add_argument("--data-dir", type=Path, default=Path("./aegis-data"))
    parser.add_argument(
        "--environment",
        choices=[item.value for item in Environment],
        default="development",
    )
    parser.add_argument(
        "--watch", type=Path, action="append", default=[],
        help="explicit root to poll/watch for file changes (can be repeated)"
    )
    parser.add_argument("--interval-seconds", type=float, default=10.0)
    parser.add_argument("--run-seconds", type=float, help="run for this duration; omit for one cycle")
    parser.add_argument(
        "--no-auth", action="store_true", default=False,
        help="disable authentication event collection"
    )
    parser.add_argument(
        "--capability-report", action="store_true",
        help="print capability report and exit (no data collection)"
    )
    parser.add_argument(
        "--legacy", action="store_true",
        help="use legacy ProcessSnapshot+FilePolling collectors instead of full pipeline"
    )
    parser.add_argument(
        "--analyze", action="store_true",
        help="analyze existing canonical evidence without starting collectors"
    )
    args = parser.parse_args()

    if args.capability_report:
        print_capability_report(args.watch)
        return 0
    if args.analyze:
        return analyze_stored_events(args.data_dir)

    config = MonitoringConfig(Environment(args.environment), args.data_dir, interval_seconds=args.interval_seconds)

    if args.legacy:
        # Legacy mode: original simple collectors
        collectors = [ProcessSnapshotCollector()]
        if args.watch:
            collectors.append(FilePollingCollector(tuple(args.watch)))
        engine = MonitoringEngine(config, collectors=collectors)
    else:
        # Production mode: full auto-discovered pipeline
        engine = _build_engine(args)

    if args.run_seconds:
        engine.run_for(args.run_seconds)
        store = EvidenceStore(config.data_directory / "evidence.sqlite3")
        try:
            total = store.count_events()
            chain_valid = store.verify_chain()
            print(f"bounded run complete — events={total} chain_valid={chain_valid}")
        finally:
            store.close()
    else:
        engine.start()
        try:
            findings = engine.run_once()
            total = engine.store.count_events()
            chain_valid = engine.store.verify_chain()
            print(
                f"collection complete — events={total} "
                f"findings={len(findings)} "
                f"chain_valid={chain_valid}"
            )
        finally:
            engine.stop()

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
