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


def main() -> int:
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

    config = MonitoringConfig(
        Environment(args.environment),
        args.data_dir,
        interval_seconds=args.interval_seconds,
    )

    if args.legacy:
        # Legacy mode: original simple collectors
        collectors = [ProcessSnapshotCollector()]
        if args.watch:
            collectors.append(FilePollingCollector(tuple(args.watch)))
        engine = MonitoringEngine(config, collectors=collectors)
    else:
        # Production mode: full auto-discovered pipeline
        engine = MonitoringEngine.build_from_capability(
            config=config,
            watch_roots=args.watch,
            enable_auth=not args.no_auth,
        )

    engine.start()
    if args.run_seconds:
        engine.run_for(args.run_seconds)
        total = engine.store.count_events()
        print(f"bounded run complete — events={total} chain_valid={engine.store.verify_chain()}")
    else:
        findings = engine.run_once()
        total = engine.store.count_events()
        print(
            f"collection complete — events={total} "
            f"findings={len(findings)} "
            f"chain_valid={engine.store.verify_chain()}"
        )
        engine.stop()

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
