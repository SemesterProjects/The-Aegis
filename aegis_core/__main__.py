"""Safe command-line smoke runner; service installation is intentionally external."""
from __future__ import annotations

import argparse
from datetime import datetime, timezone
from pathlib import Path

from .collectors import FilePollingCollector, ProcessSnapshotCollector
from .engine import MonitoringConfig, MonitoringEngine
from .models import Environment
from .storage import EvidenceStore


def _cmd_analyze(data_dir: Path, limit: int) -> int:
    """Read the evidence store and print deterministic analysis."""
    from .analysis import analyze_event, Correlator, format_analysis
    from .models import Event, EventKind

    db_path = data_dir / "evidence.sqlite3"
    if not db_path.exists():
        print(f"[ERROR] No evidence store found at {db_path}")
        print("Run a monitoring session first (omit --analyze).")
        return 1

    store = EvidenceStore(db_path)
    try:
        since = datetime(2000, 1, 1, tzinfo=timezone.utc)
        raw_rows = store.recent_events(since)
    finally:
        store.close()

    if not raw_rows:
        print("Evidence store is empty — no events to analyze.")
        return 0

    # Reconstruct minimal Event objects from stored canonical dicts
    events: list[Event] = []
    for row in raw_rows[-limit:]:          # analyze the most recent N events
        try:
            kind = EventKind(row["kind"])
            ts_raw = row["observed_at"]
            if ts_raw.endswith("Z"):
                ts_raw = ts_raw[:-1] + "+00:00"
            observed_at = datetime.fromisoformat(ts_raw)
            ev = Event(
                kind=kind,
                source=row.get("source", "unknown"),
                data=row.get("data", {}),
                observed_at=observed_at,
                event_id=row["event_id"],
                host_id=row.get("host_id", "unknown"),
            )
            events.append(ev)
        except Exception:
            continue  # skip malformed rows

    analyses = [analyze_event(e) for e in events]
    correlated = Correlator().correlate(analyses)

    print(f"\n=== AEGIS TELEMETRY ANALYSIS ({len(correlated)} events) ===\n")
    for analysis in correlated:
        print(format_analysis(analysis))
        print()

    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description="Run one safe Aegis monitoring collection cycle")
    parser.add_argument("--data-dir", type=Path, default=Path("./aegis-data"))
    parser.add_argument("--environment", choices=[item.value for item in Environment], default="development")
    parser.add_argument("--watch", type=Path, action="append", default=[], help="explicit root to poll for file changes")
    parser.add_argument("--interval-seconds", type=float, default=10.0, help="collection interval for a bounded run")
    parser.add_argument("--run-seconds", type=float, help="run the monitored loop for this duration; omit for one cycle")
    parser.add_argument("--no-network", action="store_true", help="disable network telemetry collection")
    parser.add_argument("--analyze", action="store_true",
                        help="read the existing evidence store and print deterministic analysis (no collection)")
    parser.add_argument("--analyze-limit", type=int, default=50,
                        help="maximum number of recent events to analyze (default: 50)")
    args = parser.parse_args()

    if args.analyze:
        return _cmd_analyze(args.data_dir, args.analyze_limit)

    collectors = [ProcessSnapshotCollector()]
    if not args.no_network:
        try:
            from .network import NetworkCollector
            collectors.append(NetworkCollector())
        except Exception as exc:
            print(f"[WARN] Network collector could not be initialized: {exc}")
    if args.watch:
        collectors.append(FilePollingCollector(tuple(args.watch)))
    engine = MonitoringEngine(MonitoringConfig(Environment(args.environment), args.data_dir,
        interval_seconds=args.interval_seconds), collectors=collectors)
    engine.start()
    try:
        if args.run_seconds:
            engine.run_for(args.run_seconds)
            findings = ()
        else:
            findings = engine.run_once()
            engine.stop()
        total = engine.store.count_events()
        chain_valid = engine.store.verify_chain()
        if args.run_seconds:
            print("bounded monitoring run completed")
            print(f"events={total}; chain_valid={chain_valid}")
        else:
            print("collection completed")
            print(f"events={total}; findings={len(findings)}; chain_valid={chain_valid}")
    finally:
        engine.close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
