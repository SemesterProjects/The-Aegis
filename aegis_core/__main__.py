"""Safe command-line smoke runner; service installation is intentionally external."""
from __future__ import annotations

import argparse
from pathlib import Path

from .collectors import FilePollingCollector, ProcessSnapshotCollector
from .engine import MonitoringConfig, MonitoringEngine
from .models import Environment


def main() -> int:
    parser = argparse.ArgumentParser(description="Run one safe Aegis monitoring collection cycle")
    parser.add_argument("--data-dir", type=Path, default=Path("./aegis-data"))
    parser.add_argument("--environment", choices=[item.value for item in Environment], default="development")
    parser.add_argument("--watch", type=Path, action="append", default=[], help="explicit root to poll for file changes")
    parser.add_argument("--interval-seconds", type=float, default=10.0, help="collection interval for a bounded run")
    parser.add_argument("--run-seconds", type=float, help="run the monitored loop for this duration; omit for one cycle")
    args = parser.parse_args()
    collectors = [ProcessSnapshotCollector()]
    if args.watch:
        collectors.append(FilePollingCollector(tuple(args.watch)))
    engine = MonitoringEngine(MonitoringConfig(Environment(args.environment), args.data_dir,
        interval_seconds=args.interval_seconds), collectors=collectors)
    engine.start()
    if args.run_seconds:
        engine.run_for(args.run_seconds)
        print("bounded monitoring run completed")
    else:
        findings = engine.run_once()
        print(f"collection completed; findings={len(findings)}; chain_valid={engine.store.verify_chain()}")
        engine.stop()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
