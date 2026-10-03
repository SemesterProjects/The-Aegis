"""Safe local Monitoring -> Evidence -> Triage -> Case demonstration.

Uses a caller-selected, dedicated directory only.  It starts a short-lived
Python child, performs controlled file lifecycle operations, and requests a
loopback HTTP endpoint.  It never attacks external systems or user files.
"""
from __future__ import annotations

import argparse
import http.server
import json
from pathlib import Path
import subprocess
import sys
import threading
import time
import urllib.request

# Support direct execution from a clean source checkout before installation.
REPOSITORY_ROOT = Path(__file__).resolve().parents[1]
if str(REPOSITORY_ROOT) not in sys.path:
    sys.path.insert(0, str(REPOSITORY_ROOT))

from aegis_core.detection import DetectionPipeline, FileChangeBurstDetector
from aegis_core.engine import MonitoringConfig, MonitoringEngine
from aegis_core.models import Environment
from aegis_core.storage import EvidenceStore


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--root", type=Path, required=True, help="empty or dedicated Aegis test root")
    args = parser.parse_args()
    root = args.root.resolve()
    watch = root / "watch"
    data = root / "data"
    watch.mkdir(parents=True, exist_ok=True)
    engine = MonitoringEngine.build_from_capability(
        MonitoringConfig(Environment.DEVELOPMENT, data, interval_seconds=0.15, health_interval_seconds=0.2),
        watch_roots=(watch,), enable_auth=False,
    )
    # Lower threshold only for this safe demonstration; production defaults remain unchanged.
    engine.pipeline = DetectionPipeline([FileChangeBurstDetector(window_seconds=10, threshold=4)])
    runner = threading.Thread(target=lambda: engine.run_for(2.5), name="aegis-safe-demo")
    runner.start()
    time.sleep(0.45)

    child = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(0.7)"], stdout=subprocess.DEVNULL)
    server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), http.server.SimpleHTTPRequestHandler)
    server_thread = threading.Thread(target=server.serve_forever, daemon=True)
    server_thread.start()
    try:
        with urllib.request.urlopen(f"http://127.0.0.1:{server.server_port}/", timeout=2) as response:
            response.read(64)
        for index in range(4):
            path = watch / f"safe-{index}.txt"
            path.write_text("created", encoding="utf-8")
            path.write_text("modified", encoding="utf-8")
        renamed = watch / "safe-0-renamed.txt"
        (watch / "safe-0.txt").rename(renamed)
        renamed.unlink()
    finally:
        child.wait(timeout=3)
        server.shutdown()
        runner.join(timeout=5)

    store = EvidenceStore(data / "evidence.sqlite3")
    try:
        events = store.query_events()
        cases = store.query_cases()
        result = {
            "process_events": sum(event["kind"] == "process" for event in events),
            "file_events": sum(event["kind"] == "file" for event in events),
            "network_events": sum(event["kind"] == "network" for event in events),
            "case_count": len(cases),
            "case_ids": [case["case_id"] for case in cases],
            "chain_valid": store.verify_chain(),
        }
        print(json.dumps(result, indent=2, sort_keys=True))
        return 0 if result["file_events"] and result["network_events"] and result["case_count"] and result["chain_valid"] else 1
    finally:
        store.close()


if __name__ == "__main__":
    raise SystemExit(main())
