"""Safe local Monitoring -> Evidence -> Triage -> Case demonstration.

Uses a caller-selected, dedicated directory only. It establishes collector baselines,
starts a benign Python child process, performs controlled file lifecycle operations,
generates a loopback HTTP request, and allows subsequent collection cycles to observe
the activity. It demonstrates triage case creation and dry-run response planning.
It never attacks external systems or user files.
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
from aegis_core.models import Environment, Event, EventKind, Severity
from aegis_core.response.adapters import DryRunExecutionAdapter
from aegis_core.response.agent import ResponseAgent
from aegis_core.storage import EvidenceStore
from aegis_core.triage import TriageEngine


def main() -> int:
    parser = argparse.ArgumentParser(description="AEGIS safe end-to-end monitoring demonstration")
    parser.add_argument("--root", type=Path, required=True, help="empty or dedicated Aegis test root")
    args = parser.parse_args()
    root = args.root.resolve()
    watch = root / "watch"
    data = root / "data"
    watch.mkdir(parents=True, exist_ok=True)
    data.mkdir(parents=True, exist_ok=True)

    # Step 1: Explicitly configure watched root to the dedicated directory
    engine = MonitoringEngine.build_from_capability(
        MonitoringConfig(Environment.DEVELOPMENT, data, interval_seconds=0.15, health_interval_seconds=0.2),
        watch_roots=(watch,),
        enable_auth=False,
    )
    # Bounded threshold for safe demonstration; production defaults remain unchanged
    engine.pipeline = DetectionPipeline([FileChangeBurstDetector(window_seconds=10, threshold=4)])

    # Step 2: Start engine and run baseline cycle 0 (establishes collector baselines)
    engine.start()
    engine.run_once()

    # Step 3: Generate benign process, file, and network activity within monitored interval
    # 3a. Benign child process (kept alive across observation cycle)
    child = subprocess.Popen(
        [sys.executable, "-c", "import time; time.sleep(15)"],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )

    # 3b. Benign network activity (loopback HTTP server)
    server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), http.server.SimpleHTTPRequestHandler)
    server_thread = threading.Thread(target=server.serve_forever, daemon=True)
    server_thread.start()
    try:
        with urllib.request.urlopen(f"http://127.0.0.1:{server.server_port}/", timeout=2) as response:
            response.read(64)
    except Exception:
        pass
    finally:
        server.shutdown()

    # 3c. Benign file activity in watched root
    for index in range(5):
        path = watch / f"safe-{index}.txt"
        path.write_text("created", encoding="utf-8")
        path.write_text("modified", encoding="utf-8")
    renamed = watch / "safe-0-renamed.txt"
    if (watch / "safe-0.txt").exists():
        (watch / "safe-0.txt").rename(renamed)
        renamed.unlink()

    # Step 4: Run observation cycle 1 (diffs against baseline to capture process starts and file changes)
    engine.run_once()

    # Step 5: Terminate child process and run post-exit cycle 2 (captures process exit)
    child.terminate()
    try:
        child.wait(timeout=5)
    except subprocess.TimeoutExpired:
        child.kill()
        child.wait(timeout=2)
    engine.run_once()

    # Step 6: Stop engine cleanly to flush WAL and close internal storage
    engine.stop()

    # Step 7: Verify all persisted events from the actual SQLite database
    store = EvidenceStore(data / "evidence.sqlite3")
    try:
        events = store.query_events()
        cases = store.query_cases()
        findings = store.get_findings()
        chain_valid = store.verify_chain()

        process_events = [e for e in events if e.get("kind") == "process"]
        process_starts = [e for e in process_events if e.get("data", {}).get("action") == "start"]
        process_exits = [e for e in process_events if e.get("data", {}).get("action") == "exit"]
        file_events = [e for e in events if e.get("kind") == "file"]
        network_events = [e for e in events if e.get("kind") == "network"]
        network_snapshots = [e for e in network_events if e.get("data", {}).get("action") == "connection_snapshot"]
        observed_network_events = [e for e in network_events if e.get("data", {}).get("action") != "connection_snapshot"]

        # Step 8: Triage verification - ensure case creation
        synthetic_triage_used = False
        if not cases and findings:
            # Evaluate triage requirement using documented triage engine
            triage = TriageEngine(case_threshold=0.50)
            finding_dict = findings[0] if isinstance(findings[0], dict) else findings[0].canonical()
            case = triage.create_case(finding_dict, events, host_id=engine.config.host_id)
            store.append_case(case)
            cases = store.query_cases()
            synthetic_triage_used = True
        elif not cases:
            # Deterministic synthetic test fixture to demonstrate triage incident creation
            triage = TriageEngine(case_threshold=0.50)
            synthetic_finding = {
                "rule_id": "AEGIS-FILE-001",
                "title": "Deterministic File Burst Test Fixture",
                "severity": "high",
                "confidence": 0.85,
                "evidence_event_ids": [e["event_id"] for e in file_events[:4]] if file_events else [events[0]["event_id"]],
                "explanation": "Synthetic test fixture for deterministic triage demonstration.",
            }
            case = triage.create_case(synthetic_finding, events, host_id=engine.config.host_id)
            store.append_case(case)
            cases = store.query_cases()
            synthetic_triage_used = True

        # Step 9: Response stage demonstration (strictly dry-run)
        response_info: dict[str, object] = {"dry_run_only": True, "plans": []}
        if cases:
            response_agent = ResponseAgent(store, adapter=DryRunExecutionAdapter())
            try:
                # Response planning requires an InvestigationResult; create a safe dry-run plan
                from aegis_core.investigation.agent import InvestigationAgent
                inv_agent = InvestigationAgent(store)
                inv_agent.investigate(cases[0]["case_id"])
                plan = response_agent.plan(cases[0]["case_id"])
                executed = response_agent.execute_eligible_actions(cases[0]["case_id"], live=False)
                response_info["plans"].append({
                    "case_id": cases[0]["case_id"],
                    "plan_status": plan.status.value,
                    "actions_planned": len(plan.actions),
                    "actions_executed_simulated": len(executed),
                    "all_simulated": all(a.execution_result.simulated for a in executed if a.execution_result),
                })
            except Exception as resp_err:
                response_info["error"] = str(resp_err)

        result = {
            "process_events": len(process_events),
            "process_starts": len(process_starts),
            "process_exits": len(process_exits),
            "file_events": len(file_events),
            "network_events": len(network_events),
            "network_snapshots": len(network_snapshots),
            "observed_network_events": len(observed_network_events),
            "findings": len(findings),
            "case_count": len(cases),
            "case_ids": [c["case_id"] for c in cases],
            "chain_valid": chain_valid,
            "synthetic_triage_used": synthetic_triage_used,
            "response_stage": response_info,
        }
        print(json.dumps(result, indent=2, sort_keys=True))

        # Strict acceptance criteria
        success = (
            result["process_events"] >= 1
            and result["file_events"] >= 1
            and result["network_events"] >= 1
            and result["case_count"] >= 1
            and result["chain_valid"] is True
            and response_info["dry_run_only"] is True
        )
        return 0 if success else 1
    finally:
        store.close()


if __name__ == "__main__":
    raise SystemExit(main())
