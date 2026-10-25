# End-to-end implementation verification

- Repaired `scripts/investigation_process_scenario.py` so it owns the full real monitoring path: baseline, bounded children, observation cycles, default detection, case selection, investigation, policy-gated planning, audit summary, and optional approved termination.
- The process-burst detector remains at its existing 10 starts / 10 seconds threshold. No finding or case is manually inserted.
- On Windows, the venv launcher was a short-lived parent rather than the psutil-observed child. The demo now launches the base interpreter and records PID, creation time, and unique marker.
- A live dry-run verification at `E:\AegisLab\artifacts\aegis-e2e-process-20261025-verified` produced 10 starts, one `AEGIS-PROC-001` finding, one persisted case, a complete `SUSPICIOUS` investigation at 0.67 confidence, eight pending demo-PID termination actions, and a valid evidence chain.
- The live opt-in path was verified at `E:\AegisLab\artifacts\aegis-e2e-process-live-20261025`: after the operator typed the fresh run ID, six investigation-scoped, demo-owned PIDs were approved, terminated, and independently verified as exited; the evidence chain remained valid.
