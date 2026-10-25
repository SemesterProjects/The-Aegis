# AEGIS end-to-end demonstration

This is a safe local demonstration. It starts ten benign Python child processes, writes only to a chosen demo directory, uses loopback only, and leaves live termination off unless an operator opts in.

## Before the panel

1. In VS Code, open the repository root and open **Terminal > New Terminal**.
2. Ensure the virtual environment exists, then run:

```powershell
.\.venv\Scripts\python.exe -m pytest -q tests\test_investigation_handoff.py tests\test_response_agent.py
```

3. Use a dedicated folder outside OneDrive so the file collector does not intentionally exclude it:

```powershell
$root = 'E:\AegisLab\artifacts\aegis-panel-e2e'
```

## Terminal 1: complete dry-run workflow

Paste this one command. It establishes a process baseline, starts ten uniquely marked children for 30 seconds, collects their starts plus local file/loopback activity, then runs detection, triage, investigation, planning, and audit.

```powershell
.\.venv\Scripts\python.exe scripts\investigation_process_scenario.py --root $root --count 10 --hold-seconds 30
```

Expected final fields include `process_starts: 10`, `findings: 1`, `investigation_status: "COMPLETE"`, `classification: "SUSPICIOUS"`, non-zero `termination_actions`, and `chain_valid: true`. The detected rule is `AEGIS-PROC-001`; no detection threshold was changed.

Say: “The monitoring engine observed a real burst, stored canonical evidence, triage created the case, and the response plan has pending human approvals. No host containment occurred.”

Take screenshots:

| File name | Capture | Proves |
| --- | --- | --- |
| `01-e2e-summary.png` | final JSON summary | real pipeline transitions and valid chain |
| `02-case-and-plan.png` | command below | persisted case and approval-gated targets |

In the same terminal, inspect the durable records:

```powershell
.\.venv\Scripts\python.exe -c "from pathlib import Path; import json; from aegis_core.storage import EvidenceStore; s=EvidenceStore(Path(r'$root')/'data'/'evidence.sqlite3'); c=s.query_cases()[-1]; p=s.get_response_plan_by_case(c['case_id']); print(json.dumps({'case_id':c['case_id'],'trigger':c['trigger'],'signals':c['detection_signals'],'actions':[(a['action_type'],a['target'],a['status']) for a in p['actions'] if a['action_type']=='TERMINATE_PROCESS'],'chain_valid':s.verify_chain()},indent=2)); s.close()"
```

## Optional live termination (Terminal 1 only)

This is a separate, explicit opt-in. It affects only children launched by this exact invocation. The script displays a fresh run ID; type it exactly when prompted. It records the operator identity, exact action target, rationale, execution result, and independent process-exit verification.

```powershell
.\.venv\Scripts\python.exe scripts\investigation_process_scenario.py --root $root --count 10 --hold-seconds 30 --live-terminate --approver-id 'panel-operator'
```

At the prompt, type the printed `aegis-demo-...` run ID exactly. Any other input leaves the process untouched. The adapter verifies PID creation time and the unique command-line marker immediately before termination; a mismatch is refused. Capture `03-live-verified-termination.png` only when the output reports `verified: true` for each executed termination.

Say: “Approval is stored per action and exact target. The adapter rejects PID reuse or identity mismatch, and independent verification checks that the approved demo PID has exited.”

## Troubleshooting and cleanup

- If no case is reported, use a non-cloud root such as `E:\AegisLab`; OneDrive roots are intentionally excluded from file monitoring. Rerun the single command; do not invent a case.
- If the live command declines authorization, rerun it and enter the newly displayed run ID. Run IDs are deliberately one-use.
- If `psutil` is unavailable, the collector and live identity guard cannot verify process lifecycle; repair the project environment before presenting.
- The script normally stops its children and closes the engine. To retain evidence, keep `$root\data\evidence.sqlite3`; deleting `$root` after the panel is safe because it is the dedicated demo directory.

Live execution is distinct from the default dry run. Automated tests use controlled adapters and are not proof of host termination. LLM interpretation is optional and is not required for, and cannot authorize, this workflow.
