# Response Agent live verification

For the literal Windows operator walkthrough, including the LLM-to-response
handoff, use [Windows LLM and Response Agent walkthrough](windows_llm_response_agent_walkthrough.md).

## Scope and safety boundary

The Aegis Response Agent consumes a persisted `InvestigationCase` and its
completed deterministic `InvestigationResult`. It creates an evidence-linked
response plan, applies the central policy gate, records human approvals, and
persists every action result.

The normal CLI uses `DryRunExecutionAdapter`; its results are simulations and
must never be represented as host changes. The only included live adapter is
`LocalLabExecutionAdapter`, intended solely for a dedicated lab sandbox. It
can quarantine a file inside that sandbox and terminate only a PID explicitly
registered by the lab script. Firewall blocking, host isolation, notification
delivery, account review, and additional-telemetry requests do not have live
handlers in this checkpoint.

Pipeline:

```text
collectors -> canonical events -> EvidenceStore -> detection/triage
-> InvestigationCase -> InvestigationAgent -> InvestigationResult
-> ResponseAgent -> policy + approval -> adapter -> verifier + audit
```

## Windows prerequisites

- Run from the repository root using the project virtual environment.
- Use a dedicated watch root outside OneDrive/Dropbox/other cloud-sync paths.
  Aegis deliberately excludes cloud-synced directories from file monitoring.
- The validated lab location is `E:\AegisLab\artifacts`.
- `psutil` is required for process lifecycle telemetry. `watchdog` enables
  native file notifications. Network and authentication collection depend on
  local Windows capabilities and privileges.

```powershell
# Repository root
.\.venv\Scripts\python.exe -m aegis_core --capability-report
```

The report should list `process_lifecycle`, `network_bridge`, and any available
authentication collector. To assess a specific file root, use the controlled
demo below rather than watching the repository itself.

## Provider readiness

The LLM is optional and disabled unless `--llm` is passed to `investigate`.
It is interpretation-only: it cannot collect evidence, call tools, execute
response actions, or change a deterministic classification.

Set credentials only in the process environment or ignored `.env`; never put a
key in a command line, evidence database, or report.

```powershell
$env:GEMINI_API_KEY = "<credential>"
.\.venv\Scripts\python.exe scripts\live_llm_smoke.py

# Alternative HTTPS OpenAI-compatible provider
$env:AEGIS_LLM_PROVIDER = "openai-compatible"
$env:AEGIS_LLM_BASE_URL = "https://<approved-provider>/v1"
$env:AEGIS_LLM_API_KEY = "<credential>"
$env:AEGIS_LLM_MODEL = "<model-id>"
.\.venv\Scripts\python.exe scripts\live_llm_smoke.py
```

If no credential/network/quota is available, record the result as blocked. A
provider smoke test is not evidence of response execution.

## Controlled Windows monitoring and dry-run response

This creates a temporary child process, files only under the supplied lab
root, and loopback HTTP traffic. It runs genuine host collectors and writes a
separate evidence database.

```powershell
$root = 'E:\AegisLab\artifacts\aegis-windows-safe-e2e'
.\.venv\Scripts\python.exe scripts\safe_e2e_demo.py --root $root
```

Expected JSON has nonzero `process_events`, `file_events`, and
`network_events`, `chain_valid: true`, and at least one case. `response_stage`
explicitly says `dry_run_only: true`; any reported action there is simulated.

Inspect persisted state with:

```powershell
$data = 'E:\AegisLab\artifacts\aegis-windows-safe-e2e\data'
.\.venv\Scripts\python.exe -m aegis_core --analyze --data-dir $data
.\.venv\Scripts\python.exe -m aegis_core investigate pending --data-dir $data --json
```

For an existing completed case, use the normal response workflow:

```powershell
$case = '<INCIDENT_CASE_ID>'
.\.venv\Scripts\python.exe -m aegis_core respond plan --case-id $case --data-dir $data
.\.venv\Scripts\python.exe -m aegis_core respond show --case-id $case --data-dir $data --json
.\.venv\Scripts\python.exe -m aegis_core respond audit --case-id $case --data-dir $data --json
```

`respond approve` records human approval. `respond execute` remains dry-run in
this checkpoint because the CLI constructs the default dry-run policy/adapter.
The JSON audit must show action status, `execution_result.simulated`, and
evidence-chain validity; an approved plan alone is not execution.

## Live LocalLab containment test

Only run this on a student-controlled lab machine. It creates
`aegis_sandbox`, starts one demo child process, creates one demo payload file,
then asks for approval. On approval it may terminate only that registered child
PID and move only that file to `aegis_sandbox\quarantine`.

```powershell
.\.venv\Scripts\python.exe scripts\live_containment_demo.py
```

Success requires all of the following output conditions:

- `TERMINATE_PROCESS` has `STATUS: VERIFIED` and the physical check says the
  demo PID is dead.
- `QUARANTINE_FILE` has `STATUS: VERIFIED`, the original file is absent, and
  the quarantine vault contains the payload.
- The cryptographic audit chain is `True`.

`BLOCK_NETWORK_IP` is expected to be `UNSUPPORTED` in this checkpoint. It is
not a firewall test and must not be called live containment.

## Negative and safety checks

```powershell
.\.venv\Scripts\python.exe -m pytest -q tests\test_response_agent.py tests\test_safe_demo_regression.py
```

The suite covers missing evidence, invalid case/result relationships, missing
or expired approvals, policy denial, duplicate execution, adapter failure,
prompt-injection-like telemetry, protected resources, cross-case action scope,
and LocalLab path/PID restrictions. To test provider absence, run an LLM
command without the required key; it must return a disabled/error
interpretation without changing investigation classification.

## Monitoring lifecycle and troubleshooting

```powershell
$data = 'E:\AegisLab\artifacts\aegis-manual\data'
$watch = 'E:\AegisLab\artifacts\aegis-manual\watch'
New-Item -ItemType Directory -Force -Path $watch | Out-Null
.\.venv\Scripts\python.exe -m aegis_core monitor start --data-dir $data --watch $watch
# Second terminal:
.\.venv\Scripts\python.exe -m aegis_core monitor status --data-dir $data
.\.venv\Scripts\python.exe -m aegis_core monitor stop --data-dir $data
```

If file telemetry is empty, confirm the watch path exists and is not inside a
cloud-sync root; use `E:\AegisLab\artifacts`, not this OneDrive repository.
If imports fail, invoke `.venv\Scripts\python.exe` from the repository root.
If the evidence store is empty, ensure the monitor and response CLI use the
same `--data-dir`. If a response is unsupported, inspect its adapter and policy
status rather than treating an approval or printed plan as success.

## Ubuntu / Hyper-V procedure

The VM must be on, reachable, and have Guest Service Interface enabled before
transfer. Start it and verify its guest identity before changing anything.

```powershell
# Windows host, after the source checkpoint has been committed
git rev-parse HEAD
git archive --format=tar HEAD -o 'E:\AegisLab\artifacts\aegis-checkpoint.tar'
Copy-VMFile -VMName 'aegis-target-ubuntu' `
  -SourcePath 'E:\AegisLab\artifacts\aegis-checkpoint.tar' `
  -DestinationPath '/home/aegisdev/aegis-checkpoint.tar' -FileSource Host
```

```bash
# Ubuntu guest
mkdir -p ~/aegis-checkpoint && tar -xf ~/aegis-checkpoint.tar -C ~/aegis-checkpoint
cd ~/aegis-checkpoint
python3 -m venv .venv
. .venv/bin/activate
python -m pip install -e '.[enhanced,test]'
python -m pytest -q
python -m aegis_core --capability-report
```

Choose a dedicated non-synchronised Linux watch directory and repeat the safe
demo only after verifying Linux collector capability. Record Linux results
separately; Windows success does not validate Linux runtime telemetry.

## Demonstration checklist

- [ ] Correct committed SHA recorded.
- [ ] Evidence chain validates.
- [ ] A real collected event and persisted case are identified.
- [ ] Every response status is labelled simulated, verified, failed, or unsupported.
- [ ] Human approval is recorded before each disruptive LocalLab action.
- [ ] No firewall, host isolation, external blocking, or unimplemented action is claimed.
- [ ] Monitor is stopped and the dedicated lab directory is retained or removed deliberately.
