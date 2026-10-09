# Aegis — Panel Demonstration Guide

This is the authoritative rehearsal guide for the current working tree. It is
written for a Windows presentation host with an optional Ubuntu VM. Commands
are shown for PowerShell unless marked `[VM]`.

The most important accuracy rule for the panel is:

> Aegis currently monitors, normalizes, stores, detects, triages, and creates
> durable investigation cases. The Investigation Agent is implemented and
> tested, but it is invoked explicitly through the investigation CLI after a
> case exists. Monitoring does not automatically start the agent in the
> background.

## 1. Purpose of the Demo

By the end of the demonstration, the panel should be able to see one complete,
auditable path:

```text
local activity
  -> collector
  -> canonical Event
  -> SQLite EvidenceStore
  -> hash-chain integrity
  -> behavioral Finding
  -> deterministic triage score
  -> InvestigationCase
  -> explicit Investigation Agent run
  -> persisted InvestigationResult
```

The demo also makes the safety boundary visible:

- Collection and investigation are read-only.
- Evidence is referenced by real event IDs.
- The agent uses deterministic rule-based logic, not GPT/LLM reasoning.
- The agent has bounded tool calls, time, evidence expansion, and context.
- The agent can recommend actions, but does not kill processes, delete files,
  quarantine files, block networks, isolate hosts, or execute shell commands.
- A high-risk case means “investigate this”; it is not automatically proof of
  malware.

## 2. What Aegis Can Demonstrate TODAY

The status labels below are intentionally conservative:

- **IMPLEMENTED / LIVE-SAFE** — reliable to show directly on the presentation
  host.
- **IMPLEMENTED / CONTROLLED** — real code exists, but use the bounded scenario
  or a prepared data directory rather than relying on arbitrary live timing.
- **PARTIALLY VALIDATED** — implemented and tested, but platform or timing
  limitations make a live claim unsafe.
- **NOT IMPLEMENTED** — do not present as an existing feature.

### Monitoring engine

- **What it does:** `MonitoringEngine` starts collectors, ingests batches,
  persists events, evaluates findings, creates cases, emits health events, and
  writes `monitor-status.json`.
- **Implementation:** `aegis_core/engine.py`.
- **Demonstrate:** run:

  ```powershell
  $demo = Join-Path $env:TEMP "aegis-panel"
  $watch = Join-Path $demo "watch"
  $data = Join-Path $demo "data"
  New-Item -ItemType Directory -Force $watch, $data | Out-Null
  py -m aegis_core monitor test --data-dir $data --watch $watch `
    --interval-seconds 1 --seconds 5 --environment development --no-auth
  ```

- **Expected output:** `Aegis monitoring test complete; events=...`.
- **Status:** **IMPLEMENTED / CONTROLLED**. The bounded command is reliable;
  collector availability depends on the host.

### Process telemetry

- **What it does:** emits normalized process start/exit/snapshot events using
  `psutil` when available, with `/proc` or snapshot fallbacks.
- **Implementation:** `aegis_core/collectors.py`,
  `aegis_core/normalizers.py`.
- **Demonstrate:** use the capability report and inspect stored events:

  ```powershell
  py -m aegis_core --capability-report --watch $watch
  py -c "from pathlib import Path; from aegis_core.storage import EvidenceStore; s=EvidenceStore(Path(r'$data')/'evidence.sqlite3'); print('process_events=', s.count_events(kinds=['process'])); print([e['data'] for e in s.query_events(kinds=['process'])[:5]]); s.close()"
  ```

- **Expected output:** `process_lifecycle : AVAILABLE` and a non-negative
  process-event count.
- **Status:** **IMPLEMENTED / CONTROLLED**. On Windows, initial process
  baseline establishment and short-lived processes can make start events
  timing-sensitive.

### File telemetry

- **What it does:** watches only explicit roots, using watchdog when installed
  and polling otherwise. It records create, modify, and delete events. It
  never follows symlinks.
- **Implementation:** `aegis_core/collectors.py`,
  `FileEventCollector` and `FilePollingCollector`.
- **Demonstrate:** while monitoring a dedicated `$watch` directory, run:

  ```powershell
  Set-Content -LiteralPath (Join-Path $watch "panel-file.txt") -Value "one"
  Add-Content -LiteralPath (Join-Path $watch "panel-file.txt") -Value "two"
  Remove-Item -LiteralPath (Join-Path $watch "panel-file.txt")
  ```

  Then inspect:

  ```powershell
  py -c "from pathlib import Path; from aegis_core.storage import EvidenceStore; s=EvidenceStore(Path(r'$data')/'evidence.sqlite3'); [print(e['kind'], e['data']) for e in s.query_events(kinds=['file'])]; s.close()"
  ```

- **Expected output:** file events containing the dedicated path and actions
  such as `create`, `modify`, or `delete`.
- **Status:** **IMPLEMENTED / CONTROLLED**. Always use a disposable directory;
  never point the monitor at Documents, Desktop, OneDrive, or system folders.

### Network telemetry

- **What it does:** bridges the `network_monitor` subsystem into canonical
  network events for connections, traffic, DNS, and process-network activity.
  Windows uses a psutil-based adapter; Linux can use polling and has an eBPF
  capability path.
- **Implementation:** `aegis_core/collectors.py`,
  `aegis_core/normalizers.py`, `network_monitor/adapters/`.
- **Demonstrate:** first show the Aegis capability report:

  ```powershell
  py -m aegis_core --capability-report --watch $watch
  ```

  On Windows, optionally show the subsystem directly:

  ```powershell
  py -m network_monitor.sensors --duration 5 --interval 1 `
    --output (Join-Path $demo "network_events.jsonl") --monitor
  ```

  Then inspect Aegis events:

  ```powershell
  py -c "from pathlib import Path; from aegis_core.storage import EvidenceStore; s=EvidenceStore(Path(r'$data')/'evidence.sqlite3'); print('network_events=', s.count_events(kinds=['network'])); [print(e['data']) for e in s.query_events(kinds=['network'])[:5]]; s.close()"
  ```

- **Expected output:** capability status for `network_bridge`; the direct
  sensor prints adapter and collector capability information.
- **Status:** **IMPLEMENTED / PARTIALLY VALIDATED**. The adapter is real, but
  the exact events visible depend on OS permissions and active connections.
  Do not claim that Windows is using ETW: the capability report explicitly says
  ETW consumption requires a dedicated signed implementation.

### Authentication telemetry

- **What it does:** reads available authentication sources:
  Linux `journalctl` or `/var/log/auth.log`; Windows Security events via
  `wevtutil`.
- **Implementation:** `AuthEventCollector` in
  `aegis_core/collectors.py`.
- **Demonstrate:** show the capability report:

  ```powershell
  py -m aegis_core --capability-report --watch $watch
  ```

  Look for `auth_events : AVAILABLE` or an honest unavailable reason. Do not
  generate repeated login failures for the panel.
- **Expected output:** the selected mechanism, commonly `wevtutil` on Windows
  or `journalctl` on Linux.
- **Status:** **IMPLEMENTED / PARTIALLY VALIDATED**. Collection is capability
  gated and may require permissions; an empty stream is not a failure.

### Canonical event normalization

- **What it does:** converts platform-specific objects into the validated
  `aegis_core.models.Event` model with kind, source, timestamps, host ID,
  schema version, run ID, and collector provenance.
- **Implementation:** `aegis_core/models.py` and
  `aegis_core/normalizers.py`.
- **Demonstrate:** inspect one stored event:

  ```powershell
  py -c "from pathlib import Path; import json; from aegis_core.storage import EvidenceStore; s=EvidenceStore(Path(r'$data')/'evidence.sqlite3'); events=s.query_events(); print(json.dumps(events[0] if events else {'message':'no events'}, indent=2, default=str)); s.close()"
  ```

- **Expected output:** a JSON event with `event_id`, `kind`, `source`,
  `observed_at`, `host_id`, and normalized `data`.
- **Status:** **IMPLEMENTED / LIVE-SAFE**.

### EvidenceStore and SQLite persistence

- **What it does:** stores events, findings, investigation cases, and
  investigation results in `evidence.sqlite3` with WAL mode and query helpers.
- **Implementation:** `aegis_core/storage.py`.
- **Demonstrate:**

  ```powershell
  py -c "from pathlib import Path; import sqlite3; db=Path(r'$data')/'evidence.sqlite3'; c=sqlite3.connect(db); print(c.execute(\"select name from sqlite_master where type='table' order by name\").fetchall()); c.close()"
  ```

- **Expected output:** tables including `events`, `findings`,
  `investigation_cases`, and `investigation_results`.
- **Status:** **IMPLEMENTED / LIVE-SAFE**.

### Hash/evidence integrity

- **What it does:** each event record includes `previous_hash` and
  `record_hash`; `verify_chain()` independently checks the chain.
- **Implementation:** `EvidenceStore.append_events()` and
  `EvidenceStore.verify_chain()` in `aegis_core/storage.py`.
- **Demonstrate:**

  ```powershell
  py -c "from pathlib import Path; from aegis_core.storage import EvidenceStore; s=EvidenceStore(Path(r'$data')/'evidence.sqlite3'); print('chain_valid=', s.verify_chain()); s.close()"
  ```

- **Expected output:** `chain_valid= True`.
- **Status:** **IMPLEMENTED / LIVE-SAFE**. This proves internal chain
  consistency, not encryption at rest or a remote immutable archive.

### Detection

- **What it does:** applies explainable behavioral detectors, not malware
  signatures or claims of zero-day identification by itself:
  `FileChangeBurstDetector`, `NetworkRateDetector`,
  `NewProcessWithNetworkDetector`, `ProcessCreationBurstDetector`, and
  `AuthFailureBurstDetector`.
- **Implementation:** `aegis_core/detection.py`.
- **Demonstrate:** use the controlled test scenario or inspect findings:

  ```powershell
  py -c "from pathlib import Path; import json; from aegis_core.storage import EvidenceStore; s=EvidenceStore(Path(r'$data')/'evidence.sqlite3'); print(json.dumps(s.get_findings(), indent=2, default=str)); s.close()"
  ```

- **Expected output:** finding records with `rule_id`, severity, confidence,
  explanation, recommendation, and real `evidence_event_ids`.
- **Status:** **IMPLEMENTED / CONTROLLED**. Findings require the correct event
  pattern and threshold.

### Triage and risk scoring

- **What it does:** converts finding signals into a bounded risk score, signal
  list, severity, and transparent triage reason. The default case threshold
  is `0.50`.
- **Implementation:** `aegis_core/triage.py`.
- **Demonstrate:** inspect cases:

  ```powershell
  py -c "from pathlib import Path; import json; from aegis_core.storage import EvidenceStore; s=EvidenceStore(Path(r'$data')/'evidence.sqlite3'); print(json.dumps(s.query_cases(), indent=2, default=str)); s.close()"
  ```

- **Expected output:** `risk_score`, `severity`, `detection_signals`,
  `triage_reason`, and `status: NEW`.
- **Status:** **IMPLEMENTED / LIVE-SAFE** once a finding exists.

### InvestigationCase

- **What it does:** is the durable handoff object containing host, severity,
  risk score, trigger rule, trigger event ID, evidence event IDs, time window,
  detection signals, and initial assessment.
- **Implementation:** `InvestigationCase` in `aegis_core/triage.py`; persistence
  in `aegis_core/storage.py`.
- **Demonstrate:** show the case query above, then copy a `case_id` for the
  Investigation Agent.
- **Expected output:** an `INC-...` case with `status: NEW`.
- **Status:** **IMPLEMENTED / LIVE-SAFE** when a finding crosses threshold.

### Investigation Agent and adaptive investigation

- **What it does:** claims a `NEW` case, loads its evidence, expands related
  evidence, checks process/file/network/auth context, builds a timeline,
  evaluates competing hypotheses, classifies the case, and persists a result.
- **Implementation:** `aegis_core/investigation/agent.py`,
  `state.py`, `tools.py`, and `result.py`.
- **Demonstrate:** after obtaining `$caseId`:

  ```powershell
  py -m aegis_core investigate run --case-id $caseId `
    --data-dir $data --max-tool-calls 30 --max-seconds 120
  ```

- **Expected output:** the formatted `AEGIS INVESTIGATION RESULT` showing case
  ID, result status, classification, confidence, tool calls, evidence used,
  summary, timeline, uncertainties, and read-only recommended actions.
- **Status:** **IMPLEMENTED / CONTROLLED**. Automated handoff and idempotency
  tests pass. The live Windows telemetry-to-case part is timing-sensitive.

### Investigation tools

- **What it does:** provides controlled, read-only access to cases, events,
  related events, process info/tree, PID events, file activity, network
  activity, authentication activity, timeline, event analysis, and suspicious
  process/network pairs.
- **Implementation:** `aegis_core/investigation/tools.py`.
- **Demonstrate:** point to the tool-call count and evidence list in the
  result; use `--json` when you need the full structured record:

  ```powershell
  py -m aegis_core investigate run --case-id $caseId `
    --data-dir $data --json > (Join-Path $demo "investigation-result.json")
  Get-Content (Join-Path $demo "investigation-result.json") -TotalCount 80
  ```

- **Expected output:** structured result fields and real event IDs.
- **Status:** **IMPLEMENTED / LIVE-SAFE** once a case exists.

### Hypotheses and classification

- **What it does:** maintains benign, suspicious, and malicious hypotheses;
  updates confidence from observed signals and supporting/contradictory
  evidence; returns `BENIGN`, `SUSPICIOUS`, `MALICIOUS`, or `UNKNOWN`.
- **Implementation:** `Hypothesis` in `state.py`; evaluation and
  classification in `agent.py`.
- **Demonstrate:** use JSON output:

  ```powershell
  py -c "from pathlib import Path; import json; from aegis_core.storage import EvidenceStore; s=EvidenceStore(Path(r'$data')/'evidence.sqlite3'); r=s.get_investigation_result(r'$caseId'); print(json.dumps({'classification':r['classification'],'confidence':r['confidence'],'supporting':r['supporting_evidence'],'contradictory':r['contradictory_evidence'],'reasoning_summary':r['reasoning_summary'],'stop_reason':r['stop_reason']}, indent=2, default=str)); s.close()"
  ```

- **Expected output:** classification plus supporting and contradictory
  evidence references.
- **Status:** **IMPLEMENTED / LIVE-SAFE**, with the important caveat that
  confidence is an investigation estimate, not a calibrated probability.

### InvestigationResult and case lifecycle

- **What it does:** persists one result per case, with an `investigation_id`,
  status, classification, confidence, timeline, evidence, coverage,
  uncertainties, recommendations, tool-call count, and stop reason.
- **Lifecycle:** `NEW -> INVESTIGATING -> BENIGN/SUSPICIOUS/MALICIOUS`; errors
  are recorded as `ERROR`. Repeating a completed case returns the existing
  persisted result.
- **Implementation:** `result.py`, `storage.py`, and `agent.py`.
- **Demonstrate:**

  ```powershell
  py -m aegis_core investigate run --case-id $caseId --data-dir $data
  py -m aegis_core investigate run --case-id $caseId --data-dir $data
  ```

- **Expected output:** the second invocation returns the same
  `investigation_id`; it does not create a duplicate result.
- **Status:** **IMPLEMENTED / LIVE-SAFE**.

### CLI

- **Implemented commands:**

  ```powershell
  py -m aegis_core --capability-report
  py -m aegis_core --data-dir $data --analyze
  py -m aegis_core monitor start --data-dir $data --watch $watch
  py -m aegis_core monitor test --data-dir $data --watch $watch --seconds 5
  py -m aegis_core monitor status --data-dir $data
  py -m aegis_core monitor stop --data-dir $data
  py -m aegis_core investigate <CASE_ID> --data-dir $data
  py -m aegis_core investigate run --case-id <CASE_ID> --data-dir $data
  py -m aegis_core investigate pending --data-dir $data
  ```

- **Status:** **IMPLEMENTED / LIVE-SAFE**. The monitor is a foreground
  process; it is not installed as a Windows or Linux service.

### Windows, Linux, VM, and macOS boundaries

- **Windows:** process lifecycle via psutil, file watchdog/polling,
  Windows network adapter through `network_monitor`, authentication through
  `wevtutil`, and capability reporting. **IMPLEMENTED / CONTROLLED.**
- **Linux/VM:** process and file collection, network polling, optional eBPF
  connection tracing, and authentication through `journalctl` or
  `/var/log/auth.log`. eBPF requires Linux kernel/privilege/BTF/tracepoint
  prerequisites. **IMPLEMENTED / PARTIALLY VALIDATED.**
- **macOS:** capability boundaries and adapter stubs exist; do not claim
  complete native Endpoint Security telemetry. **PARTIALLY IMPLEMENTED.**
- **Why use Windows for the panel:** it is the current development host and
  the basic capability report, process collector, file collector, SQLite
  store, and Investigation Agent tests are available there. Use the VM only
  if you want to show the Linux/eBPF architecture.

### Tests and validation

- **What it does:** tests models, normalizers, collectors, storage, detection,
  triage, integration, stability, network adapters, adaptive investigation,
  agent features, and durable handoff.
- **Demonstrate:**

  ```powershell
  py -m pytest -q
  ```

- **Expected output:** current audited result: `246 passed`.
- **Status:** **IMPLEMENTED / LIVE-SAFE**. Test count can change if the suite
  changes; use the actual output rather than memorizing the number.

## 3. Recommended 10–15 Minute Panel Demo

Use two PowerShell terminals:

- **PowerShell 1:** foreground monitor.
- **PowerShell 2:** commands, activity generation, inspection, and agent run.

### STEP 1 — Open the repository and prepare disposable paths

**Goal:** prove the demo is isolated and reproducible.

**ACTION:**

```powershell
Set-Location "C:\Users\Visha\OneDrive\Documents\Sem 7\Major Project"
$demo = Join-Path $env:TEMP "aegis-panel"
Remove-Item -LiteralPath $demo -Recurse -Force -ErrorAction SilentlyContinue
$watch = Join-Path $demo "watch"
$data = Join-Path $demo "data"
New-Item -ItemType Directory -Force $watch, $data | Out-Null
.\.venv\Scripts\Activate.ps1
```

**WHAT I SHOULD SEE:** The prompt is at the repository root and the two
dedicated directories exist.

**WHAT I SHOULD SAY:** “I am using a disposable watch directory and a separate
SQLite data directory. Aegis is not pointed at personal or system files.”

**IF IT FAILS:** Use `.\.venv\Scripts\python.exe` instead of activating the
environment, and recreate the two directories.

### STEP 2 — Show host capabilities

**Goal:** show that Aegis reports what is actually available instead of
pretending every sensor is present.

**ACTION:**

```powershell
py --version
py -m aegis_core --capability-report --watch $watch
```

**WHAT I SHOULD SEE:** Windows OS information, `psutil`, process lifecycle,
network bridge, authentication mechanism, and any explicit limitations.

**WHAT I SHOULD SAY:** “Capability discovery is honest. The collector path is
selected from what this host can actually provide, and unavailable mechanisms
are reported rather than fabricated.”

**IF IT FAILS:** Run `.\.venv\Scripts\python.exe -m aegis_core --capability-report
--watch $watch`. If a collector says unavailable, show that limitation and
continue; it is an intended capability-gated result.

### STEP 3 — Start monitoring

**Goal:** prove the monitoring engine is a real foreground process with
durable status and evidence output.

**ACTION in PowerShell 1:**

```powershell
py -m aegis_core monitor start --data-dir $data --watch $watch `
  --interval-seconds 1 --environment development --no-auth
```

**WHAT I SHOULD SEE:** `Aegis monitoring started in foreground...`; the command
stays running.

**WHAT I SHOULD SAY:** “The engine is running in the foreground for this
demonstration. Each cycle collects available telemetry, stores it, evaluates
detectors, and writes runtime status.”

**IF IT FAILS:** In PowerShell 2 run:

```powershell
py -m aegis_core monitor test --data-dir $data --watch $watch `
  --interval-seconds 1 --seconds 5 --environment development --no-auth
```

Then proceed with the inspection and backup path.

### STEP 4 — Prove status and generate harmless file activity

**Goal:** prove monitoring status and file telemetry without modifying user
files.

**ACTION in PowerShell 2:**

```powershell
py -m aegis_core monitor status --data-dir $data
Set-Content -LiteralPath (Join-Path $watch "panel-file.txt") -Value "one"
Add-Content -LiteralPath (Join-Path $watch "panel-file.txt") -Value "two"
Remove-Item -LiteralPath (Join-Path $watch "panel-file.txt")
Start-Sleep -Seconds 3
```

**WHAT I SHOULD SEE:** JSON status with `state: running`, collector details,
event count, and `evidence_chain_valid: true`.

**WHAT I SHOULD SAY:** “This is a bounded local file lifecycle. The collector
records observations; it does not repair, delete, or roll back anything on my
behalf.”

**IF IT FAILS:** Run the bounded `monitor test` command from Step 3 and
continue. The process-burst path is not required to prove file telemetry.

### STEP 5 — Inspect canonical events and integrity

**Goal:** prove raw platform observations became canonical, persisted events.

**ACTION:**

```powershell
py -c "from pathlib import Path; import json; from aegis_core.storage import EvidenceStore; s=EvidenceStore(Path(r'$data')/'evidence.sqlite3'); print('event_count=',s.count_events()); print('file_events=',s.count_events(kinds=['file'])); print('process_events=',s.count_events(kinds=['process'])); print('network_events=',s.count_events(kinds=['network'])); print('chain_valid=',s.verify_chain()); print(json.dumps(s.query_events(kinds=['file'])[:3],indent=2,default=str)); s.close()"
```

**WHAT I SHOULD SEE:** Event counts, `chain_valid= True`, and file events with
real event IDs and observed timestamps.

**WHAT I SHOULD SAY:** “The evidence boundary is SQLite. Each event has
provenance, and the hash chain lets us verify that the stored sequence is
internally consistent.”

**IF IT FAILS:** If the database is missing, check `$data` and rerun the
monitor. If the file count is zero, show process/health events and continue;
file notifications can be timing-dependent.

### STEP 6 — Demonstrate the controlled real-process scenario

**Goal:** attempt the real telemetry path using the repository’s harmless,
bounded process generator.

**ACTION in PowerShell 2:**

```powershell
py scripts\investigation_process_scenario.py `
  --count 20 --interval 0.05 --hold-seconds 15
Start-Sleep -Seconds 3
py -c "from pathlib import Path; from aegis_core.storage import EvidenceStore; s=EvidenceStore(Path(r'$data')/'evidence.sqlite3'); print('process_starts=',sum(e.get('data',{}).get('action')=='start' for e in s.query_events(kinds=['process']))); print('findings=',len(s.get_findings())); print('cases=',len(s.query_cases())); s.close()"
```

**WHAT I SHOULD SEE:** The scenario exits cleanly. Counts may show process
starts, findings, and cases.

**WHAT I SHOULD SAY:** “This is a safe local process-creation pattern, not a
malware simulation. The detector uses behavior and event timing, not the name
of this script.”

**IF IT FAILS:** Do not claim automatic live detection. Use the reliable
backup in Section 10, which runs the actual tested handoff with persisted
canonical evidence.

### STEP 7 — Inspect finding and case

**Goal:** prove the detection-to-triage boundary.

**ACTION:**

```powershell
py -c "from pathlib import Path; import json; from aegis_core.storage import EvidenceStore; s=EvidenceStore(Path(r'$data')/'evidence.sqlite3'); print('FINDINGS'); print(json.dumps(s.get_findings(),indent=2,default=str)); print('CASES'); print(json.dumps(s.query_cases(),indent=2,default=str)); s.close()"
```

**WHAT I SHOULD SEE:** A finding with `rule_id`, severity, explanation, and
real event IDs; if threshold was crossed, a case with `INC-...`, `risk_score`,
`detection_signals`, and `status: NEW`.

**WHAT I SHOULD SAY:** “Detection creates an evidence-backed finding. Triage
adds a transparent risk score and opens a case when the score reaches the
threshold. This is an attention decision, not a final malware verdict.”

**IF IT FAILS:** If there is no case, record that live timing did not cross the
threshold and go to Section 10. Do not fabricate a case ID.

### STEP 8 — Run the Investigation Agent explicitly

**Goal:** prove case claiming, adaptive investigation, classification, and
result persistence.

**ACTION:**

```powershell
$caseId = (py -c "from pathlib import Path; from aegis_core.storage import EvidenceStore; s=EvidenceStore(Path(r'$data')/'evidence.sqlite3'); c=s.query_cases(status='NEW'); print(c[0]['case_id'] if c else ''); s.close()").Trim()
$caseId
py -m aegis_core investigate run --case-id $caseId `
  --data-dir $data --max-tool-calls 30 --max-seconds 120
```

**WHAT I SHOULD SEE:** `AEGIS INVESTIGATION RESULT`, case ID, result status,
classification, confidence, tool calls, evidence used, timeline, and
uncertainties/recommendations.

**WHAT I SHOULD SAY:** “The agent is explicit and bounded. It claims the
persisted case, checks evidence gaps, uses only read-only tools, evaluates
hypotheses, and stores an auditable result.”

**IF IT FAILS:** If `$caseId` is empty, use Section 10. If the result is
`PARTIAL`, show the stop reason and uncertainties; that is an honest bounded
outcome. If it is `ERROR`, preserve the output and use the prepared backup.

### STEP 9 — Prove persistence, provenance, and idempotency

**Goal:** prove the result survived the process and references real evidence.

**ACTION:**

```powershell
py -c "from pathlib import Path; import json; from aegis_core.storage import EvidenceStore; s=EvidenceStore(Path(r'$data')/'evidence.sqlite3'); r=s.get_investigation_result(r'$caseId'); c=s.get_case_by_id(r'$caseId'); stored={e['event_id'] for e in s.query_events()}; used=set(r['evidence_ids_used']) if r else set(); print(json.dumps({'case_status':c['status'] if c else None,'result_exists':r is not None,'investigation_id':r.get('investigation_id') if r else None,'evidence_used':len(used),'missing_evidence_ids':sorted(used-stored),'chain_valid':s.verify_chain()},indent=2)); s.close()"
py -m aegis_core investigate run --case-id $caseId --data-dir $data
```

**WHAT I SHOULD SEE:** `result_exists: true`, an investigation ID, an empty
`missing_evidence_ids` list, `chain_valid: true`, and the second run returning
the same result.

**WHAT I SHOULD SAY:** “The result does not merely say ‘malicious’ or
‘suspicious’. Every evidence reference resolves to a stored event, and
reprocessing the same case reuses the durable result.”

**IF IT FAILS:** Show the persisted JSON directly with
`py -m aegis_core investigate run --case-id $caseId --data-dir $data --json`
and explain the exact error rather than claiming success.

### STEP 10 — Stop cleanly

**Goal:** prove controlled shutdown and persistence after shutdown.

**ACTION:**

```powershell
py -m aegis_core monitor stop --data-dir $data
Start-Sleep -Seconds 2
py -m aegis_core monitor status --data-dir $data
```

**WHAT I SHOULD SEE:** `Stop requested...` followed by status with
`state: stopped` or `stopped: true`.

**WHAT I SHOULD SAY:** “Stopping the monitor closes collectors and the
database cleanly. The evidence and investigation result remain on disk for
later review.”

**IF IT FAILS:** Press Ctrl+C in PowerShell 1, then rerun the status command.

## 4. Pre-Demo Setup — Tomorrow Before the Panel

Run this checklist from the moment the laptop is opened.

- [ ] Open VS Code.
- [ ] Open `C:\Users\Visha\OneDrive\Documents\Sem 7\Major Project`.
- [ ] Open two integrated PowerShell terminals.
- [ ] Confirm the branch and current commit:

  ```powershell
  Set-Location "C:\Users\Visha\OneDrive\Documents\Sem 7\Major Project"
  git branch --show-current
  git log -1 --oneline
  git status --short
  ```

- [ ] Do not discard existing working-tree changes. This guide describes the
  current working tree; do not run `git reset`, `git clean`, or `git checkout`.
- [ ] Activate the existing environment:

  ```powershell
  .\.venv\Scripts\Activate.ps1
  py --version
  py -c "import aegis_core, psutil; print(aegis_core.__file__); print(psutil.__version__)"
  ```

- [ ] Verify CLI help:

  ```powershell
  py -m aegis_core --help
  py -m aegis_core monitor --help
  py -m aegis_core investigate --help
  ```

- [ ] Create a clean disposable directory:

  ```powershell
  $demo = Join-Path $env:TEMP "aegis-panel"
  Remove-Item -LiteralPath $demo -Recurse -Force -ErrorAction SilentlyContinue
  $watch = Join-Path $demo "watch"
  $data = Join-Path $demo "data"
  New-Item -ItemType Directory -Force $watch, $data | Out-Null
  ```

- [ ] Verify the host capability report:

  ```powershell
  py -m aegis_core --capability-report --watch $watch
  ```

- [ ] Run the full automated suite before leaving setup:

  ```powershell
  py -m pytest -q
  ```

  The current audited result is `246 passed`.

- [ ] Keep the existing `docs/AEGIS_INVESTIGATION_AGENT_TEST.md` open as a
  secondary operator reference and this file open as the panel script.
- [ ] If using the VM, start the existing Hyper-V Ubuntu VM, verify its
  repository checkout, activate its Python 3.11+ environment, and run:

  ```bash
  python3 -m aegis_core --capability-report --watch /tmp/aegis-panel/watch
  python3 -m pytest -q
  ```

- [ ] Prepare the reliable backup command from Section 10 before the panel.

## 5. LIVE ATTACK / SUSPICIOUS ACTIVITY DEMO

This is a benign activity demonstration, not an attack simulation.

### PRIMARY live method — foreground Windows monitor plus bounded process burst

1. Start the monitor with a dedicated watch/data directory:

   ```powershell
   py -m aegis_core monitor start --data-dir $data --watch $watch `
     --interval-seconds 1 --environment development --no-auth
   ```

2. In the second terminal run:

   ```powershell
   py scripts\investigation_process_scenario.py `
     --count 20 --interval 0.05 --hold-seconds 15
   ```

3. Inspect counts:

   ```powershell
   py -c "from pathlib import Path; from aegis_core.storage import EvidenceStore; s=EvidenceStore(Path(r'$data')/'evidence.sqlite3'); print('starts=',sum(e.get('data',{}).get('action')=='start' for e in s.query_events(kinds=['process']))); print('findings=',len(s.get_findings())); print('cases=',len(s.query_cases())); s.close()"
   ```

4. If a case exists, continue with the Investigation Agent commands in
   Section 6.

**Safety:** the scenario starts at most 20 local children, uses loopback
`ping` on Windows, has bounded timing, and cleans up its children.

**Known limitation:** this is not guaranteed to cross the default threshold
on Windows. `ProcessLifecycleCollector` establishes an initial process
baseline, and short-lived children can be missed by polling. This was observed
during previous Windows validation.

### SECONDARY live method — bounded file activity

Use this if the panel is more interested in collection than process-burst
detection:

```powershell
Set-Content -LiteralPath (Join-Path $watch "panel-file.txt") -Value "one"
Add-Content -LiteralPath (Join-Path $watch "panel-file.txt") -Value "two"
Remove-Item -LiteralPath (Join-Path $watch "panel-file.txt")
Start-Sleep -Seconds 3
py -c "from pathlib import Path; from aegis_core.storage import EvidenceStore; s=EvidenceStore(Path(r'$data')/'evidence.sqlite3'); [print(e['data']) for e in s.query_events(kinds=['file'])]; s.close()"
```

This proves real file telemetry and canonical persistence, but it does not
necessarily create a case because the default file-burst threshold is much
higher than three file operations.

### RELIABLE backup method — deterministic tested handoff

Use this when live telemetry does not create a case. It is the real
Investigation Agent and real SQLite persistence, but it uses deterministic
canonical fixture events inside the automated handoff test rather than claiming
that the live OS generated the case:

```powershell
py -m pytest -q tests\test_investigation_handoff.py -s
```

Expected result:

```text
2 passed
```

The second test constructs 20 canonical process-start events, runs the actual
`MonitoringEngine` ingestion/detection/triage path with a test threshold of 3,
creates a real `InvestigationCase`, runs the actual `InvestigationAgent`, and
verifies that every result evidence ID resolves in `EvidenceStore`.

Say this exactly:

> “The live Windows collector did not cross the burst threshold reliably in
> this short demonstration window, so I am not claiming automatic live
> detection. This backup uses the same engine, detector, triage, case, agent,
> and persistence code with deterministic canonical events, and the test
> verifies the complete handoff and provenance.”

## 6. Investigation Agent Demonstration

### How to obtain a case

List cases from the selected data directory:

```powershell
py -c "from pathlib import Path; import json; from aegis_core.storage import EvidenceStore; s=EvidenceStore(Path(r'$data')/'evidence.sqlite3'); print(json.dumps(s.query_cases(),indent=2,default=str)); s.close()"
```

Select one `case_id`:

```powershell
$caseId = "INC-REPLACE-WITH-ACTUAL-ID"
```

Never invent a case ID for the panel.

### How the case is claimed

The agent first checks for an existing result. If none exists, it calls the
durable atomic claim path, which changes `NEW` to `INVESTIGATING` only if the
case is still `NEW`.

Show the status before and after:

```powershell
py -c "from pathlib import Path; from aegis_core.storage import EvidenceStore; s=EvidenceStore(Path(r'$data')/'evidence.sqlite3'); print(s.get_case_by_id(r'$caseId')['status']); s.close()"
py -m aegis_core investigate run --case-id $caseId --data-dir $data
py -c "from pathlib import Path; from aegis_core.storage import EvidenceStore; s=EvidenceStore(Path(r'$data')/'evidence.sqlite3'); print(s.get_case_by_id(r'$caseId')['status']); s.close()"
```

The final status is normally `BENIGN`, `SUSPICIOUS`, or `MALICIOUS`; an
unrecoverable failure is `ERROR`.

### What the agent can use

The read-only tools are backed by `EvidenceStore`, `CorrelationIndex`, and
`Timeline`. They include:

- case and event retrieval;
- case events and nearby same-host events;
- process metadata, process trees, and PID-associated events;
- file activity;
- network activity by PID;
- authentication activity;
- timeline construction;
- event analysis;
- suspicious process/network pair correlation.

Telemetry values are treated as data. They are not evaluated or executed as
commands.

### How it chooses missing evidence

The adaptive loop repeatedly:

1. checks whether trigger and seed events are loaded;
2. checks whether related events were expanded;
3. checks process, file, network, and authentication coverage;
4. checks whether suspicious process/network pairs were queried;
5. checks newly discovered PIDs and file paths;
6. builds a timeline and evaluates hypotheses;
7. stops on sufficient evidence, no useful action, or a budget limit.

Each tool call records a tool name, arguments, reason, evidence gap,
returned event IDs, and any error.

### How hypotheses change

The agent initializes `H_BENIGN`, `H_SUSPICIOUS`, and `H_MALICIOUS`.
High-severity findings raise suspicion and lower benign confidence.
Process/file/network correlation raises suspicion. Suspicious process/network
overlap can raise the malicious hypothesis. Missing corroborating file or
network evidence is recorded as contradictory/uncertain evidence and lowers
malicious confidence.

`MALICIOUS` requires more than a high triage score: malicious hypothesis
confidence must exceed the internal threshold, at least two strong signals
must exist, and at least three supporting evidence items must exist. A
process-creation burst alone should not be presented as proof of malware.

### Whether this is GPT/LLM

It is not. The current agent docstring explicitly says it does not require an
LLM. Tool selection, evidence expansion, hypothesis updates, classification,
and stop conditions are deterministic Python logic. A future LLM could propose
queries or summarize evidence, but the current implementation does not contain
an LLM provider or GPT call.

### How it stops

The default budget is:

```text
30 tool calls
120 seconds
500 evidence items
1 MB investigation context
```

The result records a machine-readable stop reason such as
`sufficient_evidence`, `max_tool_calls`, `max_time`,
`max_evidence_expansion`, `max_context_size`, `telemetry_unavailable`, or
`error`.

### How to display the final result

Human-readable:

```powershell
py -m aegis_core investigate run --case-id $caseId --data-dir $data
```

Full structured JSON:

```powershell
py -m aegis_core investigate run --case-id $caseId `
  --data-dir $data --json
```

Persisted database record:

```powershell
py -c "from pathlib import Path; import json; from aegis_core.storage import EvidenceStore; s=EvidenceStore(Path(r'$data')/'evidence.sqlite3'); print(json.dumps(s.get_investigation_result(r'$caseId'),indent=2,default=str)); s.close()"
```

## 7. Evidence / Proof

Use these commands live with `$data` set to the selected data directory.

### Prove events were captured

```powershell
py -c "from pathlib import Path; from aegis_core.storage import EvidenceStore; s=EvidenceStore(Path(r'$data')/'evidence.sqlite3'); print('all=',s.count_events()); print('process=',s.count_events(kinds=['process'])); print('file=',s.count_events(kinds=['file'])); print('network=',s.count_events(kinds=['network'])); print('auth=',s.count_events(kinds=['authentication'])); s.close()"
```

### Prove evidence was persisted

```powershell
Test-Path (Join-Path $data "evidence.sqlite3")
Get-ChildItem $data
```

### Prove evidence integrity

```powershell
py -c "from pathlib import Path; from aegis_core.storage import EvidenceStore; s=EvidenceStore(Path(r'$data')/'evidence.sqlite3'); print(s.verify_chain()); s.close()"
```

### Prove a finding and case exist

```powershell
py -c "from pathlib import Path; import json; from aegis_core.storage import EvidenceStore; s=EvidenceStore(Path(r'$data')/'evidence.sqlite3'); print(json.dumps({'findings':s.get_findings(),'cases':s.query_cases()},indent=2,default=str)); s.close()"
```

### Prove an investigation happened

```powershell
py -c "from pathlib import Path; import json; from aegis_core.storage import EvidenceStore; s=EvidenceStore(Path(r'$data')/'evidence.sqlite3'); print(json.dumps(s.query_investigation_results(),indent=2,default=str)); s.close()"
```

### Prove the result exists and references real evidence

```powershell
py -c "from pathlib import Path; import json; from aegis_core.storage import EvidenceStore; s=EvidenceStore(Path(r'$data')/'evidence.sqlite3'); r=s.get_investigation_result(r'$caseId'); stored={e['event_id'] for e in s.query_events()}; used=set(r['evidence_ids_used']) if r else set(); print(json.dumps({'result_exists':r is not None,'investigation_id':r.get('investigation_id') if r else None,'missing_evidence_ids':sorted(used-stored),'chain_valid':s.verify_chain()},indent=2)); s.close()"
```

The required proof is an empty `missing_evidence_ids` list.

## 8. Windows vs Linux/VM Demo

### Recommended: Windows host

Use Windows for the panel because it is the current development host and the
operator flow is already available:

```powershell
py -m aegis_core --capability-report --watch $watch
py -m aegis_core monitor test --data-dir $data --watch $watch --seconds 5
py -m pytest -q
```

Windows-specific facts to state accurately:

- process telemetry is available through psutil;
- the network adapter is Windows-aware and currently uses polling/psutil
  capability paths;
- authentication is attempted through `wevtutil`;
- ETW is only a capability probe/limitation in the current core;
- process-burst detection can miss short-lived processes due to polling and
  baseline timing.

### Alternative: Ubuntu VM

Use the existing Hyper-V VM only if it is already prepared. In the VM:

```bash
cd /path/to/The-Aegis
python3 -m venv .venv
source .venv/bin/activate
python3 -m pip install -e ".[enhanced,test]"
mkdir -p /tmp/aegis-panel/watch /tmp/aegis-panel/data
python3 -m aegis_core --capability-report --watch /tmp/aegis-panel/watch
python3 -m aegis_core monitor test \
  --data-dir /tmp/aegis-panel/data \
  --watch /tmp/aegis-panel/watch \
  --interval-seconds 1 --seconds 10 --environment development --no-auth
python3 -m pytest -q
```

For the network subsystem:

```bash
python3 -m network_monitor.sensors --duration 10 --interval 1 \
  --output /tmp/aegis-panel/network_events.jsonl --monitor
```

If the capability report says eBPF is inactive, show the reason and the
polling fallback. Do not claim eBPF is active unless the report says so.

## 9. What NOT to Demonstrate

- Do not claim the monitor automatically dispatches every new case to the
  Investigation Agent. The current dispatch is explicit CLI/pending polling.
- Do not claim the current agent is GPT, an LLM, or autonomous natural-language
  reasoning.
- Do not claim a process burst alone proves maliciousness.
- Do not claim Windows ETW ingestion is implemented; the capability report
  identifies it as requiring a dedicated signed implementation.
- Do not rely on the short `safe_e2e_demo.py` as the primary live Windows
  command. It is implemented, but its short collection window produced zero
  events on the current Windows host.
- Do not point collectors at personal, cloud-synced, system, or production
  directories.
- Do not generate real brute-force login failures or destructive file changes.
- Do not claim macOS Endpoint Security collection is complete.
- Do not claim encryption at rest, remote immutable storage, enterprise
  deployment, or service installation.
- Do not present `reports/` as the current durable result store; results are
  currently in SQLite.
- Do not demonstrate a Response Agent or automatic remediation. It is not
  implemented.

## 10. Backup Plan

## PANIC MODE

Use this if the live telemetry does not create a case.

### 1. Stop the live monitor if it is still running

```powershell
py -m aegis_core monitor stop --data-dir $data
```

If needed, press Ctrl+C in PowerShell 1.

### 2. Run the actual deterministic handoff tests

```powershell
py -m pytest -q tests\test_investigation_handoff.py -s
```

### 3. Show the test source in VS Code

Open:

```text
tests/test_investigation_handoff.py
```

Show that it:

- creates canonical process events;
- runs `MonitoringEngine._ingest`;
- uses `ProcessCreationBurstDetector`;
- creates a high case through triage;
- calls `InvestigationAgent.investigate`;
- checks persisted result existence;
- verifies every result evidence ID resolves in the store.

### 4. Say this

> “The live host collector did not cross the process-burst threshold within
> this short polling window, so I am not claiming that it did. I am now
> demonstrating the same implemented handoff with deterministic canonical
> events: engine, detector, triage, case persistence, agent investigation,
> result persistence, and evidence provenance are all exercised by the
> repository’s automated integration test.”

### 5. Show the full suite result

```powershell
py -m pytest -q
```

Expected current result: `246 passed`.

This is a valid demonstration of the Investigation Agent, but it is not a
claim of automatic live OS detection. Keep that distinction explicit.

## 11. Demo Talking Script

### 30-second introduction

“Aegis is a cross-platform defensive monitoring core. It observes process,
file, network, and authentication activity, normalizes those observations into
a common event model, stores them in a tamper-evident SQLite evidence store,
detects explainable behavioral patterns, and opens investigation cases for
human review. The current Investigation Agent then performs a bounded,
read-only, evidence-backed investigation and persists its result.”

### Architecture explanation

“The pipeline is collector to canonical event, then EvidenceStore, detection,
triage, InvestigationCase, and finally the explicitly invoked Investigation
Agent. The agent does not bypass the evidence store or consume raw platform
output.”

### Monitoring explanation

“The engine is a foreground process for this implementation. It polls or
receives from capability-gated collectors, isolates collector failures with
health events and backoff, and writes runtime status and evidence to the
selected data directory.”

### Detection and triage explanation

“Detection is behavior-based and explainable. A detector emits a finding with
real evidence IDs. Triage combines transparent signal weights into a bounded
risk score and creates a case only when the configured threshold is crossed.”

### Investigation Agent explanation

“The agent is not GPT. It is deterministic adaptive Python logic. It identifies
missing evidence, selects read-only tools to close those gaps, maintains
benign/suspicious/malicious hypotheses, records supporting and contradictory
evidence, respects budgets, and persists a structured result.”

### Evidence integrity explanation

“Each event is chained to the previous event hash. I can call `verify_chain()`
live, and the result’s evidence IDs are checked against stored events.”

### Limitation explanation

“The current implementation is strongest as a monitored evidence and
investigation foundation. Windows short-lived process detection is timing
sensitive, automatic case-to-agent dispatch is not yet present, and response
or remediation is deliberately outside the current safety boundary.”

### Future work explanation

“Future work is a supervised dispatcher, stronger native sensors such as a
dedicated signed ETW implementation, calibrated detection models, optional
LLM-assisted summarization behind deterministic policy checks, enterprise
durability, and a human-approved Response Agent.”

## 12. Likely Panel Questions

### Why zero-day detection?

**Answer:** “The current system does not claim perfect zero-day detection. It
uses behavior-oriented patterns such as bursts, correlations, rates, and
process/network relationships rather than only known malware signatures. That
can surface previously unseen behavior, but it still requires investigation and
can produce false positives.”

### How do you detect something you have never seen before?

**Answer:** “The detector can reason from observed behavior and relationships,
such as rapid process creation or a new process connecting to a network
endpoint. It does not need a stored malware name. It produces an explainable
finding, not a guaranteed malware label.”

### What is the difference between detection and investigation?

**Answer:** “Detection is the first-stage pattern check that emits a finding.
Triage scores it and may create a case. Investigation expands the evidence,
checks context and contradictions, evaluates hypotheses, and writes a
structured result.”

### Why deterministic detection?

**Answer:** “Deterministic rules are explainable, testable, reproducible, and
safe for a panel and an initial production foundation. Every finding carries
the event IDs and explanation that caused it.”

### Why use an agent?

**Answer:** “The agent coordinates multiple evidence queries and avoids
forcing a human to manually inspect every related process, file, network, and
authentication event. Its current policy is bounded and deterministic.”

### Is the Investigation Agent an LLM?

**Answer:** “No. The current implementation has no GPT or LLM provider. It is
rule-based adaptive logic with explicit tool selection and hypothesis updates.”

### Why do you not let GPT control the system?

**Answer:** “The current safety boundary keeps telemetry as data and tools
read-only. A future LLM could assist with prioritization or summarization,
but deterministic policy, evidence validation, budgets, and human approval
should remain authoritative.”

### How does the agent choose its next step?

**Answer:** “It checks evidence coverage and creates candidate actions for
unexpanded related events, missing process/file/network/auth context,
unqueried suspicious pairs, newly discovered PIDs/paths, timeline construction,
and hypothesis evaluation. It selects the highest-priority unexecuted action.”

### How do you prevent false positives?

**Answer:** “The system does not eliminate false positives. It uses thresholds,
multiple signals, corroboration, contradictory evidence, confidence estimates,
and an `UNKNOWN` classification. A process burst alone is not enough for a
malicious classification.”

### How is evidence integrity maintained?

**Answer:** “Events are stored with a previous hash and record hash. The store
can verify the chain. Findings, cases, and results retain real event IDs, so
the conclusion can be traced back to evidence.”

### What happens if telemetry is incomplete?

**Answer:** “Collectors report capability or health limitations, the agent
records uncertainties and coverage gaps, and it can stop with `PARTIAL`,
`UNKNOWN`, or a telemetry-unavailable reason. It does not invent missing
events.”

### What happens if the agent is wrong?

**Answer:** “The result is an investigation estimate, not an irreversible
action. Supporting evidence, contradictory evidence, uncertainty, confidence,
and recommendations are persisted for human review. No remediation is
executed.”

### How is the case lifecycle handled?

**Answer:** “Cases are created as `NEW`, atomically claimed as
`INVESTIGATING`, and then updated to a final classification status or
`ERROR`. Results are keyed by case ID and repeated processing returns the
persisted result.”

### Why SQLite?

**Answer:** “SQLite is local, portable, transactional, easy to inspect during
the foundation phase, and supports the event, finding, case, and result
boundary without adding a service dependency. Enterprise scaling would need a
different deployment architecture.”

### Why eBPF?

**Answer:** “On Linux, eBPF can provide low-level connection tracing and
process-network association. The repository has an optional eBPF capability
path and polling fallback. It is not assumed active unless capability checks
say so.”

### Windows versus Linux?

**Answer:** “Windows currently uses psutil/process polling, watchdog or polling
for files, a Windows network adapter, and `wevtutil` for authentication.
Linux supports `/proc`, journald/auth.log, polling, and optional eBPF. The
adapter boundary is shared, but native capabilities differ.”

### What happens after investigation?

**Answer:** “The current system persists the InvestigationResult and
recommendations for human review. There is no automatic Response Agent or
remediation path in this repository.”

### Why is remediation not implemented?

**Answer:** “The project deliberately keeps observation and reasoning separate
from high-impact actions. Killing processes, deleting or quarantining files,
blocking networks, and isolating hosts require authorization, policy, and
additional safety controls.”

### What is the next step?

**Answer:** “A supervised dispatcher could consume `NEW` cases, retry stale
claims, and invoke the agent with operational policy. Other next steps are
stronger native sensors, calibrated scoring, enterprise persistence, and
human-approved response.”

### How would you add an LLM safely later?

**Answer:** “Use the LLM as a bounded planner or summarizer over typed evidence,
never as an unrestricted command executor. Validate every proposed tool call
against an allow-list, preserve event-ID provenance, enforce budgets, and
require deterministic policy and human approval for any response.”

### How would this scale to enterprise deployment?

**Answer:** “The current SQLite/local foreground design is a foundation, not an
enterprise deployment. Scaling would require durable remote ingestion,
multi-worker case queues, authentication/authorization, encryption and key
management, retention, observability, tenant isolation, and a carefully
designed evidence integrity service.”

## 13. Exact Demo Files

| Path | Why it is useful | When to use it |
|---|---|---|
| `aegis_core/engine.py` | Monitoring lifecycle, ingestion, triage, status | Explain architecture |
| `aegis_core/collectors.py` | Process, file, network, auth collectors | Explain platform behavior |
| `aegis_core/normalizers.py` | Canonical event conversion and provenance | Show event normalization |
| `aegis_core/models.py` | `Event`, `Finding`, severity, environment | Explain schemas |
| `aegis_core/storage.py` | SQLite tables, hash chain, case/result APIs | Prove persistence/integrity |
| `aegis_core/detection.py` | Behavioral detectors and thresholds | Explain detection |
| `aegis_core/triage.py` | Scores, signals, case creation | Explain risk and handoff |
| `aegis_core/investigation/agent.py` | Adaptive loop, hypotheses, classification | Explain agent |
| `aegis_core/investigation/tools.py` | Read-only investigation surface | Explain safety |
| `aegis_core/investigation/state.py` | Budgets, coverage, stop reasons | Explain bounded reasoning |
| `aegis_core/investigation/result.py` | Persisted result schema | Explain output |
| `aegis_core/__main__.py` | Exact CLI parsing and output | Run commands |
| `scripts/investigation_process_scenario.py` | Bounded Windows/Linux process activity | Primary live attempt |
| `scripts/safe_e2e_demo.py` | Isolated file/process/loopback demo | Optional, not primary Windows path |
| `tests/test_investigation_handoff.py` | Deterministic full handoff proof | Panic mode |
| `docs/AEGIS_INVESTIGATION_AGENT_TEST.md` | Detailed two-window operator runbook | Secondary reference |
| `docs/agentic-defense/investigation-case-schema.md` | Case fields/statuses/result boundary | Panel questions |
| `docs/agentic-defense/architecture.md` | Current architecture boundary | Panel questions |
| `pyproject.toml` | Python requirement, extras, `aegis` entry point | Setup explanation |

## 14. Final 30-Minute Checklist

- [ ] Laptop is charged and the presentation host has network-independent
  access to the repository.
- [ ] VS Code is open at the repository root.
- [ ] Two PowerShell terminals are open.
- [ ] `.venv` activates successfully.
- [ ] `py --version` reports Python 3.11 or newer.
- [ ] `py -m aegis_core --capability-report --watch $watch` has been run.
- [ ] The current capability limitations are understood and will not be
  overstated.
- [ ] `$demo`, `$watch`, and `$data` are disposable and empty.
- [ ] `py -m aegis_core monitor --help` and
  `py -m aegis_core investigate --help` work.
- [ ] `py -m pytest -q` passes.
- [ ] The process scenario command has been checked:

  ```powershell
  py scripts\investigation_process_scenario.py --count 20 `
    --interval 0.05 --hold-seconds 15
  ```

- [ ] The reliable backup command is ready:

  ```powershell
  py -m pytest -q tests\test_investigation_handoff.py -s
  ```

- [ ] This guide is open in VS Code.
- [ ] `tests/test_investigation_handoff.py` is bookmarked.
- [ ] `aegis_core/investigation/agent.py` and
  `aegis_core/storage.py` are bookmarked.
- [ ] No personal or production directory is being monitored.
- [ ] No destructive or brute-force activity is planned.
- [ ] The panel script explicitly says the live-to-agent handoff is explicit
  CLI-driven, not automatic.

## 15. Final "Do Not Panic" Section

### Monitor does not start

```text
Check Python/venv
  -> run .\.venv\Scripts\python.exe -m aegis_core monitor --help
  -> rerun monitor test instead of foreground start
  -> inspect the capability report
```

### No events

```text
Check the data directory and monitor status
  -> confirm --data-dir is the same $data
  -> use a valid dedicated --watch path
  -> run monitor test for 10 seconds
  -> show health/capability events if a collector is unavailable
```

### No finding

```text
No finding is not a crash
  -> detector thresholds were not crossed
  -> show stored events and chain_valid=True
  -> do not lower production thresholds live
  -> use PANIC MODE for the deterministic detector/triage proof
```

### No case

```text
No case means triage threshold was not crossed
  -> do not invent an INC- ID
  -> show findings and their scores/signals
  -> run tests\test_investigation_handoff.py -s
```

### Investigation fails

```text
Show the ERROR/PARTIAL result and its uncertainty/stop_reason
  -> verify the database exists
  -> rerun with --max-tool-calls 30 --max-seconds 120
  -> use the persisted handoff test
```

### Result is not visible

```text
Use the exact same $data directory
  -> inspect Test-Path $data\evidence.sqlite3
  -> query get_investigation_result(case_id)
  -> run investigate ... --json
```

### VM is unavailable

```text
Use the Windows host
  -> show the Windows capability report
  -> state that Linux/eBPF is an alternative capability path
  -> do not pretend the VM was used
```

## Current Repository Validation

The following checks were performed against the current working tree while
preparing this guide:

- `py -m aegis_core --capability-report --watch ...` — passed on the current
  Windows host; reported process lifecycle, network bridge, and `wevtutil`
  authentication availability, plus the ETW limitation.
- `py -m aegis_core monitor --help` — passed.
- `py -m aegis_core investigate --help` — passed.
- `py -m pytest -q` — **246 passed**.
- `py -m pytest -q tests\test_investigation_handoff.py ...` — focused
  investigation handoff tests passed during the current validation.
- `py -m pytest -q tests\test_investigation_handoff.py -s` — the documented
  deterministic backup path is the repository’s direct handoff proof.
- `scripts\investigation_process_scenario.py` — command and bounds verified;
  it is harmless and exits cleanly.
- `scripts\safe_e2e_demo.py` — command verified, but on this Windows host its
  short run produced zero events and no case; it is therefore not presented as
  the primary live path.
- `git diff --check` — passed before this documentation-only change.

No application code is changed by this guide. The guide intentionally records
the current implementation and its limitations rather than promising automatic
dispatch, guaranteed Windows process-burst capture, LLM reasoning, or
remediation that the repository does not currently provide.
