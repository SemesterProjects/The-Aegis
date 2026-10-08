# Aegis Demonstration Runbook

This is the canonical operator guide for demonstrating:

```text
Monitoring -> canonical events -> tamper-evident evidence -> deterministic
triage -> NEW InvestigationCase
```

The commands below are the commands implemented by this repository. Run
commands labelled `[HOST]` in Windows PowerShell from the repository root and
commands labelled `[VM]` in the Linux guest. The monitor is a foreground
process; it is not installed as a Windows or Linux service.

## Fast demo

### Host demo

```powershell
# [HOST] From the repository root
py -m pip install -e ".[enhanced,test]"
py -m aegis_core --capability-report --watch .\aegis-demo\watch
New-Item -ItemType Directory -Force .\aegis-demo\watch | Out-Null
py scripts\safe_e2e_demo.py --root (Join-Path $env:TEMP "aegis-safe-e2e")
```

The safe demo prints JSON containing event counts, case IDs, and
`"chain_valid": true`. It runs a complete isolated collection for about three
seconds and exits by itself.

### VM demo

```text
[HOST] Start the powered-off `aegis-target-ubuntu` VM in Hyper-V Manager.
[VM]   Clone or update this repository, create/activate a Python 3.11+
       virtual environment, and install `.[enhanced,test]`.
[VM]   Run `python3 -m aegis_core --capability-report --watch /tmp/aegis-demo`.
[VM]   Run `python3 -m aegis_core monitor test --data-dir ./aegis-data
       --watch /tmp/aegis-demo --seconds 10`.
[VM]   Inspect status/evidence with the commands in "Inspect evidence".
[VM]   Remove `/tmp/aegis-demo` after preserving any evidence required for review.
```

## 1. Set up the repository

### Step 1 — Clone and enter the repository

On a fresh Windows machine:

```powershell
# [HOST]
git clone https://github.com/SemesterProjects/The-Aegis.git
Set-Location .\The-Aegis
```

Expected: the current directory contains `aegis_core`, `scripts`, `tests`, and
`pyproject.toml`.

If the repository already exists, update it instead:

```powershell
# [HOST]
git pull --ff-only
```

### Step 2 — Verify branch, commit, and clean state

```powershell
# [HOST]
git branch --show-current
git log -1 --oneline
git status --short
```

The demonstration branch is `master`. `git status --short` should be empty
before starting. Do not run the demo from a checkout containing unreviewed
changes to collectors or storage.

### Step 3 — Verify Python and install dependencies

```powershell
# [HOST]
py --version
py -m venv .venv
.\.venv\Scripts\Activate.ps1
py -m pip install --upgrade pip
py -m pip install -e ".[enhanced,test]"
py -c "import aegis_core, psutil; print(aegis_core.__file__); print(psutil.__version__)"
```

Expected: Python 3.11 or newer, an import path inside this checkout, and a
`psutil` version. If PowerShell blocks activation, use
`.\.venv\Scripts\python.exe` in place of `py` for the remaining commands.

### Step 4 — Run the automated baseline

```powershell
# [HOST]
py -m pytest -q
```

Expected: all tests pass. The count is intentionally read from the current
test run rather than hard-coded because the suite can grow.

### Repository map

```text
aegis_core/                 monitoring, collectors, normalization, evidence,
                            detection, triage, and case storage
network_monitor/            platform network adapters
scripts/safe_e2e_demo.py    isolated benign end-to-end demonstration
tests/                      core, integration, stability, and triage tests
docs/AEGIS_DEMO_RUNBOOK.md  this canonical operator guide
docs/agentic-defense/       architecture, schemas, and Investigation handoff
```

## 2. Prepare a controlled host demonstration

Use a dedicated test directory. Do not monitor `Documents`, `Desktop`,
OneDrive, system directories, or a cloud-sync root for a demo.

```powershell
# [HOST]
$demo = Join-Path $env:TEMP "aegis-demo"
$watch = Join-Path $demo "watch"
$data = Join-Path $demo "data"
New-Item -ItemType Directory -Force $watch, $data | Out-Null
```

### Capability check

```powershell
# [HOST]
py -m aegis_core --capability-report --watch $watch
```

Look for available process, file, and network collectors. A collector marked
`UNAVAILABLE` is reported as unavailable; it is not silently counted as zero.
Windows authentication collection may require an elevated terminal and an
actual Security Event Log event.

## 3. Start continuous monitoring

Continuous mode runs until a stop request or Ctrl+C. It does not stop by
itself.

```powershell
# [HOST] Terminal 1
py -m aegis_core monitor start `
  --data-dir $data `
  --watch $watch `
  --interval-seconds 2 `
  --environment production
```

Expected:

```text
Aegis monitoring started in foreground.
```

Leave this terminal running. In a second PowerShell terminal, verify status:

```powershell
# [HOST] Terminal 2
py -m aegis_core monitor status --data-dir $data
```

The JSON must contain a running state (the exact status payload also includes
host, collector, event-count, and timestamp fields). The status file is
`$data\monitor-status.json`; evidence is `$data\evidence.sqlite3`.

### Checkpoint

You should now have:

- a foreground Aegis process;
- status reporting `running`;
- a dedicated watch directory;
- a data directory containing `monitor-status.json` after startup.

## 4. Generate and inspect host telemetry

Wait at least one collector interval after each operation. Events are written
to SQLite and health events record collector availability and errors.

### Process lifecycle

```powershell
# [HOST] Terminal 2
$child = Start-Process notepad.exe -PassThru
$child.Id
Start-Sleep -Seconds 4
Stop-Process -Id $child.Id
```

The process collector uses snapshot differences. Look for process start/exit
events with a PID, process name, timestamp, and (when available) executable or
command line. Very short-lived processes can be missed.

### File lifecycle

```powershell
# [HOST] Terminal 2
$file = Join-Path $watch "operator-test.txt"
New-Item -ItemType File -Path $file -Force | Out-Null
Set-Content -Path $file -Value "Aegis controlled file test"
Rename-Item -Path $file -NewName "operator-test-renamed.txt"
Remove-Item -Path (Join-Path $watch "operator-test-renamed.txt")
Start-Sleep -Seconds 4
```

Look for file create/modify/rename/delete evidence with the path, action,
suffix, and size fields. File process attribution is explicitly unavailable
with the polling/watchdog implementation.

### Network activity

Use a loopback endpoint, not suspicious or uncontrolled infrastructure:

```powershell
# [HOST] Terminal 2
$listener = [System.Net.Sockets.TcpListener]::new(
  [System.Net.IPAddress]::Loopback, 0)
$listener.Start()
$port = $listener.LocalEndpoint.Port
$client = [System.Net.Sockets.TcpClient]::new()
$client.Connect("127.0.0.1", $port)
$client.Close()
$listener.Stop()
Start-Sleep -Seconds 4
```

Network evidence contains local/remote addresses, ports, protocol, action, and
an associated process when the platform adapter can provide it. Polling can
miss connections that begin and end between samples.

### Inspect events and findings

There is no separate case/event CLI. Use the canonical store from a short
Python command:

```powershell
# [HOST]
py -c "from pathlib import Path; from aegis_core.storage import EvidenceStore; s=EvidenceStore(Path(r'$data')/'evidence.sqlite3'); print('events:', len(s.query_events())); print('findings:', len(s.get_findings())); print('cases:', len(s.query_cases())); print('chain_valid:', s.verify_chain()); s.close()"
py -m aegis_core --data-dir $data --analyze
```

The analysis command renders deterministic explanations for canonical events.
The store query prints the persisted event/finding/case counts and hash-chain
result.

## 5. Run the safe end-to-end triage demonstration

The preferred demonstration is deliberately isolated and benign:

```powershell
# [HOST]
$safeRoot = Join-Path $env:TEMP "aegis-safe-e2e"
New-Item -ItemType Directory -Force $safeRoot | Out-Null
py scripts\safe_e2e_demo.py --root $safeRoot
```

The script:

1. watches only `$safeRoot\watch`;
2. starts a short-lived local Python child;
3. requests a loopback HTTP endpoint;
4. creates, modifies, renames, and deletes four test files; and
5. lowers only this demo's file-burst threshold to make deterministic triage
   visible.

It does not contact external infrastructure, attack a service, modify user
files, or describe the activity as malware.

Expected JSON includes positive process/file/network counts, one or more
`case_ids`, and `"chain_valid": true`. The case is stored in
`$safeRoot\data\evidence.sqlite3`.

### Inspect a persisted InvestigationCase

```powershell
# [HOST]
py -c "from pathlib import Path; from aegis_core.storage import EvidenceStore; s=EvidenceStore(Path(r'$safeRoot')/'data'/'evidence.sqlite3'); cases=s.query_cases(); print('case_count:', len(cases)); [print({'case_id': c['case_id'], 'status': c['status'], 'severity': c['severity'], 'risk_score': c['risk_score'], 'trigger': c['trigger'], 'event_ids': c['event_ids'], 'detection_signals': c['detection_signals'], 'created_at': c['created_at']}) for c in cases]; s.close()"
```

The schema uses `case_id`, `status` (`NEW` for monitoring-created cases),
`severity`, `risk_score`, `trigger`, `event_ids`, `detection_signals`,
timestamps, and host identity. To inspect the exact evidence references:

```powershell
# [HOST]
py -c "from pathlib import Path; from aegis_core.storage import EvidenceStore; s=EvidenceStore(Path(r'$safeRoot')/'data'/'evidence.sqlite3'); c=s.query_cases()[0]; print('case:', c['case_id']); print('related_events:'); [print(e['event_id'], e['kind'], e['observed_at'], e['data']) for e in s.query_events_for_case(c['case_id'])]; s.close()"
```

This proves persistence: close and reopen the SQLite store, query the case and
its referenced events, and verify the chain.

### Checkpoint

You should now have:

- process, file, and network telemetry;
- a deterministic finding and a `NEW` case;
- stable event IDs linking the case back to evidence; and
- a valid tamper-evident hash chain.

## 6. Run bounded monitoring tests

`monitor test` runs the same capability-selected pipeline for the requested
duration, then exits normally. It accepts any positive floating-point seconds;
10, 30, and 60 seconds are useful demonstration durations.

```powershell
# [HOST]
py -m aegis_core monitor test --data-dir $data --watch $watch --seconds 10 --no-auth
py -m aegis_core monitor test --data-dir $data --watch $watch --seconds 30 --no-auth
py -m aegis_core monitor test --data-dir $data --watch $watch --seconds 60 --no-auth
```

Expected output is `Aegis monitoring test complete; events=...`. Results remain
in `$data\evidence.sqlite3`; inspect them with the commands in "Inspect
events and findings". `--no-auth` is optional and is useful when demonstrating
process/file/network collection without Security Event Log permissions.

## 7. Stop continuous monitoring and verify persistence

From the second terminal:

```powershell
# [HOST]
py -m aegis_core monitor stop --data-dir $data
Start-Sleep -Seconds 4
py -m aegis_core monitor status --data-dir $data
```

The monitor sees `monitor-stop.request` at a loop boundary, records shutdown
health evidence, closes collectors, flushes SQLite, and changes status to
`stopped`. A stop request is not a forced process kill. If the foreground
process is still present after a normal interval, press Ctrl+C in Terminal 1.

Verify that evidence remains readable:

```powershell
# [HOST]
py -c "from pathlib import Path; from aegis_core.storage import EvidenceStore; s=EvidenceStore(Path(r'$data')/'evidence.sqlite3'); print('events:', len(s.query_events())); print('cases:', len(s.query_cases())); print('chain_valid:', s.verify_chain()); s.close()"
```

To restart, wait for `stopped`, then run `monitor start` again. There is no
service installer, automatic restart, or retention policy in this repository.

## 8. Periodic operation and persistent directories

Collectors poll at `--interval-seconds` and health events use the engine health
interval. This is periodic telemetry collection, not scheduled report
generation. Scheduled triage, periodic security summaries, and a scheduler
are **not implemented**. Do not document or demonstrate them as features.

The current persistence layout is:

```text
<data-dir>/
    evidence.sqlite3       events, findings, investigation_cases, and results
    monitor-status.json    runtime status for the operational CLI
    monitor-stop.request   transient graceful-stop request
    .aegis_auth_cursor     authentication source cursor when auth is enabled
```

`reports/` is reserved for a future export surface. Investigation results are
currently persisted in `evidence.sqlite3`; the current monitor does not write
human-readable report files there. Preserve `evidence.sqlite3` and its WAL
files while a case is under review.

## 9. Hyper-V Linux VM demonstration

The supported lab uses Generation 2 Ubuntu VM `aegis-target-ubuntu` and the
private Hyper-V switch `Aegis-Lab-Private`. The lab network is intentionally
isolated. The attacker VM is not required for this benign telemetry demo.

### Step 1 — Prepare a checkpoint

Before experimental changes, power off the VM and create a standard checkpoint
in Hyper-V Manager: right-click `aegis-target-ubuntu` -> **Checkpoint**.
Restore the checkpoint after destructive experiments if the lab owner requires
a clean baseline. Do not delete evidence before copying it out for review.

### Step 2 — Start and verify the VM

In Hyper-V Manager:

1. Select `aegis-target-ubuntu`.
2. Select **Start**.
3. Select **Connect** and log in to Ubuntu.

From elevated host PowerShell:

```powershell
# [HOST]
Get-VM -Name aegis-target-ubuntu
Get-VMNetworkAdapter -VMName aegis-target-ubuntu |
  Format-Table VMName, SwitchName, Status
```

Expected: the VM is `Running`, the adapter is attached to
`Aegis-Lab-Private`, and adapter status is connected.

Inside Ubuntu:

```bash
# [VM]
ip -br address
ip route
ping -c 3 127.0.0.1
```

The private switch may have no default route. Do not add Internet access just
to make the demo work. If the repository is not already present in the VM,
use an approved transfer path or a temporary controlled network connection,
then return the VM to the isolated lab network.

### Step 3 — Install Aegis in the VM

```bash
# [VM] From the repository root
python3 --version
python3 -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip
python -m pip install -e ".[enhanced,test]"
python -c "import aegis_core; print(aegis_core.__file__)"
python -m pytest -q
```

Expected: Python 3.11+, import from the checkout, and a passing test suite.

### Step 4 — Verify the Linux adapter

```bash
# [VM]
python -m aegis_core --capability-report --watch /tmp/aegis-demo
```

Look for the Linux process/file/network mechanisms and no Windows-only
assumption. If `psutil` is missing, install the editable package again with
`.[enhanced]`. If a collector is unavailable, read the capability report and
health events before treating its count as zero.

### Step 5 — Run bounded Linux monitoring

```bash
# [VM]
mkdir -p /tmp/aegis-demo
python -m aegis_core monitor test \
  --data-dir ./aegis-data \
  --watch /tmp/aegis-demo \
  --seconds 30 \
  --no-auth
```

Expected: `Aegis monitoring test complete; events=...`.

Generate safe process and file activity while a continuous run is active, or
before a sufficiently long bounded run:

```bash
# [VM]
python3 -c "import time; time.sleep(30)" &
sleep 1
touch /tmp/aegis-demo/test.txt
echo "Aegis test" > /tmp/aegis-demo/test.txt
mv /tmp/aegis-demo/test.txt /tmp/aegis-demo/test-renamed.txt
rm /tmp/aegis-demo/test-renamed.txt
```

For a controlled network observation, use a local listener in one VM terminal
and connect from another:

```bash
# [VM] Terminal 1
python3 -m http.server 8765 --bind 127.0.0.1 &
# [VM] Terminal 2
curl --max-time 3 http://127.0.0.1:8765/
```

Inspect Linux evidence using the same store query, changing the data path:

```bash
# [VM]
python -c "from pathlib import Path; from aegis_core.storage import EvidenceStore; s=EvidenceStore(Path('aegis-data')/'evidence.sqlite3'); print('events:', len(s.query_events())); print('cases:', len(s.query_cases())); print('chain_valid:', s.verify_chain()); s.close()"
```

### Step 6 — Stop and clean up

For a continuous VM run:

```bash
# [VM] Terminal 2
python -m aegis_core monitor stop --data-dir ./aegis-data
sleep 4
python -m aegis_core monitor status --data-dir ./aegis-data
```

Expected: status is `stopped` and the SQLite evidence/case data remains
readable. Remove only the synthetic activity:

```bash
# [VM]
rm -rf /tmp/aegis-demo
deactivate
```

Keep `aegis-data` if the evidence is part of the demonstration record.
Otherwise archive it before restoring the VM checkpoint or shutting down the
guest.

## 10. Troubleshooting and fast recovery

| Symptom | Diagnose | Fix |
| --- | --- | --- |
| Aegis will not start | `py -m aegis_core --capability-report --watch $watch` | Activate the venv and reinstall `py -m pip install -e ".[enhanced,test]"`. |
| Python import error | `py -c "import aegis_core; print(aegis_core.__file__)"` | Run from the checkout and install editable package. |
| No process events | Capability report; wait one interval | Use a process lasting several seconds; snapshot polling can miss short-lived processes. |
| No file events | Confirm `$watch` exists and is the selected `--watch` root | Write a new file inside the dedicated root and wait for the interval. |
| No network events | Capability report and health events | Use the loopback listener test; polling can miss very short connections. |
| No authentication events | Run elevated and inspect Security Event Log capability | Authentication requires a supported source and a new matching event; zero is not automatically an error. |
| No triage case | Query findings/cases and run `safe_e2e_demo.py` | The case threshold is detector-specific; use the safe demo for a deterministic multi-signal path. |
| SQLite/database locked | Stop the foreground monitor and inspect the data directory | Do not open the database for writes from another process; restart after the monitor closes. |
| Monitoring does not stop | `monitor status`, then Ctrl+C in the foreground terminal | Remove only a stale stop request after the process is confirmed stopped, then restart. |
| Status says running after shutdown | Read `$data\monitor-status.json` and check the process | Wait for flush; if the process is gone, start once to repair runtime status. |
| VM has no IP | `[VM] ip -br address; ip route` and `[HOST] Get-VMNetworkAdapter -VMName aegis-target-ubuntu` | Confirm the private switch attachment and the guest's approved lab network configuration. |
| VM cannot reach GitHub | `[VM] ip route` | This private lab intentionally may have no default route. Transfer the checkout through an approved path instead of adding uncontrolled connectivity. |
| Linux adapter unavailable | `[VM] python -m aegis_core --capability-report --watch /tmp/aegis-demo` | Install optional dependencies and check permissions; use health evidence for the precise reason. |
| Evidence not visible | Verify `<data-dir>\evidence.sqlite3` exists and the monitor is stopped | Query with `EvidenceStore`; WAL files are normal while SQLite is open. |

### If the demo breaks

1. Run `monitor status`.
2. Request `monitor stop`.
3. Wait for `stopped`; use Ctrl+C only in the foreground terminal if needed.
4. Verify the evidence database and `chain_valid`.
5. Restart with the same data and watch directories, or use a fresh dedicated
   directory for a clean demonstration.
6. Restore the VM checkpoint only when the guest baseline is damaged or the
   lab owner requires a reset.

## 11. Command reference

| Purpose | Machine | Command |
| --- | --- | --- |
| Install | HOST | `py -m pip install -e ".[enhanced,test]"` |
| Install | VM | `python3 -m pip install -e ".[enhanced,test]"` |
| Capability report | HOST | `py -m aegis_core --capability-report --watch <existing-root>` |
| Capability report | VM | `python3 -m aegis_core --capability-report --watch <existing-root>` |
| Start continuous | HOST | `py -m aegis_core monitor start --data-dir <dir> --watch <root> --interval-seconds 2` |
| Start continuous | VM | `python3 -m aegis_core monitor start --data-dir <dir> --watch <root> --interval-seconds 2` |
| Start timed test | HOST | `py -m aegis_core monitor test --data-dir <dir> --watch <root> --seconds 30` |
| Start timed test | VM | `python3 -m aegis_core monitor test --data-dir <dir> --watch <root> --seconds 30` |
| Request stop | HOST | `py -m aegis_core monitor stop --data-dir <dir>` |
| Request stop | VM | `python3 -m aegis_core monitor stop --data-dir <dir>` |
| Read status | HOST | `py -m aegis_core monitor status --data-dir <dir>` |
| Read status | VM | `python3 -m aegis_core monitor status --data-dir <dir>` |
| Analyze events | HOST | `py -m aegis_core --data-dir <dir> --analyze` |
| Analyze events | VM | `python3 -m aegis_core --data-dir <dir> --analyze` |
| Run safe E2E | HOST | `py scripts\safe_e2e_demo.py --root (Join-Path $env:TEMP "aegis-safe-e2e")` |
| Run tests | HOST | `py -m pytest -q` |
| Run tests | VM | `python3 -m pytest -q` |

`<dir>` and `<root>` in this table mean operator-selected directories; all
complete procedures above provide concrete values. The implementation does not
provide a `cases` CLI command or an automatic periodic-report command.

## 12. Investigation Agent handoff

The Investigation Agent starts from a persisted `InvestigationCase`, not raw
operating-system output. The contract and schema are documented in
`docs/agentic-defense/agent-handoff.md` and
`docs/agentic-defense/investigation-case-schema.md`.

The supported handoff query is:

```python
from pathlib import Path
from aegis_core.storage import EvidenceStore

store = EvidenceStore(Path("aegis-data") / "evidence.sqlite3")
case = store.get_case_by_id("INC-...")
evidence = store.query_events_for_case(case["case_id"])
store.close()
```

Run the investigation with:

```powershell
py -m aegis_core investigate run --case-id <case-id> --data-dir <dir>
```

The agent atomically claims the case, performs bounded read-only analysis, and
persists an idempotent result in SQLite. It must not modify collectors, event
or evidence references, or execute remediation. See
`docs/AEGIS_INVESTIGATION_AGENT_TEST.md` for the two-window validation.
