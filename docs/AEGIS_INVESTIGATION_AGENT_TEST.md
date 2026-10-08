# Aegis Investigation Agent Test Runbook

This runbook validates the persisted handoff:

```text
monitoring -> canonical events -> detection -> triage -> InvestigationCase
           -> case claim -> InvestigationAgent -> InvestigationResult
```

The Investigation Agent is deterministic in the current implementation. It
does not claim to use an LLM and it is strictly read-only.

## Part A - Preconditions

Use a dedicated checkout and a disposable directory. Do not monitor OneDrive,
Documents, Desktop, or a system directory.

```powershell
Set-Location "C:\Users\Visha\OneDrive\Documents\Sem 7\Major Project"
py --version
py -m venv .venv
.\.venv\Scripts\Activate.ps1
py -m pip install -e ".[enhanced,test]"
$demo = Join-Path $env:TEMP "aegis-investigation-demo"
$watch = Join-Path $demo "watch"
$data = Join-Path $demo "data"
New-Item -ItemType Directory -Force $watch, $data | Out-Null
```

## Part B - Verify the baseline

```powershell
git status --short --branch
git branch --show-current
py -m pytest -q
```

The working tree should be clean and the full suite should pass.

## Part C - Start monitoring

Open **PowerShell 1** and run:

```powershell
py -m aegis_core monitor start `
  --data-dir $data `
  --watch $watch `
  --interval-seconds 1 `
  --environment development `
  --no-auth
```

The monitor remains in the foreground.

## Part D - Verify monitoring

In **PowerShell 2**:

```powershell
py -m aegis_core monitor status --data-dir $data
```

The JSON status should report `"running": true` or an equivalent running
state, together with collector, event-count, and timestamp fields.

## Part E - Run the bounded process scenario

The scenario is labelled `AEGIS TEST SCENARIO`, spawns at most 20 bounded
children, performs no external network access, and cleans up its children.
On Windows it uses local `cmd.exe` and loopback `ping`; on Linux it uses local
Python sleep processes.

In **PowerShell 2**:

```powershell
py scripts\investigation_process_scenario.py `
  --count 20 `
  --interval 0.05 `
  --hold-seconds 8
```

This is a safe activity generator. It is not a malware simulator.

## Part F - Verify process telemetry

```powershell
py -c "from pathlib import Path; from aegis_core.storage import EvidenceStore; s=EvidenceStore(Path(r'$data')/'evidence.sqlite3'); events=s.query_events(kinds=['process']); print('process_events:', len(events)); print('starts:', sum(e.get('data',{}).get('action') == 'start' for e in events)); [print(e['event_id'], e['data'].get('name'), e['data'].get('pid'), e['data'].get('ppid')) for e in events if e.get('data',{}).get('action') == 'start']; s.close()"
```

If there are no starts, allow another collector interval and rerun the
bounded scenario. Snapshot polling can miss processes that finish between
polls.

## Part G - Verify triage

The default `ProcessCreationBurstDetector` is behavior-based and does not
match the scenario name. It detects a rapid process-start burst. Inspect
findings and cases:

```powershell
py -c "from pathlib import Path; from aegis_core.storage import EvidenceStore; s=EvidenceStore(Path(r'$data')/'evidence.sqlite3'); print('findings:'); [print({'finding_id': f['finding_id'], 'rule_id': f['rule_id'], 'severity': f['severity'], 'evidence_event_ids': f['evidence_event_ids']}) for f in s.get_findings()]; print('cases:'); [print({'case_id': c['case_id'], 'status': c['status'], 'severity': c['severity'], 'risk_score': c['risk_score'], 'trigger': c['trigger'], 'trigger_event_id': c['trigger_event_id'], 'event_ids': c['event_ids']}) for c in s.query_cases()]; s.close()"
```

The expected case has a high severity/risk score, a process-burst trigger, and
real process event IDs. The case is initially persisted with status `NEW`.

## Part H - Verify the handoff

Copy the `case_id` printed above and set it in PowerShell 2:

```powershell
$caseId = "INC-REPLACE-WITH-CASE-ID"
py -c "from pathlib import Path; from aegis_core.storage import EvidenceStore; s=EvidenceStore(Path(r'$data')/'evidence.sqlite3'); c=s.get_case_by_id(r'$caseId'); print({'case_id': c['case_id'], 'status': c['status'], 'event_ids': c['event_ids']}); print('resolved_events:', len(s.query_events_for_case(r'$caseId'))); s.close()"
```

The resolved events must be non-empty and must match the case's event IDs.

## Part I - Run the investigation

Use the explicit operational form:

```powershell
py -m aegis_core investigate run `
  --case-id $caseId `
  --data-dir $data `
  --max-tool-calls 30 `
  --max-seconds 120
```

The legacy equivalent `py -m aegis_core investigate $caseId` remains
supported. To process every pending `NEW` case, use:

```powershell
py -m aegis_core investigate pending --data-dir $data
```

## Part J - Observe the investigation

The command emits the result summary. Structured logs identify case receipt,
claiming, investigation start, completion, and result persistence. The
expected lifecycle is:

```text
NEW -> INVESTIGATING -> BENIGN/SUSPICIOUS/MALICIOUS
```

An error result leaves an auditable `ERROR` case. A bounded partial result is
persisted and retains the evidence collected so far.

## Part K - Inspect the persisted result

```powershell
py -c "from pathlib import Path; import json; from aegis_core.storage import EvidenceStore; s=EvidenceStore(Path(r'$data')/'evidence.sqlite3'); r=s.get_investigation_result(r'$caseId'); print(json.dumps(r, indent=2, sort_keys=True)); s.close()"
```

The result includes `case_id`, `investigation_id`, status, classification,
confidence, timeline, affected processes, supporting evidence, uncertainties,
and recommended actions.

## Part L - Verify evidence provenance

```powershell
py -c "from pathlib import Path; from aegis_core.storage import EvidenceStore; s=EvidenceStore(Path(r'$data')/'evidence.sqlite3'); r=s.get_investigation_result(r'$caseId'); ids=set(r['evidence_ids_used']); stored={e['event_id'] for e in s.query_events()}; print('result_evidence_ids:', len(ids)); print('missing_evidence_ids:', sorted(ids-stored)); print('chain_valid:', s.verify_chain()); s.close()"
```

`missing_evidence_ids` must be an empty list. The agent never invents event
IDs and never executes telemetry values as commands.

## Part M - Stop and clean up

In **PowerShell 2**:

```powershell
py -m aegis_core monitor stop --data-dir $data
Start-Sleep -Seconds 3
py -m aegis_core monitor status --data-dir $data
Remove-Item -LiteralPath $demo -Recurse -Force
```

The final status should be `stopped`. Remove only the dedicated demo
directory. Preserve it instead if the evidence is required for review.

## Part N - Persistence test

Before cleanup, close the CLI and reopen the SQLite database in a fresh
process:

```powershell
py -c "from pathlib import Path; from aegis_core.storage import EvidenceStore; s=EvidenceStore(Path(r'$data')/'evidence.sqlite3'); print('case_exists:', s.get_case_by_id(r'$caseId') is not None); print('result_exists:', s.get_investigation_result(r'$caseId') is not None); s.close()"
```

The case and result must remain available after the monitor and investigation
processes exit.

## Two-window demonstration

- **PowerShell 1:** run the foreground monitoring command and show its running
  status.
- **PowerShell 2:** run the bounded process scenario, inspect the resulting
  case, run `investigate run`, and show the persisted result/provenance query.

The current investigation path is verified on the Windows development host.
The Linux VM path is not yet verified for the Investigation Agent, and macOS
is not verified. The monitoring adapters remain separately capability-gated.
