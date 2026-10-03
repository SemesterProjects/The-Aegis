# Monitoring + Triage Completion Report

## Delivered pipeline

```text
Process/File/Network collectors -> canonical events -> hash-chained SQLite evidence
-> deterministic findings -> thresholded triage -> persistent NEW investigation case
```

The existing `MonitoringEngine`, capability factory, collectors, normalizers, network bridge, correlation index, evidence store, and detection pipeline were retained. This work wired the previously incomplete case boundary, added durable case storage/querying, a foreground operational CLI (`aegis monitor start|test|stop|status`), status files, batch evidence ingestion, and safe E2E tooling.

## Actual host validation — Windows, October 3, 2026

`py scripts\safe_e2e_demo.py --root <fresh-temp-root>` produced **267 process events**, **14 file events**, **234 network events**, **1 NEW investigation case**, and a valid evidence hash chain after shutdown. The safe activity was one short-lived Python child, controlled files in the supplied temporary root, and a loopback HTTP request. The case is an unusual file-burst priority signal, not a malware verdict.

The full suite passed: **141 passed**. `py -m compileall -q aegis_core network_monitor scripts` passed. A new virtual environment installed the root project with `pip install --no-deps .` and successfully imported both `aegis_core` and `network_monitor`.

## Operations

See [monitoring-operations.md](monitoring-operations.md), [e2e-test.md](e2e-test.md), and [agent-handoff.md](agent-handoff.md). The report directory contract is [reports/README.md](../../reports/README.md).

## Known limitations

- Windows host telemetry was tested; Linux VM and macOS were not tested in this task.
- Windows network collection is psutil polling/snapshot diffing through `network_monitor`, not ETW consumption; short-lived connections can be missed.
- File watcher telemetry has no process attribution; watcher duplicates are deduplicated at the triage-burst level, not discarded from evidence.
- Process lifecycle uses snapshots and can miss a process that begins and exits between polls.
- Authentication needs OS log permissions and was not part of the safe host E2E simulation.
- There is no OS service installer, retention deletion, encrypted-at-rest key management, remote evidence sink, response agent, mitigation, rollback, or Investigation Agent.
