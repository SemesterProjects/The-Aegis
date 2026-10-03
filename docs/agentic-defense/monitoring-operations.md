# Monitoring Operations

## Install and capability check

From repository root, create a Python 3.11+ environment and install the package with `py -m pip install -e ".[enhanced,test]"`. Then run `py -m aegis_core --capability-report --watch .\aegis-test-data`.

## Continuous monitoring

```powershell
py -m aegis_core monitor start --data-dir .\aegis-data --watch .\aegis-test-data --interval-seconds 2
```

This is intentionally a foreground process. From another terminal, request graceful stop with:

```powershell
py -m aegis_core monitor stop --data-dir .\aegis-data
py -m aegis_core monitor status --data-dir .\aegis-data
```

`stop` writes a local stop request; the running monitor sees it at the next loop boundary, records shutdown evidence, closes collectors, flushes SQLite, and updates `<data-dir>/monitor-status.json`. Restart means run `monitor start` again after `status` reports `"state": "stopped"`; there is no OS-service installer in this repository yet.

## Bounded test and evidence

```powershell
py -m aegis_core monitor test --data-dir .\aegis-data --watch .\aegis-test-data --seconds 15
py -m aegis_core --data-dir .\aegis-data --analyze
```

Evidence is `<data-dir>/evidence.sqlite3`; WAL files beside it are normal while it is open. Cases are in its `investigation_cases` table. Do not delete evidence while an investigation is pending. Retention is **not implemented**; storage must be monitored and retained by operational policy.

## Logs and troubleshooting

Startup, collector errors/recovery, heartbeat, case creation context, and shutdown are persisted as `health` events. If no events appear, run the capability report, verify `psutil`/`watchdog`, use a dedicated existing watch directory, and inspect `health` events. Windows auth collection needs Security Event Log permissions; network polling can legitimately miss short-lived connections; file watcher events require an actual write in the selected root. A storage error is not recoverable in-process—protect the data directory and restart after correcting disk/permission issues.
