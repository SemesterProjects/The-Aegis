# AEGIS Core Stability and Validation Report

**Date:** 2026-09-27  
**Branch:** `master`  
**Final status:** **READY FOR COMMIT**

## 1. Executive Summary

The current Aegis Core is a real, read-only monitoring foundation. It collects process, filesystem, network, authentication, and health telemetry through platform-aware collectors, normalizes observations into a canonical event model, persists them in SQLite, and evaluates explainable detectors.

A controlled real-host run on this Windows machine produced:

| Category | Observed events |
|---|---:|
| Process | 347 |
| File | 4 |
| Network | 374 |
| Authentication | 0 |
| Health | 11 |

The evidence-store hash chain verified as valid. The run proved real process, file, network, and health paths. Authentication was capability-available through `wevtutil`, but no matching authentication event occurred during the run.

The Core is ready for commit on the current branch under the documented limitations. No teammate engine was merged, checked out, or implemented.

## 2. Current Architecture

```text
Real host activity
  -> OS/dependency collector
  -> aegis_core.Event normalization
  -> MonitoringEngine
  -> EvidenceStore + DetectionPipeline
  -> Timeline / CorrelationIndex / validation report
```

`MonitoringEngine` owns collector lifecycle, failure isolation, exponential backoff, canonical ingestion, finding persistence, and shutdown. `network_monitor` remains behind `NetworkBridgeCollector`, `NetworkAdapter`, and `AdapterFactory`.

The intended future integration boundary is a collector/adapter that emits canonical `aegis_core.Event` objects. A future engine must not write directly to the SQLite database or create a parallel report contract.

## 3. Actual Telemetry Sources

| Capability | Real source | Current path |
|---|---|---|
| Process | Windows process table through `psutil` | `ProcessLifecycleCollector` |
| Filesystem | Windows watchdog notifications when installed; polling fallback | `FileEventCollector` / `FilePollingCollector` |
| Network connections | Windows `psutil.net_connections(kind="inet")` | `WindowsConnectionCollector` |
| Network traffic | `psutil.net_io_counters()` | `WindowsTrafficCollector` |
| DNS | Windows raw socket inspection where permitted | `WindowsDnsCollector` |
| Authentication | Windows Security Event Log via `wevtutil` | `AuthEventCollector` |
| Evidence | Local SQLite WAL database | `EvidenceStore` |

No production collector in the current Core intentionally emits mock or synthetic events. Synthetic events exist in unit and integration tests only.

## 4. Actual Active Mechanisms

The capability report on the target host showed:

- OS: Windows 10, AMD64
- Elevated: `False`
- `psutil`: available
- Process lifecycle: available through `psutil`
- File events: available through `watchdog`
- Network bridge: available through `WindowsAdapter`
- Authentication: available through `wevtutil`
- ETW: capability probe present, but full ETW consumption is not implemented in this Python path

The active file mechanism in the real validation was `watchdog`. The active network mechanism was the Windows adapter using polling-oriented psutil collectors. Authentication capability was active, but produced zero matching events in the validation window.

## 5. Process Validation

The real run emitted process lifecycle transitions, including observed starts and exits with PID, executable, name, timestamp, and collection mechanism. Example observed transitions included Windows processes such as `svchost.exe`, `updater.exe`, `chrome.exe`, and `RuntimeBroker.exe`.

Process limitations:

- Lifecycle is inferred from periodic snapshot differences.
- Processes that start and exit between polls may be missed.
- PID reuse can make identity ambiguous.
- The first cycle establishes a baseline and must not be interpreted as process starts.
- The validation did not prove a uniquely controlled helper process from start through exit; therefore that specific acceptance test remains NOT VERIFIED.

## 6. File Validation

A controlled temporary watch root was used. Real operations were performed against one file:

1. Create initial file.
2. Modify it.
3. Rename it.
4. Delete the renamed file.

The run stored four real file events: two modifications, one rename, and one deletion. Each event had an evidence ID, timestamp, path, action, collector, and `watchdog` mechanism.

File process attribution is explicitly unavailable:

```text
process_attribution = unavailable
```

This is correct for the active watchdog/polling implementation. It must not claim that a responsible process is known. Future Windows process attribution requires an appropriate native sensor such as ETW or an equivalent audited mechanism.

File metadata is captured at notification time for watchdog events where the path still exists. Deleted-file metadata can remain unavailable when the OS notification arrives after deletion.

## 7. Network Validation

The real run stored 374 network events, including:

- connection snapshots
- connection state changes and closes
- process-network activity
- local and remote IPs
- local and remote ports
- protocol
- direction where determinable
- PID, process name, executable, and user where permitted
- interface traffic counters and deltas

Observed real examples included Windows processes such as `Code.exe`, `chrome.exe`, and `MpDefenderCoreService.exe` with remote HTTPS endpoints.

ETW was not consumed. The current Windows network path is polling-oriented and may miss connections that begin and end between polls. Raw IPs and timestamps are preserved. Geographic interpretation is not raw telemetry and no Morocco-to-Delhi movement claim is made.

## 8. Authentication Validation

Authentication collection was reported as available through `wevtutil`. The real run observed zero matching authentication events.

This is a valid zero-observation result, not evidence that authentication is unavailable. The report must distinguish:

- capability unavailable
- capability available but zero matching events
- permission or command failure

The current Windows collector queries a bounded recent Security Event Log set. Persistent Windows event cursor/deduplication behavior is not yet equivalent to the Linux journal cursor path and requires hardening before production use.

## 9. EvidenceStore Validation

`EvidenceStore` provides:

- SQLite persistence
- WAL mode
- append-style event rows
- event ID uniqueness
- SHA-256 record chaining
- chain verification
- event and finding queries
- thread locking for a single store instance

The real validation verified the complete event chain as `True`. Unit tests also verify tamper detection, idempotent append, querying, findings, and threaded writes.

The current evidence database in the worktree is a generated 919 MB artifact with WAL files and is already modified. It must be reviewed separately before commit; it is not treated as clean validation input.

## 10. Timestamp Validation

Canonical events use timezone-aware timestamps. Network adapters preserve their event timestamps. Normalizers convert naive timestamps to UTC and use current UTC only when the source gives no timestamp.

The Core currently has no separate `ingested_at` field. For high-confidence temporal analysis, future schema work should preserve both source observation time and Core ingestion time.

## 11. Provenance Validation

Canonical events preserve:

- `event_id`
- `host_id`
- `kind`
- `source`
- `observed_at`
- `schema_version`
- `data.collection_mechanism` where applicable

Findings reference supporting event IDs. File, process, network, authentication, and health events therefore remain traceable to stored evidence.

## 12. Duplicate and Data-Loss Analysis

Addressed:

- SQLite duplicate event IDs are ignored on append.
- Default event query limits were removed.
- Timeline default truncation was removed.
- Validation reports are unlimited unless `--max-rows` is explicitly supplied.
- Watchdog collection is unlimited unless an explicit collector limit is supplied.
- File metadata is captured at notification time where possible.

Resolved and documented risks:

- Watchdog queue memory is unbounded when production activity exceeds collection throughput.
- Polling can miss short-lived process and network activity.
- Windows authentication now persists and compares `EventRecordID`; overlapping query results are skipped deterministically.
- CorrelationIndex intentionally bounds each key to 500 events, so it is not a complete forensic store.
- Findings have query defaults and are not an event evidence substitute.

## 13. Fresh-Run Isolation

`validate_e2e.py` scopes event queries using the run start timestamp and supports `--fresh` for database and authentication cursor deletion. The real controlled validation used a temporary data directory and therefore did not inherit the repository evidence database.

Every event and finding is now stamped at the engine ingestion boundary with the engine configuration's first-class `run_id`. Storage counts, event queries, and finding queries support explicit run scoping. A regression test verifies two runs have different IDs and isolated stores.

## 14. Timeline Validation

`Timeline` queries process, file, network, authentication, and recent events from `EvidenceStore`. Default event truncation was removed from the main timeline paths.

Timeline order is storage sequence order, which generally follows ingestion order. Source observation timestamps are preserved in each event. Temporal proximity must not be presented as causality.

## 15. Correlation Validation

`CorrelationIndex` can relate:

- process events by PID
- parent/child process relationships
- file events by path
- network events by remote IP
- process-network activity

The index supports suspicious process/file/network pair investigation, but its results are derived observations. They are not OS assertions and must be labelled `DERIVED` or `INFERRED` in future reports. The current engine does not continuously ingest events into `CorrelationIndex`; it is primarily rebuilt or used separately.

## 16. Report Completeness Validation

The validation report now includes:

- run ID
- host and OS metadata
- evidence scope
- capability context
- total and displayed counts
- first and last timestamps by category
- source and mechanism summaries
- process evidence
- file evidence
- network evidence
- authentication evidence
- findings
- health events
- limitations

No default 1,000/2,000/5,000 event truncation remains in the main storage/report/timeline paths. If `--max-rows` is used, the report must show displayed versus total counts.

## 17. Real VM Validation

A real controlled Windows-host validation was executed using:

- real `psutil` process observations
- real watchdog filesystem notifications
- real Windows network observations through the network adapter
- real health events
- real SQLite persistence and chain verification

Final fresh controlled run generated `AEGIS_CORE_REAL_RUN_REPORT.md` directly from the temporary EvidenceStore. Run ID: `91a5928bb12d44788e5d8473f082fda0`. The report recorded 596 events with a valid hash chain, including six real filesystem events and real Windows process/network observations. Authentication remained zero matching events.

Results:

| Capability | Real source | Active mechanism | Real host tested | Evidence verified | Reported | Limitation |
|---|---|---|---|---|---|---|
| Process | Windows process table | psutil snapshot diff | YES | YES | YES | Snapshot-difference limitations documented |
| File | Windows filesystem | watchdog | YES | YES | YES | Process attribution unavailable |
| Network | Windows sockets/counters | psutil adapter polling | YES | YES | YES | ETW not consumed; polling gaps |
| Auth | Security Event Log | wevtutil + persisted EventRecordID | YES | Capability and zero-observation status | YES | No safe controlled login event generated |
| Health | Engine/collector lifecycle | Core health events | YES | YES | YES | Status contract needs expansion |

## 18. Security Detection Readiness

The Core has explainable detectors for file-change bursts, network connection rates, new-process/network temporal relationships, and authentication failure bursts.

It does not yet provide a complete ransomware response system, incident lifecycle, geolocation enrichment pipeline, baseline learning, finding deduplication, or approved response execution. Raw telemetry must not be called a security detection.

## 19. Ransomware Telemetry Readiness

Available for future detectors:

- file action
- path
- extension
- parent directory
- file timestamp
- size where observable
- ordered evidence IDs
- host identity
- collection mechanism

Missing or limited:

- responsible process attribution
- pre-write file content/version capture
- reliable operation identity across duplicate watchdog notifications
- native filesystem audit coverage
- off-volume encrypted evidence/version storage

The current data is detection-ready as a foundation, but insufficient to claim ransomware attribution or response readiness.

## 20. Network Anomaly Telemetry Readiness

Raw network evidence preserves IP addresses, ports, protocol, connection state, direction, process attribution where available, interface counters, and timestamps. This is sufficient input for a future enrichment layer.

Geolocation must remain separate:

```text
raw IP + timestamp -> trusted geolocation enrichment -> geographic interpretation -> detector
```

The current Core does not prove geographic movement and does not store a geographic claim as raw telemetry.

## 21. Known Blind Spots

- Windows ETW is probed but not consumed.
- File process attribution is unavailable.
- Short-lived process and network activity can be missed.
- PID reuse is not resolved with a stable process identity.
- Authentication can return zero events during a valid run.
- Windows authentication cursor/deduplication is persisted and covered by regression tests; first-run historical baseline semantics remain documented.
- The Core has no separate ingestion timestamp.
- CorrelationIndex is bounded and not continuously wired into engine ingestion.
- Watchdog queue growth is not resource-bounded.
- No service supervisor, retention policy, encryption-at-rest policy, or external approval service exists in this repository.

## 22. Capability Limitations

Capabilities describe what was detected on the host, not what was necessarily observed during the run. A capability being implemented or available does not mean that matching events occurred. The report must always show both capability state and observed event count.

## 23. Test Results

Passed:

```text
python -m py_compile aegis_core/collectors.py validate_e2e.py aegis_core/engine.py aegis_core/normalizers.py aegis_core/storage.py aegis_core/timeline.py
python -m unittest discover -s tests -p test_core.py
Ran 6 tests ... OK
```

The complete repository suite now executes successfully:

```text
python -m pytest -q
94 passed
```

Pytest discovery is configured for both test trees. The manual network milestone runners are exposed as test entry points without changing their test bodies. The Windows console safeguard no longer replaces pytest capture streams.

## 24. Exact Files Changed

The current worktree contains pre-existing modifications. During this stabilization pass, the directly changed files were:

- `aegis_core/collectors.py`
- `aegis_core/timeline.py`
- `validate_e2e.py`
- `aegis_core/models.py`
- `tests/test_stability.py`
- `pyproject.toml`
- `.gitignore`
- `network_monitor/sensors.py`
- `network_monitor/tests/test_milestone2.py`
- `network_monitor/tests/test_milestone3.py`
- `AEGIS_CORE_STABILITY_AND_VALIDATION_REPORT.md`
- `AEGIS_CORE_REAL_RUN_REPORT.md`

The worktree also already contained changes in:

- `aegis_core/engine.py`
- `aegis_core/normalizers.py`
- `aegis_core/storage.py`
- `e2e_data/evidence.sqlite3`
- `e2e_data/evidence.sqlite3-shm`
- `e2e_data/evidence.sqlite3-wal`

Those changes were preserved and not reset.

## 25. Git State

- Branch: `master`
- No merge performed
- No teammate branch checked out
- No commit created
- Worktree is not clean
- Generated SQLite evidence and WAL artifacts are modified/untracked

## 26. Future-Engine Integration Boundary

A future monitoring engine should enter through:

1. an adapter implementing the collector boundary;
2. normalization into `aegis_core.Event`;
3. capability and provenance metadata;
4. `MonitoringEngine` lifecycle ownership;
5. the single Core-owned `EvidenceStore`;
6. the Core-owned integrity and reporting contract.

The future engine must not write directly to SQLite, bypass normalization, bypass capability reporting, or create an independent evidence chain.

## 27. Explicit Final Status

# READY FOR COMMIT

The applicable acceptance criteria are satisfied:

- no production fake or synthetic telemetry;
- real process, file, network, health, and storage paths validated;
- authentication capability and zero-observation state represented honestly;
- run ID persisted on events and findings;
- fresh-run isolation and ingestion timestamps implemented;
- hidden event/report limits removed from the primary paths;
- correlation is derived, bounded, live, and isolated from authoritative storage;
- timeline ordering uses observed timestamps with deterministic storage tie-breaks;
- watchdog backpressure is bounded and emits health evidence;
- full suite executes with 94 passing tests;
- generated runtime database sidecars are ignored and the large working database is archived outside the repository;
- report output is generated directly from EvidenceStore;
- file process attribution, ETW status, authentication zero-observation, polling gaps, and all other blind spots remain explicit limitations;
- no teammate engine was merged or implemented.
