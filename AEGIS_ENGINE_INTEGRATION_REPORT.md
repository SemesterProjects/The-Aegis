# Aegis Unified Monitoring Engine Integration Report

> [!NOTE]
> **HISTORICAL ARCHIVE & INTEGRATION RECORD:** Dated 2026-09-27. This document details the architectural merge and integration between the Aegis Core and the `network_monitor` platform telemetry subsystem, including deduplication rationale and component boundaries.

**Date:** 2026-09-27  
**Integration branch:** `integration/unified-monitoring-engine`  
**Base:** current `master` at `44ba797` (`MOnitoring engine - V2`)  
**Teammate PR ref:** `origin/pr-1` / `origin/feature/network-monitor` at `20703f0`  
**Status:** **READY FOR MERGE (Merged into master)**

**Purva PR #2 addendum:** `origin/purva-aegis-work` at `30dd229` was merged
into `master` as `c0c4bd0`. Its destructive replacement of the validated Core
was resolved by retaining the Core contracts and adopting its compatible
deterministic event-analysis layer plus the Linux eBPF struct-alignment fix.

## 1. Executive Summary

The teammate PR is already an ancestor of the current master history. The current master contains the PR's substantive network implementation under the production package `network_monitor/`, connected to the Core through `NetworkBridgeCollector` and `aegis_core.normalizers`.

The correct enterprise-grade integration decision is therefore not to merge the PR a second time and not to retain two network engines. The unified engine retains the validated Core lifecycle/evidence architecture and the teammate's platform network subsystem behind one adapter boundary:

```text
MonitoringEngine
  -> ProcessLifecycleCollector
  -> FileEventCollector
  -> NetworkBridgeCollector
       -> SystemDiscovery
       -> AdapterFactory
       -> Windows/Linux/macOS NetworkAdapter
       -> canonical aegis_core.Event
  -> AuthEventCollector
  -> EvidenceStore
  -> DetectionPipeline / Timeline / CorrelationIndex / report
```

No duplicate `network-monitor/` implementation was copied into the current tree. No teammate branch was checked out, merged, or rewritten in this turn. The exact PR implementation is represented by the current `network_monitor/` subsystem, while `network-monitor/` remains only on the remote PR ref.

## 2. Git and PR Provenance

- Current branch before integration work: `master`.
- Current stable master commit: `44ba797`.
- Teammate PR commit: `20703f0`.
- `git merge-base master origin/pr-1` equals `20703f0`.
- `origin/pr-1` is an ancestor of `master`.
- Integration branch created from current master: `integration/unified-monitoring-engine`.
- No history rewrite, reset, force push, or teammate-branch checkout was performed.

The current master already contains the PR contribution through the existing history. This report is the integration assessment and architectural record; it is not a second merge commit.

## 3. Current Core vs Teammate Comparison

| Capability | Current Core on master | Teammate PR | Decision | Reason |
|---|---|---|---|---|
| Process | psutil or `/proc` lifecycle snapshots/diffs | No independent endpoint process engine | Keep Core | Core owns process lifecycle and canonical process events. |
| Filesystem | watchdog with polling fallback | No filesystem subsystem | Keep Core | Core provides the real file evidence path. |
| Network abstraction | `NetworkBridgeCollector` into Core | `NetworkAdapter`, factory, discovery | Combine, already integrated | Adapter boundary is complementary; bridge prevents a second evidence pipeline. |
| Network connections | Canonical events from adapter output | psutil polling, Linux eBPF plus polling | Keep validated adapter | Platform-specific coverage is richer than Core-only polling. |
| Network traffic | Canonical normalized traffic events | psutil/proc counters and deltas | Keep adapter | Adds interface counters and deltas without changing UEM. |
| DNS | Canonical network events when adapter supports it | Linux/Windows/macOS adapter mechanisms | Keep adapter, report capability | Preserve real DNS observations and unsupported status. |
| Process-network association | Canonical network events with PID/process fields | Adapter-level socket attribution | Combine | Network attribution enriches Core process/network correlation. |
| Authentication | journalctl/auth.log/wevtutil collector | No competing auth engine | Keep Core | One authentication lifecycle and cursor owner. |
| Evidence | SQLite WAL plus hash chain | JSONL/standalone sensor output only | Keep Core | One authoritative evidence store and integrity contract. |
| Detection | One Core `DetectionPipeline` | No separate detection pipeline | Keep Core | Prevent duplicate findings. |
| Timeline | One Core `Timeline` | No competing timeline | Keep Core | One forensic query contract. |
| Correlation | One Core `CorrelationIndex` | No competing correlation layer | Keep Core | One derived index over canonical evidence. |
| Lifecycle | `MonitoringEngine` owns startup, retry, shutdown | Standalone sensor runner | Keep Core owner | Avoid two lifecycle managers. |

## 4. Components Retained From Current Core

- `MonitoringEngine` and `MonitoringConfig`.
- Collector protocol and per-collector failure isolation/backoff.
- Canonical `Event` and `Finding` models.
- `EvidenceStore` SQLite persistence and hash chain.
- Run identity and ingestion timestamps.
- File and process lifecycle collectors.
- Authentication collector and persisted cursor state.
- Capability reporting and health events.
- Detection pipeline, timeline, correlation, and validation report.
- Report limitations that distinguish observed, derived, unavailable, and inferred information.

## 5. Components Adopted From Teammate

The following PR implementation is present in `network_monitor/` and is used by the Core bridge:

- OS-independent `NetworkAdapter` contract.
- `SystemDiscovery` host and privilege discovery.
- `AdapterFactory` deferred platform selection.
- Linux adapter with polling and optional eBPF connection tracing.
- Linux traffic and DNS collectors.
- Windows connection, process association, traffic, and DNS collectors.
- macOS adapter capability boundary and fallback collector structure.
- Explicit `CollectorNotImplementedError` behavior for unsupported implementations.
- Adapter capability reports with actual mechanism and limitation notes.
- Network event structures for connections, traffic, DNS, and process-network activity.

The standalone PR `sensors.py` console/JSONL runner is not used as a second lifecycle or persistence system. Its useful adapter logic is reached through the Core bridge; its independent event sink is intentionally not authoritative.

## 6. Components Combined

### Network telemetry to canonical UEM

```text
network_monitor.ConnectionEvent
network_monitor.TrafficEvent
network_monitor.DnsEvent
network_monitor.ProcessNetworkEvent
        |
        v
NetworkBridgeCollector
        |
        v
aegis_core.normalizers
        |
        v
aegis_core.Event
```

Normalization preserves source fields where available, extracts enum values, converts timestamps to UTC, records `collection_mechanism=network_monitor_adapter`, and omits unavailable fields rather than fabricating them.

### Process plus network

Process lifecycle events come from the Core process collector. Network process association comes from the adapter. The resulting canonical events share PID, executable, user, endpoint, and timestamp fields where the OS exposes them.

### Health plus capability

The adapter capability report remains platform-specific, while the Core stores lifecycle/failure/capability status as health evidence. “Available,” “active,” and “observed” remain distinct states.

## 7. Components Rejected as Redundant

The following must not be introduced into the current production tree:

- the hyphenated duplicate package `network-monitor/`;
- a second `MonitoringEngine` or standalone long-running lifecycle;
- a second SQLite database or independent hash chain;
- JSONL as the authoritative evidence sink;
- a second detection, timeline, or correlation system;
- direct adapter writes that bypass `aegis_core.Event` normalization.

## 8. Final Architecture

```text
                    AEGIS MONITORING ENGINE
                              |
          +-------------------+-------------------+
          |                   |                   |
       Process             Filesystem          Network
       subsystem           subsystem           subsystem
          |                   |                   |
          +-------------------+-------------------+
                              |
                    Authentication subsystem
                              |
                              v
                    Canonical Aegis Event/UEM
                              |
                              v
                     EvidenceStore/hash chain
                              |
              +---------------+---------------+
              v               v               v
          Detection       Timeline       Correlation
```

There is one lifecycle owner: `MonitoringEngine`. All production observations enter through the collector protocol, become canonical events, are durably stored, and then reach downstream analysis.

## 9. Canonical Event and Provenance Contract

Every ingested event contains:

- `event_id`
- `kind`
- `source`
- `observed_at`
- `ingested_at`
- `host_id`
- `run_id`
- `schema_version`
- canonical `data`

Network events preserve adapter provenance in `source`, `nm_collector`, and `collection_mechanism`. Process, file, authentication, and health events preserve their collector and mechanism. Missing OS fields remain absent.

## 10. Deduplication and Reconciliation

The current network adapter uses connection IDs and state snapshots internally. The Core preserves each canonical observation as evidence rather than silently collapsing distinct source observations. This is important because a connection snapshot, state transition, close event, traffic counter, and process-network association are complementary observations, not necessarily duplicates.

The authoritative deduplication guarantees are:

- event IDs are unique in `EvidenceStore`;
- authentication Windows `EventRecordID` cursoring prevents replay across cycles/restarts;
- connection lifecycle IDs are preserved from the adapter;
- source and mechanism remain queryable;
- conflicting or incomplete source fields are not overwritten by a second engine.

A future cross-mechanism reconciliation layer may group observations by a deterministic identity/window, but it must preserve all source evidence and never turn a derived grouping into a raw OS event.

## 11. EvidenceStore Behavior

`EvidenceStore` is the only authoritative Aegis evidence sink. It provides:

- SQLite WAL persistence;
- event and finding storage;
- hash-chain verification;
- run-scoped queries;
- event ID uniqueness;
- thread-safe transactions;
- query APIs used by Timeline and reports.

The standalone teammate JSONL sink is not part of the Core evidence contract.

## 12. Lifecycle and Health

`MonitoringEngine` owns:

1. capability-aware collector construction;
2. adapter/observer initialization;
3. startup health event;
4. collection cycles;
5. per-collector exception isolation and exponential backoff;
6. finding persistence;
7. correlation-index update after durable event append;
8. collector and adapter shutdown;
9. final health and store closure.

A derived correlation failure cannot discard a canonical event. Adapter unsupported methods are reported as unavailable/not implemented rather than converted to fake empty telemetry.

## 13. Detection, Timeline, and Correlation

All detections consume canonical Core events. The existing detectors cover file-change bursts, network rates, process/network temporal relationships, and authentication failure bursts.

Timeline orders events by source observation timestamp with deterministic sequence tie-breaking. Correlation indexes PID, parent process, paths, remote IPs, and process-network relationships. The EvidenceStore remains authoritative when the bounded derived index is insufficient.

No current finding claims ransomware, impossible travel, geographic movement, or causality without a detector and sufficient evidence.

## 14. Real Validation Evidence

The committed Core's fresh real-host report was generated from an actual Windows EvidenceStore and recorded:

- run ID: `91a5928bb12d44788e5d8473f082fda0`;
- 319 process events;
- 268 network events;
- 6 file events;
- 0 authentication events;
- 596 total events;
- valid hash chain;
- real watchdog file events;
- real Windows process and network observations;
- authentication capability available through `wevtutil`, with zero matching events in that window.

The network tests exercised the adapter path, including Windows and Linux adapter behavior/capability probes, local connection lifecycle behavior, process association, traffic collection, and JSONL serialization of the subsystem's internal event objects. The Core report confirms that JSONL is not the authoritative store.

## 15. Tests Executed

The complete current suite was executed after integration:

```text
python -m pytest -q
94 passed
```

Coverage includes:

- Core lifecycle and hash-chain tests;
- canonical normalizer tests;
- EvidenceStore, Timeline, CorrelationIndex, and detector integration tests;
- run identity and restart isolation tests;
- authentication cursor deduplication tests;
- network milestone 2 and milestone 3 adapter tests;
- failure isolation and resource/backpressure behavior.

## 16. Before / Teammate / After

### Before: current Core-only baseline

- Canonical event and EvidenceStore foundation.
- Process and file monitoring.
- Portable authentication monitoring.
- Core detection/timeline/correlation.
- Network bridge boundary existed, but platform network quality depended on adapter implementation.

### Teammate contribution

- Platform network adapter architecture.
- Linux eBPF capability/tracing path with polling fallback.
- Windows connection/process attribution and traffic collection.
- DNS event structures and platform capability reporting.
- Adapter lifecycle and explicit unsupported capability semantics.

### After: unified engine

- One MonitoringEngine consumes all validated subsystems.
- Network telemetry is richer while downstream consumers see only canonical Aegis events.
- Network process association can enrich process/network correlation.
- DNS and traffic are preserved as first-class network observations.
- Platform limitations remain visible through capability and health evidence.
- No duplicate standalone engine, database, detection pipeline, or report contract exists.

These are architectural improvements supported by code and tests. They do not imply that ETW, macOS Network Extension, or Linux eBPF is active on every host.

## 17. Enterprise Limitations and Risks

- Windows ETW is capability-detected but not consumed by the Python path.
- Windows file process attribution is unavailable with watchdog/polling.
- Polling can miss very short-lived process or network activity.
- Linux eBPF requires actual kernel, privilege, tracepoint, and loader support.
- macOS native Network Extension requires signed, entitled system components.
- Authentication zero events is a valid observation; an event source must be active and permitted to observe matching activity.
- Geolocation is an enrichment layer, not raw network telemetry.
- The current subsystem has a standalone CLI for diagnostics, but Core `MonitoringEngine` remains the production lifecycle owner.
- Generated runtime databases must remain outside source commits; only intentional evidence reports should be committed.

## 18. Files and Integration Status

No duplicate PR tree was added in this integration turn. The current source already contains the PR's network implementation under `network_monitor/`.

The integration branch adds this report as the architectural record. The current master code and prior validated changes remain intact.

## 19. Purva PR #2 Conflict Resolution

The Purva PR was evaluated as a substantial rewrite rather than accepted
wholesale.

Retained from Purva:

- `aegis_core/analysis.py`: structured, deterministic explanations for
        canonical process, file, network, authentication, and health events;
- `Correlator`: explicit temporal/PID/host relationship explanations over
        canonical events;
- read-only `aegis_core --analyze` CLI mode using the existing EvidenceStore;
- Linux eBPF raw-event structure alignment correction;
- 498 focused analysis tests, adapted without removing existing Core tests.

Rejected during conflict resolution:

- Purva's replacement `MonitoringEngine`;
- replacement collector, normalizer, storage, timeline, and correlation
        contracts;
- duplicate `aegis_core/network.py` bridge;
- duplicate integration test path that depended on the rejected bridge;
- CLI lifecycle changes that bypassed capability-based Core construction.

The resulting engine has one lifecycle owner, one canonical UEM, one
EvidenceStore, one detection path, one Timeline, one CorrelationIndex, and a
compatible analysis/reporting layer over stored canonical evidence.

Post-merge validation:

```text
python -m pytest -q
138 passed
python -m aegis_core --analyze --data-dir e2e_data
exit code 0
```

## 20. Final Status

# MERGED AND VALIDATED

The teammate PR's validated network capabilities and Purva PR #2's compatible
analysis capabilities are integrated into one coherent Aegis Monitoring
Engine. The current implementation has one canonical UEM, one EvidenceStore,
one lifecycle owner, one detection path, one Timeline, one CorrelationIndex,
preserved provenance, explicit capability boundaries, and 138 passing tests.

The duplicate hyphenated PR package and duplicate Purva bridge were not copied
into the repository. The merge was performed without rewriting Git history.
