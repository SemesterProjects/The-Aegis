# Aegis Core Completion Report

> [!NOTE]
> **HISTORICAL ARCHIVE:** Completed September 2026. This report records the historical implementation and architectural unification of `NetworkBridgeCollector`, `normalizers.py`, `ProcessLifecycleCollector`, `FileEventCollector`, and `AuthEventCollector` into the Aegis Core.

This report outlines the work completed to integrate the existing `network_monitor` pipeline into `aegis_core` and to complete the `ProcessLifecycleCollector`, `FileEventCollector`, and `AuthEventCollector`, resulting in a unified, end-to-end telemetry observability engine.

## 1. Network Monitor Bridge Integration

The core directive was to **not build another parallel monitoring architecture**, but to connect the existing `network_monitor` to `aegis_core`. 

This was accomplished via the `NetworkBridgeCollector` (in `aegis_core/collectors.py`). 
*   **Discovery and Initialization:** The bridge utilizes `SystemDiscovery` and `AdapterFactory` from `network_monitor` to create the appropriate native OS adapter (e.g. `LinuxAdapter`, `WindowsAdapter`). 
*   **Telemetry Normalization:** A new module, `aegis_core/normalizers.py`, was created. This module acts as the Universal Event Model (UEM) translation layer. It transforms platform-specific network events (`ConnectionEvent`, `TrafficEvent`, `DnsEvent`, `ProcessNetworkEvent`) into the canonical `aegis_core.Event` structures. It does this strictly and honestly (no field fabrication, enum extraction, UTC standardisation).
*   **Graceful Degradation:** The bridge honestly reports capabilities via the new `build_from_capability()` engine constructor. If a particular capability (e.g., DNS tracing) is not implemented on an OS, it catches `CollectorNotImplementedError` and continues seamlessly.

## 2. Telemetry Collector Expansion

We completed the core observation pipeline with the missing collectors, all implemented in `collectors.py` alongside the bridge:

*   **ProcessLifecycleCollector:** Transitioned from a simple periodic snapshot to real lifecycle tracking (PROCESS_START and PROCESS_EXIT). It uses `psutil` or `/proc` filesystem enumeration to detect new or terminated PIDs between observation cycles, and periodically issues full state snapshots.
*   **FileEventCollector:** Implemented a hybrid file monitoring solution. It defaults to the native OS file monitoring APIs (via the `watchdog` Python library: `inotify` on Linux, `ReadDirectoryChangesW` on Windows, `FSEvents` on macOS). Crucially, if `watchdog` is not installed or the user lacks privilege, it silently falls back to the original `FilePollingCollector` semantics. 
*   **AuthEventCollector:** Implemented a robust, OS-aware security event collector. 
    *   **Linux:** Prioritizes reading the `systemd` journal (`journalctl`) for SSH, sudo, and login events. If unavailable, falls back to parsing `/var/log/auth.log`.
    *   **Windows:** Interrogates the Security Event Log via the `wevtutil` utility (Event IDs: 4624, 4625, 4648, 4672, 4634).

## 3. Storage and Query Enhancements

To support correlation and the future AI investigation agent, the `EvidenceStore` (`aegis_core/storage.py`) was significantly upgraded while maintaining its tamper-evident hash chain guarantees.

*   **Rich Querying:** Added `query_events(since, until, kinds, sources, host_ids, action, pid)` to offload filtering to SQLite, leveraging JSON extraction (`json_extract`) on supported versions of SQLite (>= 3.38), falling back to Python-side filtering for older versions.
*   **Indexes:** Added `CREATE INDEX` statements for `observed_at` and `kind` to drastically improve query performance.
*   **New Accessors:** Added `count_events()`, `get_findings()`, and `get_event_by_id()` methods.

## 4. Timeline and Correlation Layers

Two new modules were created to provide investigation-ready abstractions over raw SQL queries:

*   **Timeline (`aegis_core/timeline.py`):** Provides a temporal view of events. It supports querying events by recent windows, date ranges, and entity-focused timelines (e.g., `process_timeline(pid)`, `file_timeline(path)`, `network_timeline(remote_ip)`).
*   **CorrelationIndex (`aegis_core/correlation.py`):** An in-memory graph index built by ingesting events. It maps processes, files, and network connections. It provides crucial context methods such as `get_process_tree(pid)` and `suspicious_process_network_pairs()`. 

## 5. Explainable Behaviour Detectors

The `DetectionPipeline` was extended with two new behavioural detectors (in `aegis_core/detection.py`):

*   **NewProcessWithNetworkDetector (AEGIS-PROC-NET-001):** Detects when a process starts and immediately establishes an outbound network connection (a pattern common in both legitimate software updaters and malicious droppers/C2). 
*   **AuthFailureBurstDetector (AEGIS-AUTH-001):** Detects bursts of failed authentication attempts for a single user within a short time window, indicating potential brute-force activity. 

## 6. Execution and Orchestration

The orchestration layer (`aegis_core/engine.py` and `aegis_core/__main__.py`) was updated to manage the new complexity safely:

*   **Capability Factory:** Created `MonitoringEngine.build_from_capability()`. This factory method interrogates the host (using `discover_capabilities()`) and automatically instantiates the appropriate collectors based on OS support, privileges, and installed dependencies (like `watchdog`). It gracefully degrades where necessary.
*   **CLI Enhancements:** 
    *   Added `--capability-report` to dump a human-readable list of what Aegis Core can monitor on the current system.
    *   Added `--no-auth` to easily disable security log polling if it's causing issues.
    *   The CLI now uses the `build_from_capability()` factory by default, turning it into a true "auto-sensing" agent.

## 7. Testing and Validation

*   **Unit Tests:** Wrote `tests/test_normalizers.py` to ensure the UEM layer handles edge cases, correctly extracts Enums, formats datetimes, and strips `None` values.
*   **Integration Tests:** Created `tests/test_integration.py` to test the pipeline end-to-end: Collector -> Storage -> Timeline -> Correlation -> Detection -> Finding. 
*   **E2E Validation:** Authored `validate_e2e.py` to execute a real monitoring loop for 10 seconds against the host filesystem and network, verifying event ingestion, finding generation, and hash chain integrity.

All code has been applied and validated. Aegis Core is now a functional, unified real-host observation pipeline.
