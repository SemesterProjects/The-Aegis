# Aegis Core Implementation Gap Analysis

This is an implementation audit of the current `aegis_core` baseline. A class, enum, comment, or capability label is not treated as implemented functionality.

| Requirement | Status | Actually implemented | Gap before the requirement is met |
| --- | --- | --- | --- |
| 1. Production 24/7 monitoring | Partial | Bounded/immediate collection loop, per-collector failure backoff, periodic health records, graceful stop, SQLite durability. | No OS service units, watchdog, restart policy, configuration loading, metrics/alerts, retention, resource limits, or HA. |
| 2. Windows/Linux/macOS capability adapters | Partial | Runtime OS/privilege discovery; portable process polling; Linux `/proc` fallback. | No adapter registry or native ETW, eBPF/audit, macOS Endpoint Security/System Extension integrations. Capability labels do not collect native telemetry. |
| 3. Normalized evidence model | Partial | Canonical `Event`/`Finding`, UTC timestamps, provenance source, host ID, stable JSON, local hash-chain records. | No schema validation/version migration, field-level sensitivity policy, cross-source correlation IDs, signed remote attestation, or evidence export API. |
| 4. Process/file/network telemetry | Partial | Process snapshots; opt-in file metadata polling; file change events. | No continuous process lifecycle sensor, file pre-write sensor, authentication/config sensor, or active network collector. The blocked networking PR is not used. |
| 5. Behavioral correlation/detection | Partial | Sliding-window file-change burst and supplied-network-event rate rules create evidence-linked findings. | No baselining, multi-signal correlation, suppression/deduplication, model/rule management, ATT&CK mapping, or incident lifecycle. |
| 6. Ransomware versioning/verified rollback | Partial | Opt-in regular-file version store with SHA-256 capture, size cap, approval identity check, and restore test. | Not integrated with pre-change collection; no protected external storage, restore hash verification, immutable audit record, retention/quota management, or recovery validation workflow. |
| 7. Controlled response | Missing | Findings only recommend human review. | No approval/RBAC service, signed response plan, policy enforcement, action executor, rollback orchestration, or action audit trail. |
| 8. Development security-assessment mode | Missing | A `development` environment value and local CLI mode exist. | No configuration audit, vulnerability/dependency checks, hardening benchmarks, report, or assessment workflow. |
| 9. Health, recovery, auditability | Partial | Startup/shutdown/error/heartbeat health events; collector backoff; SQLite WAL; hash-chain verification. | No encrypted storage/key management, remote audit sink, integrity anchoring, disk-pressure handling, recovery drill, health endpoint, or alert delivery. |
| 10. Automated tests and CI | Partial | Six deterministic `unittest` cases and a bounded runnable CLI demonstration. | No GitHub Actions, lint/type/security checks, coverage gate, packaging test, platform matrix, integration test, or release signing. |

## Selected next vertical slice

The first priority is **reliable monitored runtime operation** (requirements 1 and 9), because endpoint detections are not useful if the engine silently stops collecting after a transient collector failure. This slice is intentionally limited to immediate collection, a bounded service loop, per-collector exponential backoff, persisted health events, status inspection, and deterministic tests. It does not add response execution, native OS telemetry, or new product surfaces.

## Runnable demonstration

```powershell
py -m aegis_core --environment development --data-dir .\aegis-demo-data --interval-seconds 0.25 --run-seconds 1
```

The command performs repeated safe process snapshots, writes startup/heartbeat/shutdown audit events, and exits cleanly. It is a local demonstration—not a Windows service or production deployment.
