# The Aegis — Codebase Analysis Report
> **Generated:** 2026-09-22 | **Scope:** Full repository audit | **Goal:** Understand feature maturity across the entire system

---

## 1. What Is Aegis?

Aegis is an **autonomous AI security engineer** — a startup-grade, enterprise-level platform designed to:

1. **Observe** running software systems continuously
2. **Detect** suspicious behavior without signatures (behavioral analysis)
3. **Reason** about attack paths, root causes, and blast radius
4. **Propose** verified mitigations
5. **Verify** fixes in an isolated sandbox
6. **Present** findings to a human for approval before any production action

The product is decomposed into three architectural layers:
- **Aegis Core** — shared reasoning, orchestration, and evidence management engine
- **Aegis Forge** — offensive pre-production validation environment *(planned)*
- **Aegis Shield** — runtime defensive and incident-response surface *(planned)*

Five non-negotiable product rules govern all design decisions:
> *Observe before acting · Reason before responding · Verify before deployment · Explain every decision · Humans are the final authority*

---

## 2. Repository Structure

```
The-Aegis/
├── aegis_core/          ← Milestone 1 core: event model, engine, collectors, storage, detection
├── network_monitor/     ← Milestone 2 + 3: cross-platform network telemetry subsystem
│   ├── core/            ← Abstract adapter contract + event types + factory
│   ├── discovery/       ← System/OS/privilege runtime discovery
│   └── adapters/
│       ├── linux/       ← Full M3 implementation (eBPF + polling)
│       ├── windows/     ← M2 implementation (psutil + IP Helper + raw socket DNS)
│       └── macos/       ← M1 implementation (capability probes only)
├── tests/               ← Core test suite (6 deterministic unit tests)
├── docs/                ← 15 planning/architecture/governance documents
└── pyproject.toml       ← Package definitions (aegis-core v0.1.0)
```

---

## 3. Feature Status Matrix

### 🟢 FULLY IMPLEMENTED

These features are complete, tested, and production-quality in their scope.

---

#### 3.1 Universal Event Model (`aegis_core/models.py`)

| What | Detail |
|---|---|
| `Event` dataclass | Frozen, slotted, immutable after construction. Carries `kind`, `source`, `host_id`, `observed_at`, `schema_version`, and a free-form `data` map. |
| `Finding` dataclass | Links detection results to evidence via `evidence_event_ids`. Requires non-empty evidence and validated `confidence ∈ [0.0, 1.0]`. |
| Enumerations | `EventKind` (PROCESS, NETWORK, FILE, AUTHENTICATION, CONFIGURATION, HEALTH), `Severity` (INFO → CRITICAL), `Environment` (DEVELOPMENT, PRODUCTION) |
| Canonical serialization | `event.canonical()` → normalized dict (Enums → string values, datetimes → UTC ISO 8601). |
| Content-addressed digest | `event.digest()` → SHA-256 of JSON-serialized canonical form. Enables tamper detection and deduplication. |
| Timezone enforcement | `observed_at` is validated to be timezone-aware; bare datetimes are rejected at construction. |
| Data immutability | `data` dict is deep-copied at `__post_init__` to prevent post-ingest mutation by callers. |

**Assessment:** Enterprise-grade. The design correctly prevents platform-specific data from leaking into detection logic.

---

#### 3.2 SQLite Evidence Store with Hash Chain (`aegis_core/storage.py`)

| What | Detail |
|---|---|
| WAL-mode SQLite | `PRAGMA journal_mode=WAL` + `PRAGMA foreign_keys=ON` — crash-safe, concurrent-read capable. |
| Hash chain | Each row stores `previous_hash` and `record_hash = SHA-256(previous_hash + payload)`. Blockchain-style tamper-evidence. |
| Chain verification | `verify_chain()` replays the entire chain; returns `False` on first break. Tested deterministically. |
| Thread safety | `threading.RLock()` guards all DB access; safe for multi-collector engines. |
| Append-only semantics | `INSERT OR IGNORE` prevents duplicate event_ids — idempotent ingestion. |
| Findings storage | Separate `findings` table with severity index. |
| `recent_events()` | Time-windowed query returning canonical dicts (not raw Event objects — correct boundary). |

**Assessment:** Fully implemented. The chain-of-custody design is audit-ready for compliance scenarios.

---

#### 3.3 Host Capability Discovery (`aegis_core/capabilities.py`)

| What | Detail |
|---|---|
| OS detection | `platform.system()` → Linux / Windows / Darwin / other |
| Privilege probing | Linux: `os.geteuid()`. Windows: `ctypes.windll.shell32.IsUserAnAdmin()`. Both never raise. |
| Feature set | `{"process_snapshot", "file_polling", "sqlite_store"}` as baseline; extended with `"procfs"`, `"journalctl"`, `"powershell"`, `"etw_capability_probe"`, `"endpoint_security_capability_probe"`, `"psutil"` based on runtime detection. |
| Honest limitations | Platform-specific limitations (ETW requires signed implementation, macOS ES requires entitlement) are recorded as strings — never hidden. |
| Safety | The function **never raises** — capability detection must not stop monitoring. |

**Assessment:** Production-quality. Correctly distinguishes "label" from "capability" — a common failure mode in naive implementations.

---

#### 3.4 Monitoring Engine (`aegis_core/engine.py`)

| What | Detail |
|---|---|
| Lifecycle | `start()` → `run_once()` / `run_forever()` / `run_for(N)` → `stop()`. Clear state machine with guards against restart-after-stop. |
| Collector isolation | Each collector runs in its own try/except. One collector failure **cannot blind the engine**. |
| Exponential backoff | Failed collectors back off with `2^n × interval` up to `max_collector_backoff_seconds`. Backoff state is tracked per-collector in `CollectorRuntime`. |
| Periodic health events | `AEGIS-HEALTH` events emitted at `health_interval_seconds` cadence, including chain integrity check and per-collector status. |
| Startup transparency | Emits a capability report event on `start()` — every monitoring session begins with a verifiable, auditable capability snapshot. |
| `status()` API | Returns live engine state, per-collector failure counts, and chain validity. |
| Detection integration | Every ingested event is immediately evaluated by the `DetectionPipeline`. Findings are stored and returned. |

**Assessment:** Robust, production-quality lifecycle management. The collector isolation pattern is exactly right for a 24/7 security daemon.

---

#### 3.5 File Polling Collector (`aegis_core/collectors.py` — `FilePollingCollector`)

| What | Detail |
|---|---|
| Allow-listed roots only | Only explicitly configured directory roots are scanned — no implicit whole-system scanning. |
| Symlink safety | Symlinks are explicitly skipped (`path.is_symlink()`) — prevents symlink traversal attacks. |
| Metadata-based change detection | Uses `(st_mtime_ns, st_size)` tuples. No file content read → privacy-preserving and low-overhead. |
| Lifecycle tracking | Emits `created`, `modified`, and `deleted` events correctly. |
| Scan cap | `max_files_per_cycle` (default 10,000) prevents runaway scans. Emits a `HEALTH` warning when capped. |
| Baseline behavior | First pass only establishes baseline — no false `created` events on initial run. |

**Assessment:** Fully implemented with careful security properties.

---

#### 3.6 Behavioral Detection Engine (`aegis_core/detection.py`)

| What | Detail |
|---|---|
| `FileChangeBurstDetector` (AEGIS-FILE-001) | Sliding-window (default 60s) count of unique file paths changed. Triggers at `threshold` (default 25). Detects ransomware-like mass-modification patterns. Confidence is dynamically computed based on path count and dominant suffix ratio. |
| `NetworkRateDetector` (AEGIS-NET-001) | Per-process sliding-window connection rate monitor. Triggers at 100 connections/60s. Detects port-scan or C2-beacon behavior. |
| `Detector` Protocol | Clean interface: any object with `evaluate(event) -> Iterable[Finding]` is a valid detector. Fully extensible. |
| `DetectionPipeline` | Composes N detectors; returns merged `tuple[Finding, ...]`. Stateless from the engine's perspective. |
| Evidence linking | Every finding carries `evidence_event_ids` — a tuple of UUIDs linking to the stored events that triggered it. Full audit trail. |
| Human-first design | Findings include `explanation` (what was observed) and `recommendation` (what a human should do). No auto-remediation. |

**Assessment:** Solid foundation. The two implemented detectors are correct and explainable — not signature-based black boxes.

---

#### 3.7 File Version Vault (`aegis_core/versioning.py`)

| What | Detail |
|---|---|
| Content-addressed blob store | Files stored as `blobs/{digest[:2]}/{digest}` — deduplicates identical content versions. |
| Size cap enforcement | Files > `max_version_bytes` (default 64MB) are silently skipped. |
| Symlink safety | Refuses to capture or restore through symlinks. |
| Approval-gated restore | `restore()` requires a non-empty `approved_by` string — structurally enforces human authorization. Tested deterministically. |
| SQLite metadata | Version records stored with `version_id`, `original_path`, `digest`, `size`, `captured_at`. |
| Idempotent capture | Re-captures of an existing `(path, digest)` pair return the existing version without duplicating the blob. |
| Context manager support | `with FileVersionVault(...) as vault:` pattern — resource-safe. |

**Assessment:** Fully implemented. The approval-gating makes unauthorized rollback structurally impossible, not just convention-impossible.

---

#### 3.8 Network Monitor — Core Abstractions (`network_monitor/core/`)

| What | Detail |
|---|---|
| `NetworkAdapter` ABC | Abstract base defining `get_adapter_info()`, `discover_capabilities()`, `start()`, `stop()`, and four `collect_*()` methods. |
| `CollectorNotImplementedError` | Distinct from `NotImplementedError` — allows callers to distinguish "not built yet" from "no data". Excellent API contract design. |
| `CapabilityReport` | Per-adapter capabilities dict, per-collector `CollectorInfo` list, and human-readable notes. |
| `AdapterFactory` | Single dispatching point for OS → adapter class selection. Uses deferred imports to prevent cross-platform import errors. Raises `UnsupportedOSError` for unknown OS. |
| Network event types | `ConnectionEvent`, `TrafficEvent`, `DnsEvent`, `ProcessNetworkEvent` — all with `to_dict()` / `to_json()` serialization. Rich enum types for `ConnectionState`, `Protocol`, `ConnectionDirection`. |
| `CollectorStatus` enum | `AVAILABLE / NOT_IMPLEMENTED / UNAVAILABLE / PERMISSION_DENIED / ERROR` — extremely honest status taxonomy. |

**Assessment:** Enterprise-grade contract design. The strict interface with explicit `CollectorNotImplementedError` means the system will never silently return empty data and pretend it succeeded.

---

#### 3.9 System Discovery (`network_monitor/discovery/system.py`)

| What | Detail |
|---|---|
| `SystemDiscovery.discover()` | Never raises. Each of 7 probes is independently try/caught. Failures recorded in `discovery_errors`. |
| Probes | OS name/version/edition, Python version/implementation, hostname, machine architecture, network interfaces (psutil preferred, socket fallback), privileges (Unix eUID/eGID, Windows IsUserAnAdmin), raw platform dict. |
| `SystemInfo` | Rich structured result: OS, hardware, Python, network interfaces, privilege info, psutil availability flag, discovery errors. |
| Psutil/stdlib duality | Uses psutil if available (rich interface data), falls back to `socket.getaddrinfo` (limited but honest). |

**Assessment:** Fully implemented. The "never raises + record errors" design is production-quality.

---

#### 3.10 Linux Network Adapter — Milestone 3 (`network_monitor/adapters/linux/`)

| What | Detail |
|---|---|
| eBPF Connection Tracer (`ebpf/connection_tracer.py`) | Attaches to `sock:inet_sock_set_state` kernel tracepoint (Linux ≥ 4.16) via BCC. Captures TCP state transitions at kernel level including sub-millisecond ephemeral connections that polling misses. Background polling thread. `try_load()` classmethod returns `None` with reason string instead of raising. |
| eBPF Loader (`ebpf/loader.py`) | `load_connection_tracer()` — runs capability checks (platform, kernel version, privilege, BCC availability), then attempts load. **Never raises.** Returns `(tracer | None, reason_str)`. |
| eBPF Capability Probe (`ebpf/capability.py`) | Checks Linux platform, kernel version ≥ 4.4, privilege (root or unprivileged_bpf_disabled=0), BCC import, `sock:inet_sock_set_state` tracepoint via debugfs, BTF availability. |
| Connection Collector (`connections.py`) | Hybrid eBPF + polling. eBPF events take precedence (kernel timestamps, PID from in-kernel `comm`). Deduplication prevents double-reporting. Fallback to psutil snapshot diffing + `/proc/net/{tcp,udp}` parsing. |
| Traffic Collector (`traffic.py`) | psutil/`/proc/net/dev` interface counters with cumulative + per-interval deltas. Zero-change intervals suppressed. |
| DNS Collector (`dns.py`) | Available where supported. |
| Process Network Activity | Derived from connection attribution; PIDs matched via psutil + `/proc/{pid}/comm`. |

**Assessment:** The Linux adapter is the most mature. The eBPF integration is architecturally sound and operationally honest about its prerequisites.

---

#### 3.11 Windows Network Adapter — Milestone 2 (`network_monitor/adapters/windows/`)

| What | Detail |
|---|---|
| Connection Collector | psutil snapshot diffing with IP Helper fallback. Tracks new connections, state transitions, closed connections. Process attribution with `AccessDenied` graceful handling. |
| Traffic Collector | `psutil.net_io_counters()` with per-interval deltas, zero-change suppression. |
| DNS Collector | Raw socket inspection of UDP port 53 plaintext DNS. Correctly reports `PERMISSION_DENIED` when not Administrator (WinError 10013). Encrypted DNS (DoH/DoT) limitation explicitly documented. |
| ETW Capability Probe | Checks admin privilege, Python ETW package availability, IP Helper DLL. Documents architectural limitation (full ETW from pure Python is not feasible for kernel-level telemetry). |
| ETW stub directory | `etw/` with `capability.py` — placeholder for future native ETW integration. |

**Assessment:** Milestone 2 complete. Collectors are functional. ETW is honestly documented as a future native-component requirement.

---

#### 3.12 CLI Entry Point (`aegis_core/__main__.py`)

- `python -m aegis_core` — production smoke runner
- Supports `--environment`, `--data-dir`, `--watch`, `--interval-seconds`, `--run-seconds`
- Single-cycle and bounded-run modes
- Reports findings count and chain validity on exit

---

#### 3.13 Test Suite (`tests/test_core.py`)

| Test | What it proves |
|---|---|
| `test_evidence_chain_detects_tampering` | Hash chain correctly detects single-record payload modification |
| `test_file_burst_is_explainable` | `FileChangeBurstDetector` fires at threshold with correct rule_id and evidence_count |
| `test_version_restore_requires_approver` | `FileVersionVault.restore()` enforces non-empty `approved_by` |
| `test_file_collector_reports_change_after_baseline` | `FilePollingCollector` emits `modified` event after baseline |
| `test_runtime_emits_heartbeat_and_recovers_from_a_collector_failure` | Engine correctly isolates a failing collector, records backoff, and recovers |
| `test_bounded_runner_collects_immediately_and_stops` | `run_for()` terminates cleanly and `status()["stopped"]` is True |

**Assessment:** 6 deterministic, meaningful tests — all test real security-critical behaviors.

---

## 4. Partial Implementations

These features exist with correct foundations but are incomplete relative to their production requirements.

| Feature | What Exists | What's Missing |
|---|---|---|
| **24/7 Production Monitoring** | Bounded loop, per-collector backoff, health events, graceful shutdown, SQLite durability | OS service units (systemd/Windows Service), watchdog, restart policy, config file loading, metrics/alerting, retention policy, resource limits |
| **Cross-Platform Telemetry** | Linux M3 (eBPF + polling), Windows M2 (psutil), macOS M1 (detection only), runtime OS/privilege discovery | macOS collectors (blocked by Apple entitlement requirement), full ETW-native Windows telemetry, authentication/config event sensors |
| **Network → Core Integration** | `network_monitor` is a standalone subsystem with its own event model | `network_monitor` events are NOT yet bridged into `aegis_core`'s `Event` / `Finding` pipeline. The two systems are architecturally adjacent but not connected. |
| **Behavioral Detection** | 2 sliding-window detectors (file burst, connection rate) | No baseline learning, no multi-signal correlation, no rule management, no ATT&CK mapping, no suppression/deduplication, no incident lifecycle |
| **File Recovery** | `FileVersionVault` with SHA-256 capture, size cap, approval-gated restore | Not hooked into pre-write collection (currently post-fact only), no encrypted/off-volume storage, no restore hash verification, no quota management |
| **Evidence Model** | Canonical events, hash chain, `Finding` with evidence links | No schema version migration, no sensitivity policy, no cross-source correlation IDs, no signed remote attestation, no evidence export API |
| **Test Coverage** | 6 unit tests for `aegis_core` | No tests for `network_monitor`, no CI/CD pipeline, no linting/type-check pipeline, no coverage gate, no multi-platform test matrix |

---

## 5. Foundational (Scaffolding / Stubs Only)

These are structural placeholders that define the architecture but contain no working runtime logic.

| Component | Status |
|---|---|
| `network_monitor/adapters/windows/etw/` | Capability probe only. No ETW consumer. Documented architectural blocker: full kernel ETW from pure Python requires a native signed helper process. |
| `network_monitor/adapters/macos/network_extension/` | Capability probe only. Blocked by Apple's Network Extension framework requiring system extension + Apple-granted entitlement — structurally impossible from a Python process. |
| `MacOSConnectionCollector` | Class exists, raises `CollectorNotImplementedError`. |
| `MacOSTrafficCollector` | Class exists, raises `CollectorNotImplementedError`. |
| `MacOSDnsCollector` | Class exists, raises `CollectorNotImplementedError`. |
| **Aegis Forge** | Documented in architecture. Zero code. Planned as pre-production offensive validation environment. |
| **Aegis Shield** | Documented in architecture. Zero code. Planned as runtime defense and IR surface. |
| **Approval / RBAC Service** | Documented in threat model and architecture. Zero code. Required before any automated response capability is added. |
| **Sandbox / Verification Engine** | Documented in roadmap (Phase 4). Zero code. |
| **AI Reasoning Layer** | Documented as the core mission of the product. Zero code. The project is in the data collection and detection foundation phase. |
| **Multi-agent Orchestration** | Documented in roadmap (Month 8). Zero code. |

---

## 6. Next Steps (Priority Order)

### Immediate (unblocks everything else)

1. **Bridge `network_monitor` → `aegis_core`**
   - Translate `ConnectionEvent` / `TrafficEvent` / `DnsEvent` from the network monitor into `aegis_core.Event` objects
   - Wire `NetworkRateDetector` to receive live network events from the adapter pipeline
   - Currently the two systems are side-by-side but disconnected

2. **Extend test coverage to `network_monitor`**
   - Unit tests for `SystemDiscovery`, `AdapterFactory`, `WindowsConnectionCollector`
   - Mock-based tests for all three platform adapters
   - End-to-end integration test through the full chain

### Near-Term (MVP-critical)

3. **Authentication and Configuration event sensors**
   - Windows: Security Event Log (login, privilege use, policy change)
   - Linux: PAM/auditd events via journalctl
   - These are the missing third telemetry pillar alongside process and file

4. **Continuous process lifecycle sensor** (currently only snapshots)
   - Linux: `/proc` events via `inotify` or `netlink/proc connector`
   - Windows: WMI `Win32_ProcessStartTrace` or ETW process provider

5. **Production service packaging**
   - `systemd` unit file for Linux
   - Windows Service wrapper for `MonitoringEngine.run_forever()`
   - Configuration file loading (YAML/TOML) instead of CLI-only config

6. **macOS Milestone 2** — implement `MacOSConnectionCollector` using `lsof`/`netstat` fallback (no Apple entitlement needed for polling-based collection)

### Medium-Term (making detection useful)

7. **Baseline learning** — replace hard-coded thresholds with learned normal-behavior baselines per-host
8. **Multi-signal correlation** — correlate file burst + network rate + new process → higher-confidence incident hypothesis
9. **ATT&CK framework mapping** — link detectors to MITRE ATT&CK technique IDs for compliance and SOC interoperability
10. **Finding deduplication and suppression** — prevent alert storms for sustained anomalies

### Architecture-Completing Steps

11. **Approval workflow service** — REST API for human review and approval of findings/actions (required before any response capability is added)
12. **Evidence export API** — SIEM-compatible event streaming (syslog/CEF or OTLP)
13. **AI Reasoning Layer** — attach an LLM reasoning loop that consumes findings, generates hypotheses, and produces mitigation plans
14. **Sandbox verification** — Aegis Forge foundation for verifying proposed mitigations in isolated environments

---

## 7. Architecture Quality Assessment

| Dimension | Score | Notes |
|---|---|---|
| **Safety-first design** | ⭐⭐⭐⭐⭐ | Read-only sensors. No auto-remediation. Approval gates enforced structurally, not just by convention. |
| **Honesty about capability** | ⭐⭐⭐⭐⭐ | `CollectorNotImplementedError` vs empty list. `limitations` recorded in capability reports. ETW/macOS limitations documented, not faked. |
| **Evidence integrity** | ⭐⭐⭐⭐⭐ | SHA-256 hash chain. Immutable Event objects. Canonical JSON. Content-addressed blob versioning. |
| **Code quality** | ⭐⭐⭐⭐½ | Frozen/slotted dataclasses. Protocol-based interfaces. Deferred imports for cross-platform safety. Consistent error handling. |
| **Extensibility** | ⭐⭐⭐⭐½ | `Collector` and `Detector` protocols make extension clean. `AdapterFactory` centralizes all OS dispatch. Single responsibility throughout. |
| **Test quality** | ⭐⭐⭐½ | Core tests are meaningful and deterministic. `network_monitor` (majority of code) has zero tests. |
| **Documentation** | ⭐⭐⭐⭐⭐ | 15 docs covering product vision, architecture, threat model, roadmap, lab environment, and an implementation gap analysis that is self-aware about what is and isn't done. |
| **Production readiness** | ⭐⭐½ | The core is production-quality as a library. Missing: OS service packaging, encrypted storage, retention, remote audit sink, CI/CD pipeline. |

---

## 8. Summary

Aegis has built a **solid, architecturally honest foundation** for a serious security product. The design decisions — immutable events, hash-chain evidence, approval-gated actions, capability-honest adapters, explainable findings — are all correct for a startup aiming at enterprise and compliance markets.

The system is currently in **Phase 1 (Observation Infrastructure)**:
- The data collection pipeline is sound on Linux (including eBPF), functional on Windows (psutil), and scaffolded on macOS
- The event model, storage, and basic behavioral detection are proven
- The AI reasoning, mitigation, verification, and approval layers are documented and planned but not yet built

The most important next step is **bridging the `network_monitor` into `aegis_core`** so all telemetry flows into one unified evidence pipeline, unlocking multi-signal detection.

> **Bottom line:** This is not a toy project. The architecture decisions reflect serious production security engineering. The implementation is at early Phase 1 of a correctly designed 12-month plan toward a genuinely differentiated security product.
