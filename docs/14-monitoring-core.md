# Aegis Monitoring Core

The first implementation is a portable, safety-governed monitoring foundation in `aegis_core`. It supplies a normalized event model, honest host-capability discovery, real-host collectors, a SQLite evidence store with a hash chain, behavioural anomaly detections, in-memory correlation, timeline reconstruction, and an opt-in local file-version vault.

## Active Telemetry Collectors

The unified `MonitoringEngine` coordinates observation through four primary collectors:

1. **`ProcessLifecycleCollector` (`aegis_core/collectors.py`):** Tracks process creation (`PROCESS_START`) and termination (`PROCESS_EXIT`) between observation cycles using `psutil` or `/proc` filesystem enumeration, augmented by periodic full process snapshots.
2. **`FileEventCollector` (`aegis_core/collectors.py`):** Captures real-time filesystem events (`CREATE`, `MODIFY`, `DELETE`, `MOVE`) using the native OS watcher (`watchdog`: `inotify` on Linux, `ReadDirectoryChangesW` on Windows, `FSEvents` on macOS), with automatic fallback to `FilePollingCollector` if privileges or dependencies are absent.
3. **`AuthEventCollector` (`aegis_core/collectors.py`):** Observes authentication lifecycle and privilege escalation via platform-native security logs:
   - **Linux:** Interrogates `systemd-journald` via `journalctl` for SSH, sudo, and login events (fallback to `/var/log/auth.log`).
   - **Windows:** Interrogates Windows Security Event Log via `wevtutil` (Event IDs: 4624, 4625, 4648, 4672, 4634).
4. **`NetworkBridgeCollector` (`aegis_core/collectors.py`):** Bridges platform-specific network telemetry from the `network_monitor` subsystem (Linux eBPF connection tracing and polling, Windows psutil connections/DNS, macOS stubs) and translates them into canonical `aegis_core.Event` records via `aegis_core.normalizers`.

## Operating modes

- **Development:** Runs against local workspace paths, providing immediate console visibility and telemetry inspection for developers and security analysts.
- **Production:** Intended to run under a supervised service manager with restricted filesystem permissions, encrypted storage, retention limits, and a separate approval/RBAC service. The engine itself never kills processes, blocks networks, changes configuration, or restores files automatically.

## Platform strategy

Core dynamically discovers host capabilities at startup via `discover_capabilities()`:
- Linux selects `/proc` or `psutil` with optional eBPF connection tracing.
- Windows selects `psutil` network/process enumeration and `wevtutil` authentication log queries.
- macOS reports Apple Endpoint Security capability boundaries and raises `CollectorNotImplementedError` for unimplemented collectors, allowing Core to degrade gracefully without crashing.

## File recovery

`FileVersionVault` is opt-in and versions regular files in approved roots under a size cap. A reliable ransomware recovery deployment needs a native pre-write sensor to capture the prior version before modification, encrypted/versioned storage outside the protected volume, quotas, and an external human approval record. The included `restore` call rejects an empty approver identity and symlink overwrite, and production should invoke it only through an authenticated approval service.

## Command-Line Interface (CLI)

The CLI entrypoint is `python -m aegis_core` (`aegis_core/__main__.py`).

```powershell
# 1. Print current host capability and telemetry provider availability
python -m aegis_core --capability-report

# 2. Run a bounded observation cycle with all available collectors
python -m aegis_core --environment development --data-dir .\aegis-data --interval-seconds 1 --run-seconds 10

# 3. Watch specific directory roots for filesystem changes
python -m aegis_core --data-dir .\aegis-data --watch C:\SecureApp\src --run-seconds 30

# 4. Disable authentication event collection (if permissions are restricted)
python -m aegis_core --data-dir .\aegis-data --no-auth --run-seconds 10

# 5. Analyze existing stored canonical evidence without starting new collectors
python -m aegis_core --data-dir .\aegis-data --analyze

# 6. Fallback legacy mode (ProcessSnapshot + FilePolling collectors)
python -m aegis_core --data-dir .\aegis-data --legacy --run-seconds 5
```

