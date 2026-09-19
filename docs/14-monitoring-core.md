# Aegis Monitoring Core

The first implementation is a portable, safety-governed monitoring foundation in `aegis_core`. It supplies a normalized event model, honest host-capability discovery, read-only polling collectors, a SQLite evidence store with a hash chain, behaviour detections, and an opt-in local file-version vault.

## Operating modes

- **Development** is for an explicitly selected local workspace and produces findings for engineers to inspect.
- **Production** is intended to run under a supervised service manager with restricted filesystem permissions, encrypted storage, retention limits, and a separate approval/RBAC service. The engine itself never kills processes, blocks networks, changes configuration, or restores files automatically.

## Platform strategy

Core selects portable collectors and reports the platform capability boundary at startup. Linux can use `/proc` with permissions limiting process detail; Windows has an ETW capability boundary; macOS requires an Apple Endpoint Security entitlement and system extension for endpoint event monitoring. Those native sources must be implemented as signed adapter packages and emit the canonical `Event` model. The Core does not pretend that a Python polling loop is equivalent to kernel telemetry.

## File recovery

`FileVersionVault` is opt-in and only versions regular files in approved roots under a size cap. A reliable ransomware recovery deployment needs a native pre-write sensor to capture the prior version before modification, encrypted/versioned storage outside the protected volume, quotas, and an external human approval record. The included `restore` call rejects an empty approver identity and symlink overwrite, but production should invoke it only through the approval service.

## Run a safe local smoke cycle

```powershell
py -m aegis_core --environment development --data-dir .\aegis-data --watch .\sample-workspace
```

The first file-polling pass establishes an in-memory baseline. It should not be run over an entire user profile or production volume without a retention and privacy review.
