# Safe End-to-End Test

Create a dedicated disposable location, never a user document directory:

```powershell
$root = Join-Path $env:TEMP "aegis-safe-e2e"
New-Item -ItemType Directory -Force $root | Out-Null
py scripts\safe_e2e_demo.py --root $root
```

Expected result: JSON with nonzero `process_events`, `file_events`, and `network_events`, at least one `case_id`, and `chain_valid: true`. The script starts a harmless Python sleep child, creates/modifies/renames/deletes files under `$root\watch`, and makes only a loopback HTTP request. It then stops Aegis and queries evidence after shutdown.

If file events are zero, verify the watcher dependency and ensure the root is not a cloud-sync directory. If network events are zero, check `monitor-status.json`/health evidence and run the capability report; do not create fake events. If no case appears, inspect the default threshold and the safe simulation's actual file events.
