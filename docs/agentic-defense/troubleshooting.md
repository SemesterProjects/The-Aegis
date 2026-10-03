# Troubleshooting

- **Engine does not start:** run `py -m aegis_core --capability-report`; verify Python 3.11+, dependencies, and write access to `--data-dir`.
- **No file events:** use a dedicated non-cloud-sync `--watch` directory and create a real file change after the monitor starts.
- **No process/network events:** inspect `monitor status`, `health` events, and `psutil` availability. Snapshot polling cannot capture activity that exists entirely between polls.
- **Network unavailable:** this is distinct from no activity; `network_bridge` emits a capability health event with the reason.
- **No case:** query findings first; cases require score ≥ 0.50 and only evidence-backed deterministic signals create them.
- **Storage unavailable:** stop safely, correct space/permissions, preserve the database and WAL files, then restart. Do not edit SQLite payloads; it invalidates the hash chain.
