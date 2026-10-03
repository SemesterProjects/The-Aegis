# Monitoring, Triage, and Investigation Boundary

`MonitoringEngine.build_from_capability()` creates the supported pipeline:

```text
collectors -> canonical Event -> EvidenceStore -> DetectionPipeline -> TriageEngine -> InvestigationCase
```

The only durable evidence database is `<data-dir>/evidence.sqlite3`. `events` are hash chained in sequence order; `findings` and `investigation_cases` reference stable event IDs. Triage is deterministic and does not execute any response action. The future Investigation Agent consumes persisted cases and evidence through `EvidenceStore`; it must not parse OS output or modify collectors.

`NetworkBridgeCollector` adapts `network_monitor` into canonical Aegis events. On this Windows host it uses the network package's psutil snapshot-diffing path, not ETW. Native macOS Endpoint Security and Linux eBPF capability boundaries remain adapter-specific and are not represented as universally available.
