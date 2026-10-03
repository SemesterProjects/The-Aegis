# Aegis

Aegis is an autonomous AI security engineer designed to observe software systems, reason about abnormal behavior, identify likely vulnerabilities, propose verified mitigations, and assist humans during secure incident response and software hardening.

## Product concept
Aegis is composed of three architectural layers:

- Aegis Core: the shared reasoning and orchestration engine
- Aegis Forge: the pre-production offensive validation environment
- Aegis Shield: the runtime defensive and incident-response environment

The design intentionally keeps a single reasoning core while exposing different product surfaces for defense and validation.

## Documentation set

The canonical operator path is the [Aegis Demonstration Runbook](docs/AEGIS_DEMO_RUNBOOK.md).
It covers setup, host and Linux VM monitoring, safe telemetry generation,
triage/case inspection, shutdown, persistence, recovery, and command
reference. Do not use an older operational guide instead.

Architecture and handoff references retained alongside the runbook:

- [System Architecture Overview](docs/05-system-architecture.md)
- [Threat Model and Safety Policy](docs/06-threat-model-and-safety.md)
- [Data and Event Model](docs/10-data-and-event-model.md)
- [Research and Learning Roadmap](docs/12-research-learning-roadmap.md)
- [Aegis Monitoring Core Specification](docs/14-monitoring-core.md)
- [Investigation Agent Handoff](docs/agentic-defense/agent-handoff.md)
- [Investigation Case Schema](docs/agentic-defense/investigation-case-schema.md)
- [Event Schema](docs/agentic-defense/event-schema.md)
- [Agentic Defense Architecture](docs/agentic-defense/architecture.md)

## Product principles
Aegis is built around five non-negotiable rules:

- Observe before acting
- Reason before responding
- Verify before deployment
- Explain every decision
- Keep humans as the final authority for production changes

## Architectural and Platform Focus
Per project architecture (`OSInstruction.txt`), Aegis is designed as a **cross-platform platform from Day 1** across Linux, Windows, and macOS:

- Dynamic host environment and privilege discovery
- Platform-aware telemetry adapters behind clear abstraction boundaries
- Canonical Universal Event Model (`aegis_core.Event`) and tamper-evident SQLite storage
- Non-signature behavioral anomaly detection
- Reconstructing attack progression via temporal and graph correlation

## Current status
**Active Implementation & Production Foundation:**

- **Aegis Core (`aegis_core/`):** 13 implemented modules including the unified `MonitoringEngine`, `ProcessLifecycleCollector`, `FileEventCollector` (with `watchdog` and polling fallback), `AuthEventCollector` (supporting `journalctl`/`auth.log` on Linux and `wevtutil` on Windows), and `NetworkBridgeCollector`.
- **Network Telemetry Subsystem (`network_monitor/`):** Platform adapters for Linux (polling + eBPF connection tracing), Windows (psutil connection polling, DNS, process attribution), and macOS (capability boundaries and stubs).
- **Evidence & Detection:** Tamper-evident SQLite `EvidenceStore` with cryptographic hash chain, four explainable detectors (`AuthFailureBurstDetector`, `FileChangeBurstDetector`, `NetworkRateDetector`, `NewProcessWithNetworkDetector`), in-memory `CorrelationIndex`, and `Timeline` reconstruction.
- **Automated Test Suite:** 138 deterministic tests passing across `tests/` and `network_monitor/tests/`.
- **E2E Validation:** End-to-end real host validation is available through
  `validate_e2e.py` and the isolated procedure in the
  [Aegis Demonstration Runbook](docs/AEGIS_DEMO_RUNBOOK.md).

### Quick Start / CLI Usage

```powershell
# Display host capability report
python -m aegis_core --capability-report

# Run a safe observation cycle in development mode
python -m aegis_core --environment development --data-dir .\aegis-data --interval-seconds 1 --run-seconds 10

# Analyze existing evidence store
python -m aegis_core --data-dir .\aegis-data --analyze

# Run automated test suite
python -m pytest -q
```
