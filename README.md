# Aegis

Aegis is an autonomous AI security engineer designed to observe software systems, reason about abnormal behavior, identify likely vulnerabilities, propose verified mitigations, and assist humans during secure incident response and software hardening.

## Product concept
Aegis is composed of three architectural layers:

- Aegis Core: the shared reasoning and orchestration engine
- Aegis Forge: the pre-production offensive validation environment
- Aegis Shield: the runtime defensive and incident-response environment

The design intentionally keeps a single reasoning core while exposing different product surfaces for defense and validation.

## Documentation set
This repository contains comprehensive architecture, governance, specification, and operational documentation:

1. [Documentation Charter](docs/01-documentation-charter.md)
2. [Product Vision and Principles](docs/02-product-vision-and-principles.md)
3. [Problem, Market, and Positioning](docs/03-problem-market-and-positioning.md)
4. [MVP Requirements and Success Metrics](docs/04-mvp-scope-and-success-metrics.md)
5. [System Architecture Overview](docs/05-system-architecture.md)
6. [Threat Model and Safety Policy](docs/06-threat-model-and-safety.md)
7. [Validation and Test Strategy](docs/07-validation-and-test-strategy.md)
8. [Roadmap and Milestones](docs/08-roadmap-and-milestones.md)
9. [Engineering Governance and Standards](docs/09-engineering-governance.md)
10. [Data and Event Model](docs/10-data-and-event-model.md)
11. [Deployment and Operations Strategy](docs/11-deployment-and-operations.md)
12. [Research and Learning Roadmap](docs/12-research-learning-roadmap.md)
13. [Aegis Lab Environment (Historical Overview)](docs/13-lab-environment.md)
14. [Aegis Monitoring Core Specification](docs/14-monitoring-core.md)
15. [Core Implementation Gap Analysis](docs/15-core-implementation-gap-analysis.md)
16. [Laboratory Runbooks (Hyper-V Testbed)](docs/lab/README.md) — 14-runbook operational package

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
- **E2E Validation:** End-to-end real host validation verified on Windows and Linux (see `validate_e2e.py` and `AEGIS_CORE_REAL_RUN_REPORT.md`).

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

