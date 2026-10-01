# Roadmap and Milestones

## Product roadmap phases
### Phase 0: product and architecture foundation
Define the product charter, architecture boundaries, and safety requirements.

### Phase 1: observation and runtime understanding
Build the telemetry and monitoring layer for Linux applications.

### Phase 2: detection and anomaly reasoning
Convert raw telemetry into suspicious behavior detection with explanation.

### Phase 3: investigation and root-cause localization
Create timeline reconstruction and likely code-to-runtime linkage.

### Phase 4: mitigation planning and verification
Generate and validate candidate fixes in a sandbox.

### Phase 5: human-reviewed response workflow
Present evidence, capture approvals, and support execution with auditability.

### Phase 6: enterprise integration and scale
Expand operational maturity without breaking the core architecture.

## Current Implementation Progress

| Phase | Focus Area | Status | Deliverables Completed |
| --- | --- | --- | --- |
| **Phase 0** | Product & Architecture Foundation | **Complete** | Documentation charter, system architecture, safety boundaries, data/event model, and cross-platform mandate (`OSInstruction.txt`). |
| **Phase 1** | Observation & Runtime Understanding | **Complete** | Cross-platform `network_monitor` (Linux eBPF + polling, Windows psutil/DNS, macOS stubs), `MonitoringEngine`, collectors for process lifecycle, filesystem events (`watchdog`), authentication (`wevtutil`/`journalctl`), and network bridge. |
| **Phase 2** | Detection & Anomaly Reasoning | **Foundation Complete** | Explainable detectors (`AuthFailureBurstDetector`, `FileChangeBurstDetector`, `NetworkRateDetector`, `NewProcessWithNetworkDetector`) generating evidence-linked `Finding` objects. |
| **Phase 3** | Investigation & Root-Cause Localization | **Foundation Complete** | Temporal `Timeline` filtering, graph `CorrelationIndex` (process trees, entity mapping), and deterministic `EventAnalysis` with forensic terminal formatting. |
| **Phase 4** | Mitigation Planning & Sandbox Verification | **Planned** | Verification sandbox orchestration, candidate fix ranking, isolated patch testing. |
| **Phase 5** | Human-Reviewed Response Workflow | **Planned** | Approval-gated RBAC service, signed response plan executor, human verification dashboard. |
| **Phase 6** | Enterprise Integration & Scale | **Planned** | Distributed fleet orchestration, SIEM integrations, continuous packaging/deployment. |


## Monthly sequence
- Month 1: product understanding and architecture
- Month 2: Linux and systems fundamentals
- Month 3: networking observability
- Month 4: offensive security lab
- Month 5: observation engine
- Month 6: detection engine
- Month 7: investigation engine
- Month 8: multi-agent reasoning engine
- Month 9: verification sandbox
- Month 10: dashboard and approvals
- Month 11: integrated MVP
- Month 12: startup-grade demonstration

## Release gates
Every milestone must pass product, architecture, safety, and validation gates before being treated as complete.

## Deferral strategy
Some capabilities belong in future platform evolution, including broad cloud orchestration, wider operating system support, and highly autonomous remediation. These should be explicitly identified as future work, not hidden scope creep.

## Why this matters
The roadmap must be proof-driven. Each phase should produce a demo or measurable product signal rather than a pile of exploratory experiments.
