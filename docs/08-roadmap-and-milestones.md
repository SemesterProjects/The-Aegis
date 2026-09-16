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
