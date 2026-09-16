# Data and Event Model

## Purpose
Aegis must reason over a canonical set of events, evidence, and actions. The platform needs a consistent data model so that detection, investigation, mitigation, and audit all operate against the same semantics.

## Core entities
- Event: any observed runtime or system signal
- Evidence: a fact that supports or refutes a hypothesis
- Incident: a tracked security-relevant investigation
- Context: the application, host, and environment state surrounding an event
- Mitigation candidate: a proposed fix ranked by safety and likelihood
- Approval record: the human review result for a critical action
- Action log: the runtime record of enacted response steps

## Model principles
- Every event must carry provenance and timestamp
- Every conclusion must reference supporting evidence
- Every mitigation must include trade-offs and confidence
- Every production action must be audit logged

## Why this matters
Without a shared event model, the platform cannot reason coherently across detection, investigation, and remediation.
