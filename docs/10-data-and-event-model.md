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

## Canonical Implementation Specification (`aegis_core/models.py`)

The operational contract is implemented as immutable dataclasses in `aegis_core/models.py`:

### Universal Event Model (`Event`)
Every telemetry observation is normalized into an `Event` before persistence:

- `event_id`: Unique identifier (UUID4 string).
- `kind`: Enumeration `EventKind` (`PROCESS`, `NETWORK`, `FILE`, `AUTHENTICATION`, `CONFIGURATION`, `HEALTH`).
- `source`: Subsystem or adapter generating the observation (e.g. `process_lifecycle`, `network_monitor`, `watchdog`).
- `data`: Free-form key-value dictionary containing structured, canonical observation fields (e.g. `action`, `pid`, `exe`, `remote_ip`, `remote_port`, `collection_mechanism`).
- `observed_at`: RFC3339 UTC timestamp when the event occurred on the host.
- `ingested_at`: RFC3339 UTC timestamp when the engine ingested the event.
- `host_id`: Unique persistent identifier of the observed host.
- `schema_version`: String indicating event schema version (currently `"1.0"`).
- `run_id`: UUID isolating the monitoring session.

### Finding Model (`Finding`)
Detectors emit `Finding` records linked directly to supporting evidence:

- `finding_id`: Unique identifier (UUID4 string).
- `title`: Short descriptive title.
- `description`: Human-readable explanation of why the activity is anomalous or suspicious.
- `severity`: Enumeration `Severity` (`INFO`, `LOW`, `MEDIUM`, `HIGH`, `CRITICAL`).
- `confidence`: Float in range `[0.0, 1.0]`.
- `evidence_event_ids`: Non-empty tuple of `event_id` strings providing cryptographic proof.
- `recommended_action`: Plain-text recommendation for human responder.
- `created_at`: UTC timestamp.

### Durability and Tamper-Evidence (`aegis_core/storage.py`)
Events are persisted in SQLite (WAL mode) with an append-only SHA-256 hash chain:
`current_hash = SHA256(previous_hash + event_json)`
The chain integrity is verifiable at any time via `EvidenceStore.verify_chain()`.

## Why this matters
Without a shared event model, the platform cannot reason coherently across detection, investigation, and remediation.
