# Aegis Agent Handoff Specifications

This document defines the interface boundaries and handoff contracts between the pipeline stages:

```text
Collectors -> Canonical Events -> EvidenceStore -> DetectionPipeline -> TriageEngine
           -> InvestigationCase -> InvestigationAgent -> InvestigationResult
           -> ResponseAgent -> ResponsePolicy Gate -> ExecutionAdapter -> OutcomeVerifier
```

---

## 1. Triage to Investigation Agent Handoff

The input to the **Investigation Agent** is an `InvestigationCase`, never raw telemetry.

```python
from pathlib import Path
from aegis_core.storage import EvidenceStore
store = EvidenceStore(Path("aegis-data") / "evidence.sqlite3")
case = store.get_case_by_id("INC-...")
evidence = store.query_events_for_case(case["case_id"])
```

### Operational Entry Point
```powershell
py -m aegis_core investigate run --case-id INC-... --data-dir <data-dir>
```

The command atomically claims a `NEW` case as `INVESTIGATING`, retrieves surrounding evidence with read-only tools, correlates, classifies (`BENIGN`, `SUSPICIOUS`, `MALICIOUS`, `UNKNOWN`), maps observed behavior, and persists one idempotent `InvestigationResult` in `investigation_results`.

The Investigation Agent is strictly **read-only**: it never modifies host state and never executes remediation. Its `recommended_actions` are human advisories, not execution authorization.

---

## 2. Investigation to Response Agent Handoff

The input to the **Response Agent** is a completed `InvestigationResult` and its corresponding `InvestigationCase`.

```python
from pathlib import Path
from aegis_core.storage import EvidenceStore
from aegis_core.response.agent import ResponseAgent

store = EvidenceStore(Path("aegis-data") / "evidence.sqlite3")
agent = ResponseAgent(store)

# Phase A-D: Generate policy-gated plan
plan = agent.plan("INC-...")
```

### Operational Entry Point
```powershell
py -m aegis_core respond plan --case-id INC-... --data-dir <data-dir>
```

### Handoff Invariants
1. **Evidence Provenance**: The Response Agent consumes existing persisted investigation results. It never fabricates evidence or rerun investigations unnecessarily.
2. **Terminal Status Required**: Only investigations with status `COMPLETE` or `PARTIAL` may be planned. Investigations ending in `ERROR` prohibit all containment actions.
3. **Identifier Consistency**: The `case_id` of the investigation result must match the case identifier in `investigation_cases`.
4. **Advisory Interpretation**: `recommended_actions` from the investigation result are interpreted as candidate proposals, never as direct execution commands.
5. **Policy & Approval Gate**: No disruptive action (process termination, file quarantine, network block, host isolation) may execute without satisfying centralized safety invariants and explicit, recorded human approval.
6. **Dry-Run by Default**: All actions default to safe simulation. Live execution requires explicit configuration (`dry_run=False`) and authorization.
