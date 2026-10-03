# Investigation Agent Handoff

Start here. Your input is an `InvestigationCase`, not raw Windows/Linux/macOS telemetry.

```python
from pathlib import Path
from aegis_core.storage import EvidenceStore
store = EvidenceStore(Path("aegis-data") / "evidence.sqlite3")
case = store.get_case_by_id("INC-...")
evidence = store.query_events_for_case(case["case_id"])
```

Implement: retrieve case/evidence, query surrounding evidence with `query_events`, correlate, classify, map observed behavior, and persist an InvestigationResult under `reports/investigations/<case_id>/`. Do not modify `Event`, `InvestigationCase`, collectors, evidence tables, or case lifecycle semantics. Do not execute remediation.

Current production boundary: events, findings, cases, and evidence queries are local SQLite data. The data directory is selected by the monitoring command; default is `./aegis-data`.
