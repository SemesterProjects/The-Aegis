# Investigation Agent Handoff

Start here. Your input is an `InvestigationCase`, not raw Windows/Linux/macOS telemetry.

```python
from pathlib import Path
from aegis_core.storage import EvidenceStore
store = EvidenceStore(Path("aegis-data") / "evidence.sqlite3")
case = store.get_case_by_id("INC-...")
evidence = store.query_events_for_case(case["case_id"])
```

The operational entry point is:

```powershell
py -m aegis_core investigate run --case-id INC-... --data-dir <data-dir>
```

The command atomically claims a `NEW` case as `INVESTIGATING`, retrieves the
case/evidence, queries surrounding evidence with read-only tools, correlates,
classifies, maps observed behavior, and persists one idempotent
`InvestigationResult` in `investigation_results`. It then records the final
case status. Do not modify `Event`, collectors, evidence references, or
execute remediation.

Current production boundary: events, findings, cases, results, and evidence
queries are local SQLite data. The data directory is selected by the
monitoring command; default is `./aegis-data`. A future reporting surface may
export results under `reports/investigations/<case_id>/`.
