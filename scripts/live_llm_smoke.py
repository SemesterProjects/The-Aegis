"""Run a live LLM integration check using synthetic Aegis evidence only."""
from __future__ import annotations

import tempfile
from pathlib import Path

from aegis_core.config import load_local_env
from aegis_core.intelligence import IntelligenceService
from aegis_core.investigation.agent import InvestigationAgent
from aegis_core.models import Event, EventKind
from aegis_core.storage import EvidenceStore
from aegis_core.triage import InvestigationCase


def main() -> int:
    load_local_env()
    directory = Path(tempfile.mkdtemp(prefix="aegis-llm-smoke-"))
    store = EvidenceStore(directory / "evidence.sqlite3")
    try:
        event = Event(EventKind.PROCESS, "live-smoke", {"action": "start", "pid": 4242, "name": "synthetic.exe"}, host_id="synthetic-host")
        store.append_event(event)
        case = InvestigationCase(host_id="synthetic-host", severity="high", risk_score=0.7, trigger="LIVE-SMOKE", trigger_event_id=event.event_id, event_ids=(event.event_id,), time_window_start=event.observed_at, time_window_end=event.observed_at, detection_signals=("synthetic",))
        store.append_case(case)
        result = InvestigationAgent(store, intelligence=IntelligenceService.from_environment(enabled=True)).investigate(case.case_id)
        interpretation = result.llm_interpretation
        persisted = store.get_investigation_result(case.case_id)
        print(f"status={interpretation.status.value}")
        print(f"provider={interpretation.provider or 'none'}")
        print(f"model={interpretation.model or 'none'}")
        print(f"grounded_references={len(interpretation.evidence_event_ids)}")
        print(f"persisted={bool(persisted and persisted.get('llm_interpretation'))}")
        if interpretation.failure_reason:
            print(f"failure={interpretation.failure_reason}")
        return 0 if interpretation.status.value == "COMPLETE" else 1
    finally:
        store.close()


if __name__ == "__main__":
    raise SystemExit(main())
