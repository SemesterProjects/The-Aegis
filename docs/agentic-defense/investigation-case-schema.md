# Investigation Case Schema

`InvestigationCase` is stored in `investigation_cases.payload` and has `schema_version: 1`.

Required populated fields: `case_id`, `created_at`, `updated_at`, `host_id`, `severity`, `risk_score`, `status`, `trigger`, `trigger_event_id`, `event_ids`, `time_window_start`, `time_window_end`, `detection_signals`, `initial_assessment`, `triage_reason`, `source`, and `schema_version`.

Optional-only-when-observed fields: `hostname`, `os`, `related_processes`, `related_files`, `related_network_activity`, `user_context`, `parent_process`, `child_processes`.

Statuses are `NEW`, `QUEUED`, `INVESTIGATING`, `BENIGN`, `SUSPICIOUS`, `MALICIOUS`, `CLOSED`, and `ERROR`. Monitoring produces `NEW`; only the future Investigation Agent/workflow may transition it. Query a case with `EvidenceStore.get_case_by_id(case_id)` and its evidence with `query_events_for_case(case_id)`.
