# Aegis Report Storage Contract

Investigation Agent output belongs below this directory. The monitoring and triage layers do not generate final incident reports.

- `incidents/` — approved incident reports.
- `investigations/` — Investigation Agent work products keyed by `case_id`.
- `periodic/` — approved operational summaries.

Never place raw credentials, VM disks, or unredacted sensitive evidence here. Evidence references use `case_id` and immutable `event_id` values in `evidence.sqlite3`.
