# Canonical Event Schema

Every persisted event is JSON with `event_id`, `kind`, `source`, `host_id`, `observed_at` (UTC), `ingested_at` (UTC), `run_id`, `schema_version`, and a `data` object. Unknown source fields are absent, never invented.

| Kind | Confirmed data fields when available |
| --- | --- |
| `process` | `action` (`start`, `exit`, `snapshot`), `pid`, `ppid`, `name`, `exe`, `user`, `cmdline`, `create_time`, `status`, `collection_mechanism` |
| `file` | `action` (`create`, `modify`, `delete`, `move`), `path`, `dest_path`, `size`, `previous_size`, `suffix`, `collection_mechanism` |
| `network` | `action`, `protocol`, `local_ip`, `local_port`, `remote_ip`, `remote_port`, `state`, `direction`, `pid`, `process_name`, `executable_path`, `user`, `interface`, `collection_mechanism` |
| `authentication` | `action`, `user`, `source_ip`, `auth_mechanism`, `message` |
| `health` | `status`/`action`, collector state, capability or failure details |

File-to-process attribution is unavailable in the current watcher/polling implementation. Process exits are snapshot-difference observations and can miss a process that completes between polls. Network snapshots can miss short-lived connections between polls.

Query APIs: `get_event_by_id(id)`, `query_events(since=..., kinds=..., host_ids=..., action=..., pid=..., run_id=...)`, `get_findings()`, `query_cases()`, and `query_events_for_case(case_id)`.
