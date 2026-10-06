"""Read-only Investigation Tools — controlled access to Aegis evidence.

Every tool:
  - is read-only (never modifies system state)
  - has a documented input schema (docstring + type hints)
  - has a documented output schema
  - references an actual Aegis data source (EvidenceStore / CorrelationIndex)
  - handles missing telemetry gracefully

PROMPT-INJECTION PROTECTION
----------------------------
All telemetry fields (process names, paths, command lines, DNS names, etc.)
are treated as DATA, not instructions.  Values are extracted into typed
Python structures and never interpolated into executed code or passed to
any evaluator as commands.

IMPORTANT: These tools do NOT support:
  - kill_process
  - delete_file
  - quarantine_file
  - block_network
  - isolate_host
  - arbitrary shell execution
  - any system modification

Missing capabilities are documented as LIMITATION strings rather than
fabricated results.
"""
from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

from ..analysis import Correlator, EventAnalysis, analyze_event
from ..correlation import CorrelationIndex
from ..models import Event, EventKind
from ..storage import EvidenceStore
from ..timeline import Timeline
from ..triage import InvestigationCase


_UNAVAILABLE = "UNAVAILABLE"

# Fields that are attacker-controlled and must ONLY be used as data.
_UNTRUSTED_FIELDS = frozenset({
    "name", "exe", "cmdline", "path", "query_name",
    "process_name", "filename", "remote_ip", "local_ip",
})


def _safe_str(value: Any) -> str:
    """Convert a telemetry value to a safe string label (DATA only)."""
    if value is None:
        return _UNAVAILABLE
    return str(value)[:512]   # bound length; never eval'd


class InvestigationTools:
    """Controlled, read-only investigation tool layer.

    Backed by:
      - EvidenceStore  (SQLite, existing Aegis evidence DB)
      - CorrelationIndex  (in-memory cross-signal index rebuilt from store)
      - Timeline  (existing Aegis timeline query layer)

    Usage:
        tools = InvestigationTools(store)
        case  = tools.get_case(case_id)
        evts  = tools.get_events(case_id)
    """

    def __init__(self, store: EvidenceStore) -> None:
        self._store = store
        self._timeline = Timeline(store)
        # Build in-memory index from full store for post-facto investigation
        self._correlation = CorrelationIndex()
        self._correlation.build_from_store(store)

    # ------------------------------------------------------------------
    # Case retrieval
    # ------------------------------------------------------------------

    def get_case(self, case_id: str) -> dict[str, Any] | None:
        """Return the InvestigationCase canonical dict, or None if not found.

        Input:  case_id: str
        Output: dict (InvestigationCase.canonical()) | None
        Source: EvidenceStore.get_case_by_id()
        """
        return self._store.get_case_by_id(case_id)

    # ------------------------------------------------------------------
    # Event retrieval
    # ------------------------------------------------------------------

    def get_event(self, event_id: str) -> dict[str, Any] | None:
        """Return a single event canonical dict, or None.

        Input:  event_id: str
        Output: dict (Event.canonical()) | None
        Source: EvidenceStore.get_event_by_id()
        """
        return self._store.get_event_by_id(event_id)

    def get_events(self, case_id: str) -> list[dict[str, Any]]:
        """Return all events referenced by a case, in time order.

        Input:  case_id: str
        Output: list[dict]  — empty list if case not found or has no events
        Source: EvidenceStore.query_events_for_case()
        """
        return self._store.query_events_for_case(case_id)

    def get_related_events(
        self,
        event_ids: list[str],
        *,
        window_seconds: float = 60.0,
        kinds: list[str] | None = None,
    ) -> list[dict[str, Any]]:
        """Return events observed near a set of seed events (same host, time window).

        Does NOT invent events.  Returns empty list if no related events found.

        Input:
            event_ids: list of seed event IDs
            window_seconds: time expansion radius
            kinds: optional kind filter (process/file/network/authentication)
        Output: list[dict] — related events ordered by observation time
        Source: EvidenceStore.query_events()
        LIMITATION: cross-host correlation not supported.
        """
        if not event_ids:
            return []

        # Resolve seeds to determine time window and host
        seeds: list[dict[str, Any]] = []
        for eid in event_ids:
            ev = self._store.get_event_by_id(eid)
            if ev:
                seeds.append(ev)
        if not seeds:
            return []

        # Derive time window from seed events
        times = []
        for ev in seeds:
            try:
                times.append(datetime.fromisoformat(str(ev["observed_at"])))
            except (KeyError, ValueError):
                pass
        if not times:
            return []

        min_t = min(times)
        max_t = max(times)
        from datetime import timedelta
        since = min_t - timedelta(seconds=window_seconds)
        until = max_t + timedelta(seconds=window_seconds)

        # Collect host IDs from seeds
        host_ids = list({str(ev.get("host_id", "unknown")) for ev in seeds
                         if ev.get("host_id") and ev.get("host_id") != "unknown"})

        related = self._store.query_events(
            since=since,
            until=until,
            kinds=kinds,
            host_ids=host_ids if host_ids else None,
        )

        # Exclude already-known seeds from result to avoid duplicates
        seed_ids = set(event_ids)
        return [e for e in related if e.get("event_id") not in seed_ids]

    # ------------------------------------------------------------------
    # Process investigation
    # ------------------------------------------------------------------

    def get_process_info(self, pid: int) -> dict[str, Any] | None:
        """Return last-known process metadata for a PID from the correlation index.

        Input:  pid: int
        Output: dict with name/exe/user/ppid/cmdline (fields may be absent)
                | None if PID not observed
        Source: CorrelationIndex.get_process_info()
        LIMITATION: Only processes observed since this index was built.
        """
        info = self._correlation.get_process_info(pid)
        if info is None:
            return None
        # Sanitize: all string values are DATA; wrap with _safe_str
        return {k: _safe_str(v) if isinstance(v, str) else v
                for k, v in info.items()}

    def get_process_tree(self, pid: int, max_depth: int = 4) -> dict[str, Any]:
        """Return recursive process tree rooted at pid.

        Input:  pid: int, max_depth: int (default 4)
        Output: {pid, name, exe, user, children: [...], network_events: N, file_events: N}
        Source: CorrelationIndex.get_process_tree()
        LIMITATION: Reflects only events observed since the index was built.
        """
        return self._correlation.get_process_tree(pid, max_depth)

    def get_events_for_pid(self, pid: int) -> list[dict[str, Any]]:
        """All events (any kind) attributed to a PID.

        Input:  pid: int
        Output: list[dict] ordered by ingestion order
        Source: CorrelationIndex.get_events_for_pid()
        """
        return self._correlation.get_events_for_pid(pid)

    # ------------------------------------------------------------------
    # File investigation
    # ------------------------------------------------------------------

    def get_file_activity(
        self,
        path: str,
        since: datetime | None = None,
        until: datetime | None = None,
    ) -> list[dict[str, Any]]:
        """File events for a path (substring match).

        Input:  path: str (treated as DATA; no shell expansion)
                since / until: optional datetime bounds
        Output: list[dict] FILE events ordered by observation time
        Source: EvidenceStore.query_events() + CorrelationIndex
        LIMITATION: Process attribution for file events depends on pid field
                    presence in the event data; may be absent for some collectors.
        """
        # Use store for time-bounded queries
        events = self._store.query_events(
            since=since,
            until=until,
            kinds=[EventKind.FILE.value],
        )
        # Substring match on path (path value is DATA, never executed)
        return [e for e in events if _safe_str(path) in _safe_str(e.get("data", {}).get("path", ""))]

    def get_files_for_pid(self, pid: int) -> list[dict[str, Any]]:
        """File events attributed to a specific PID.

        Input:  pid: int
        Output: list[dict] FILE events
        Source: CorrelationIndex.get_files_for_pid()
        """
        return self._correlation.get_files_for_pid(pid)

    # ------------------------------------------------------------------
    # Network investigation
    # ------------------------------------------------------------------

    def get_network_activity(
        self,
        pid: int | None = None,
        remote_ip: str | None = None,
        since: datetime | None = None,
        until: datetime | None = None,
    ) -> list[dict[str, Any]]:
        """Network events, optionally filtered by PID and/or remote IP.

        Input:
            pid: optional int
            remote_ip: optional str (treated as DATA)
            since / until: optional datetime bounds
        Output: list[dict] NETWORK events ordered by observation time
        Source: EvidenceStore.query_events() + python-side IP filter
        LIMITATION: DNS-to-IP mapping not automatically resolved.
        DO NOT label IPs malicious without additional Aegis evidence.
        """
        events = self._store.query_events(
            since=since,
            until=until,
            kinds=[EventKind.NETWORK.value],
            pid=pid,
        )
        if remote_ip is not None:
            # remote_ip is DATA; compared literally
            safe_ip = _safe_str(remote_ip)
            events = [e for e in events if e.get("data", {}).get("remote_ip") == safe_ip]
        return events

    def get_network_for_pid(self, pid: int) -> list[dict[str, Any]]:
        """Network events for a specific PID (from correlation index).

        Input:  pid: int
        Output: list[dict] NETWORK events
        Source: CorrelationIndex.get_network_for_pid()
        """
        return self._correlation.get_network_for_pid(pid)

    # ------------------------------------------------------------------
    # Authentication investigation
    # ------------------------------------------------------------------

    def get_auth_activity(
        self,
        since: datetime | None = None,
        until: datetime | None = None,
        user: str | None = None,
    ) -> list[dict[str, Any]]:
        """Authentication events, optionally filtered by user.

        Input:
            since / until: optional datetime bounds
            user: optional str (treated as DATA)
        Output: list[dict] AUTHENTICATION events ordered by observation time
        Source: EvidenceStore.query_events()
        LIMITATION: auth telemetry availability depends on OS and elevation.
        """
        events = self._store.query_events(
            since=since,
            until=until,
            kinds=[EventKind.AUTHENTICATION.value],
        )
        if user is not None:
            safe_user = _safe_str(user)
            events = [e for e in events if e.get("data", {}).get("user") == safe_user]
        return events

    # ------------------------------------------------------------------
    # Timeline construction
    # ------------------------------------------------------------------

    def build_timeline(
        self,
        event_ids: list[str],
    ) -> list[dict[str, Any]]:
        """Construct a chronological timeline from a set of event IDs.

        Every entry references a real event_id — no fabricated entries.

        Input:  event_ids: list[str]
        Output: list of timeline dicts ordered by observed_at ASC:
                {timestamp, event_id, event_kind, description, pid?, process_name?}
        Source: EvidenceStore.get_event_by_id()
        """
        entries = []
        for eid in event_ids:
            ev = self._store.get_event_by_id(eid)
            if ev is None:
                continue
            data = ev.get("data", {})
            kind = str(ev.get("kind", "unknown"))
            ts = str(ev.get("observed_at", ""))
            pid = data.get("pid")
            proc_name = _safe_str(data.get("name") or data.get("process") or "")

            # Build human description from telemetry fields (all are DATA)
            if kind == "process":
                action = _safe_str(data.get("action") or data.get("operation") or "activity")
                desc = f"[PROCESS] {proc_name} (PID {pid}) — {action}"
            elif kind == "file":
                action = _safe_str(data.get("action") or data.get("operation") or "activity")
                path = _safe_str(data.get("path", ""))
                desc = f"[FILE] {action} — {path}"
                if proc_name and proc_name != _UNAVAILABLE:
                    desc += f" (by PID {pid})"
            elif kind == "network":
                action = _safe_str(data.get("action") or "connection")
                remote = _safe_str(data.get("remote_ip", ""))
                rport = _safe_str(data.get("remote_port", ""))
                dest = f"{remote}:{rport}" if remote and rport else remote
                desc = f"[NETWORK] {action} → {dest}"
                if proc_name and proc_name != _UNAVAILABLE:
                    desc += f" (by {proc_name} PID {pid})"
            elif kind == "authentication":
                action = _safe_str(data.get("action", "auth"))
                user = _safe_str(data.get("user", "unknown"))
                desc = f"[AUTH] {action} — user: {user}"
            else:
                desc = f"[{kind.upper()}] event"

            entries.append({
                "timestamp": ts,
                "event_id": eid,
                "event_kind": kind,
                "description": desc,
                "pid": int(pid) if pid is not None else None,
                "process_name": proc_name if proc_name != _UNAVAILABLE else None,
            })

        entries.sort(key=lambda e: e["timestamp"])
        return entries

    # ------------------------------------------------------------------
    # Event analysis
    # ------------------------------------------------------------------

    def analyze_event(self, event_id: str) -> dict[str, Any] | None:
        """Run the existing Aegis EventAnalysis on a stored event.

        Input:  event_id: str
        Output: dict (EventAnalysis attributes) | None if event not found
        Source: aegis_core.analysis.analyze_event()
        """
        ev_dict = self._store.get_event_by_id(event_id)
        if ev_dict is None:
            return None
        try:
            event = Event(
                kind=EventKind(ev_dict["kind"]),
                source=ev_dict["source"],
                data=ev_dict.get("data", {}),
                observed_at=datetime.fromisoformat(str(ev_dict["observed_at"])),
                event_id=ev_dict["event_id"],
                host_id=ev_dict.get("host_id", "unknown"),
                schema_version=ev_dict.get("schema_version", 1),
                run_id=ev_dict.get("run_id", "unknown"),
                ingested_at=datetime.fromisoformat(str(ev_dict.get("ingested_at") or ev_dict["observed_at"])),
            )
            analysis = analyze_event(event)
            return {
                "event_id": analysis.event_id,
                "event_kind": analysis.event_kind,
                "observed_at": analysis.observed_at,
                "host_id": analysis.host_id,
                "source": analysis.source,
                "summary": analysis.summary,
                "subject": analysis.subject,
                "location": analysis.location,
                "actor": analysis.actor,
                "reason": analysis.reason,
                "confidence": analysis.confidence,
            }
        except Exception as exc:
            return {"error": str(exc)[:300], "event_id": event_id}

    # ------------------------------------------------------------------
    # Suspicious pair detection (re-uses existing correlation logic)
    # ------------------------------------------------------------------

    def get_suspicious_process_network_pairs(self) -> list[dict[str, Any]]:
        """Return PIDs exhibiting both file-write and outbound network activity.

        Re-uses CorrelationIndex.suspicious_process_network_pairs().
        DO NOT interpret results as confirmed malware without additional evidence.
        """
        return self._correlation.suspicious_process_network_pairs()
