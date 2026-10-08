"""Durable local evidence store with an independently verifiable hash chain."""
from __future__ import annotations

from contextlib import contextmanager
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import sqlite3
import threading
from typing import Any, Iterator

from .models import Event, Finding
from .triage import InvestigationCase


class EvidenceStore:
    """SQLite evidence sink; callers own encryption-at-rest and retention policy."""
    def __init__(self, path: Path) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        self._connection = sqlite3.connect(path, check_same_thread=False)
        self._connection.row_factory = sqlite3.Row
        self._lock = threading.RLock()
        with self._connection:
            self._connection.executescript("""
            PRAGMA journal_mode=WAL;
            PRAGMA foreign_keys=ON;
            CREATE TABLE IF NOT EXISTS events (
              sequence INTEGER PRIMARY KEY AUTOINCREMENT, event_id TEXT UNIQUE NOT NULL,
              observed_at TEXT NOT NULL, kind TEXT NOT NULL, source TEXT NOT NULL,
              host_id TEXT NOT NULL, payload TEXT NOT NULL, previous_hash TEXT NOT NULL,
              record_hash TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS findings (
              finding_id TEXT PRIMARY KEY, created_at TEXT NOT NULL, severity TEXT NOT NULL,
              payload TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS investigation_cases (
              case_id TEXT PRIMARY KEY, created_at TEXT NOT NULL, updated_at TEXT NOT NULL,
              severity TEXT NOT NULL, status TEXT NOT NULL, host_id TEXT NOT NULL,
              risk_score REAL NOT NULL, payload TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS investigation_results (
              case_id TEXT PRIMARY KEY, investigation_id TEXT UNIQUE NOT NULL,
              created_at TEXT NOT NULL, updated_at TEXT NOT NULL,
              status TEXT NOT NULL, payload TEXT NOT NULL
            );
            CREATE INDEX IF NOT EXISTS idx_events_observed_at ON events(observed_at);
            CREATE INDEX IF NOT EXISTS idx_events_kind ON events(kind);
            CREATE INDEX IF NOT EXISTS idx_findings_created_at ON findings(created_at);
            CREATE INDEX IF NOT EXISTS idx_cases_created_at ON investigation_cases(created_at);
            CREATE INDEX IF NOT EXISTS idx_cases_status ON investigation_cases(status);
            CREATE INDEX IF NOT EXISTS idx_cases_host_id ON investigation_cases(host_id);
            """)
        with self._lock:
            row = self._connection.execute("SELECT record_hash FROM events ORDER BY sequence DESC LIMIT 1").fetchone()
        self._chain_tail = row["record_hash"] if row else "0" * 64

    def close(self) -> None:
        with self._lock:
            self._connection.close()

    def append_event(self, event: Event) -> None:
        self.append_events((event,))

    def append_events(self, events: Iterator[Event] | list[Event] | tuple[Event, ...]) -> None:
        """Append a collector batch atomically while retaining the hash chain."""
        with self._transaction() as connection:
            for event in events:
                payload = json.dumps(event.canonical(), sort_keys=True, separators=(",", ":"))
                previous_hash = self._chain_tail
                record_hash = hashlib.sha256((previous_hash + payload).encode("utf-8")).hexdigest()
                cursor = connection.execute("""INSERT OR IGNORE INTO events
                    (event_id, observed_at, kind, source, host_id, payload, previous_hash, record_hash)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
                    (event.event_id, event.observed_at.isoformat(), event.kind.value, event.source,
                     event.host_id, payload, previous_hash, record_hash))
                if cursor.rowcount:
                    self._chain_tail = record_hash

    def append_finding(self, finding: Finding) -> None:
        payload = json.dumps(finding.canonical(), sort_keys=True, separators=(",", ":"))
        with self._transaction() as connection:
            connection.execute("INSERT OR IGNORE INTO findings VALUES (?, ?, ?, ?)",
                               (finding.finding_id, finding.created_at.isoformat(), finding.severity.value, payload))

    def append_case(self, case: InvestigationCase) -> None:
        payload = json.dumps(case.canonical(), sort_keys=True, separators=(",", ":"))
        with self._transaction() as connection:
            connection.execute(
                "INSERT OR REPLACE INTO investigation_cases "
                "(case_id, created_at, updated_at, severity, status, host_id, risk_score, payload) "
                "VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                (case.case_id, case.created_at.isoformat(), case.updated_at.isoformat(),
                 case.severity, case.status.value, case.host_id, case.risk_score, payload),
            )

    def get_case_by_id(self, case_id: str) -> dict[str, Any] | None:
        with self._lock:
            row = self._connection.execute(
                "SELECT payload FROM investigation_cases WHERE case_id = ?", (case_id,)
            ).fetchone()
            return json.loads(row["payload"]) if row else None

    def query_cases(self, status: str | None = None, host_id: str | None = None, limit: int = 200) -> list[dict[str, Any]]:
        query = "SELECT payload FROM investigation_cases WHERE 1=1"
        params: list[Any] = []
        if status is not None:
            query += " AND status = ?"
            params.append(status)
        if host_id is not None:
            query += " AND host_id = ?"
            params.append(host_id)
        query += " ORDER BY created_at DESC LIMIT ?"
        params.append(limit)
        with self._lock:
            rows = self._connection.execute(query, params).fetchall()
        return [json.loads(row["payload"]) for row in rows]

    def count_cases(self, status: str | None = None) -> int:
        query = "SELECT COUNT(*) AS c FROM investigation_cases"
        params: list[Any] = []
        if status is not None:
            query += " WHERE status = ?"
            params.append(status)
        with self._lock:
            row = self._connection.execute(query, params).fetchone()
        return int(row["c"]) if row else 0

    def claim_case(self, case_id: str) -> dict[str, Any] | None:
        """Atomically claim a NEW case for one investigation worker."""
        with self._transaction() as connection:
            row = connection.execute(
                "SELECT payload FROM investigation_cases WHERE case_id = ? AND status = 'NEW'",
                (case_id,),
            ).fetchone()
            if row is None:
                return None
            payload = json.loads(row["payload"])
            payload["status"] = "INVESTIGATING"
            payload["updated_at"] = datetime.now(timezone.utc).isoformat()
            connection.execute(
                "UPDATE investigation_cases SET status = ?, updated_at = ?, payload = ? "
                "WHERE case_id = ? AND status = 'NEW'",
                ("INVESTIGATING", payload["updated_at"],
                 json.dumps(payload, sort_keys=True, separators=(",", ":")), case_id),
            )
            return payload

    def update_case_status(self, case_id: str, status: str) -> bool:
        """Update a persisted case status without changing its evidence references."""
        with self._transaction() as connection:
            row = connection.execute(
                "SELECT payload FROM investigation_cases WHERE case_id = ?", (case_id,)
            ).fetchone()
            if row is None:
                return False
            payload = json.loads(row["payload"])
            updated_at = datetime.now(timezone.utc).isoformat()
            payload["status"] = status
            payload["updated_at"] = updated_at
            connection.execute(
                "UPDATE investigation_cases SET status = ?, updated_at = ?, payload = ? "
                "WHERE case_id = ?",
                (status, updated_at,
                 json.dumps(payload, sort_keys=True, separators=(",", ":")), case_id),
            )
            return True

    def append_investigation_result(self, result: Any) -> None:
        """Persist a structured result idempotently by case ID."""
        payload = json.dumps(result.canonical(), sort_keys=True, separators=(",", ":"))
        now = datetime.now(timezone.utc).isoformat()
        with self._transaction() as connection:
            connection.execute(
                "INSERT OR REPLACE INTO investigation_results "
                "(case_id, investigation_id, created_at, updated_at, status, payload) "
                "VALUES (?, ?, COALESCE((SELECT created_at FROM investigation_results WHERE case_id = ?), ?), ?, ?, ?)",
                (result.case_id, result.investigation_id, result.case_id, now, now,
                 result.status.value, payload),
            )

    def get_investigation_result(self, case_id: str) -> dict[str, Any] | None:
        """Return the persisted result for a case, if one exists."""
        with self._lock:
            row = self._connection.execute(
                "SELECT payload FROM investigation_results WHERE case_id = ?", (case_id,)
            ).fetchone()
        return json.loads(row["payload"]) if row else None

    def query_investigation_results(self, limit: int = 200) -> list[dict[str, Any]]:
        with self._lock:
            rows = self._connection.execute(
                "SELECT payload FROM investigation_results ORDER BY updated_at DESC LIMIT ?",
                (limit,),
            ).fetchall()
        return [json.loads(row["payload"]) for row in rows]
    def latest_event_time(self) -> str | None:
        with self._lock:
            row = self._connection.execute("SELECT observed_at FROM events ORDER BY sequence DESC LIMIT 1").fetchone()
        return str(row["observed_at"]) if row else None
    def verify_chain(self) -> bool:
        previous = "0" * 64
        with self._lock:
            rows = self._connection.execute("SELECT payload, previous_hash, record_hash FROM events ORDER BY sequence").fetchall()
        for row in rows:
            if row["previous_hash"] != previous:
                return False
            expected = hashlib.sha256((previous + row["payload"]).encode("utf-8")).hexdigest()
            if expected != row["record_hash"]:
                return False
            previous = row["record_hash"]
        return True

    def recent_events(self, since: datetime) -> list[dict]:
        with self._lock:
            rows = self._connection.execute(
                "SELECT payload FROM events WHERE observed_at >= ? ORDER BY sequence",
                (since.isoformat(),)
            ).fetchall()
        return [json.loads(row["payload"]) for row in rows]

    # ------------------------------------------------------------------
    # Rich query API (added for Timeline and CorrelationIndex)
    # ------------------------------------------------------------------

    def query_events(
        self,
        since: datetime | None = None,
        until: datetime | None = None,
        kinds: list[str] | None = None,
        sources: list[str] | None = None,
        host_ids: list[str] | None = None,
        run_id: str | None = None,
        action: str | None = None,
        pid: int | None = None,
        limit: int | None = None,
        offset: int = 0,
    ) -> list[dict]:
        """Query events with filters. Returns list of canonical dicts ordered by sequence ASC.

        Filters action and pid via SQLite json_extract() on SQLite >= 3.38.0,
        otherwise falls back to Python-side filtering.
        """
        query = "SELECT payload FROM events WHERE 1=1"
        params: list[Any] = []

        if since is not None:
            query += " AND observed_at >= ?"
            params.append(since.isoformat())
        if until is not None:
            query += " AND observed_at <= ?"
            params.append(until.isoformat())
        if kinds:
            placeholders = ",".join("?" * len(kinds))
            query += f" AND kind IN ({placeholders})"
            params.extend(kinds)
        if sources:
            placeholders = ",".join("?" * len(sources))
            query += f" AND source IN ({placeholders})"
            params.extend(sources)
        if host_ids:
            placeholders = ",".join("?" * len(host_ids))
            query += f" AND host_id IN ({placeholders})"
            params.extend(host_ids)
        if run_id is not None:
            query += " AND json_extract(payload, '$.run_id') = ?"
            params.append(run_id)

        # Use json_extract for action/pid on sufficiently new SQLite
        use_json_extract = sqlite3.sqlite_version_info >= (3, 38, 0)
        if use_json_extract:
            if action is not None:
                query += " AND json_extract(payload, '$.data.action') = ?"
                params.append(action)
            if pid is not None:
                query += " AND CAST(json_extract(payload, '$.data.pid') AS INTEGER) = ?"
                params.append(pid)

        query += " ORDER BY observed_at ASC, sequence ASC"
        if limit is not None:
            query += " LIMIT ? OFFSET ?"
            params.extend([limit, offset])
        elif offset:
            query += " LIMIT -1 OFFSET ?"
            params.append(offset)

        with self._lock:
            rows = self._connection.execute(query, params).fetchall()

        events = [json.loads(row["payload"]) for row in rows]

        # Python-side fallback filter for older SQLite
        if not use_json_extract and (action is not None or pid is not None):
            filtered = []
            for ev in events:
                data = ev.get("data", {})
                if action is not None and data.get("action") != action:
                    continue
                if pid is not None and data.get("pid") != pid:
                    continue
                filtered.append(ev)
            events = filtered

        return events

    def count_events(
        self,
        since: datetime | None = None,
        kinds: list[str] | None = None,
        run_id: str | None = None,
    ) -> int:
        """Return count of matching events."""
        query = "SELECT COUNT(*) AS c FROM events WHERE 1=1"
        params: list[Any] = []
        if since is not None:
            query += " AND observed_at >= ?"
            params.append(since.isoformat())
        if kinds:
            placeholders = ",".join("?" * len(kinds))
            query += f" AND kind IN ({placeholders})"
            params.extend(kinds)
        if run_id is not None:
            query += " AND json_extract(payload, '$.run_id') = ?"
            params.append(run_id)
        with self._lock:
            row = self._connection.execute(query, params).fetchone()
            return int(row["c"]) if row else 0

    def get_findings(
        self,
        since: datetime | None = None,
        severity: str | None = None,
        run_id: str | None = None,
        limit: int | None = 200,
    ) -> list[dict]:
        """Return findings as canonical dicts ordered by created_at DESC."""
        query = "SELECT payload FROM findings WHERE 1=1"
        params: list[Any] = []
        if since is not None:
            query += " AND created_at >= ?"
            params.append(since.isoformat())
        if severity is not None:
            query += " AND severity = ?"
            params.append(severity)
        if run_id is not None:
            query += " AND json_extract(payload, '$.run_id') = ?"
            params.append(run_id)
        query += " ORDER BY created_at DESC"
        if limit is not None:
            query += " LIMIT ?"
            params.append(limit)
        with self._lock:
            rows = self._connection.execute(query, params).fetchall()
            return [json.loads(row["payload"]) for row in rows]

    def get_event_by_id(self, event_id: str) -> dict | None:
        """Return a single event canonical dict by event_id, or None."""
        with self._lock:
            row = self._connection.execute(
                "SELECT payload FROM events WHERE event_id = ?", (event_id,)
            ).fetchone()
            return json.loads(row["payload"]) if row else None

    def query_events_for_case(self, case_id: str) -> list[dict[str, Any]]:
        """Resolve a case's immutable evidence references in time order."""
        case = self.get_case_by_id(case_id)
        if case is None:
            return []
        ids = [str(item) for item in case.get("event_ids", [])]
        if not ids:
            return []
        placeholders = ",".join("?" * len(ids))
        with self._lock:
            rows = self._connection.execute(
                f"SELECT payload FROM events WHERE event_id IN ({placeholders}) ORDER BY observed_at, sequence", ids
            ).fetchall()
        return [json.loads(row["payload"]) for row in rows]

    @contextmanager
    def _transaction(self) -> Iterator[sqlite3.Connection]:
        with self._lock:
            with self._connection:
                yield self._connection


