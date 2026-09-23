"""Durable local evidence store with an independently verifiable hash chain."""
from __future__ import annotations

from contextlib import contextmanager
from datetime import datetime
import hashlib
import json
from pathlib import Path
import sqlite3
import threading
from typing import Any, Iterator

from .models import Event, Finding


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
            CREATE INDEX IF NOT EXISTS idx_events_observed_at ON events(observed_at);
            CREATE INDEX IF NOT EXISTS idx_events_kind ON events(kind);
            CREATE INDEX IF NOT EXISTS idx_findings_created_at ON findings(created_at);
            """)

    def close(self) -> None:
        with self._lock:
            self._connection.close()

    def append_event(self, event: Event) -> None:
        payload = json.dumps(event.canonical(), sort_keys=True, separators=(",", ":"))
        with self._transaction() as connection:
            row = connection.execute("SELECT record_hash FROM events ORDER BY sequence DESC LIMIT 1").fetchone()
            previous_hash = row["record_hash"] if row else "0" * 64
            record_hash = hashlib.sha256((previous_hash + payload).encode("utf-8")).hexdigest()
            connection.execute("""INSERT OR IGNORE INTO events
                (event_id, observed_at, kind, source, host_id, payload, previous_hash, record_hash)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
                (event.event_id, event.observed_at.isoformat(), event.kind.value, event.source,
                 event.host_id, payload, previous_hash, record_hash))

    def append_finding(self, finding: Finding) -> None:
        payload = json.dumps(finding.canonical(), sort_keys=True, separators=(",", ":"))
        with self._transaction() as connection:
            connection.execute("INSERT OR IGNORE INTO findings VALUES (?, ?, ?, ?)",
                               (finding.finding_id, finding.created_at.isoformat(), finding.severity.value, payload))

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
        action: str | None = None,
        pid: int | None = None,
        limit: int = 1000,
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

        # Use json_extract for action/pid on sufficiently new SQLite
        use_json_extract = sqlite3.sqlite_version_info >= (3, 38, 0)
        if use_json_extract:
            if action is not None:
                query += " AND json_extract(payload, '$.data.action') = ?"
                params.append(action)
            if pid is not None:
                query += " AND CAST(json_extract(payload, '$.data.pid') AS INTEGER) = ?"
                params.append(pid)

        query += " ORDER BY sequence ASC LIMIT ? OFFSET ?"
        params.extend([limit, offset])

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
        with self._lock:
            row = self._connection.execute(query, params).fetchone()
            return int(row["c"]) if row else 0

    def get_findings(
        self,
        since: datetime | None = None,
        severity: str | None = None,
        limit: int = 200,
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
        query += " ORDER BY created_at DESC LIMIT ?"
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

    @contextmanager
    def _transaction(self) -> Iterator[sqlite3.Connection]:
        with self._lock:
            with self._connection:
                yield self._connection
