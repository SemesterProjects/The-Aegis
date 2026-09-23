"""Durable local evidence store with an independently verifiable hash chain."""
from __future__ import annotations

from contextlib import contextmanager
from datetime import datetime
import hashlib
import json
from pathlib import Path
import sqlite3
import threading
from typing import Iterator

from .models import Event, Finding


class EvidenceStore:
    """SQLite evidence sink; callers own encryption-at-rest and retention policy."""
    def __init__(self, path: Path) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        self._connection = sqlite3.connect(path, check_same_thread=False)
        self._connection.row_factory = sqlite3.Row
        self._closed = False
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
            """)

    def close(self) -> None:
        with self._lock:
            if not self._closed:
                self._connection.close()
                self._closed = True

    @property
    def is_closed(self) -> bool:
        with self._lock:
            return self._closed

    def count_events(self) -> int:
        with self._lock:
            row = self._connection.execute("SELECT count(*) AS cnt FROM events").fetchone()
            return int(row["cnt"]) if row else 0

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

    def recent_events(self, since: datetime) -> list[Event]:
        with self._lock:
            rows = self._connection.execute("SELECT payload FROM events WHERE observed_at >= ? ORDER BY sequence", (since.isoformat(),)).fetchall()
        # Deliberately return canonical dictionaries at API boundaries in the future;
        # detection gets live events directly to avoid unsafe implicit deserialisation.
        return [json.loads(row["payload"]) for row in rows]  # type: ignore[return-value]

    @contextmanager
    def _transaction(self) -> Iterator[sqlite3.Connection]:
        with self._lock:
            with self._connection:
                yield self._connection
