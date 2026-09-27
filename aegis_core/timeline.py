"""Chronological event timeline built on top of EvidenceStore.

Provides investigation-ready queries so the future reasoning agent
does not need to reconstruct basic chronology from raw SQL.
"""
from __future__ import annotations

from datetime import datetime, timedelta, timezone

from .models import EventKind
from .storage import EvidenceStore


class Timeline:
    """Query interface over the EvidenceStore with investigator-friendly methods.

    All time parameters accept UTC-aware datetimes. Methods returning lists
    order by source observation time ASC, with store sequence as a deterministic
    tie-breaker.
    """

    def __init__(self, store: EvidenceStore) -> None:
        self._store = store

    # ------------------------------------------------------------------
    # Core queries
    # ------------------------------------------------------------------

    def recent(self, seconds: float = 300, limit: int | None = None) -> list[dict]:
        """Return events from the last N seconds, ordered by observation time ASC."""
        since = datetime.now(timezone.utc) - timedelta(seconds=seconds)
        return self._store.query_events(since=since, limit=limit)

    def range(
        self,
        since: datetime,
        until: datetime | None = None,
        kinds: list[str] | None = None,
        limit: int | None = None,
    ) -> list[dict]:
        """Return events in a time range, optionally filtered by kind."""
        return self._store.query_events(
            since=since, until=until, kinds=kinds, limit=limit
        )

    # ------------------------------------------------------------------
    # Entity-focused queries
    # ------------------------------------------------------------------

    def process_timeline(self, pid: int, window_seconds: float = 300) -> list[dict]:
        """All events attributed to a PID in the recent window.

        Covers PROCESS events with matching pid AND NETWORK/FILE events
        where data.pid matches — giving a full picture of a process's activity.
        """
        since = datetime.now(timezone.utc) - timedelta(seconds=window_seconds)
        return self._store.query_events(since=since, pid=pid)

    def file_timeline(self, path: str, window_seconds: float = 300) -> list[dict]:
        """All file events for a path substring in the recent window."""
        since = datetime.now(timezone.utc) - timedelta(seconds=window_seconds)
        events = self._store.query_events(
            since=since,
            kinds=[EventKind.FILE.value],
        )
        # Substring filter — covers both exact paths and parent directory queries
        return [e for e in events if path in str(e.get("data", {}).get("path", ""))]

    def network_timeline(
        self,
        remote_ip: str | None = None,
        pid: int | None = None,
        limit: int | None = None,
    ) -> list[dict]:
        """Network events, optionally filtered by remote IP or PID."""
        events = self._store.query_events(
            kinds=[EventKind.NETWORK.value],
            pid=pid,
        )
        if remote_ip:
            events = [
                e for e in events
                if e.get("data", {}).get("remote_ip") == remote_ip
            ]
        return events if limit is None else events[:limit]

    def auth_timeline(self, window_seconds: float = 3600) -> list[dict]:
        """Authentication events in the recent window."""
        since = datetime.now(timezone.utc) - timedelta(seconds=window_seconds)
        return self._store.query_events(
            since=since,
            kinds=[EventKind.AUTHENTICATION.value],
        )

    def findings_timeline(self, window_seconds: float = 3600) -> list[dict]:
        """Findings in the recent window, newest first."""
        since = datetime.now(timezone.utc) - timedelta(seconds=window_seconds)
        return self._store.get_findings(since=since, limit=500)

    # ------------------------------------------------------------------
    # Summary
    # ------------------------------------------------------------------

    def summary(self, window_seconds: float = 300) -> dict:
        """Summary event counts by kind for the recent window."""
        since = datetime.now(timezone.utc) - timedelta(seconds=window_seconds)
        kinds = [k.value for k in EventKind]
        counts: dict[str, int] = {}
        for kind in kinds:
            counts[kind] = self._store.count_events(since=since, kinds=[kind])
        counts["total"] = sum(counts.values())
        counts["findings"] = len(self.findings_timeline(window_seconds))
        return counts
