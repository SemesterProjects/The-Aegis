"""Cross-signal correlation index for Aegis Core.

Maintains an in-memory index linking process, file, network, and auth
events by PID, file path, and remote IP. Enables investigation queries
without full table scans against the EvidenceStore.

Usage patterns:
    # Live ingestion (called from engine._ingest or directly):
    index = CorrelationIndex()
    index.ingest(event_dict)

    # Build from existing store (for post-facto investigation):
    index.build_from_store(store, since=datetime.now(tz=...) - timedelta(hours=1))

    # Query:
    index.get_process_tree(pid=1234)
    index.suspicious_process_network_pairs()
"""
from __future__ import annotations

from collections import defaultdict
from datetime import datetime, timezone
from typing import Any

from .models import EventKind
from .storage import EvidenceStore


class CorrelationIndex:
    """In-memory cross-signal correlation index.

    Thread-safety: NOT thread-safe. Callers must serialize access if
    ingest() and query methods are called from multiple threads.
    """

    def __init__(self, max_events_per_key: int = 500) -> None:
        # pid (int) -> list of ALL event dicts for that PID (all kinds)
        self._by_pid: dict[int, list[dict]] = defaultdict(list)
        # path (str) -> list of FILE event dicts
        self._by_path: dict[str, list[dict]] = defaultdict(list)
        # remote_ip (str) -> list of NETWORK event dicts
        self._by_remote_ip: dict[str, list[dict]] = defaultdict(list)
        # ppid -> list of child pids observed
        self._children: dict[int, list[int]] = defaultdict(list)
        # pid -> latest process metadata dict (from last PROCESS event for that pid)
        self._process_info: dict[int, dict] = {}
        self._max_per_key = max_events_per_key

    # ------------------------------------------------------------------
    # Ingestion
    # ------------------------------------------------------------------

    def ingest(self, event: dict) -> None:
        """Add a single canonical event dict to the index.

        Operates on the canonical dict form (as returned by Event.canonical()
        or EvidenceStore.query_events()), NOT on Event objects.
        """
        data = event.get("data") or {}
        kind = event.get("kind")
        pid_raw = data.get("pid")
        pid: int | None = int(pid_raw) if pid_raw is not None else None
        ppid_raw = data.get("ppid")
        ppid: int | None = int(ppid_raw) if ppid_raw is not None else None

        # Index by PID for any event that carries a PID
        if pid is not None:
            bucket = self._by_pid[pid]
            bucket.append(event)
            if len(bucket) > self._max_per_key:
                bucket.pop(0)  # drop oldest to bound memory

            # Track latest process metadata
            if kind == EventKind.PROCESS.value:
                self._process_info[pid] = event

            # Track parent → child relationship
            if ppid is not None and pid not in self._children[ppid]:
                self._children[ppid].append(pid)

        # Index file events by path
        if kind == EventKind.FILE.value:
            path = data.get("path")
            if path:
                bucket = self._by_path[str(path)]
                bucket.append(event)
                if len(bucket) > self._max_per_key:
                    bucket.pop(0)

        # Index network events by remote_ip
        if kind == EventKind.NETWORK.value:
            remote_ip = data.get("remote_ip")
            if remote_ip:
                bucket = self._by_remote_ip[str(remote_ip)]
                bucket.append(event)
                if len(bucket) > self._max_per_key:
                    bucket.pop(0)

    def build_from_store(
        self,
        store: EvidenceStore,
        since: datetime | None = None,
    ) -> None:
        """Rebuild index from all events in the store since datetime."""
        events = store.query_events(since=since, limit=100_000)
        for ev in events:
            self.ingest(ev)

    # ------------------------------------------------------------------
    # Process queries
    # ------------------------------------------------------------------

    def get_events_for_pid(self, pid: int) -> list[dict]:
        """All events attributed to a PID, ordered by ingestion order."""
        return list(self._by_pid.get(pid, []))

    def get_process_info(self, pid: int) -> dict | None:
        """Last known process metadata dict for a PID (from PROCESS events)."""
        info_event = self._process_info.get(pid)
        if info_event is None:
            return None
        return info_event.get("data") or {}

    def get_network_for_pid(self, pid: int) -> list[dict]:
        """Network events attributed to a PID."""
        return [e for e in self._by_pid.get(pid, []) if e.get("kind") == EventKind.NETWORK.value]

    def get_files_for_pid(self, pid: int) -> list[dict]:
        """File events attributed to a PID."""
        return [e for e in self._by_pid.get(pid, []) if e.get("kind") == EventKind.FILE.value]

    def get_child_pids(self, ppid: int) -> list[int]:
        """Direct child PIDs of a parent PID."""
        return list(self._children.get(ppid, []))

    def get_process_tree(self, pid: int, max_depth: int = 5) -> dict[str, Any]:
        """Recursive process tree from a root PID.

        Returns:
            {pid, name, exe, children: [...], network_events: N, file_events: N}
        """
        info = self.get_process_info(pid) or {}
        tree: dict[str, Any] = {
            "pid": pid,
            "name": info.get("name"),
            "exe": info.get("exe"),
            "user": info.get("user"),
            "children": [],
            "network_events": len(self.get_network_for_pid(pid)),
            "file_events": len(self.get_files_for_pid(pid)),
        }
        if max_depth > 0:
            for child_pid in self.get_child_pids(pid):
                tree["children"].append(self.get_process_tree(child_pid, max_depth - 1))
        return tree

    # ------------------------------------------------------------------
    # File / network queries
    # ------------------------------------------------------------------

    def get_events_for_path(self, path: str, exact: bool = False) -> list[dict]:
        """File events for a path.

        By default performs substring matching across all indexed paths.
        Set exact=True to require an exact path match.
        """
        if exact:
            return list(self._by_path.get(path, []))
        result = []
        for indexed_path, evs in self._by_path.items():
            if path in indexed_path:
                result.extend(evs)
        return result

    def get_events_for_remote_ip(self, ip: str) -> list[dict]:
        """Network events for a remote IP address."""
        return list(self._by_remote_ip.get(ip, []))

    # ------------------------------------------------------------------
    # Cross-signal detection aids
    # ------------------------------------------------------------------

    def suspicious_process_network_pairs(self) -> list[dict[str, Any]]:
        """Return PIDs with both file-modification activity AND outbound network connections.

        This pattern is consistent with data exfiltration or ransomware + C2.
        Returns a list of dicts:
            {pid, name, exe, file_events: N, network_events: N, evidence: {...}}
        """
        results = []
        for pid in self._by_pid:
            net_events = self.get_network_for_pid(pid)
            file_events = self.get_files_for_pid(pid)

            has_outbound_net = any(
                e.get("data", {}).get("direction") in ("outbound", "OUTBOUND")
                for e in net_events
            )
            has_file_write = any(
                e.get("data", {}).get("action") in ("modify", "create", "delete")
                for e in file_events
            )

            if has_outbound_net and has_file_write:
                info = self.get_process_info(pid) or {}
                results.append({
                    "pid": pid,
                    "name": info.get("name"),
                    "exe": info.get("exe"),
                    "file_events": len(file_events),
                    "network_events": len(net_events),
                    "evidence": {
                        "network_sample": [e.get("event_id") for e in net_events[:5]],
                        "file_sample": [e.get("event_id") for e in file_events[:5]],
                    },
                })
        return results

    # ------------------------------------------------------------------
    # Stats
    # ------------------------------------------------------------------

    def stats(self) -> dict[str, Any]:
        """Summary statistics about the current index state."""
        return {
            "tracked_pids": len(self._by_pid),
            "tracked_paths": len(self._by_path),
            "tracked_remote_ips": len(self._by_remote_ip),
            "known_process_infos": len(self._process_info),
            "parent_child_edges": sum(len(v) for v in self._children.values()),
        }
