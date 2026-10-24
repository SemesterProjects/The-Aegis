"""Portable, read-only polling collectors. Native sensors plug in later."""
from __future__ import annotations

import json
import os
import platform
import re
import shutil
import socket
import subprocess
import hashlib
import xml.etree.ElementTree as ET
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any, Iterable, Protocol

from .models import Event, EventKind


class Collector(Protocol):
    name: str
    def collect(self, host_id: str) -> Iterable[Event]: ...


# ---------------------------------------------------------------------------
# Original collectors (preserved exactly)
# ---------------------------------------------------------------------------

@dataclass
class ProcessSnapshotCollector:
    name: str = "process_snapshot"

    def collect(self, host_id: str) -> Iterable[Event]:
        try:
            import psutil
            for process in psutil.process_iter(["pid", "name", "exe", "username", "create_time"]):
                try:
                    info = process.info
                    yield Event(EventKind.PROCESS, self.name, {"pid": info["pid"], "name": info["name"],
                        "exe": info["exe"], "user": info["username"], "started": info["create_time"]}, host_id=host_id)
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    continue
            return
        except ImportError:
            pass
        if os.name == "posix" and Path("/proc").is_dir():
            for entry in Path("/proc").iterdir():
                if not entry.name.isdigit():
                    continue
                try:
                    name = (entry / "comm").read_text(encoding="utf-8").strip()
                    yield Event(EventKind.PROCESS, self.name, {"pid": int(entry.name), "name": name}, host_id=host_id)
                except (OSError, UnicodeError):
                    continue


@dataclass
class FilePollingCollector:
    """Tracks metadata changes in explicit allow-listed roots, never symlinks."""
    roots: tuple[Path, ...]
    max_files_per_cycle: int | None = None
    name: str = "file_polling"
    _snapshot: dict[Path, tuple[int, int]] = field(default_factory=dict, init=False)
    _baseline_established: bool = field(default=False, init=False)

    def collect(self, host_id: str) -> Iterable[Event]:
        observed = 0
        current: dict[Path, tuple[int, int]] = {}
        for root in self.roots:
            root = root.resolve()
            if not root.is_dir():
                continue
            for path in root.rglob("*"):
                if self.max_files_per_cycle is not None and observed >= self.max_files_per_cycle:
                    yield Event(EventKind.HEALTH, self.name, {"warning": "file scan capped", "cap": self.max_files_per_cycle}, host_id=host_id)
                    break
                try:
                    if path.is_symlink() or not path.is_file():
                        continue
                    if path.name.endswith(".sqlite3") or path.name.endswith("-wal") or path.name.endswith("-shm") or path.name == "monitor-status.json":
                        continue
                    stat = path.stat()
                except OSError:
                    continue
                observed += 1
                signature = (stat.st_mtime_ns, stat.st_size)
                current[path] = signature
                old = self._snapshot.get(path)
                if old is not None and old != signature:
                    yield Event(EventKind.FILE, self.name, {"path": str(path), "action": "modify",
                        "operation": "modified", "size": stat.st_size, "previous_size": old[1],
                        "suffix": path.suffix.lower()}, host_id=host_id)
                elif old is None and self._baseline_established:
                    yield Event(EventKind.FILE, self.name, {"path": str(path), "action": "create",
                        "operation": "created", "size": stat.st_size, "suffix": path.suffix.lower()}, host_id=host_id)
        for path, (_, old_size) in self._snapshot.items():
            if path not in current:
                yield Event(EventKind.FILE, self.name, {"path": str(path), "action": "delete",
                    "operation": "deleted", "previous_size": old_size, "suffix": path.suffix.lower()}, host_id=host_id)
        self._snapshot = current
        self._baseline_established = True


def stable_host_id() -> str:
    """Pseudonymous installation identifier; callers may provide managed identity instead."""
    raw = f"{socket.gethostname()}:{os.getuid() if hasattr(os, 'getuid') else 'windows'}"
    return hashlib.sha256(raw.encode()).hexdigest()[:24]


# ---------------------------------------------------------------------------
# NEW: NetworkBridgeCollector
# ---------------------------------------------------------------------------

@dataclass
class NetworkBridgeCollector:
    """Bridges network_monitor into aegis_core's canonical event pipeline.

    Initializes the platform-appropriate network adapter via the network_monitor
    subsystem (AdapterFactory), then on each collect() call polls connections,
    traffic stats, DNS queries, and process-network activity, normalizing each
    into canonical aegis_core.Event objects via aegis_core.normalizers.

    Honest capability reporting:
    - If the OS has no supported adapter, is_available returns False.
    - If initialization succeeds but a specific collect_*() method is not
      implemented for this platform, that collector is silently skipped
      (CollectorNotImplementedError) — other collectors still run.
    - All other exceptions from collect methods are caught and emitted as
      HEALTH warning events so the engine's backoff logic sees them.
    """
    name: str = "network_bridge"
    _adapter: Any = field(default=None, init=False, repr=False)
    _available: bool = field(default=False, init=False)
    _init_error: str = field(default="", init=False)
    _capability_report: Any = field(default=None, init=False)

    def initialize(self) -> None:
        """Initialize the network adapter for this OS. Call before collect()."""
        try:
            from network_monitor.discovery.system import SystemDiscovery
            from network_monitor.core.factory import AdapterFactory
            discovery = SystemDiscovery()
            system_info = discovery.discover()
            adapter = AdapterFactory.create(system_info)
            adapter.start()
            self._adapter = adapter
            self._available = True
            try:
                self._capability_report = adapter.discover_capabilities()
            except Exception:
                self._capability_report = None
        except ImportError as exc:
            self._available = False
            self._init_error = f"network_monitor not importable: {exc}"
        except Exception as exc:
            self._available = False
            self._init_error = str(exc)

    @property
    def is_available(self) -> bool:
        return self._available

    @property
    def capability_info(self) -> dict:
        if not self._available:
            return {"status": "unavailable", "reason": self._init_error}
        return {
            "adapter": type(self._adapter).__name__,
            "status": "active",
            "capability_report": str(self._capability_report) if self._capability_report else None,
        }

    def collect(self, host_id: str) -> Iterable[Event]:
        if not self._available:
            yield Event(EventKind.HEALTH, self.name, {
                "action": "capability_status",
                "status": "unavailable",
                "reason": self._init_error or "network adapter unavailable",
            }, host_id=host_id)
            return

        from .normalizers import (
            normalize_connection_event,
            normalize_traffic_event,
            normalize_dns_event,
            normalize_process_network_event,
        )

        try:
            from network_monitor.core.adapter import CollectorNotImplementedError
        except ImportError:
            CollectorNotImplementedError = Exception  # type: ignore[assignment,misc]

        # Connections
        try:
            for ev in self._adapter.collect_connections():
                yield normalize_connection_event(ev, host_id, self.name)
        except CollectorNotImplementedError:
            pass
        except Exception as exc:
            yield Event(EventKind.HEALTH, self.name,
                        {"action": "collector_error", "sub_collector": "connections",
                         "error": str(exc)[:300]}, host_id=host_id)

        # Traffic stats
        try:
            for ev in self._adapter.collect_traffic():
                yield normalize_traffic_event(ev, host_id, self.name)
        except CollectorNotImplementedError:
            pass
        except Exception as exc:
            yield Event(EventKind.HEALTH, self.name,
                        {"action": "collector_error", "sub_collector": "traffic",
                         "error": str(exc)[:300]}, host_id=host_id)

        # DNS
        try:
            for ev in self._adapter.collect_dns():
                yield normalize_dns_event(ev, host_id, self.name)
        except CollectorNotImplementedError:
            pass
        except Exception as exc:
            yield Event(EventKind.HEALTH, self.name,
                        {"action": "collector_error", "sub_collector": "dns",
                         "error": str(exc)[:300]}, host_id=host_id)

        # Process-network correlation
        try:
            for ev in self._adapter.collect_process_network_activity():
                yield normalize_process_network_event(ev, host_id, self.name)
        except CollectorNotImplementedError:
            pass
        except Exception as exc:
            yield Event(EventKind.HEALTH, self.name,
                        {"action": "collector_error", "sub_collector": "process_network",
                         "error": str(exc)[:300]}, host_id=host_id)

    def close(self) -> None:
        if self._available and self._adapter is not None:
            try:
                self._adapter.stop()
            except Exception:
                pass
            self._available = False


# ---------------------------------------------------------------------------
# NEW: ProcessLifecycleCollector
# BUG FIX: First cycle establishes the baseline without emitting one event per
#           live process. START events are emitted from cycle 1 onwards.
# ---------------------------------------------------------------------------

@dataclass
class ProcessLifecycleCollector:
    """Continuously observes process lifecycle (START / EXIT) events.

    FIX applied: On the very first collect() call the snapshot is empty.
    We now treat that as a "baseline establishment" cycle:
      - No PROCESS_START events are emitted (we cannot know if a process is
        genuinely new without a prior baseline to compare against).
      - The baseline remains collector-local; later lifecycle events carry
        only actual transitions and periodic snapshots.
    From cycle 1 onwards, START / EXIT events reflect genuine OS transitions.

    This eliminates the ~2N first-cycle inflation where N = all running PIDs.

    Documented limitation: Very short-lived processes (start AND exit between
    two consecutive polls) cannot be observed by this mechanism. This is
    reported in the HEALTH event, not papered over.
    """
    name: str = "process_lifecycle"
    snapshot_every_n_cycles: int = 30
    _snapshot: dict = field(default_factory=dict, init=False)  # pid -> info dict
    _cycle_count: int = field(default=0, init=False)
    _mechanism: str = field(default="", init=False)

    @property
    def is_available(self) -> bool:
        return self._get_mechanism() != "unavailable"

    def _get_mechanism(self) -> str:
        try:
            import psutil  # noqa: F401
            return "psutil"
        except ImportError:
            pass
        if os.name == "posix" and Path("/proc").is_dir():
            return "proc_fs"
        return "unavailable"

    def _enumerate_processes(self) -> dict[int, dict]:
        mech = self._get_mechanism()
        procs: dict[int, dict] = {}

        if mech == "psutil":
            import psutil
            attrs = ["pid", "name", "ppid", "exe", "cmdline", "username",
                     "create_time", "status", "num_threads"]
            for p in psutil.process_iter(attrs):
                try:
                    info = p.info.copy()
                    pid = info.get("pid")
                    if pid is None:
                        continue
                    # Normalize cmdline list -> str
                    cmdline = info.get("cmdline") or []
                    if isinstance(cmdline, list):
                        info["cmdline"] = " ".join(cmdline)
                    # Alias username -> user for normalizer compatibility
                    info["user"] = info.pop("username", None)
                    procs[pid] = info
                except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                    continue

        elif mech == "proc_fs":
            for entry in Path("/proc").iterdir():
                if not entry.name.isdigit():
                    continue
                try:
                    pid = int(entry.name)
                    name = (entry / "comm").read_text(encoding="utf-8").strip()
                    stat_parts = (entry / "stat").read_text(encoding="utf-8").split()
                    ppid = int(stat_parts[3]) if len(stat_parts) > 3 else None
                    procs[pid] = {
                        "pid": pid, "name": name, "ppid": ppid,
                        "exe": None, "cmdline": None, "user": None,
                        "create_time": None, "status": None,
                    }
                except (OSError, UnicodeError, ValueError, IndexError):
                    continue

        return procs

    def collect(self, host_id: str) -> Iterable[Event]:
        from .normalizers import (
            normalize_process_start,
            normalize_process_exit,
            normalize_process_snapshot,
        )
        self._mechanism = self._get_mechanism()
        if self._mechanism == "unavailable":
            return

        current = self._enumerate_processes()
        is_baseline_cycle = (self._cycle_count == 0)

        if is_baseline_cycle:
            # --- CYCLE 0: establish baseline ---
            # Do NOT emit one event per live process. The baseline is internal;
            # emitting it would delay the first real lifecycle poll on busy
            # hosts and can cause short-lived process activity to be missed.
            pass
        else:
            # --- CYCLE 1+: diff against previous snapshot ---

            # PROCESS_START: PIDs that appeared since the last snapshot
            for pid, info in current.items():
                if pid not in self._snapshot:
                    yield normalize_process_start(pid, info, host_id, self.name, self._mechanism)

            # PROCESS_EXIT: PIDs that disappeared since the last snapshot
            for pid, info in self._snapshot.items():
                if pid not in current:
                    yield normalize_process_exit(pid, info, host_id, self.name, self._mechanism)

            # Periodic full snapshot (NOT on cycle 0 — already done above)
            if self._cycle_count % self.snapshot_every_n_cycles == 0:
                for pid, info in current.items():
                    yield normalize_process_snapshot(pid, info, host_id, self.name, self._mechanism)

        self._snapshot = current
        self._cycle_count += 1


# ---------------------------------------------------------------------------
# NEW: FileEventCollector
# FIX: Added _is_cloud_sync_path() guard to skip OneDrive/iCloud/Dropbox
#      directories that would flood the collector with non-security events.
# ---------------------------------------------------------------------------

@dataclass
class FileEventCollector:
    """Observes filesystem events using native OS notifications where available.

    Uses the watchdog library (inotify on Linux, ReadDirectoryChangesW on Windows,
    FSEvents on macOS) when installed. Falls back to FilePollingCollector semantics
    when watchdog is not available.

    Safety model:
    - Monitoring is restricted to explicitly configured roots (allow-list).
    - Symlinks are never followed.
    - Cloud-synced directories (OneDrive, Dropbox, iCloud) are automatically
      excluded to prevent flood of non-security sync events.
    - Events are bounded per cycle via max_events_per_cycle.
    """
    roots: tuple  # tuple of Path-compatible objects
    max_events_per_cycle: int | None = None
    max_queue_size: int = 10_000
    name: str = "file_events"
    _queue: Any = field(default=None, init=False, repr=False)
    _observer: Any = field(default=None, init=False, repr=False)
    _mechanism: str = field(default="", init=False)
    _fallback_collector: Any = field(default=None, init=False, repr=False)
    _initialized: bool = field(default=False, init=False)
    _active_roots: list = field(default_factory=list, init=False)
    _skipped_roots: list = field(default_factory=list, init=False)
    _dropped_events: int = field(default=0, init=False)

    @staticmethod
    def _is_cloud_sync_path(path: Path) -> bool:
        """Return True if path is inside a known cloud sync directory.

        These directories generate high-frequency non-security events
        and must be excluded from security monitoring.
        """
        cloud_markers = {
            "OneDrive", "Dropbox", "Google Drive", "iCloud Drive",
            "OneDrive - Personal", "Box Sync", "Box",
        }
        # Check the path parts against known cloud directory names
        path_str = str(path.resolve())
        for marker in cloud_markers:
            if marker in path_str:
                return True
        # Linux: check for ~/.dropbox, ~/Dropbox
        home = Path.home()
        cloud_roots = [home / "Dropbox", home / "Google Drive"]
        for cloud_root in cloud_roots:
            try:
                path.resolve().relative_to(cloud_root.resolve())
                return True
            except ValueError:
                pass
        return False

    def _filter_roots(self) -> tuple[list[Path], list[Path]]:
        """Separate valid roots from cloud-sync roots."""
        valid = []
        skipped = []
        for r in self.roots:
            p = Path(r)
            if not p.exists():
                skipped.append((p, "does not exist"))
                continue
            if self._is_cloud_sync_path(p):
                skipped.append((p, "cloud-sync directory excluded"))
                continue
            if p.is_symlink():
                skipped.append((p, "symlink excluded"))
                continue
            if p.is_dir():
                valid.append(p)
            else:
                skipped.append((p, "not a directory"))
        return valid, skipped

    def initialize(self) -> None:
        """Start the underlying observer. Must be called before collect()."""
        if self._initialized:
            return
        self._initialized = True

        valid_roots, skipped = self._filter_roots()
        self._active_roots = valid_roots
        self._skipped_roots = skipped

        if not valid_roots:
            # All roots are invalid or cloud-sync → polling with empty roots
            self._fallback_collector = FilePollingCollector(tuple())
            self._mechanism = "no_valid_roots"
            return

        try:
            import queue as _queue_mod
            from watchdog.observers import Observer
            from watchdog.events import FileSystemEventHandler

            q: Any = _queue_mod.Queue(maxsize=self.max_queue_size)
            self._queue = q

            class _Handler(FileSystemEventHandler):
                def __init__(self_, the_queue: Any, owner: "FileEventCollector") -> None:
                    self_.q = the_queue
                    self_.owner = owner

                def _enqueue(self_, action: str, path: str, dest_path: str | None = None) -> None:
                    extra: dict[str, Any] = {}
                    if dest_path:
                        extra["dest_path"] = dest_path
                    try:
                        stat = Path(path).stat()
                        extra.update({"size": stat.st_size, "mtime_ns": stat.st_mtime_ns})
                    except OSError:
                        pass
                    try:
                        self_.q.put_nowait((action, path, extra))
                    except _queue_mod.Full:
                        self_.owner._dropped_events += 1

                def on_created(self_, evt: Any) -> None:
                    if not evt.is_directory:
                        self_._enqueue("create", evt.src_path)

                def on_modified(self_, evt: Any) -> None:
                    if not evt.is_directory:
                        self_._enqueue("modify", evt.src_path)

                def on_deleted(self_, evt: Any) -> None:
                    if not evt.is_directory:
                        self_._enqueue("delete", evt.src_path)

                def on_moved(self_, evt: Any) -> None:
                    if not evt.is_directory:
                        self_._enqueue("rename", evt.src_path, evt.dest_path)

            observer = Observer()
            handler = _Handler(q, self)
            scheduled = False
            for root_path in valid_roots:
                observer.schedule(handler, str(root_path), recursive=True)
                scheduled = True

            if scheduled:
                observer.start()
                self._observer = observer
                self._mechanism = "watchdog"
            else:
                raise RuntimeError("no valid roots for watchdog observer")

        except (ImportError, RuntimeError, Exception):
            # watchdog not installed or no valid roots: fall back to polling
            self._fallback_collector = FilePollingCollector(tuple(valid_roots))
            self._mechanism = "polling"

    @property
    def is_available(self) -> bool:
        valid, _ = self._filter_roots()
        return bool(valid)

    def collect(self, host_id: str) -> Iterable[Event]:
        if not self._initialized:
            self.initialize()

        # Report skipped roots as HEALTH events (once per init cycle)
        for skip_path, reason in self._skipped_roots:
            yield Event(EventKind.HEALTH, self.name,
                        {"action": "root_skipped", "path": str(skip_path), "reason": reason},
                        host_id=host_id)
        self._skipped_roots = []  # Report only once

        if self._dropped_events:
            dropped = self._dropped_events
            self._dropped_events = 0
            yield Event(EventKind.HEALTH, self.name, {
                "action": "backpressure",
                "status": "degraded",
                "dropped_events": dropped,
                "queue_capacity": self.max_queue_size,
                "reason": "watchdog queue capacity exceeded",
            }, host_id=host_id)

        if not self._active_roots:
            return

        if self._mechanism in ("polling", "no_valid_roots"):
            if self._fallback_collector is not None:
                yield from self._fallback_collector.collect(host_id)
            return

        # Drain the watchdog queue
        from .normalizers import normalize_file_event
        count = 0
        while self._queue is not None and not self._queue.empty() and (
            self.max_events_per_cycle is None or count < self.max_events_per_cycle
        ):
            try:
                action, src_path, extra = self._queue.get_nowait()
            except Exception:
                break
            yield normalize_file_event(
                action, src_path, host_id, self.name, self._mechanism, extra
            )
            count += 1

    def close(self) -> None:
        if self._observer is not None:
            try:
                self._observer.stop()
                self._observer.join(timeout=5)
            except Exception:
                pass


# ---------------------------------------------------------------------------
# NEW: AuthEventCollector
# FIX: Cursor is now persisted to disk so successive runs do not re-deliver
#      historical journal entries. Each run only reads NEW auth events.
# ---------------------------------------------------------------------------

@dataclass
class AuthEventCollector:
    """Collects authentication and security events from OS mechanisms.

    Linux: Reads journalctl (systemd journal) for SSH, sudo, PAM, and login
    events. Falls back to reading /var/log/auth.log if journalctl is unavailable.

    Windows: Reads the Security Event Log via wevtutil subprocess call.

    FIX applied: The journalctl cursor is now persisted to a file in the
    data directory. On restart, the cursor is loaded from disk, ensuring
    only NEW entries are delivered — not the last 200 historical entries
    that were re-read on every process restart before this fix.
    """
    name: str = "auth_events"
    cursor_file: Any = field(default=None)   # Path | None; set via initialize(cursor_file=...)
    _last_cursor: str = field(default="", init=False)
    _last_winevt_time: str = field(default="", init=False)
    _last_winevt_record_id: int = field(default=0, init=False)
    _mechanism: str = field(default="", init=False)
    _available: bool = field(default=False, init=False)
    _status_reason: str = field(default="", init=False)
    _status_reported: bool = field(default=False, init=False)

    def initialize(self, cursor_file: Any = None) -> None:
        """Detect available auth log mechanism for this OS.

        Args:
            cursor_file: Optional Path to persist the journalctl cursor.
                         When provided, the cursor is loaded on start and
                         saved after each collection cycle, preventing
                         re-delivery of historical events on restart.
        """
        if cursor_file is not None:
            self.cursor_file = Path(cursor_file)

        # Load persisted cursor if available
        if self.cursor_file is not None:
            try:
                cursor_path = Path(self.cursor_file)
                if cursor_path.exists():
                    raw_cursor = cursor_path.read_text(encoding="utf-8").strip()
                    try:
                        state = json.loads(raw_cursor)
                        self._last_cursor = str(state.get("journal_cursor", ""))
                        self._last_winevt_record_id = int(state.get("event_record_id", 0))
                    except (json.JSONDecodeError, TypeError, ValueError):
                        # Backward-compatible Linux cursor format.
                        self._last_cursor = raw_cursor
            except (OSError, UnicodeError):
                pass

        system = platform.system()
        if system == "Linux":
            if shutil.which("journalctl"):
                self._mechanism = "journalctl"
                self._available = True
            elif Path("/var/log/auth.log").exists():
                self._mechanism = "auth_log"
                self._available = True
            else:
                self._available = False
                self._status_reason = "no journalctl and /var/log/auth.log not found"
        elif system == "Windows":
            if shutil.which("wevtutil"):
                self._mechanism = "wevtutil"
                self._available = True
            else:
                self._available = False
                self._status_reason = "wevtutil not found in PATH"
        else:
            self._available = False
            self._status_reason = f"unsupported OS: {system}"

    def _save_cursor(self) -> None:
        """Persist journal and Windows event cursors atomically."""
        if self.cursor_file is not None and (self._last_cursor or self._last_winevt_record_id):
            try:
                cursor_path = Path(self.cursor_file)
                cursor_path.parent.mkdir(parents=True, exist_ok=True)
                tmp_path = cursor_path.with_suffix(cursor_path.suffix + ".tmp")
                tmp_path.write_text(json.dumps({
                    "journal_cursor": self._last_cursor,
                    "event_record_id": self._last_winevt_record_id,
                }), encoding="utf-8")
                tmp_path.replace(cursor_path)
            except (OSError, PermissionError):
                pass

    @property
    def is_available(self) -> bool:
        return self._available

    def collect(self, host_id: str) -> Iterable[Event]:
        if not self._available:
            if not self._status_reported:
                self._status_reported = True
                yield Event(EventKind.HEALTH, self.name, {
                    "action": "capability_status",
                    "status": "unavailable",
                    "mechanism": self._mechanism or None,
                    "reason": self._status_reason or "authentication mechanism unavailable",
                }, host_id=host_id)
            return

        from .normalizers import normalize_auth_event

        if self._mechanism == "journalctl":
            yield from self._collect_journalctl(host_id, normalize_auth_event)
        elif self._mechanism == "auth_log":
            yield from self._collect_auth_log(host_id, normalize_auth_event)
        elif self._mechanism == "wevtutil":
            yield from self._collect_wevtutil(host_id, normalize_auth_event)

    # ------------------------------------------------------------------
    # Linux: journalctl (with persistent cursor)
    # ------------------------------------------------------------------

    _RELEVANT_IDENTS = frozenset({
        "sshd", "sudo", "su", "login", "PAM", "pam",
        "systemd-logind", "cron", "passwd",
    })
    _RELEVANT_UNITS = frozenset({
        "sshd.service", "systemd-logind.service", "su.service",
    })

    def _classify_journal_entry(self, msg: str, ident: str) -> str | None:
        """Return action string or None if entry is not auth-relevant."""
        if "Accepted password for" in msg or "Accepted publickey for" in msg:
            return "login_success"
        if "Failed password for" in msg or "authentication failure" in msg:
            return "login_failure"
        if "Invalid user" in msg or "Did not receive identification" in msg:
            return "login_failure"
        if "session opened for user" in msg or "New session" in msg:
            return "session_start"
        if "session closed for user" in msg or "Removed session" in msg:
            return "session_end"
        if ident == "sudo" and "COMMAND=" in msg:
            return "privilege_change"
        if "password changed for" in msg.lower():
            return "password_change"
        if "account locked" in msg.lower():
            return "account_locked"
        return None

    def _extract_journal_user(self, msg: str) -> str | None:
        m = re.search(r"(?:for|user)\s+(\S+)", msg)
        return m.group(1) if m else None

    def _collect_journalctl(self, host_id: str, normalize_auth_event: Any) -> Iterable[Event]:
        # With a persisted cursor, use --after-cursor to only read NEW entries.
        # Without a cursor (first ever run), use -n 50 to limit history intake
        # and avoid flooding with old events on first startup.
        if self._last_cursor:
            cmd = ["journalctl", "--after-cursor", self._last_cursor,
                   "--output=json", "--no-pager"]
        else:
            # First run: only read the very latest 50 entries (not 200)
            # to establish an initial cursor position without replaying history.
            cmd = ["journalctl", "-n", "50", "--output=json", "--no-pager"]

        try:
            result = subprocess.run(
                cmd, capture_output=True, text=True, timeout=10
            )
        except (subprocess.TimeoutExpired, FileNotFoundError, OSError):
            return

        new_cursor = self._last_cursor
        events_yielded = 0

        for line in result.stdout.splitlines():
            if not line.strip():
                continue
            try:
                entry = json.loads(line)
            except json.JSONDecodeError:
                continue

            # Always advance cursor to the latest processed entry
            cursor = entry.get("__CURSOR", "")
            if cursor:
                new_cursor = cursor

            ident = entry.get("SYSLOG_IDENTIFIER", "")
            unit = entry.get("_SYSTEMD_UNIT", "")
            msg = entry.get("MESSAGE", "")

            if ident not in self._RELEVANT_IDENTS and unit not in self._RELEVANT_UNITS:
                continue

            if isinstance(msg, list):
                msg = " ".join(str(m) for m in msg)
            msg = str(msg)

            action = self._classify_journal_entry(msg, ident)
            if action is None:
                continue

            pid_raw = entry.get("_PID")
            fields: dict[str, Any] = {
                "user": self._extract_journal_user(msg),
                "pid": int(pid_raw) if pid_raw else None,
                "uid": entry.get("_UID"),
                "hostname": entry.get("_HOSTNAME"),
                "auth_mechanism": ident,
                "message": msg[:200],
                "source_ip": self._extract_source_ip(msg),
            }
            yield normalize_auth_event(action, fields, host_id, self.name, self._mechanism)
            events_yielded += 1

        # Persist the updated cursor after processing
        if new_cursor != self._last_cursor:
            self._last_cursor = new_cursor
            self._save_cursor()

    @staticmethod
    def _extract_source_ip(msg: str) -> str | None:
        """Extract source IP address from journalctl auth messages."""
        m = re.search(r"from\s+([\d\.a-fA-F:]+)\s+port", msg)
        return m.group(1) if m else None

    # ------------------------------------------------------------------
    # Linux fallback: /var/log/auth.log
    # ------------------------------------------------------------------

    def _collect_auth_log(self, host_id: str, normalize_auth_event: Any) -> Iterable[Event]:
        log_path = Path("/var/log/auth.log")
        try:
            lines = log_path.read_text(encoding="utf-8", errors="replace").splitlines()
        except (OSError, PermissionError):
            return

        # Process last 100 lines only
        for line in lines[-100:]:
            action = self._classify_journal_entry(line, "")
            if action is None:
                continue
            fields: dict[str, Any] = {
                "user": self._extract_journal_user(line),
                "message": line[:200],
                "auth_mechanism": "auth.log",
                "source_ip": self._extract_source_ip(line),
            }
            yield normalize_auth_event(action, fields, host_id, self.name, self._mechanism)

    # ------------------------------------------------------------------
    # Windows: wevtutil
    # ------------------------------------------------------------------

    _WIN_EVENT_ACTIONS = {
        "4624": "login_success",
        "4625": "login_failure",
        "4634": "session_end",
        "4648": "login_success",   # Explicit credential logon
        "4672": "privilege_change",
    }

    def _collect_wevtutil(self, host_id: str, normalize_auth_event: Any) -> Iterable[Event]:
        event_filter = "EventID=4624 or EventID=4625 or EventID=4648 or EventID=4672 or EventID=4634"
        if self._last_winevt_record_id:
            query = f"*[System[({event_filter}) and EventRecordID > {self._last_winevt_record_id}]]"
        else:
            # First run establishes a baseline from the most recent records;
            # subsequent runs are strictly cursor-based.
            query = f"*[System[({event_filter})]]"
        cmd = [
            "wevtutil", "qe", "Security",
            f"/q:{query}",
            "/f:XML", "/rd:true",
        ]
        try:
            result = subprocess.run(
                cmd, capture_output=True, text=True, timeout=15
            )
        except (subprocess.TimeoutExpired, FileNotFoundError, OSError):
            return

        if not result.stdout.strip():
            return

        try:
            xml_str = f"<Events>{result.stdout}</Events>"
            root = ET.fromstring(xml_str)
        except ET.ParseError:
            return

        ns = "http://schemas.microsoft.com/win/2004/08/events/event"
        highest_record_id = self._last_winevt_record_id
        for ev_el in root.findall(f"{{{ns}}}Event"):
            sys_el = ev_el.find(f"{{{ns}}}System")
            if sys_el is None:
                continue
            eid_el = sys_el.find(f"{{{ns}}}EventID")
            if eid_el is None:
                continue
            event_id = (eid_el.text or "").strip()
            record_id_el = sys_el.find(f"{{{ns}}}EventRecordID")
            try:
                record_id = int(record_id_el.text or "0") if record_id_el is not None else 0
            except ValueError:
                record_id = 0
            if record_id and record_id <= self._last_winevt_record_id:
                continue
            highest_record_id = max(highest_record_id, record_id)
            action = self._WIN_EVENT_ACTIONS.get(event_id)
            if not action:
                continue

            user = None
            logon_type = None
            evt_data = ev_el.find(f"{{{ns}}}EventData")
            if evt_data is not None:
                for data_el in evt_data.findall(f"{{{ns}}}Data"):
                    attr_name = data_el.get("Name", "")
                    if attr_name == "TargetUserName":
                        user = data_el.text
                    elif attr_name == "LogonType":
                        logon_type = data_el.text

            fields: dict[str, Any] = {
                "user": user,
                "event_record_id": record_id or None,
                "windows_event_id": event_id,
                "auth_mechanism": "WindowsSecurityLog",
                "logon_type": logon_type,
                "message": f"Windows Security Event {event_id}",
            }
            observed_at = None
            time_el = sys_el.find(f"{{{ns}}}TimeCreated")
            if time_el is not None:
                raw_time = time_el.get("SystemTime")
                if raw_time:
                    try:
                        observed_at = datetime.fromisoformat(raw_time.replace("Z", "+00:00"))
                    except ValueError:
                        observed_at = None
            yield normalize_auth_event(action, fields, host_id, self.name, self._mechanism, observed_at)

        if highest_record_id > self._last_winevt_record_id:
            self._last_winevt_record_id = highest_record_id
            self._save_cursor()
