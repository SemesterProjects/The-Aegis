"""Portable, read-only polling collectors. Native sensors plug in later."""
from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
import hashlib
import os
import socket
from typing import Iterable, Protocol

from .models import Event, EventKind
from .network import NetworkCollector


class Collector(Protocol):
    name: str
    def collect(self, host_id: str) -> Iterable[Event]: ...


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
    max_files_per_cycle: int = 10_000
    name: str = "file_polling"
    _snapshot: dict[Path, tuple[int, int]] = field(default_factory=dict, init=False)

    def collect(self, host_id: str) -> Iterable[Event]:
        observed = 0
        current: dict[Path, tuple[int, int]] = {}
        for root in self.roots:
            root = root.resolve()
            if not root.is_dir():
                continue
            for path in root.rglob("*"):
                if observed >= self.max_files_per_cycle:
                    yield Event(EventKind.HEALTH, self.name, {"warning": "file scan capped", "cap": self.max_files_per_cycle}, host_id=host_id)
                    break
                try:
                    if path.is_symlink() or not path.is_file():
                        continue
                    stat = path.stat()
                except OSError:
                    continue
                observed += 1
                signature = (stat.st_mtime_ns, stat.st_size)
                current[path] = signature
                old = self._snapshot.get(path)
                if old is not None and old != signature:
                    yield Event(EventKind.FILE, self.name, {"path": str(path), "operation": "modified",
                        "size": stat.st_size, "previous_size": old[1], "suffix": path.suffix.lower()}, host_id=host_id)
                elif old is None and self._snapshot:
                    yield Event(EventKind.FILE, self.name, {"path": str(path), "operation": "created",
                        "size": stat.st_size, "suffix": path.suffix.lower()}, host_id=host_id)
        for path, (_, old_size) in self._snapshot.items():
            if path not in current:
                yield Event(EventKind.FILE, self.name, {"path": str(path), "operation": "deleted",
                    "previous_size": old_size, "suffix": path.suffix.lower()}, host_id=host_id)
        self._snapshot = current


def stable_host_id() -> str:
    """Pseudonymous installation identifier; callers may provide managed identity instead."""
    raw = f"{socket.gethostname()}:{os.getuid() if hasattr(os, 'getuid') else 'windows'}"
    return hashlib.sha256(raw.encode()).hexdigest()[:24]
