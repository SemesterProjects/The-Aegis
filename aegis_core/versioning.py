"""Opt-in, quota-bounded file versions and approval-gated restoration."""
from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
import hashlib
from pathlib import Path
import shutil
import sqlite3
import uuid


@dataclass(frozen=True, slots=True)
class FileVersion:
    version_id: str
    original_path: Path
    digest: str
    size: int
    captured_at: datetime


class FileVersionVault:
    """Stores versions only for operator-approved roots and never restores automatically."""
    def __init__(self, root: Path, max_version_bytes: int = 64 * 1024 * 1024) -> None:
        self.root = root
        self.max_version_bytes = max_version_bytes
        self.root.mkdir(parents=True, exist_ok=True)
        self._db = sqlite3.connect(self.root / "versions.sqlite3")
        with self._db:
            self._db.execute("""CREATE TABLE IF NOT EXISTS versions (
                version_id TEXT PRIMARY KEY, original_path TEXT NOT NULL, digest TEXT NOT NULL,
                size INTEGER NOT NULL, captured_at TEXT NOT NULL, stored_path TEXT NOT NULL)""")

    def close(self) -> None:
        """Release the local database lock; required before service shutdown on Windows."""
        self._db.close()

    def __enter__(self) -> "FileVersionVault":
        return self

    def __exit__(self, *_: object) -> None:
        self.close()

    def capture(self, path: Path) -> FileVersion | None:
        """Copy a regular file before an observed change. Returns None when out of policy."""
        try:
            resolved = path.resolve(strict=True)
            if resolved.is_symlink() or not resolved.is_file():
                return None
            size = resolved.stat().st_size
        except OSError:
            return None
        if size > self.max_version_bytes:
            return None
        digest = _sha256(resolved)
        existing = self._db.execute("SELECT version_id FROM versions WHERE original_path=? AND digest=?", (str(resolved), digest)).fetchone()
        if existing:
            return self.get(existing[0])
        version_id = str(uuid.uuid4())
        destination = self.root / "blobs" / digest[:2] / digest
        destination.parent.mkdir(parents=True, exist_ok=True)
        if not destination.exists():
            shutil.copy2(resolved, destination)
        captured_at = datetime.now(timezone.utc)
        with self._db:
            self._db.execute("INSERT INTO versions VALUES (?, ?, ?, ?, ?, ?)",
                (version_id, str(resolved), digest, size, captured_at.isoformat(), str(destination)))
        return FileVersion(version_id, resolved, digest, size, captured_at)

    def get(self, version_id: str) -> FileVersion:
        row = self._db.execute("SELECT version_id, original_path, digest, size, captured_at FROM versions WHERE version_id=?", (version_id,)).fetchone()
        if not row:
            raise KeyError(f"unknown version {version_id}")
        return FileVersion(row[0], Path(row[1]), row[2], row[3], datetime.fromisoformat(row[4]))

    def restore(self, version_id: str, *, approved_by: str, target: Path | None = None) -> Path:
        """Restore only after an external approval workflow supplies a responsible identity."""
        if not approved_by.strip():
            raise PermissionError("file restore requires a recorded human approver")
        version = self.get(version_id)
        row = self._db.execute("SELECT stored_path FROM versions WHERE version_id=?", (version_id,)).fetchone()
        source = Path(row[0])
        destination = (target or version.original_path).resolve()
        if destination.exists() and destination.is_symlink():
            raise PermissionError("refusing to overwrite a symlink")
        destination.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(source, destination)
        return destination


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()
