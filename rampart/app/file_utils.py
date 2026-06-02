"""Safe file I/O utilities for RAMPART data stores.

Provides atomic writes (temp file + rename) and file locking to prevent
data corruption from concurrent access or mid-write crashes.
"""
from __future__ import annotations

import fcntl
import json
import os
import tempfile
from contextlib import contextmanager
from pathlib import Path
from typing import Any, Generator


@contextmanager
def file_lock(path: str | Path) -> Generator[None, None, None]:
    """Acquire an exclusive file lock for the duration of a block.

    Uses a separate .lock file so the data file itself is never held open
    during the lock. Works across multiple uvicorn workers in the same container.
    """
    lock_path = Path(str(path) + ".lock")
    lock_path.parent.mkdir(parents=True, exist_ok=True)
    lock_fd = os.open(str(lock_path), os.O_CREAT | os.O_RDWR)
    try:
        fcntl.flock(lock_fd, fcntl.LOCK_EX)
        yield
    finally:
        fcntl.flock(lock_fd, fcntl.LOCK_UN)
        os.close(lock_fd)


def atomic_write_json(path: str | Path, data: Any, indent: int = 2) -> None:
    """Write JSON data atomically using temp file + rename.

    1. Write to a temporary file in the same directory
    2. Flush and fsync to ensure data is on disk
    3. Rename (atomic on POSIX) to the target path

    If the process crashes at any point, the original file is untouched.
    """
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp_path = tempfile.mkstemp(dir=target.parent, suffix=".tmp")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=indent, sort_keys=True)
            f.write("\n")
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp_path, str(target))
    except BaseException:
        # Clean up temp file if rename didn't happen
        try:
            os.unlink(tmp_path)
        except OSError:
            pass
        raise


def locked_atomic_write_json(path: str | Path, data: Any, indent: int = 2) -> None:
    """Atomic write with an exclusive file lock. Use for stores where
    multiple workers may write concurrently."""
    with file_lock(path):
        atomic_write_json(path, data, indent)


def locked_read_json(path: str | Path) -> Any:
    """Read JSON with a shared-compatible lock. Returns None if file doesn't exist."""
    p = Path(path)
    if not p.exists():
        return None
    with file_lock(path):
        with p.open("r", encoding="utf-8") as f:
            return json.load(f)
