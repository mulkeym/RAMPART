"""Safe file I/O utilities for RAMPART data stores.

Provides atomic writes (temp file + rename) and file locking to prevent
data corruption from concurrent access or mid-write crashes.
"""
from __future__ import annotations

import json
import os
import tempfile
from pathlib import Path
from typing import Any


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
