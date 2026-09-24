from __future__ import annotations

import hashlib
import json
import shutil
from datetime import datetime
from pathlib import Path
from typing import Any


class BackupError(RuntimeError):
    pass


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _timestamp() -> str:
    return datetime.now().strftime("%Y%m%d_%H%M%S_%f")


def create_manifest(root: Path, items: dict[str, Any]) -> Path:
    """Create a manifest and hash every JSON-serializable item.

    This preserves the existing API while making the integrity information
    explicit. Values are hashed from canonical JSON.
    """
    root.mkdir(parents=True, exist_ok=True)
    normalized = {}
    for key, value in items.items():
        encoded = json.dumps(
            value, sort_keys=True, ensure_ascii=False, separators=(",", ":")
        ).encode("utf-8")
        normalized[key] = {"value": value, "sha256": sha256_bytes(encoded)}

    manifest = {
        "version": 1,
        "created_at": datetime.now().isoformat(timespec="seconds"),
        "items": normalized,
    }
    path = root / f"manifest_{_timestamp()}.json"
    path.write_text(
        json.dumps(manifest, indent=2, ensure_ascii=False),
        encoding="utf-8",
    )
    return path


def backup_file(root: Path, source: Path) -> tuple[Path, str]:
    """Copy a file into a timestamped backup directory and return its hash."""
    if not source.is_file():
        raise BackupError(f"File does not exist: {source}")
    root.mkdir(parents=True, exist_ok=True)
    destination = root / f"{_timestamp()}_{source.name}.bak"
    shutil.copy2(source, destination)
    digest = hashlib.sha256(destination.read_bytes()).hexdigest()
    return destination, digest


def load_manifest(path: Path) -> dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8"))
