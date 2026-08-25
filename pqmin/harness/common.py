from __future__ import annotations

import hashlib
import json
import os
import tempfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[2]
PQ = ROOT / "pqmin"
CONFIG = PQ / "config.json"
REFERENCE = PQ / "reference.json"
CURRENT = PQ / "current.json"
TRIALS = PQ / "trials.jsonl"
PROGRESS = PQ / "progress.jsonl"
NOTEBOOK = PQ / "NOTEBOOK.md"
STATUS = PQ / "status.json"


def now_iso() -> str:
    return datetime.now(timezone.utc).astimezone().isoformat(timespec="seconds")


def read_json(path: Path, default: Any = None) -> Any:
    try:
        return json.loads(path.read_text())
    except (FileNotFoundError, json.JSONDecodeError):
        return default


def atomic_json(path: Path, value: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, raw = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    tmp = Path(raw)
    try:
        with os.fdopen(fd, "w") as f:
            json.dump(value, f, indent=2, sort_keys=True)
            f.write("\n")
            f.flush()
            os.fsync(f.fileno())
        tmp.replace(path)
    finally:
        tmp.unlink(missing_ok=True)


def append_trial(record: dict[str, Any]) -> None:
    record = dict(record)
    record.setdefault("timestamp", now_iso())
    TRIALS.parent.mkdir(parents=True, exist_ok=True)
    with TRIALS.open("a") as f:
        f.write(json.dumps(record, separators=(",", ":"), sort_keys=True) + "\n")


def append_progress(record: dict[str, Any]) -> None:
    record = dict(record)
    record.setdefault("timestamp", now_iso())
    PROGRESS.parent.mkdir(parents=True, exist_ok=True)
    with PROGRESS.open("a") as f:
        f.write(json.dumps(record, separators=(",", ":"), sort_keys=True) + "\n")
        f.flush()
        os.fsync(f.fileno())


def sha256_file(path: Path, chunk_size: int = 16 * 1024 * 1024) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(chunk_size), b""):
            digest.update(chunk)
    return digest.hexdigest()
