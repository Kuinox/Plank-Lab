#!/usr/bin/env python3
"""Small locked subject board shared by otherwise isolated researchers."""
from __future__ import annotations

import argparse
import fcntl
import json
import os
import re
import tempfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable


DEFAULT_ROOT = Path("/coordination")
KEY_RE = re.compile(r"[a-z0-9][a-z0-9._-]{2,79}")
SUBJECT_STOPWORDS = {
    "a", "against", "an", "and", "artifact", "as", "by", "bytes", "compact", "complete",
    "compressed", "compression", "configuration", "current", "data", "different",
    "exact", "file", "for", "high", "instead", "layout", "non", "null", "of",
    "on", "one", "page", "parameter", "parameters", "parquet", "required", "same", "single",
    "stream", "test", "testing", "the", "timestamp", "to", "trade", "validated", "versus",
    "v1", "v2", "while", "winner", "with",
}


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _empty() -> dict[str, Any]:
    return {"version": 1, "updated_at": _now(), "active": [], "recent": []}


def _subject_terms(key: str, subject: str) -> set[str]:
    text = re.sub(r"([a-z])([A-Z])", r"\1 \2", f"{key} {subject}").casefold()
    words = re.findall(r"[a-z]+|[0-9]+", text)
    aliases = {
        "zstandard": "zstd",
        "sorted": "sort", "sorting": "sort", "columns": "column",
        "matching": "match", "matched": "match", "workers": "worker",
        "values": "value", "blocks": "block", "statistics": "statistic",
        "boundaries": "boundary", "transitions": "transition", "deltas": "delta",
        "splits": "split", "resets": "reset", "cuts": "cut",
    }
    return {
        aliases.get(word, word)
        for word in words
        if len(word) > 1 and word not in SUBJECT_STOPWORDS
    }


def _subject_concepts(key: str, subject: str) -> set[str]:
    terms = _subject_terms(key, subject)
    raw = f"{key} {subject}".casefold()
    concepts: set[str] = set()
    if "brotli" in terms:
        concepts.add("brotli-family")
    if "gzip" in terms:
        concepts.add("gzip-family")
    if "plain" in terms and "zstd" in terms:
        concepts.add("plain-zstd")
    if "plain" in terms:
        concepts.add("plain-encoding")
    if "byte" in terms and "split" in terms:
        concepts.add("byte-stream-split")
    if "zstd" in terms and "long" in terms and "distance" in terms:
        concepts.add("zstd-long-distance")
    if "zstd" in terms and "content" in terms and "size" in terms:
        concepts.add("zstd-content-size")
    if "zstd" in terms and ("level" in terms or "preset" in terms):
        concepts.add("zstd-level")
    if "zstd" in terms and "strategy" in terms:
        concepts.add("zstd-strategy")
    if "delta" in terms and "block" in terms:
        concepts.add("delta-block-size")
    if "block" in terms and "geometry" in terms:
        concepts.add("block-geometry")
    if "sort" in terms and ({"column", "order", "metadata"} & terms):
        concepts.add("sorting-metadata")
    if re.search(
        r"(?:page[\s_-]*(?:target|size|boundary|segmentation)|p\d+[km][_-]?boundary|"
        r"\b[0-9]+\s*mi?b\s+(?:target\s+)?(?:data\s+)?page)",
        raw,
    ):
        concepts.add("page-sizing")
    if "page" in raw and (
        re.search(r"data[\s_-]*dependent", raw)
        or {"adaptive", "disruptive", "negative", "transition"} & terms
    ) and {"boundary", "cut", "reset", "split", "transition"} & terms:
        concepts.add("adaptive-page-boundaries")
    return concepts


def _same_subject_area(
    key_a: str,
    subject_a: str,
    key_b: str,
    subject_b: str,
) -> bool:
    compact_a = re.sub(r"[^a-z0-9]", "", key_a.casefold())
    compact_b = re.sub(r"[^a-z0-9]", "", key_b.casefold())
    if compact_a == compact_b:
        return True
    shorter, longer = sorted((compact_a, compact_b), key=len)
    if len(os.path.commonprefix((shorter, longer))) >= 6:
        return True
    if _subject_concepts(key_a, subject_a) & _subject_concepts(key_b, subject_b):
        return True
    terms_a = _subject_terms(key_a, subject_a)
    terms_b = _subject_terms(key_b, subject_b)
    if not terms_a or not terms_b:
        return False
    shared = len(terms_a & terms_b)
    overlap = shared / min(len(terms_a), len(terms_b))
    return shared >= 3 and overlap >= 0.75


def _load(path: Path) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return _empty()
    if not isinstance(value, dict):
        return _empty()
    value.setdefault("version", 1)
    value.setdefault("active", [])
    value.setdefault("recent", [])
    return value


def _atomic_write(path: Path, value: dict[str, Any]) -> None:
    value["updated_at"] = _now()
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary = tempfile.mkstemp(prefix="board-", suffix=".json", dir=path.parent)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8") as stream:
            json.dump(value, stream, indent=2, sort_keys=True)
            stream.write("\n")
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
    finally:
        try:
            os.unlink(temporary)
        except FileNotFoundError:
            pass


def _locked(root: Path, mutate: Callable[[dict[str, Any]], Any]) -> Any:
    root.mkdir(parents=True, exist_ok=True)
    lock_path = root / "board.lock"
    board_path = root / "board.json"
    with lock_path.open("a+") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX)
        board = _load(board_path)
        result = mutate(board)
        _atomic_write(board_path, board)
        return result


def read_board(root: Path = DEFAULT_ROOT) -> dict[str, Any]:
    root.mkdir(parents=True, exist_ok=True)
    with (root / "board.lock").open("a+") as lock:
        fcntl.flock(lock, fcntl.LOCK_SH)
        return _load(root / "board.json")


def claim_subject(
    root: Path,
    *,
    slot: int,
    run_id: int,
    key: str,
    subject: str,
) -> tuple[bool, str]:
    key = key.casefold().strip()
    subject = " ".join(subject.split())
    if not KEY_RE.fullmatch(key):
        return False, "key must be 3-80 lowercase letters/digits with '.', '_' or '-'"
    if not 8 <= len(subject) <= 200:
        return False, "subject must be 8-200 characters"

    def mutate(board: dict[str, Any]) -> tuple[bool, str]:
        active = [item for item in board.get("active", []) if isinstance(item, dict)]
        own = next((item for item in active if item.get("run_id") == run_id), None)
        if own is not None:
            return False, f"run already owns {own.get('key')}: {own.get('subject')}"
        collision = next(
            (
                item for item in active
                if item.get("key") == key
                or _same_subject_area(
                    key,
                    subject,
                    str(item.get("key", "")),
                    str(item.get("subject", "")),
                )
            ),
            None,
        )
        if collision is not None:
            return False, (
                f"subject collision with slot {collision.get('slot')} "
                f"({collision.get('key')}): {collision.get('subject')}"
            )
        active.append({
            "slot": slot,
            "run_id": run_id,
            "key": key,
            "subject": subject,
            "claimed_at": _now(),
        })
        board["active"] = active
        return True, f"claimed {key}: {subject}"

    return _locked(root, mutate)


def finish_run(root: Path, run_id: int, status: str) -> None:
    def mutate(board: dict[str, Any]) -> None:
        active = [item for item in board.get("active", []) if isinstance(item, dict)]
        keep: list[dict[str, Any]] = []
        recent = [item for item in board.get("recent", []) if isinstance(item, dict)]
        for item in active:
            if item.get("run_id") == run_id:
                recent.append({**item, "finished_at": _now(), "status": status})
            else:
                keep.append(item)
        board["active"] = keep
        board["recent"] = recent[-96:]

    _locked(root, mutate)


def reset_active(root: Path, *, generation: int | None = None) -> None:
    def mutate(board: dict[str, Any]) -> None:
        if generation is not None and board.get("generation") != generation:
            board["generation"] = generation
            board["active"] = []
            board["recent"] = []
            return
        recent = [item for item in board.get("recent", []) if isinstance(item, dict)]
        for item in board.get("active", []):
            if isinstance(item, dict):
                recent.append({**item, "finished_at": _now(), "status": "interrupted"})
        board["active"] = []
        board["recent"] = recent[-96:]

    _locked(root, mutate)


def claim_for_run(root: Path, run_id: int) -> dict[str, Any] | None:
    board = read_board(root)
    return next(
        (item for item in board.get("active", []) if isinstance(item, dict) and item.get("run_id") == run_id),
        None,
    )


def _print_board(board: dict[str, Any]) -> None:
    active = board.get("active", [])
    recent = board.get("recent", [])[-24:]
    print("ACTIVE SUBJECTS")
    if not active:
        print("  (none)")
    for item in active:
        print(f"  slot {item.get('slot')} [{item.get('key')}]: {item.get('subject')}")
    print("RECENTLY FINISHED SUBJECTS")
    if not recent:
        print("  (none)")
    for item in recent:
        print(f"  [{item.get('key')}] ({item.get('status')}): {item.get('subject')}")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--root", type=Path, default=DEFAULT_ROOT)
    commands = parser.add_subparsers(dest="command", required=True)
    commands.add_parser("list")
    claim = commands.add_parser("claim")
    claim.add_argument("--slot", type=int, required=True)
    claim.add_argument("--run", type=int, required=True)
    claim.add_argument("--key", required=True)
    claim.add_argument("--subject", required=True)
    release = commands.add_parser("release")
    release.add_argument("--run", type=int, required=True)
    args = parser.parse_args()
    if args.command == "list":
        _print_board(read_board(args.root))
        return 0
    if args.command == "claim":
        accepted, message = claim_subject(
            args.root, slot=args.slot, run_id=args.run, key=args.key, subject=args.subject
        )
        print(message)
        return 0 if accepted else 2
    finish_run(args.root, args.run, "released")
    print(f"released run {args.run}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
