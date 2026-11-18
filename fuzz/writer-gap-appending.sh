#!/usr/bin/env bash
set -euo pipefail

repo=$(cd "$(dirname "$0")/.." && pwd)
work=$(mktemp -d "${TMPDIR:-/tmp}/plank-writer-append-gap.XXXXXX")
trap 'rm -rf "$work"' EXIT

python3 - "$work" <<'PY'
from pathlib import Path
import sys

directory = Path(sys.argv[1])
seeds = {
    "append-int32-ascending": (0xF8, 0, 0, 2, 2, 128),
    "append-int32-out-of-order": (0xF8, 0, 5, 3, 4, 100),
    "append-int64-null-first": (0xF8, 1, 2, 2, 3, 120),
    "append-int64-null-last-descending": (0xF8, 1, 3, 3, 1, 140),
    "append-int64-null-last-break": (0xF8, 1, 7, 2, 1, 80),
    "append-binary-ascending": (0xF8, 2, 0, 3, 2, 128, 30),
    "append-binary-descending-break": (0xF8, 2, 5, 2, 4, 100, 60),
}
for name, data in seeds.items():
    (directory / name).write_bytes(bytes(data))
PY

dotnet run --project "$repo/Plank.Fuzzing.Replay" -- writer "$work"
