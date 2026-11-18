#!/usr/bin/env bash
set -euo pipefail

repo=$(cd "$(dirname "$0")/.." && pwd)
work=$(mktemp -d "${TMPDIR:-/tmp}/plank-forced-integer-dictionary.XXXXXX")
trap 'rm -rf "$work"' EXIT

python3 - "$work" <<'PY'
from pathlib import Path
import sys

out = Path(sys.argv[1])
cases = {
    "int32-v2": (0xF6, 0, 0, 3, 2, 3, 0, 1, 4),
    "int32-v1-small-palette": (0xF6, 1, 0, 7, 0, 6, 5, 2, 8),
    "int64-v1": (0xF6, 1, 1, 6, 4, 5, 3, 2, 5),
    "int64-v2-small-palette": (0xF6, 0, 1, 5, 1, 2, 7, 1, 3),
}
for name, data in cases.items():
    (out / name).write_bytes(bytes(data))
PY

dotnet run --project "$repo/Plank.Fuzzing.Replay" -- writer "$work"
