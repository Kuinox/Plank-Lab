#!/usr/bin/env bash
set -euo pipefail

repo=$(cd "$(dirname "$0")/.." && pwd)
work=$(mktemp -d "${TMPDIR:-/tmp}/plank-optional-timestamp-gap.XXXXXX")
trap 'rm -rf "$work"' EXIT

python3 - "$work" <<'PY'
from pathlib import Path
import sys

out = Path(sys.argv[1])
cases = {
    "millis-v2": (0xF5, 0, 56, 137, 128, 5, 1, 0),
    "millis-v1": (0xF5, 1, 43, 200, 100, 3, 2, 2),
    "micros-v2": (0xF5, 2, 50, 17, 50, 6, 4, 1),
    "utc-v2": (0xF5, 4, 38, 77, 210, 9, 6, 0),
    "utc-indexed-v1": (0xF5, 15, 54, 99, 30, 4, 1, 2),
    "all-null-v2": (0xF5, 0x20, 56, 137, 128, 5, 1, 0),
    "empty-v1": (0xF5, 0x11, 43, 200, 100, 3, 2, 2),
    "empty-micros-utc": (0xF5, 0x37, 54, 99, 30, 4, 1, 2),
}
for name, data in cases.items():
    (out / name).write_bytes(bytes(data))
PY

dotnet run --project "$repo/Plank.Fuzzing.Replay" -- writer "$work"
