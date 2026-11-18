#!/usr/bin/env bash
set -euo pipefail

repo=$(cd "$(dirname "$0")/.." && pwd)
work=$(mktemp -d "${TMPDIR:-/tmp}/plank-writer-converter-gap.XXXXXX")
trap 'rm -rf "$work"' EXIT

python3 - "$work" <<'PY'
from pathlib import Path
import sys

directory = Path(sys.argv[1])
(directory / "value-converters-v2").write_bytes(bytes((0xF9, 6, 0, 137, 2, 0x2A, 1)))
(directory / "value-converters-v1").write_bytes(bytes((0xF9, 8, 1, 105, 5, 0xA5, 2)))
PY

dotnet run --project "$repo/Plank.Fuzzing.Replay" -- writer "$work"
