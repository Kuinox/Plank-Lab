#!/usr/bin/env bash
set -euo pipefail

repo=$(cd "$(dirname "$0")/.." && pwd)
work=$(mktemp -d "${TMPDIR:-/tmp}/plank-writer-gap.XXXXXX")
trap 'rm -rf "$work"' EXIT

python3 - "$work" <<'PY'
from pathlib import Path
import sys

directory = Path(sys.argv[1])
(directory / "optional-double-dictionary-v2").write_bytes(bytes((0xFB, 0, 7, 2, 0, 0, 1)))
(directory / "optional-double-dictionary-v1").write_bytes(bytes((0xFB, 1, 10, 4, 3, 5, 2)))
PY

dotnet run --project "$repo/Plank.Fuzzing.Replay" -- writer "$work"
