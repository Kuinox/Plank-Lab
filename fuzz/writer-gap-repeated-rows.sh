#!/usr/bin/env bash
set -euo pipefail

repo=$(cd "$(dirname "$0")/.." && pwd)
work=$(mktemp -d "${TMPDIR:-/tmp}/plank-writer-repeated-gap.XXXXXX")
trap 'rm -rf "$work"' EXIT

python3 - "$work" <<'PY'
from pathlib import Path
import sys

directory = Path(sys.argv[1])
(directory / "repeated-rows-v2").write_bytes(bytes((0xFA, 0, 6, 3, 2, 1, 99)))
(directory / "repeated-rows-v1").write_bytes(bytes((0xFA, 1, 4, 1, 4, 0, 33)))
(directory / "optional-list-v2").write_bytes(bytes((0xFA, 4, 5, 2, 1, 7, 3)))
(directory / "nested-list-v2").write_bytes(bytes((0xFA, 2, 6, 3, 2, 1, 9, 4)))
(directory / "nested-list-v1").write_bytes(bytes((0xFA, 3, 4, 1, 5, 3, 17)))
PY

dotnet run --project "$repo/Plank.Fuzzing.Replay" -- writer "$work"
