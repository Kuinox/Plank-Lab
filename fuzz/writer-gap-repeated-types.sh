#!/usr/bin/env bash
set -euo pipefail

repo=$(cd "$(dirname "$0")/.." && pwd)
work=$(mktemp -d "${TMPDIR:-/tmp}/plank-repeated-type-gap.XXXXXX")
trap 'rm -rf "$work"' EXIT

python3 - "$work" <<'PY'
from pathlib import Path
import sys

out = Path(sys.argv[1])
cases = {
    "bool-required-v2": (0xFA, 0x08, 3, 71, 9, 42, 15, 90),
    "bool-optional-v1": (0xFA, 0x0D, 5, 81, 6, 33, 47, 12, 98),
    "int64-required-v2": (0xFA, 0x10, 4, 119, 6, 11, 92, 56),
    "int64-optional-v1": (0xFA, 0x15, 6, 19, 32, 76, 4, 190, 51),
    "float-required-v1": (0xFA, 0x19, 5, 211, 21, 8, 146),
    "float-optional-v2": (0xFA, 0x1C, 4, 78, 41, 2, 120, 33),
    "double-required-v2": (0xFA, 0x20, 6, 57, 11, 93, 204, 35),
    "double-optional-v1": (0xFA, 0x25, 3, 109, 28, 171, 43, 88, 17),
    "binary-required-v2": (0xFA, 0x28, 5, 36, 80, 17, 225, 53, 8),
    "binary-optional-v2": (0xFA, 0x2C, 5, 129, 63, 41, 14, 222, 53),
    "nested-bool-v2": (0xFA, 0x0A, 4, 29, 17, 66, 5, 212, 30),
    "nested-int64-v1": (0xFA, 0x13, 5, 92, 33, 17, 76, 3, 128),
    "nested-float-v2": (0xFA, 0x1A, 3, 31, 17, 251, 48, 90),
    "nested-double-v1": (0xFA, 0x23, 6, 114, 45, 23, 83, 2, 63),
}
for name, data in cases.items():
    (out / name).write_bytes(bytes(data))
PY

dotnet run --project "$repo/Plank.Fuzzing.Replay" -- writer "$work"
