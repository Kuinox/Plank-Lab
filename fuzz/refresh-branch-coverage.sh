#!/usr/bin/env bash
# Capture both fuzz targets across four ISA tiers and refresh the HTML history.
# Usage: fuzz/refresh-branch-coverage.sh [tag]
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TAG="${1:-$(date +%Y%m%dT%H%M%S)}"
mkdir -p "$ROOT/fuzz/coverage/history"

python3 - "$ROOT" "$TAG" > "$ROOT/fuzz/coverage/history/snapshot-$TAG.json" <<'PY'
import datetime
import json
import pathlib
import subprocess
import sys

root = pathlib.Path(sys.argv[1])
def revision(path):
    return subprocess.check_output(['git', '-C', str(path), 'rev-parse', 'HEAD'], text=True).strip()

print(json.dumps({
    'tag': sys.argv[2],
    'started_at': datetime.datetime.now().astimezone().isoformat(timespec='seconds'),
    'lab_revision': revision(root),
    'library_revision': revision(root / 'library' / 'Plank'),
    'reader_seed_count': sum(1 for p in (root / 'fuzz' / 'reader-corpus').iterdir() if p.is_file()),
    'writer_seed_count': sum(1 for p in (root / 'fuzz' / 'corpus').iterdir() if p.is_file()),
}, indent=2))
PY

dotnet build "$ROOT/Plank.Fuzzing.Replay/Plank.Fuzzing.Replay.csproj" \
  -c Release --no-restore -v:q > "$ROOT/fuzz/coverage/history/build-$TAG.log" 2>&1
bash "$ROOT/fuzz/coverage-tiers.sh" "$TAG" reader
bash "$ROOT/fuzz/coverage-tiers.sh" "$TAG" writer
python3 "$ROOT/fuzz/coverage-branch-history.py"
echo "Branch coverage snapshot $TAG is in $ROOT/fuzz/coverage-branch-history.html"
