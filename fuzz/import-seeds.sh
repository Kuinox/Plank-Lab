#!/usr/bin/env bash
# Import new seed directories (fuzz/reader-findings/<name>/queue/id:NNNNNN,...)
# into a solo worker's queue. A -S instance only syncs from a -M one, so the solo
# worker never picks them up on its own: stop it, run once as -M with
# AFL_IMPORT_FIRST for a few minutes, then let the caller restart run-fleet.sh.
# Usage: import-seeds.sh [seconds=240] [core=23]
set -u
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SECONDS_TO_RUN="${1:-240}"
CORE="${2:-23}"
"$ROOT/fuzz/stop-worker.sh" main >/dev/null
rm -f "$ROOT/fuzz/.tmp/main/.cur_input"
before=$(grep -o 'corpus_imported *: [0-9]*' "$ROOT/fuzz/reader-findings/main/fuzzer_stats" | grep -o '[0-9]*$')
AFL_SKIP_BIN_CHECK=1 AFL_NO_UI=1 AFL_SKIP_CPUFREQ=1 AFL_AUTORESUME=1 AFL_I_DONT_CARE_ABOUT_MISSING_CRASHES=1 \
AFL_SKIP_CRASHES=1 AFL_IMPORT_FIRST=1 AFL_TMPDIR="$ROOT/fuzz/.tmp/main" DOTNET_DbgEnableMiniDump=0 \
DOTNET_GCHeapHardLimit=0x10000000 PLANK_FUZZ_CRASH_DIR="$ROOT/fuzz/crashes" \
PLANK_FUZZ_DISAGREEMENT_DIR="$ROOT/fuzz/disagreements" \
  timeout -s INT "$SECONDS_TO_RUN" nice -n 19 "$ROOT/fuzz/.afl/bin/afl-fuzz" -b "$CORE" -i "$ROOT/fuzz/reader-corpus" \
    -o "$ROOT/fuzz/reader-findings" -t 1100 -x "$ROOT/fuzz/parquet.dict" -M main -z -- \
    "$ROOT/Plank.Fuzzing.Reader.Target/bin/Release/net10.0/Plank.Fuzzing.Reader.Target" 2>&1 \
  | grep --line-buffered -av 'Fuzzing test case' | grep -a 'ABORT' || true
after=$(grep -o 'corpus_imported *: [0-9]*' "$ROOT/fuzz/reader-findings/main/fuzzer_stats" | grep -o '[0-9]*$')
echo "imported $((after - before)) new entries (corpus_imported $before -> $after)"
