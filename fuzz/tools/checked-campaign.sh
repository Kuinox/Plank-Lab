#!/usr/bin/env bash
# One checked-access replay shard (Plank.Fuzzing.Checked/README.md) for one ISA tier: every committed seed directory
# through reader/writer/merger, mutated reader/writer seeds, structure-aware page mutants, and optionally AFL queues.
# Restart-safe (checked-replay.py / guard-structured.py record finished batches).
# Usage: checked-campaign.sh <checked-replay.tgz> <out-dir> <tier> <reader-mutants> <writer-mutants> <structured-per-seed> <seed-base> [<afl-out-dir>]
#   <afl-out-dir> expects <afl-out>/{reader,writer}/*/queue (snapshotted first: live workers rewrite them).
# CHECKED_PARTS="seeds mutants structured queues" (default all) limits the shard.
set -u
TGZ="$1"; OUT="$2"; TIER="$3"; RM="$4"; WM="$5"; SM="$6"; BASE="$7"; AFL="${8:-}"
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
export DOTNET_ROOT=${DOTNET_ROOT:-/session/24574813-2a30-4744-ab55-c22a19c29613/workspace/.tools/dotnet} DOTNET_ROLL_FORWARD=Major
export DOTNET_gcServer=0 DOTNET_GCHeapHardLimit=${DOTNET_GCHeapHardLimit:-0x80000000}
ulimit -c 0
T=$(mktemp -d); trap 'rm -rf "$T"' EXIT
tar -xzf "$TGZ" -C "$T"; RP="$T/net10.0"
mkdir -p "$T/s"; git -C "$ROOT" archive HEAD fuzz | tar -x -C "$T/s"; F="$T/s/fuzz"
O="$OUT/$TIER"; mkdir -p "$O"
PY="python3 -I $ROOT/fuzz/tools/checked-replay.py $RP"
part() { case " ${CHECKED_PARTS:-seeds mutants structured queues} " in *" $1 "*) return 0;; *) return 1;; esac; }
READER_DIRS=$(find "$F" -mindepth 1 -maxdepth 1 -type d ! -name notes ! -name tools ! -name 'tools-*' | sort)
WRITER_DIRS="$F/corpus $F/writer-gap-seeds $F/writer-gap-findings $F/nested-gap-seeds $F/execution-seeds $F/buffer-capacity-seeds $F/schema-equality-seeds $F/decompressor-seeds $F/repros"
if part seeds; then
  $PY "$O/reader-seeds" reader "$TIER" $READER_DIRS
  $PY "$O/writer-seeds" writer "$TIER" $WRITER_DIRS
  $PY "$O/merger-seeds" merger "$TIER" $F/corpus $F/writer-gap-seeds $F/repros
fi
if part mutants; then
  if [ "$RM" -gt 0 ]; then
    python3 -I "$F/mutate-decoder-seeds.py" "$T/rm" "$RM" "$BASE" $(find $F/reader-gap-generated $F/reader-corpus $F/reader-pyarrow-seeds $F/reader-pqt-seeds $F/reader-focused-seeds $F/reader-footer-seeds $F/reader-resource-seeds -type f -size -6001c | sort) >/dev/null
    $PY "$O/reader-mutants-$BASE" reader "$TIER" "$T/rm"
  fi
  if [ "$WM" -gt 0 ]; then
    python3 -I "$ROOT/fuzz/tools/guard-mutate-writer.py" "$T/wm" "$WM" "$((BASE + 7))" $(find $F/corpus $F/writer-gap-seeds $F/nested-gap-seeds $F/execution-seeds $F/buffer-capacity-seeds -type f | sort) >/dev/null
    $PY "$O/writer-mutants-$BASE" writer "$TIER" "$T/wm"
    $PY "$O/merger-mutants-$BASE" merger "$TIER" "$T/wm"
  fi
fi
if part structured && [ "$SM" -gt 0 ]; then
  # Structured page mutants (UNCOMPRESSED and compressed seeds alike): a violation FailFasts, guard-structured.py keeps
  # the mutant (<out>/deaths/), and the chunk resumes with the next seed. Guard mode `end` is on too (deeper, slower).
  PLANK_CHECKED_FAILFAST=1 DOTNET_GCgen0size=0x10000000 python3 -I "$ROOT/fuzz/tools/guard-structured.py" "$RP" "$O/structured-$BASE" end "$TIER" "$SM" "$BASE" \
    $F/reader-pyarrow-seeds $F/reader-pqt-seeds $F/reader-corpus $F/corpus $F/reader-gap-generated $F/reader-converter-seeds
fi
if part queues && [ -n "$AFL" ]; then
  for k in reader writer; do mkdir -p "$T/q/$k"; for q in "$AFL"/$k/*/queue; do w=$(basename "$(dirname "$q")"); cp -r "$q" "$T/q/$k/$w" 2>/dev/null; done; done
  $PY "$O/reader-queues" reader "$TIER" "$T/q/reader"
  $PY "$O/writer-queues" writer "$TIER" "$T/q/writer"
  $PY "$O/merger-queues" merger "$TIER" "$T/q/writer"
fi
cat "$O"/*/summary.txt
echo "SHARD-DONE $TIER"
