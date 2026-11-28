#!/usr/bin/env bash
# One guard-mode replay shard: every committed seed directory through reader/writer/merger, then structure-aware
# mutants, under PLANK_FUZZ_GUARD=<mode> and one ISA tier. Restart-safe (guard-replay.py records finished batches).
# Usage: guard-campaign.sh <replay.tgz> <out-dir> <mode end|start> <tier> <reader-mutants> <writer-mutants> <seed-base>
set -u
TGZ="$1"; OUT="$2"; MODE="$3"; TIER="$4"; RM="$5"; WM="$6"; BASE="$7"
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
export DOTNET_ROOT=${DOTNET_ROOT:-/session/24574813-2a30-4744-ab55-c22a19c29613/workspace/.tools/dotnet} DOTNET_ROLL_FORWARD=Major
export DOTNET_gcServer=0 DOTNET_GCHeapHardLimit=0x60000000
ulimit -c 0
T=$(mktemp -d); trap 'rm -rf "$T"' EXIT
tar -xzf "$TGZ" -C "$T"; RP="$T/net10.0"
# Seeds straight from git: the clone may be sparse.
mkdir -p "$T/s"; git -C "$ROOT" archive HEAD fuzz | tar -x -C "$T/s"; F="$T/s/fuzz"
O="$OUT/$MODE-$TIER"; mkdir -p "$O"
PY="python3 -I $ROOT/fuzz/tools/guard-replay.py $RP"
# GUARD_TARGETS="reader writer merger" (default all) limits the shard to some targets.
want() { case " ${GUARD_TARGETS:-reader writer merger} " in *" $1 "*) return 0;; *) return 1;; esac; }
READER_DIRS=$(find "$F" -mindepth 1 -maxdepth 1 -type d ! -name notes ! -name tools ! -name 'tools-*' | sort)
WRITER_DIRS="$F/corpus $F/writer-gap-seeds $F/writer-gap-findings $F/nested-gap-seeds $F/execution-seeds $F/buffer-capacity-seeds $F/schema-equality-seeds $F/decompressor-seeds $F/repros"
want reader && $PY "$O/reader-seeds" reader "$MODE" "$TIER" $READER_DIRS
want writer && $PY "$O/writer-seeds" writer "$MODE" "$TIER" $WRITER_DIRS
want merger && $PY "$O/merger-seeds" merger "$MODE" "$TIER" $F/corpus $F/writer-gap-seeds $F/repros
if [ "$RM" -gt 0 ] && want reader; then
  python3 -I "$F/mutate-decoder-seeds.py" "$T/rm" "$RM" "$BASE" $(find $F/reader-gap-generated $F/reader-corpus $F/reader-pyarrow-seeds $F/reader-pqt-seeds $F/reader-focused-seeds $F/reader-footer-seeds $F/reader-resource-seeds -type f -size -6001c | sort) >/dev/null
  $PY "$O/reader-mutants-$BASE" reader "$MODE" "$TIER" "$T/rm"
fi
if [ "$WM" -gt 0 ]; then
  python3 -I "$ROOT/fuzz/tools/guard-mutate-writer.py" "$T/wm" "$WM" "$((BASE + 7))" $(find $F/corpus $F/writer-gap-seeds $F/nested-gap-seeds $F/execution-seeds $F/buffer-capacity-seeds -type f | sort) >/dev/null
  want writer && $PY "$O/writer-mutants-$BASE" writer "$MODE" "$TIER" "$T/wm"
  want merger && $PY "$O/merger-mutants-$BASE" merger "$MODE" "$TIER" "$T/wm"
fi
cat "$O"/*/summary.txt
echo "SHARD-DONE $MODE $TIER"
