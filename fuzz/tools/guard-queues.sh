#!/usr/bin/env bash
# Replay AFL queues under PLANK_FUZZ_GUARD (snapshot first: live workers rewrite them).
# Usage: guard-queues.sh <replay.tgz> <out-dir> <mode end|start> <tier> <afl-out-dir> (expects <afl-out>/{reader,writer}/*/queue)
set -u
TGZ="$1"; OUT="$2"; MODE="$3"; TIER="$4"; AFL="$5"
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
export DOTNET_ROOT=${DOTNET_ROOT:-/session/24574813-2a30-4744-ab55-c22a19c29613/workspace/.tools/dotnet} DOTNET_ROLL_FORWARD=Major
export DOTNET_gcServer=0 DOTNET_GCHeapHardLimit=0x60000000
ulimit -c 0
T=$(mktemp -d); trap 'rm -rf "$T"' EXIT
tar -xzf "$TGZ" -C "$T"; RP="$T/net10.0"
for k in reader writer; do mkdir -p "$T/q/$k"; for q in "$AFL"/$k/*/queue; do w=$(basename "$(dirname "$q")"); cp -r "$q" "$T/q/$k/$w" 2>/dev/null; done; done
O="$OUT/$MODE-$TIER"; mkdir -p "$O"
PY="python3 -I $ROOT/fuzz/tools/guard-replay.py $RP"
$PY "$O/reader-queues" reader "$MODE" "$TIER" "$T/q/reader"
$PY "$O/writer-queues" writer "$MODE" "$TIER" "$T/q/writer"
$PY "$O/merger-queues" merger "$MODE" "$TIER" "$T/q/writer"
cat "$O"/*/summary.txt
