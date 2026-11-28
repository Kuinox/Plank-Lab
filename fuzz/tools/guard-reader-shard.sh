#!/usr/bin/env bash
# One reader-focused guard shard: reader seeds + decoder mutants, structure-aware page mutants (structured mode,
# uncompressed rewritten pages), and the AFL reader queues, under PLANK_FUZZ_GUARD=<mode> and one ISA tier.
# Needs a replay build made with -p:PlankGuardArrays=true (exact borrowed ranges, page and scratch buffers).
# Usage: guard-reader-shard.sh <replay.tgz> <out-dir> <end|start> <tier> <decoder-mutants> <structured-per-seed> <seed-base> [afl-out-dir]
set -u
TGZ="$1"; OUT="$2"; MODE="$3"; TIER="$4"; RM="$5"; PER="$6"; BASE="$7"; AFL="${8:-}"
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
export DOTNET_ROOT=${DOTNET_ROOT:-/session/24574813-2a30-4744-ab55-c22a19c29613/workspace/.tools/dotnet} DOTNET_ROLL_FORWARD=Major
export DOTNET_gcServer=0 DOTNET_GCHeapHardLimit=${DOTNET_GCHeapHardLimit:-0x60000000}
ulimit -c 0
GUARD_TARGETS=reader bash "$ROOT/fuzz/tools/guard-campaign.sh" "$TGZ" "$OUT" "$MODE" "$TIER" "$RM" 0 "$BASE"
[ -n "$AFL" ] && GUARD_TARGETS=reader bash "$ROOT/fuzz/tools/guard-queues.sh" "$TGZ" "$OUT/queues" "$MODE" "$TIER" "$AFL"
T=$(mktemp -d); trap 'rm -rf "$T"' EXIT
tar -xzf "$TGZ" -C "$T"; mkdir -p "$T/s"; git -C "$ROOT" archive HEAD fuzz | tar -x -C "$T/s"; F="$T/s/fuzz"
DIRS=$(find "$F" -mindepth 1 -maxdepth 1 -type d -name 'reader*' | sort)
python3 -I "$ROOT/fuzz/tools/guard-structured.py" "$T/net10.0" "$OUT/structured/$MODE-$TIER" "$MODE" "$TIER" "$PER" "$BASE" $DIRS
echo "READER-SHARD-DONE $MODE $TIER"
