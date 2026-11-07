#!/usr/bin/env bash
# Replay the reader queue under coverlet once per ISA tier, in parallel on cores 18-21.
# Each tier runs from its own copy of the replay driver: coverlet instruments Plank.dll in
# place, so parallel runs sharing one directory corrupt each other (AccessViolation, 0% reports).
#
# Usage: fuzz/coverage-tiers.sh [tag]     (default tag: today's date)
# Output: fuzz/coverage/history/reader-<tag>-<tier>.{cobertura.xml,json}, run-<tag>-<tier>.txt
set -u
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SRC=$ROOT/Plank.Fuzzing.Replay/bin/Release/net10.0
TAG=${1:-$(date +%Y%m%d)}
OUT=$ROOT/fuzz/coverage/history
WORK=$ROOT/fuzz/.coverage-work
mkdir -p "$OUT" "$WORK"
declare -A ENVS=([avx512]="PLANK_TIER=avx512" [avx2]="DOTNET_EnableAVX512=0" [sse]="DOTNET_EnableAVX2=0" [scalar]="DOTNET_EnableHWIntrinsic=0")
cores=(18 19 20 21); i=0
for tier in avx512 avx2 sse scalar; do
  D=$WORK/replay-$tier; rm -rf "$D"; cp -r "$SRC" "$D"
  ( env ${ENVS[$tier]} PLANK_FUZZ_DISAGREEMENT_DIR=$WORK/disagreements-$tier taskset -c ${cores[$i]} \
      coverlet "$D" --target dotnet --targetargs "$D/Plank.Fuzzing.Replay.dll reader $ROOT/fuzz/reader-findings" \
      --format cobertura --format json --output "$OUT/reader-$TAG-$tier." --include "[Plank]*" \
      > "$OUT/run-$TAG-$tier.txt" 2>&1; echo "$tier exit $?" ) &
  i=$((i+1))
done
wait
