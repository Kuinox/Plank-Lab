#!/usr/bin/env bash
# Replay a fuzz queue under coverlet once per ISA tier, in parallel on cores 18-21.
# Each tier runs from its own copy of the replay driver: coverlet instruments Plank.dll in
# place, so parallel runs sharing one directory corrupt each other (AccessViolation, 0% reports).
#
# Usage: fuzz/coverage-tiers.sh [tag] [reader|writer]
# Output: fuzz/coverage/history/<target>-<tag>-<tier>.{cobertura.xml,json}, run-<target>-<tag>-<tier>.txt
# Set PLANK_FUZZ_KEEP_SNAPSHOT=1 to retain the frozen input tree for per-input
# coverage provenance; queue inputs are hard-linked, while mutable seeds are copied.
# Set PLANK_FUZZ_REUSE_SNAPSHOT=1 to retry the same retained input tree.
# Set PLANK_FUZZ_MAX_PARALLEL=1 or 2 to bound peak memory use.
set -u
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SRC=$ROOT/Plank.Fuzzing.Replay/bin/Release/net10.0
TAG=${1:-$(date +%Y%m%d)}
TARGET=${2:-reader}
for project in Plank.Fuzzing Plank.Fuzzing.Replay; do
  dll=$SRC/$project.dll
  if [ ! -f "$dll" ]; then
    echo "missing Release replay artifact: $dll" >&2
    exit 1
  fi
  newer=$(find "$ROOT/$project" -path '*/bin' -prune -o -path '*/obj' -prune -o \
    -type f \( -name '*.cs' -o -name '*.csproj' \) -newer "$dll" -print -quit)
  if [ -n "$newer" ]; then
    echo "Release replay artifact is older than source: $newer" >&2
    echo "build Plank.Fuzzing.Replay with -c Release before measuring coverage" >&2
    exit 1
  fi
done
library_dll=$SRC/Plank.dll
if [ ! -f "$library_dll" ]; then
  echo "missing Release library artifact: $library_dll" >&2
  exit 1
fi
newer_library=$(find "$ROOT/library/Plank/Plank" -path '*/bin' -prune -o -path '*/obj' -prune -o \
  -type f \( -name '*.cs' -o -name '*.csproj' \) -newer "$library_dll" -print -quit)
if [ -n "$newer_library" ]; then
  echo "Release library artifact is older than source: $newer_library" >&2
  echo "build Plank.Fuzzing.Replay with -c Release before measuring coverage" >&2
  exit 1
fi
case "$TARGET" in
  reader) FINDINGS="$ROOT/fuzz/reader-findings"; SEEDS="$ROOT/fuzz/reader-corpus" ;;
  writer) FINDINGS="$ROOT/fuzz/writer-findings"; SEEDS="$ROOT/fuzz/corpus" ;;
  *) echo "expected reader or writer target, got '$TARGET'" >&2; exit 2 ;;
esac
OUT=$ROOT/fuzz/coverage/history
WORK=$ROOT/fuzz/.coverage-work
mkdir -p "$OUT" "$WORK"
SNAPSHOT="$WORK/snapshot-$TARGET-$TAG"
REUSE_SNAPSHOT=${PLANK_FUZZ_REUSE_SNAPSHOT:-0}
if [ "$REUSE_SNAPSHOT" = 1 ]; then
  if [ ! -d "$SNAPSHOT/findings" ] || [ ! -d "$SNAPSHOT/seeds" ]; then
    echo "retained snapshot missing findings or seeds: $SNAPSHOT" >&2
    exit 1
  fi
else
  rm -rf "$SNAPSHOT"
  mkdir -p "$SNAPSHOT"
fi
if [ "${PLANK_FUZZ_KEEP_SNAPSHOT:-0}" != 1 ] && [ "$REUSE_SNAPSHOT" != 1 ]; then
  trap 'rm -rf "$SNAPSHOT"' EXIT
fi
# AFL can grow or rotate the live queue while four independent replays run.
# Freeze one input set first, so their merged coverage has a consistent scope.
if [ "$REUSE_SNAPSHOT" != 1 ]; then
  python3 "$ROOT/fuzz/snapshot-corpus.py" "$FINDINGS" "$SNAPSHOT/findings" || exit 1
  python3 "$ROOT/fuzz/snapshot-corpus.py" "$SEEDS" "$SNAPSHOT/seeds" --copy || exit 1
fi
INPUTS="$SNAPSHOT/findings $SNAPSHOT/seeds"
ROW_WORKERS=0
if [ "$TARGET" = reader ]; then
  # Replay can exercise row-reader workers without concurrent SharpFuzz bitmap
  # writes; the live AFL target leaves this opt-in disabled.
  ROW_WORKERS=1
fi
if [ "$TARGET" = writer ]; then
  # Keep focused seeds in replay even when a noisy marker is withheld from AFL.
  if [ "$REUSE_SNAPSHOT" != 1 ]; then
    python3 "$ROOT/fuzz/snapshot-corpus.py" "$ROOT/fuzz/writer-gap-seeds" "$SNAPSHOT/gap-seeds" --copy || exit 1
  elif [ ! -d "$SNAPSHOT/gap-seeds" ]; then
    echo "retained writer gap-seeds missing: $SNAPSHOT" >&2
    exit 1
  fi
  INPUTS="$INPUTS $SNAPSHOT/gap-seeds"
  # Prior campaigns remain part of the coverage union after their live queues
  # are rotated. Each archive gets its own path in this frozen input set.
  if [ "$REUSE_SNAPSHOT" != 1 ]; then
    for ARCHIVE in "$ROOT"/fuzz/writer-findings-archive-*; do
      [ -d "$ARCHIVE" ] || continue
      name="$(basename "$ARCHIVE")"
      python3 "$ROOT/fuzz/snapshot-corpus.py" "$ARCHIVE" "$SNAPSHOT/$name" || exit 1
    done
  fi
  for ARCHIVE in "$SNAPSHOT"/writer-findings-archive-*; do
    [ -d "$ARCHIVE" ] || continue
    INPUTS="$INPUTS $ARCHIVE"
  done
fi
declare -A ENVS=([avx512]="PLANK_TIER=avx512" [avx2]="DOTNET_EnableAVX512=0" [sse]="DOTNET_EnableAVX2=0" [scalar]="DOTNET_EnableHWIntrinsic=0")
MAX_PARALLEL=${PLANK_FUZZ_MAX_PARALLEL:-4}
if ! [[ "$MAX_PARALLEL" =~ ^[1-4]$ ]]; then
  echo "PLANK_FUZZ_MAX_PARALLEL must be 1, 2, 3, or 4" >&2
  exit 2
fi
cores=(18 19 20 21); i=0; pids=(); result=0
for tier in avx512 avx2 sse scalar; do
  D=$WORK/replay-$tier; rm -rf "$D"; cp -r "$SRC" "$D"
  ( env ${ENVS[$tier]} PLANK_FUZZ_ENABLE_ROW_WORKERS=$ROW_WORKERS PLANK_FUZZ_CONTINUE_ON_CRASH=1 PLANK_FUZZ_DISAGREEMENT_DIR=$WORK/disagreements-$tier taskset -c ${cores[$i]} \
      coverlet "$D" --target dotnet --targetargs "$D/Plank.Fuzzing.Replay.dll $TARGET $INPUTS" \
      --format cobertura --format json --output "$OUT/$TARGET-$TAG-$tier." --include "[Plank]*" \
      > "$OUT/run-$TARGET-$TAG-$tier.txt" 2>&1; rc=$?; echo "$tier exit $rc"; exit "$rc" ) &
  pids+=("$!")
  i=$((i+1))
  if [ "${#pids[@]}" -ge "$MAX_PARALLEL" ]; then
    wait "${pids[0]}" || result=1
    pids=("${pids[@]:1}")
  fi
done
for pid in "${pids[@]}"; do
  wait "$pid" || result=1
done
exit "$result"
