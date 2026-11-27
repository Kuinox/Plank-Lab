#!/usr/bin/env bash
# Replay every committed corpus/seed dir under coverlet for ALL runtime assemblies
# (Plank and the vendored Plank.K4os.LZ4; Plank.Native.Zlib ships only libz.so, no managed code).
# One run per replay target (writer, reader, merger), each from its own driver copy
# (coverlet instruments in place). Output: fuzz/coverage/all/<target>.cobertura.xml + run-<target>.txt
# Usage: fuzz/coverage-all.sh [tag]   (PLANK_FUZZ_MAX_PARALLEL default 2)
set -u
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SRC=$ROOT/Plank.Fuzzing.Replay/bin/Release/net10.0
OUT=$ROOT/fuzz/coverage/all; WORK=$ROOT/fuzz/.coverage-work; mkdir -p "$OUT" "$WORK"
F=$ROOT/fuzz
WRITER_IN="$F/corpus $F/writer-gap-seeds $F/nested-gap-seeds $F/bloom-estimate-seeds $F/buffer-capacity-seeds $F/dataset-operational-seeds $F/dataset-options-seeds $F/optional-dictionary-index-seeds $F/schema-equality-seeds $F/repros $F/writer-gap-findings"
READER_IN="$F/decompressor-seeds $F/reader-corpus $F/reader-focused-seeds $F/reader-gap-seeds $F/reader-logical-focus-seeds $F/reader-fixedwidth-samples"
MERGER_IN="$F/corpus $F/writer-gap-seeds $F/dataset-operational-seeds $F/dataset-options-seeds"
# ISA tiers: default = the host's best (ovh: AVX2+BMI2, no AVX512); avx2off drops AVX2 (SSE paths);
# scalar disables all intrinsics (portable fallbacks). AVX512 kernels need an AVX512 host (not ovh).
# Stage the writer/merger inputs as symlinks minus fuzz/coverage-skip.txt (inputs that segfault the process).
stage() { # name dirs...
  local name=$1; shift; local S=$WORK/stage-$name; rm -rf "$S"; mkdir -p "$S"
  local skip; skip=$(grep -v '^#' "$F/coverage-skip.txt" | sed '/^$/d')
  for d in "$@"; do
    [ -d "$d" ] || continue
    while IFS= read -r f; do
      rel=${f#$F/}; grep -qxF "$rel" <<<"$skip" && continue
      ln -s "$f" "$S/$(echo "$rel" | tr '/' '_')"
    done < <(find "$d" -type f)
  done
  echo "$S"
}
WRITER_IN=$(stage writer $WRITER_IN)
MERGER_IN=$(stage merger $MERGER_IN)
run() { # target inputs tier envassignment
  local t=$1 in=$2 tier=$3 e=$4 D=$WORK/all-$1-$3 suffix=""; [ "$tier" = default ] || suffix="-$tier"
  rm -rf "$D"; cp -r "$SRC" "$D"
  env $e PLANK_FUZZ_ENABLE_ROW_WORKERS=1 PLANK_FUZZ_CONTINUE_ON_CRASH=1 \
  coverlet "$D" --target dotnet --targetargs "$D/Plank.Fuzzing.Replay.dll $t $in" \
    --format cobertura --output "$OUT/$t$suffix." --include "[Plank]*" --include "[Plank.K4os*]*" \
    > "$OUT/run-$t$suffix.txt" 2>&1; echo "$t/$tier exit $?"
}
for tier in "default X=1" "avx2off DOTNET_EnableAVX2=0" "scalar DOTNET_EnableHWIntrinsic=0"; do
  set -- $tier
  run writer "$WRITER_IN" $1 "$2" & run reader "$READER_IN" $1 "$2" & wait
  run merger "$MERGER_IN" $1 "$2"
done
