#!/usr/bin/env bash
set -euo pipefail

repo=$(cd "$(dirname "$0")/.." && pwd)
work=$(mktemp -d "${TMPDIR:-/tmp}/plank-seed-gap.XXXXXX")
trap 'rm -rf "$work"' EXIT

generated="$work/generated"
selected="$work/selected"
mkdir -p "$selected"

dotnet run --project "$repo/Plank.Fuzzing.Reader.Target" -- --generate-corpus "$generated"
for pattern in \
    gen-fragmented-i32-none.bin \
    gen-fragmented-multipage-dict.bin \
    gen-fragmented-crc-i32-opt-snappy-v2.bin; do
    test -f "$generated/$pattern"
    cp "$generated/$pattern" "$selected/"
done

dotnet run --project "$repo/Plank.Fuzzing.Replay" -- reader "$selected"
