#!/usr/bin/env bash
set -euo pipefail

repo=$(cd "$(dirname "$0")/.." && pwd)
seeds="$repo/fuzz/writer-gap-seeds/compression-levels"
dotnet run --project "$repo/Plank.Fuzzing.Replay" -- writer "$seeds"
