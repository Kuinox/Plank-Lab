#!/usr/bin/env bash
# Builds the isolated probe project, drops every schema the generator rejected (classify), and repeats until the
# probe compiles. Run under the build lock: flock $W/agents/build2.lock bash fuzz/tools/probe-random-schemas.sh
set -u
cd "$(dirname "$0")/../.."
PROBE=fuzz/probe/SchemaProbe
previous=-1
for round in 1 2 3 4 5 6; do
  rm -rf "$PROBE/obj/generated"
  dotnet build "$PROBE" -c Release -m:2 -nodeReuse:false > "$PROBE/build.log" 2>&1
  errors=$(grep -c " error " "$PROBE/build.log")
  echo "round $round: $errors error lines, $(ls $PROBE/Schemas/*.cs | wc -l) schemas"
  [ "$errors" = 0 ] && exit 0
  # No progress: the remaining errors are not attributable to a schema (a harness problem), stop instead of looping.
  [ "$errors" = "$previous" ] && { echo "no progress; see $PROBE/build.log"; exit 1; }
  previous=$errors
  python3 fuzz/tools/gen_random_schemas.py classify --log "$PROBE/build.log" --generated "$PROBE/obj/generated" --schemas "$PROBE/Schemas" | head -12
done
exit 1
