#!/bin/bash
# usage: run-structured.sh <tag> <shard> <shards> <per-seed> <rng-seed> [pool]
# Seeds: the generated reader corpus (made in local /tmp) + every committed valid-file reader seed dir.
# Output: agents/oracle/runs/st-<tag>.log; findings saved to agents/oracle/sdump/<tag>/.
W=/session/24574813-2a30-4744-ab55-c22a19c29613/workspace
O=$W/agents/oracle; P=$O/Plank-Lab; F=$P/fuzz
export DOTNET_ROOT=$W/.tools/dotnet PATH=$W/.tools/dotnet:$PATH DOTNET_ROLL_FORWARD=Major DOTNET_NOLOGO=1 HOME=/tmp/h DOTNET_GCHeapHardLimit=0xC0000000
mkdir -p /tmp/h
tag=$1; shard=$2; shards=$3; per=$4; rng=$5
[ -n "$6" ] && export PLANK_FUZZ_POOL=$6
B=${STRUCT_BIN:-$O/bin-s1}/Plank.Fuzzing.Replay
mkdir -p /tmp/gen && $P/Plank.Fuzzing.Reader.Target/bin/Release/net10.0/Plank.Fuzzing.Reader.Target --generate-corpus /tmp/gen > /dev/null 2>&1
{ find /tmp/gen -type f; find $F/reader-pyarrow-seeds $F/reader-pqt-seeds $F/reader-gap-generated $F/nested-gap-seeds $F/reader-corpus $F/reader-logical-focus-seeds $F/reader-focused-seeds -type f; } | sort > /tmp/all.list
awk -v s=$shard -v n=$shards 'NR % n == s' /tmp/all.list > /tmp/shard.list
log=$O/runs/st-$tag.log
: > $log
# Chunks of 200 seeds per process so a native crash only loses its chunk.
split -l 200 -d -a 4 /tmp/shard.list /tmp/sc.
for c in /tmp/sc.*; do
  timeout 3600 $B structured $per $rng $O/sdump/$tag $(cat $c) 2>&1 | grep -aE "^(SFINDING|SBASELINE|structured)" | cut -c1-900 >> $log
  rc=${PIPESTATUS[0]}
  [ $rc -ne 0 ] && echo "CHUNKEXIT $rc $(basename $c) first=$(head -1 $c)" >> $log
  rng=$((rng + 1))
done
echo ALLDONE >> $log
