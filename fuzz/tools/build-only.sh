#!/bin/bash
# Build the replay driver into bin-s (build2.lock, build only), then snapshot it to bin-s2.
W=/session/24574813-2a30-4744-ab55-c22a19c29613/workspace
O=$W/agents/oracle; P=$O/Plank-Lab
export DOTNET_ROOT=$W/.tools/dotnet PATH=$W/.tools/dotnet:$PATH DOTNET_CLI_TELEMETRY_OPTOUT=1 DOTNET_ROLL_FORWARD=Major DOTNET_NOLOGO=1 MSBUILDDISABLENODEREUSE=1 HOME=$W
cd $P
flock $W/agents/build2.lock dotnet build Plank.Fuzzing.Replay -p:UseSharedCompilation=false -p:RunAnalyzers=false -p:EnforceCodeStyleInBuild=false -c Release -m:1 -nodeReuse:false -o $O/bin-s > $O/runs/build.log 2>&1
echo "exit $?" >> $O/runs/build.log
grep -q "^exit 0" $O/runs/build.log || exit 1
rm -rf $O/bin-s2 && cp -r $O/bin-s $O/bin-s2 && echo "snapshot bin-s2" >> $O/runs/build.log
