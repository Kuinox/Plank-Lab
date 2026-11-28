#!/bin/bash
# Waits for build-only.sh to snapshot bin-s2, then runs run-structured.sh with stacked mutations.
O=/session/24574813-2a30-4744-ab55-c22a19c29613/workspace/agents/oracle
for i in $(seq 1 720); do grep -q "snapshot bin-s2" $O/runs/build.log 2>/dev/null && break; sleep 30; done
grep -q "snapshot bin-s2" $O/runs/build.log || { echo "no build"; exit 1; }
export STRUCT_BIN=$O/bin-s2 PLANK_FUZZ_STACK=${STACK:-3}
bash $O/run-structured.sh "$@"
