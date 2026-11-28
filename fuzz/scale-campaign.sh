#!/bin/bash
# Run a Plank.Fuzzing.Scale campaign (meant for job_submit; see fuzz/notes/size-thresholds.md).
#   fuzz/scale-campaign.sh <mode> <seed0> <count> <tier> <logfile>
# The driver must be built first (dotnet build Plank.Fuzzing.Scale -c Release). Scratch files go to $SCALE_TMP (/tmp).
set -u
W=${W:-/session/24574813-2a30-4744-ab55-c22a19c29613/workspace}
export DOTNET_ROOT=${DOTNET_ROOT:-$W/.tools/dotnet} DOTNET_ROLL_FORWARD=Major DOTNET_gcServer=0
ulimit -c 0
here=$(cd "$(dirname "$0")/.." && pwd)
# Run from a private copy so a rebuild of the driver cannot change files under a running campaign.
bin=$(mktemp -d /tmp/scale-bin.XXXXXX)
cp -r "$here/Plank.Fuzzing.Scale/bin/Release/net10.0/." "$bin/"
trap 'rm -rf "$bin"' EXIT
nice "$bin/Plank.Fuzzing.Scale" campaign "$1" "$2" "$3" "$4" "$5"
