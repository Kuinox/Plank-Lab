#!/bin/bash
export DOTNET_ROOT=$W/.tools/dotnet PATH=$W/.tools/dotnet:$W/.dotnet/tools:$PATH DOTNET_ROLL_FORWARD=Major DOTNET_NOLOGO=1
cd $R/Plank-Lab; F=fuzz
IN="$R/gen5 $F/reader-corpus $F/reader-gap-generated $F/reader-pyarrow-seeds $F/reader-footer-seeds $F/reader-pqt-seeds $F/reader-focused-seeds $F/reader-gap-seeds $F/reader-logical-focus-seeds"
D=$R/cov-t; rm -rf $D; cp -r Plank.Fuzzing.Replay/bin/Release/net10.0 $D
while read name envs; do
  env $envs PLANK_FUZZ_CONTINUE_ON_CRASH=1 coverlet $D --target dotnet --targetargs "$D/Plank.Fuzzing.Replay.dll reader $IN" --format cobertura --output $R/covout/u-$name. --include "[Plank]*" > $R/cov-u-$name.log 2>&1
  echo "$name $(grep ^done $R/cov-u-$name.log | cut -c1-90)" >> $R/tiers.out
done <<'T'
default X=1
flagsall PLANK_FUZZ_ISA_MASK=all
avx2off DOTNET_EnableAVX2=0
avx2off-flagsall DOTNET_EnableAVX2=0 PLANK_FUZZ_ISA_MASK=all
vec128 DOTNET_PreferredVectorBitWidth=128
scalar DOTNET_EnableHWIntrinsic=0
scalar-flagsall DOTNET_EnableHWIntrinsic=0 PLANK_FUZZ_ISA_MASK=all
T
echo ALLDONE >> $R/tiers.out
