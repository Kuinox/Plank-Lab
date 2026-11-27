#!/bin/bash
# restart-safe: each tier writes <name>.part then renames; finished tiers are skipped
W=/session/24574813-2a30-4744-ab55-c22a19c29613/workspace; R=/session/24574813-2a30-4744-ab55-c22a19c29613/workspace/agents/reader-c; O=$R/avx512
export DOTNET_ROOT=$W/.tools/dotnet PATH=$W/.tools/dotnet:$W/.dotnet/tools:$PATH DOTNET_ROLL_FORWARD=Major DOTNET_NOLOGO=1 DOTNET_CLI_TELEMETRY_OPTOUT=1 HOME=/tmp/h-$$
mkdir -p $HOME
grep -m1 "model name" /proc/cpuinfo > $O/cpu.txt; grep -m1 flags /proc/cpuinfo | tr ' ' '\n' | grep -E "^avx|^bmi|^vaes|^gfni|^vpclmul" | sort | tr '\n' ' ' >> $O/cpu.txt
IN="$R/gen5 /session/24574813-2a30-4744-ab55-c22a19c29613/workspace/agents/reader-c/Plank-Lab/fuzz/reader-corpus /session/24574813-2a30-4744-ab55-c22a19c29613/workspace/agents/reader-c/Plank-Lab/fuzz/reader-gap-generated /session/24574813-2a30-4744-ab55-c22a19c29613/workspace/agents/reader-c/Plank-Lab/fuzz/reader-pyarrow-seeds /session/24574813-2a30-4744-ab55-c22a19c29613/workspace/agents/reader-c/Plank-Lab/fuzz/reader-footer-seeds /session/24574813-2a30-4744-ab55-c22a19c29613/workspace/agents/reader-c/Plank-Lab/fuzz/reader-pqt-seeds /session/24574813-2a30-4744-ab55-c22a19c29613/workspace/agents/reader-c/Plank-Lab/fuzz/reader-focused-seeds /session/24574813-2a30-4744-ab55-c22a19c29613/workspace/agents/reader-c/Plank-Lab/fuzz/reader-gap-seeds /session/24574813-2a30-4744-ab55-c22a19c29613/workspace/agents/reader-c/Plank-Lab/fuzz/reader-logical-focus-seeds"
run() { # name env...
  name=$1; shift
  [ -f $O/dg-$name.txt ] && return
  rm -f $O/dg-$name.part
  env "$@" PLANK_FUZZ_DIGEST_FILE=$O/dg-$name.part PLANK_FUZZ_CONTINUE_ON_CRASH=1 nice $R/rp-avx/Plank.Fuzzing.Replay reader $IN > $O/log-$name.txt 2>&1
  mv $O/dg-$name.part $O/dg-$name.txt
}
cov() { name=$1; shift
  [ -f $O/cov-$name.xml ] && return
  D=/tmp/cov-$name-$$; rm -rf $D; cp -r $R/rp-avx $D
  env "$@" PLANK_FUZZ_CONTINUE_ON_CRASH=1 nice coverlet $D --target dotnet --targetargs "$D/Plank.Fuzzing.Replay.dll reader $IN" --format cobertura --output $O/cov-$name.part. --include "[Plank]*" > $O/covlog-$name.txt 2>&1
  mv $O/cov-$name.part..cobertura.xml $O/cov-$name.xml; rm -rf $D
}
run avx512 X=1
run avx512-flagsall PLANK_FUZZ_ISA_MASK=all
run avx2 DOTNET_EnableAVX512F=0 DOTNET_EnableAVX512BW=0 DOTNET_EnableAVX512CD=0 DOTNET_EnableAVX512DQ=0 DOTNET_EnableAVX512VL=0 DOTNET_EnableAVX512=0
run scalar DOTNET_EnableHWIntrinsic=0
cov avx512 X=1
cov avx512-flagsall PLANK_FUZZ_ISA_MASK=all
cov avx2 DOTNET_EnableAVX512F=0 DOTNET_EnableAVX512=0
echo ALLDONE > $O/done
