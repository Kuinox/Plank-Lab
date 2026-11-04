#!/usr/bin/env bash
# Start a fleet of AFL++ workers for one target, in the background, surviving
# logout. Portable bash so the same script runs on the desktop and on the
# servers (which have no fish).
#
# Usage: run-fleet.sh <reader|writer> [worker_count]
#
# Workers are niced so the box stays usable when it has other work to do.
# Findings land in fuzz/<target>-findings/ and are never deleted by this
# script — collect-crashes.sh pulls them.
set -euo pipefail

TARGET="${1:-reader}"
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

# Workers run under setsid, which does not read .bashrc — so a machine whose
# toolchain lives somewhere non-standard (a private DOTNET_ROOT, say) must say
# so here rather than in a login profile. Untracked: this is machine setup, not
# project detail. Without it such a fleet starts and every worker immediately
# dies with "You must install .NET to run this application".
# shellcheck source=/dev/null
[ -f "$ROOT/fuzz/env.conf" ] && . "$ROOT/fuzz/env.conf"

AFL="$ROOT/fuzz/.afl/bin/afl-fuzz"

case "$TARGET" in
  reader) BIN="$ROOT/Plank.Fuzzing.Reader.Target/bin/Release/net10.0/Plank.Fuzzing.Reader.Target"
          CORPUS="$ROOT/fuzz/reader-corpus"; TIMEOUT=1100
          DICTIONARY="-x '$ROOT/fuzz/parquet.dict'" ;;
  writer) BIN="$ROOT/Plank.Fuzzing.Target/bin/Release/net10.0/Plank.Fuzzing.Target"
          CORPUS="$ROOT/fuzz/corpus"; TIMEOUT=5000; DICTIONARY="" ;;
  *) echo "unknown target '$TARGET' (expected reader or writer)" >&2; exit 2 ;;
esac

WORKERS="${2:-$(( $(nproc) - 2 ))}"
# First CPU to pin to; worker i gets FIRST_CORE+i. Set it to keep the fleet off
# the CPUs other work on the machine is using (e.g. PLANK_FUZZ_FIRST_CORE=23 with 1 worker).
FIRST_CORE="${PLANK_FUZZ_FIRST_CORE:-0}"
[ "$WORKERS" -lt 1 ] && WORKERS=1

OUT="$ROOT/fuzz/$TARGET-findings"
LOGS="$ROOT/fuzz/logs/$TARGET"
mkdir -p "$OUT" "$LOGS"

[ -x "$AFL" ] || { echo "run fuzz/install-afl.sh first" >&2; exit 2; }
[ -x "$BIN" ] || { echo "build the $TARGET target first" >&2; exit 2; }

# The reader's generated seeds are derived from the writer, not checked in: they
# are regenerable binaries that must track the code. Without them the fuzzer
# only ever sees uncompressed files of a few types, and no amount of mutation
# invents a valid Snappy or Zstd frame plus the matching codec field — those
# decoders simply never run.
if [ "$TARGET" = "reader" ] && ! ls "$CORPUS"/gen-*.bin >/dev/null 2>&1; then
  echo "==> Generating reader seed corpus..."
  "$BIN" --generate-corpus "$CORPUS" || echo "!! seed generation failed; continuing with checked-in seeds"
fi

echo "==> Stopping any existing $TARGET fuzzers..."
# By process tree, not pkill -f: a pattern like the binary name also matches
# any shell whose command line mentions it, and killed the caller more than once.
for tmp_dir in "$ROOT/fuzz/.tmp"/*/; do
  [ -d "$tmp_dir" ] && "$ROOT/fuzz/stop-worker.sh" "$(basename "$tmp_dir")" >/dev/null
done

ulimit -c 0

# AFL refuses to start when core dumps are piped to a helper, because the pipe
# delays crash reporting enough to look like a timeout.
if grep -q '^|' /proc/sys/kernel/core_pattern 2>/dev/null; then
  echo "core" | sudo tee /proc/sys/kernel/core_pattern >/dev/null 2>&1 \
    || echo "!! could not set core_pattern; falling back to AFL_I_DONT_CARE_ABOUT_MISSING_CRASHES"
fi

export AFL_SKIP_CPUFREQ=1 AFL_SKIP_BIN_CHECK=1 AFL_AUTORESUME=1 AFL_NO_UI=1
export AFL_I_DONT_CARE_ABOUT_MISSING_CRASHES=1
# The in-process harness saves crashing inputs itself, then terminates its
# worker. On resume, let the other workers continue instead of refusing to
# start merely because an earlier persistent worker stopped on a finding.
export AFL_SKIP_CRASHES=1
# No dumps: the harness already saves every crashing input, and even "mini"
# dumps of this process are ~45 MB each. A crash storm wrote 7 GB of them to
# tmpfs /tmp in five minutes and took the whole machine's /tmp down with it.
# Set DOTNET_DbgEnableMiniDump=1 by hand when a dump is really needed.
export DOTNET_DbgEnableMiniDump=0 DOTNET_DbgMiniDumpType=1
# Inputs are at most 1 MiB, so a 256 MiB managed heap is plenty for Plank; an
# allocation past it from such an input is a finding in itself. The cap turns a
# reference reader that sizes a buffer from a corrupt count (Parquet.Net trusts
# list counts and page num_values) into a fast OutOfMemoryException, which the
# oracle treats as "cannot judge", instead of seconds of allocating and filling:
# that outlasts AFL's timeout, a timeout kills SharpFuzz's fork server, and on
# resume the same queue entry kills it again. 1 GiB still let a 4 s fill through.
export DOTNET_GCHeapHardLimit=0x10000000
export DOTNET_DbgMiniDumpName="/tmp/plank-$TARGET-crash-%p.dmp"
# The persistent harness *is* the fork server, so a crash kills the worker and
# AFL aborts before saving anything. The harness writes the offending input here
# instead, keyed by content hash.
export PLANK_FUZZ_CRASH_DIR="$ROOT/fuzz/crashes"
mkdir -p "$PLANK_FUZZ_CRASH_DIR"
# Acceptance disagreements with the reference readers are bucketed here
# instead of crashing the worker (see DisagreementLog.cs).
export PLANK_FUZZ_DISAGREEMENT_DIR="$ROOT/fuzz/disagreements"
mkdir -p "$PLANK_FUZZ_DISAGREEMENT_DIR"

# Plank picks its decoders by instruction set (AVX-512, AVX2, PDEP, scalar),
# so a fleet on one machine only ever fuzzes one tier: on an AVX-512 box the
# scalar delta kernels for widths 1-16 measured 0% because AVX2 code always
# took them. Spread the workers over the tiers. These are the switches that
# actually work; DOTNET_EnableAVX512F=0 is silently ignored.
isa_env() {
  case "$1" in
    worker-03|worker-04|worker-07) echo "DOTNET_EnableAVX512=0" ;;    # AVX2 tier
    worker-05)           echo "DOTNET_EnableAVX2=0" ;;                # SSE tier, no BMI2/PDEP
    worker-06)           echo "DOTNET_EnableHWIntrinsic=0" ;;         # scalar only
    *)                   echo "" ;;                                   # native (AVX-512)
    # Not reachable here: AVX2 without PDEP (Plank turns PDEP off only on AMD
    # Zen 1/2, from CPUID). DOTNET_EnableBMI2=0 is ignored on .NET 10 like
    # EnableAVX512F; that tier needs a Zen 1/2 machine.
  esac
}

start_one() {
  local name="$1" core="$2"
  local isa; isa="$(isa_env "$name")"
  local tmp="$ROOT/fuzz/.tmp/$name"
  mkdir -p "$tmp"
  # Each worker needs its own AFL_TMPDIR: they all write .cur_input there.
  # Respawn loop keeps the fleet alive across the occasional worker abort.
  # PLANK_FUZZ_ROTATE_ISA=<seconds> makes the worker cycle through all four
  # instruction-set tiers instead of keeping the one isa_env gives it: a small
  # fleet (one pinned worker) otherwise never runs the scalar, SSE or AVX2
  # decoders at all. AFL is stopped with SIGINT, which saves its state, and the
  # next tier resumes the same queue.
  local rotate="${PLANK_FUZZ_ROTATE_ISA:-0}"
  nohup setsid bash -c "
    tiers=('' 'DOTNET_EnableAVX512=0' 'DOTNET_EnableAVX2=0' 'DOTNET_EnableHWIntrinsic=0')
    round=0
    fast_exits=0
    while true; do
      started=\$(date +%s)
      if [ $rotate -gt 0 ]; then
        tier=\${tiers[\$((round % 4))]}
        round=\$((round + 1))
        echo \"==> ISA tier: \${tier:-native}\" >>'$LOGS/$name.log'
        limit='timeout -s INT $rotate'
      else
        tier='$isa'
        limit=''
      fi
      # A worker killed mid-run leaves .cur_input behind, and AFL refuses to
      # start on top of it, turning one abort into a permanent respawn loop.
      # It is also the input that killed the target in a way the harness could
      # not catch (stack overflow, native fault), so keep it before removing it.
      if [ -s '$tmp/.cur_input' ]; then
        cp '$tmp/.cur_input' '$ROOT/fuzz/crashes/'fatal-\$(sha256sum '$tmp/.cur_input' | cut -c1-16).bin
      fi
      rm -f '$tmp/.cur_input'
      \$limit env \$tier AFL_TMPDIR='$tmp' nice -n 19 '$AFL' -b $core -i '$CORPUS' -o '$OUT' -t $TIMEOUT $DICTIONARY $3 -- '$BIN' 2>&1 \
        | grep --line-buffered -v 'Fuzzing test case #' >>'$LOGS/$name.log'
      # AFL_NO_UI reprints a status line continuously, which is ~1.2 GiB per
      # worker per 10 hours — enough to fill a small disk overnight while
      # telling us nothing. Everything else (warnings, aborts, crash notices)
      # still reaches the log.
      # An input that kills the fork server at start-up (a run longer than
      # AFL's timeout does, under SharpFuzz) makes every resume die in the same
      # place. That once looped silently for hours, so make it loud and back off.
      if [ \$(( \$(date +%s) - started )) -lt 120 ]; then
        fast_exits=\$((fast_exits + 1))
      else
        fast_exits=0
        rm -f '$LOGS/$name.STALLED'
      fi
      if [ \$fast_exits -ge 5 ]; then
        echo \"\$(date -Is) \$fast_exits consecutive exits under 120 s; see $LOGS/$name.log\" >'$LOGS/$name.STALLED'
        sleep 600
      else
        sleep 5
      fi
    done" >/dev/null 2>&1 &
  disown || true
}

echo "==> Starting main + $((WORKERS - 1)) workers for '$TARGET' (out: $OUT)"
# -M makes AFL walk the queue in order (-Z) and turns trimming off: right for a
# main instance whose secondaries do the random exploration, wrong for a worker
# fuzzing alone. A solo -M worker spent its cycles crawling a 28k-entry queue of
# untrimmed inputs in sequence and plateaued. Alone, run as a secondary
# (weighted queue selection, trimming) and skip the enhanced deterministic
# stages (-z), which cost minutes per entry on a queue that size.
if [ "$WORKERS" -eq 1 ]; then main_role="-S main -z"; else main_role="-M main"; fi
start_one "main" "$FIRST_CORE" "$main_role"
for i in $(seq 1 $((WORKERS - 1))); do
  name=$(printf "worker-%02d" "$i")
  start_one "$name" "$((FIRST_CORE + i))" "-S $name"
  sleep 0.2
done

sleep 5
echo "==> Running: $(pgrep -fc "$OUT" || echo 0) afl-fuzz processes"

# A machine that finds something should say so without anyone watching it.
# Same lifecycle as the workers: no cron, no service, gone when the fleet is
# killed. Guarded so starting the reader and writer fleets leaves one notifier.
if [ -f "$ROOT/fuzz/webhook.conf" ] || [ -n "${PLANK_FUZZ_WEBHOOK:-}" ]; then
  # Match on a marker rather than the script path: the supervisor's command
  # line quotes that path, so a path-based pattern never matches and every
  # fleet start would add another notifier.
  if pgrep -f PLANK_FUZZ_NOTIFIER_LOOP=1 >/dev/null 2>&1; then
    echo "==> Crash notifier already running"
  else
    nohup setsid bash -c "
      export PLANK_FUZZ_NOTIFIER_LOOP=1
      while true; do
        '$ROOT/fuzz/notify-crashes.sh' --loop >>'$ROOT/fuzz/logs/notify.log' 2>&1
        sleep 300
      done" >/dev/null 2>&1 &
    disown || true
    echo "==> Crash notifier started (every 5 min)"
  fi
else
  echo "==> No fuzz/webhook.conf — crash notifier not started"
fi
