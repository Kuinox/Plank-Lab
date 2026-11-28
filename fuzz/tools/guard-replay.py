#!/usr/bin/env python3
"""Replay inputs under PLANK_FUZZ_GUARD and survive the process dying on a guard fault.

Usage: guard-replay.py <replay-bin-dir> <out-dir> <target> <guard-mode> <tier> <input-dir-or-file>...

  target      reader | writer | merger | both   (as Plank.Fuzzing.Replay takes it)
  guard-mode  end | start
  tier        default | avx2 (AVX-512 off) | sse (AVX2 off) | scalar (no HW intrinsics) | isaflip (PLANK_FUZZ_ISA_MASK=all)

Inputs are replayed in batches. When a batch dies (an out-of-bounds access is a fatal AccessViolation or a
GUARD-VIOLATION FailFast), the last `GUARD-INPUT` line names the culprit: it is copied with the log tail to
<out>/deaths/, and the batch resumes after it. FAULT/CRASH/MISMATCH lines are collected in <out>/faults.tsv.
A summary line goes to <out>/summary.txt. Restart-safe: finished batches are recorded in <out>/done.txt.
"""
import hashlib, os, resource, shutil, subprocess, sys

# Committed writable memory per replay process (RLIMIT_DATA counts private writable mappings, not the GC's PROT_NONE
# reservations): an input that wants more gets OutOfMemory (a FAULT line) instead of the kernel OOM-killing the shard.
DATA_LIMIT = int(os.environ.get("GUARD_DATA_LIMIT_MB", "0")) * 1024 * 1024

def limit_memory():
    # Off by default: native libraries (ParquetSharp/Arrow) reserve huge writable mappings they never touch, which
    # RLIMIT_DATA counts, so a cap aborted processes that use 65 MB. GuardCore bounds the guard's own memory instead.
    if DATA_LIMIT > 0:
        resource.setrlimit(resource.RLIMIT_DATA, (DATA_LIMIT, DATA_LIMIT))

TIERS = {
    "default": {},
    "avx2": {"DOTNET_EnableAVX512": "0"},
    "sse": {"DOTNET_EnableAVX2": "0"},
    # Slack 8: with HW intrinsics off the JIT over-reads by-value structs of size 4 mod 8 (Plank.Fuzzing.Guard/README.md).
    "scalar": {"DOTNET_EnableHWIntrinsic": "0", "PLANK_FUZZ_GUARD_SLACK": "8"},
    "isaflip": {"PLANK_FUZZ_ISA_MASK": "all"},
}
BATCH = 400
# Known library bug Plank #276 (row-group row writer overruns its slots): these routes die with SIGSEGV even without
# guard mode, see fuzz/notes/master-fault-triage-2026-11-27.md. Skipped until #276 lands (PLANK_GUARD_KEEP_276=1 keeps them).
KNOWN_276 = (b"\xffRWG1", b"\xffRWN1", b"\xffRWW1", b"RWG1", b"RWN1", b"RWW1")

def known_276(path):
    if os.environ.get("PLANK_GUARD_KEEP_276") == "1":
        return False
    with open(path, "rb") as f:
        return f.read(5).startswith(KNOWN_276)

def collect(paths):
    files = []
    for p in paths:
        if os.path.isfile(p):
            files.append(p)
            continue
        for root, _, names in os.walk(p):
            for n in sorted(names):
                if n.startswith(".") or n in ("fuzzer_stats", "fuzz_bitmap", "plot_data", "cmdline", "README.md"):
                    continue
                files.append(os.path.join(root, n))
    return sorted(files)

def main():
    rp, out, target, mode, tier = sys.argv[1:6]
    files = collect(sys.argv[6:])
    skipped = sum(1 for f in files if known_276(f))
    files = [f for f in files if not known_276(f)]
    os.makedirs(os.path.join(out, "deaths"), exist_ok=True)
    env = dict(os.environ, PLANK_FUZZ_GUARD=mode, PLANK_FUZZ_CONTINUE_ON_CRASH="1",
               DOTNET_DbgEnableMiniDump="0", DOTNET_EnableCrashReport="0",
               # W^X double-maps every code page: fewer runtime mappings left for guard buffers (vm.max_map_count).
               DOTNET_EnableWriteXorExecute="0", **TIERS[tier])
    exe = os.path.join(rp, "Plank.Fuzzing.Replay")
    done_path = os.path.join(out, "done.txt")
    done = set(open(done_path).read().split()) if os.path.exists(done_path) else set()
    deaths = faults = replayed = 0
    faults_tsv = open(os.path.join(out, "faults.tsv"), "a")
    for b in range(0, len(files), BATCH):
        key = f"{b}"
        if key in done:
            continue
        pending = files[b:b + BATCH]
        while pending:
            proc = subprocess.run(["nice", "-n", "10", exe, target, *pending], env=env,
                                  stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=3600,
                                  preexec_fn=limit_memory)
            err = proc.stderr.decode("utf-8", "replace")
            outp = proc.stdout.decode("utf-8", "replace")
            for line in err.splitlines():
                if line.startswith(("FAULT\t", "CRASH\t", "MISMATCH\t")):
                    faults += 1
                    faults_tsv.write(f"{mode}\t{tier}\t{target}\t{line}\n")
            if "\ndone:" in "\n" + outp:
                replayed += len(pending)
                break
            # Died: the last input it started is the culprit.
            started = [l.split("\t", 1)[1] for l in err.splitlines() if l.startswith("GUARD-INPUT\t")]
            culprit = started[-1] if started else pending[0]
            deaths += 1
            data = open(culprit, "rb").read()
            h = hashlib.sha1(data).hexdigest()[:16]
            d = os.path.join(out, "deaths", f"{target}-{mode}-{tier}-{h}")
            os.makedirs(d, exist_ok=True)
            shutil.copy(culprit, os.path.join(d, "input.bin"))
            tail = err[err.rfind("GUARD-INPUT"):] if started else err[-20000:]
            open(os.path.join(d, "log.txt"), "w").write(
                f"culprit: {culprit}\nexit: {proc.returncode}\ntarget={target} mode={mode} tier={tier}\n\n{tail[-30000:]}")
            # Alone in a fresh process: deterministic (the input itself) or stateful (left by earlier inputs)?
            alone = subprocess.run([exe, target, culprit], env=env, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                   timeout=900, preexec_fn=limit_memory)
            verdict = "deterministic" if b"\ndone:" not in b"\n" + alone.stdout else "stateful"
            with open(os.path.join(d, "log.txt"), "a") as f:
                f.write(f"\n\n--- alone: rc={alone.returncode} -> {verdict} ---\n" + alone.stderr.decode("utf-8", "replace")[-20000:])
            print(f"DEATH {verdict} {culprit} rc={proc.returncode} -> {d}", flush=True)
            idx = pending.index(culprit) if culprit in pending else 0
            replayed += idx + 1
            pending = pending[idx + 1:]
        with open(done_path, "a") as f:
            f.write(key + "\n")
        faults_tsv.flush()
    summary = f"{target} mode={mode} tier={tier}: {len(files)} inputs, {replayed} replayed, {deaths} deaths, {faults} fault lines, {skipped} skipped (#276 routes)\n"
    open(os.path.join(out, "summary.txt"), "a").write(summary)
    print(summary, end="")

if __name__ == "__main__":
    main()
