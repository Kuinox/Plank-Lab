#!/usr/bin/env python3
"""Replay inputs through a -p:PlankCheckedAccess=true replay build and collect checked-access violations.

Usage: checked-replay.py <replay-bin-dir> <out-dir> <target> <tier> <input-dir-or-file>...

  target  reader | writer | merger | both   (as Plank.Fuzzing.Replay takes it)
  tier    default | avx2 (AVX-512 off) | sse (AVX2 off) | scalar (no HW intrinsics) | isaflip (PLANK_FUZZ_ISA_MASK=all)

Every `PLANK-OOB` line (an access outside the logical span its ref came from: Plank.Fuzzing.Checked/README.md) is
attributed to the input that printed it (PLANK_REPLAY_ECHO=1) and lands in <out>/oob.tsv, with the input copied to
<out>/oob/<target>-<tier>-<hash>/ (input.bin, log.txt). PLANK-OOB-WEAK lines (unattributable provenance) go to
<out>/weak.tsv. Process deaths are handled as in guard-replay.py (<out>/deaths/). FAULT/CRASH/MISMATCH lines go to
<out>/faults.tsv, the PLANK-CHECKED-STATS counters to <out>/stats.txt, a summary line to <out>/summary.txt.
Restart-safe: finished batches are recorded in <out>/done.txt. Routes of the known #276 bug are skipped.
Env: CHECKED_FAILFAST=1 runs with PLANK_CHECKED_FAILFAST=1 (first violation kills the process, as under AFL).
"""
import hashlib, os, shutil, subprocess, sys

TIERS = {
    "default": {},
    "avx2": {"DOTNET_EnableAVX512": "0"},
    "sse": {"DOTNET_EnableAVX2": "0"},
    "scalar": {"DOTNET_EnableHWIntrinsic": "0"},
    "isaflip": {"PLANK_FUZZ_ISA_MASK": "all"},
}
BATCH = int(os.environ.get("CHECKED_BATCH", "400"))
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


def save(out, kind, target, tier, culprit, log):
    data = open(culprit, "rb").read()
    h = hashlib.sha1(data).hexdigest()[:16]
    d = os.path.join(out, kind, f"{target}-{tier}-{h}")
    if not os.path.exists(d):
        os.makedirs(d)
        shutil.copy(culprit, os.path.join(d, "input.bin"))
        open(os.path.join(d, "log.txt"), "w").write(f"culprit: {culprit}\ntarget={target} tier={tier}\n\n{log[-30000:]}")
    return d


def main():
    rp, out, target, tier = sys.argv[1:5]
    files = collect(sys.argv[5:])
    skipped = sum(1 for f in files if known_276(f))
    files = [f for f in files if not known_276(f)]
    for sub in ("deaths", "oob"):
        os.makedirs(os.path.join(out, sub), exist_ok=True)
    env = dict(os.environ, PLANK_FUZZ_CONTINUE_ON_CRASH="1", PLANK_REPLAY_ECHO="1", PLANK_CHECKED_STATS="1",
               DOTNET_DbgEnableMiniDump="0", DOTNET_EnableCrashReport="0",
               # Managed registrations are dropped after a GC (buffers may move): keep GCs rare.
               DOTNET_GCgen0size=os.environ.get("DOTNET_GCgen0size", "0x10000000"), **TIERS[tier])
    if os.environ.get("CHECKED_FAILFAST") == "1":
        env["PLANK_CHECKED_FAILFAST"] = "1"
    exe = os.path.join(rp, "Plank.Fuzzing.Replay")
    done_path = os.path.join(out, "done.txt")
    done = set(open(done_path).read().split()) if os.path.exists(done_path) else set()
    deaths = faults = replayed = oob = weak = 0
    faults_tsv = open(os.path.join(out, "faults.tsv"), "a")
    oob_tsv = open(os.path.join(out, "oob.tsv"), "a")
    weak_tsv = open(os.path.join(out, "weak.tsv"), "a")
    stats = open(os.path.join(out, "stats.txt"), "a")
    for b in range(0, len(files), BATCH):
        key = f"{target}-{tier}-{b}"
        if key in done:
            continue
        pending = files[b:b + BATCH]
        while pending:
            proc = subprocess.run(["nice", "-n", "10", exe, target, *pending], env=env,
                                  stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=7200)
            err = proc.stderr.decode("utf-8", "replace")
            outp = proc.stdout.decode("utf-8", "replace")
            current = pending[0]
            block = []
            for line in err.splitlines():
                if line.startswith("GUARD-INPUT\t"):
                    current = line.split("\t", 1)[1]
                    block = []
                    continue
                block.append(line)
                if line.startswith(("FAULT\t", "CRASH\t", "MISMATCH\t")):
                    faults += 1
                    faults_tsv.write(f"{tier}\t{target}\t{line}\n")
                elif line.startswith("PLANK-OOB "):
                    oob += 1
                    d = save(out, "oob", target, tier, current, "\n".join(block))
                    oob_tsv.write(f"{tier}\t{target}\t{current}\t{d}\t{line}\n")
                    print(f"OOB {current} {line[:300]}", flush=True)
                elif line.startswith("PLANK-OOB-WEAK "):
                    weak += 1
                    weak_tsv.write(f"{tier}\t{target}\t{current}\t{line}\n")
                elif line.startswith("PLANK-CHECKED-STATS"):
                    stats.write(f"{key}\t{line}\n")
            if "\ndone:" in "\n" + outp:
                replayed += len(pending)
                break
            started = [l.split("\t", 1)[1] for l in err.splitlines() if l.startswith("GUARD-INPUT\t")]
            culprit = started[-1] if started else pending[0]
            deaths += 1
            tail = err[err.rfind("GUARD-INPUT"):] if started else err[-20000:]
            d = save(out, "deaths", target, tier, culprit, f"exit: {proc.returncode}\n{tail}")
            print(f"DEATH {culprit} rc={proc.returncode} -> {d}", flush=True)
            idx = pending.index(culprit) if culprit in pending else 0
            replayed += idx + 1
            pending = pending[idx + 1:]
        with open(done_path, "a") as f:
            f.write(key + "\n")
        for fh in (faults_tsv, oob_tsv, weak_tsv, stats):
            fh.flush()
    summary = (f"{target} tier={tier}: {len(files)} inputs, {replayed} replayed, {oob} PLANK-OOB, {weak} weak, "
               f"{deaths} deaths, {faults} fault lines, {skipped} skipped (#276 routes)\n")
    open(os.path.join(out, "summary.txt"), "a").write(summary)
    print(summary, end="")


if __name__ == "__main__":
    main()
