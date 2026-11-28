#!/usr/bin/env python3
"""Run the structure-aware page mutator (Replay `structured` mode) under PLANK_FUZZ_GUARD and survive guard deaths.

Usage: guard-structured.py <replay-bin-dir> <out-dir> <end|start> <tier> <mutants-per-seed> <rng-base> <seed-dir-or-file>...

Seeds are run in chunks of CHUNK per process (`structured <per-seed> <rng> <dump-dir> <seeds...>`) with the exact-fit
pool (PLANK_FUZZ_POOL=1, which is the guard pool in guard mode). The mutator writes each mutant to
<dump>/guard-current.parquet and names it on stderr before judging it, so when a process dies the culprit is copied to
<out>/deaths/ with the log tail, and the chunk resumes with the next seed. Each death is then replayed alone through
the reader target (selector 0) in a fresh process: `deterministic` if it dies again, `stateful` otherwise.
SFINDING lines (the mutator's own oracle) go to <out>/findings.tsv. Restart-safe via <out>/done.txt.
"""
import hashlib, os, resource, shutil, subprocess, sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
TIERS = {
    "default": {},
    "avx2": {"DOTNET_EnableAVX512": "0"},
    "sse": {"DOTNET_EnableAVX2": "0"},
    "scalar": {"DOTNET_EnableHWIntrinsic": "0", "PLANK_FUZZ_GUARD_SLACK": "8"},
    "isaflip": {"PLANK_FUZZ_ISA_MASK": "all"},
}
CHUNK = 40
DATA_LIMIT = int(os.environ.get("GUARD_DATA_LIMIT_MB", "0")) * 1024 * 1024


def limit_memory():
    # Off by default: native libraries (ParquetSharp/Arrow) reserve huge writable mappings they never touch, which
    # RLIMIT_DATA counts, so a cap aborted processes that use 65 MB. GuardCore bounds the guard's own memory instead.
    if DATA_LIMIT > 0:
        resource.setrlimit(resource.RLIMIT_DATA, (DATA_LIMIT, DATA_LIMIT))


def collect(paths):
    files = []
    for p in paths:
        if os.path.isfile(p):
            files.append(p)
        else:
            for root, _, names in os.walk(p):
                files += [os.path.join(root, n) for n in sorted(names) if not n.startswith(".")]
    return sorted(files)


def main():
    rp, out, mode, tier, per_seed, rng_base = sys.argv[1:7]
    seeds = collect(sys.argv[7:])
    exe = os.path.join(rp, "Plank.Fuzzing.Replay")
    env = dict(os.environ, PLANK_FUZZ_GUARD=mode, PLANK_FUZZ_POOL="1", DOTNET_DbgEnableMiniDump="0",
               DOTNET_EnableCrashReport="0", DOTNET_EnableWriteXorExecute="0", **TIERS[tier])
    dump = os.path.join(out, "dump")
    os.makedirs(os.path.join(out, "deaths"), exist_ok=True)
    done_path = os.path.join(out, "done.txt")
    done = set(open(done_path).read().split()) if os.path.exists(done_path) else set()
    findings = open(os.path.join(out, "findings.tsv"), "a")
    deaths = mutants = 0
    for c in range(0, len(seeds), CHUNK):
        if str(c) in done:
            continue
        pending = seeds[c:c + CHUNK]
        attempt = 0
        while pending:
            attempt += 1
            rng = str(int(rng_base) * 1000 + c + attempt)
            proc = subprocess.run(["nice", "-n", "10", exe, "structured", per_seed, rng, dump, *pending], env=env,
                                  stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=7200,
                                  preexec_fn=limit_memory)
            outp = proc.stdout.decode("utf-8", "replace")
            err = proc.stderr.decode("utf-8", "replace")
            for line in outp.splitlines():
                if line.startswith("SFINDING"):
                    findings.write(f"{mode}\t{tier}\t{line}\n")
                if line.startswith("structured: "):
                    try:
                        mutants += int(line.split(" mutants")[0].split()[-1])
                    except ValueError:
                        pass
            findings.flush()
            if "\nstructured: " in "\n" + outp:
                break
            started = [l.split("\t") for l in err.splitlines() if l.startswith("GUARD-INPUT\tstructured\t")]
            current = os.path.join(dump, "guard-current.parquet")
            if not started or not os.path.exists(current):
                print(f"DIED without a named mutant (rc={proc.returncode}); skipping chunk {c}", flush=True)
                open(os.path.join(out, f"died-unnamed-{c}.log"), "w").write(err[-20000:])
                break
            seed_path, index, kind = started[-1][2], started[-1][3], started[-1][4]
            data = open(current, "rb").read()
            h = hashlib.sha1(data).hexdigest()[:16]
            d = os.path.join(out, "deaths", f"structured-{mode}-{tier}-{h}")
            os.makedirs(d, exist_ok=True)
            shutil.copy(current, os.path.join(d, "mutant.parquet"))
            with open(os.path.join(d, "reader-input.bin"), "wb") as f:
                f.write(b"\x00" + data)
            tail = err[err.rfind("GUARD-INPUT"):]
            # Alone, in a fresh process, through the reader target: does it die again?
            alone = subprocess.run([exe, "reader", os.path.join(d, "reader-input.bin")], env=env,
                                   stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=600, preexec_fn=limit_memory)
            verdict = "deterministic" if alone.returncode not in (0,) and b"done:" not in alone.stdout else "stateful"
            open(os.path.join(d, "log.txt"), "w").write(
                f"seed: {seed_path}\nmutant: {index} {kind}\nexit: {proc.returncode}\nmode={mode} tier={tier}\n"
                f"alone through reader: rc={alone.returncode} -> {verdict}\n\n{tail[-30000:]}\n\n--- alone ---\n"
                + alone.stderr.decode("utf-8", "replace")[-20000:])
            deaths += 1
            print(f"DEATH {verdict} {seed_path} #{index} {kind} rc={proc.returncode} -> {d}", flush=True)
            idx = pending.index(seed_path) if seed_path in pending else 0
            pending = pending[idx + 1:]
        with open(done_path, "a") as f:
            f.write(f"{c}\n")
    summary = f"structured mode={mode} tier={tier}: {len(seeds)} seeds x {per_seed}, {mutants} mutants judged, {deaths} deaths\n"
    open(os.path.join(out, "summary.txt"), "a").write(summary)
    print(summary, end="")


if __name__ == "__main__":
    main()
