using System.Runtime.InteropServices;
using SharpFuzz.Common;

namespace Plank.Fuzzing.Harness;

// AFL++ persistent mode harness without fork.
// Implements the fork-server protocol directly so the .NET process is never
// forked — it loops in-place for its entire lifetime.
//
// This file is shared (linked) by Plank.Fuzzing.Target and
// Plank.Fuzzing.Reader.Target. Do not duplicate it: the two copies that used to
// exist drifted out of sync and hid a bug for months (see ReadTestcase).
internal static unsafe class AflPersistentHarness
{
    private const int CtlFd = 198;          // AFL++ writes here to say "go"
    private const int StFd = 199;           // we write handshake / PID / fault here
    private const int MapSize = 65536;
    private const int FaultNone = 0;
    private const int FaultCrash = 2;
    private const int SaveInterval = 10_000;
    // PLANK_FUZZ_WATCHDOG_MS=N: an execution running longer than N ms is saved under the hang dir and the worker
    // exits. AFL cannot do this for us: the harness is its own fork server, so an AFL timeout kills the whole
    // worker ("Unable to request new process"), and a restarted worker replays the same deterministic stage into the
    // same slow input forever. Inputs already in the hang dir are skipped, so each distinct hang costs one restart.
    private static readonly int WatchdogMs =
        int.TryParse(Environment.GetEnvironmentVariable("PLANK_FUZZ_WATCHDOG_MS"), out var wdMs) ? wdMs : 0;
    private static volatile byte[]? _runningInput;
    private static long _runningSinceTicks;
    private static string _watchdogTarget = "";
    private static readonly int GcEvery =
        int.TryParse(Environment.GetEnvironmentVariable("PLANK_FUZZ_GC_EVERY"), out var gcEvery) ? gcEvery : 0;
    private static readonly bool SurviveCrash =
        Environment.GetEnvironmentVariable("PLANK_FUZZ_SURVIVE_CRASH") == "1";

    // If AFL hands us this many empty inputs back-to-back, input delivery is
    // broken rather than the fuzzer being unlucky. See the watchdog below.
    private const int EmptyInputAlarmThreshold = 5_000;

    [DllImport("libc")] static extern IntPtr shmat(int shmid, IntPtr shmaddr, int shmflg);
    [DllImport("libc")] static extern int shmdt(IntPtr shmaddr);
    [DllImport("libc")] static extern int getpid();
    [DllImport("libc", SetLastError = true)] static extern nint write(int fd, void* buf, nuint count);
    [DllImport("libc", SetLastError = true)] static extern nint read(int fd, void* buf, nuint count);
    [DllImport("libc", SetLastError = true)] static extern long lseek(int fd, long offset, int whence);

    public static void Run(string targetName, Action<byte[]> execute)
    {
        ArgumentException.ThrowIfNullOrEmpty(targetName);
        ArgumentNullException.ThrowIfNull(execute);

        var lastInputPath = $"/tmp/plank-fuzz-{targetName}-last-input.bin";

        if (!TryGetEnvInt("__AFL_SHM_ID", out int shmId))
        {
            // Match the AFL loop's warm-up so state-dependent findings also
            // reproduce with the simple standalone stdin command.
            PinDummyCoverageBuffer();
            RecoverGuardDeath(targetName);
            try { execute([]); } catch { }
            execute(ReadTestcase());
            return;
        }

        // Map AFL++ coverage bitmap and wire it into SharpFuzz IL instrumentation
        IntPtr coverageMem = shmat(shmId, IntPtr.Zero, 0);
        byte* coveragePtr = (byte*)coverageMem;
        Trace.SharedMem = coveragePtr;
        SetupCoreCoverage(coveragePtr);
        // Instrumented code (this included) needs the coverage map first; the warm-up clear below drops its edges.
        RecoverGuardDeath(targetName);

        // afl-cmin passes AFL_NO_FORKSRV=1: no fork-server protocol, just run stdin once.
        // Coverage is tracked via the already-mapped SHM bitmap.
        if (Environment.GetEnvironmentVariable("AFL_NO_FORKSRV") == "1")
        {
            try { execute([]); } catch { }  // warm-up: fire cctors/JIT
            new Span<byte>(coveragePtr, MapSize).Clear();
            Trace.PrevLocation = 0;
            try { execute(ReadTestcase()); } catch { }
            shmdt(coverageMem);
            return;
        }

        // Warm-up: run once with an empty input to trigger all .NET static
        // constructors and JIT tier-0 compilations before entering the AFL loop.
        // Without this, the first real execution sees different coverage than
        // subsequent ones (cctors only fire once), causing AFL instability aborts.
        try { execute([]); } catch { }
        new Span<byte>(coveragePtr, MapSize).Clear();
        Trace.PrevLocation = 0;

        int pid = getpid();

        // Fork-server handshake: the "old model" (write 0), which AFL++ 4.x
        // handles correctly. Attempting FS_OPT_ENABLED requires a multi-step
        // negotiation we don't implement; mismatching it causes protocol
        // desync and "No instrumentation detected" aborts.
        //
        // This pins us to AFL++ 4.x. Under AFL++ 5.x the old model is accepted
        // but every edge in the bitmap is marked as already covered
        // (edges_found == total_edges == 65536), so no input is ever
        // interesting and the corpus never grows. fuzz/install-afl.sh pins the
        // supported version and fuzz/verify-harness.sh fails the run if the
        // coverage numbers come back degenerate.
        //
        // Because we stay on the old model, AFL++ delivers every testcase
        // through stdin (fd 0, its .cur_input file) — never through the
        // shared-memory testcase buffer. AFL++ >= 5.0 exports
        // __AFL_SHM_FUZZ_ID unconditionally, before it knows whether the
        // target supports shmem fuzzing. Reading that buffer here (as this
        // harness used to) yields a length prefix of 0 on every single
        // execution, so the target silently fuzzes nothing while AFL reports a
        // healthy exec rate. Do not reintroduce it without also performing the
        // FS_OPT_SHDMEM_FUZZ negotiation.
        WriteU32(StFd, 0);

        if (WatchdogMs > 0)
            StartWatchdog(targetName);

        int execCount = 0;
        int consecutiveEmptyInputs = 0;
        bool alarmRaised = false;

        while (true)
        {
            if (!ReadU32(CtlFd, out _)) break;   // AFL++ gone

            WriteU32(StFd, (uint)pid);            // "child PID" (we are the child, no fork)

            // Reset coverage bitmap and edge-tracking seed
            new Span<byte>(coveragePtr, MapSize).Clear();
            Trace.PrevLocation = 0;

            byte[] input = ReadTestcase();

            // Watchdog for the failure mode described above: an input channel
            // that is wired up wrong looks exactly like a very fast, very
            // productive fuzzing session. Leave a breadcrumb on disk so
            // fuzz/verify-harness.fish can fail the pre-flight check.
            if (input.Length == 0)
            {
                if (++consecutiveEmptyInputs == EmptyInputAlarmThreshold && !alarmRaised)
                {
                    alarmRaised = true;
                    TryWriteAllText($"/tmp/plank-fuzz-{targetName}-BROKEN.txt",
                        $"{EmptyInputAlarmThreshold} consecutive empty testcases: AFL input delivery is broken.\n");
                }
            }
            else
            {
                consecutiveEmptyInputs = 0;
            }

            if (++execCount % SaveInterval == 0)
                TryWriteAllBytes(lastInputPath, input);

            uint status;
            bool fatal;
            if (WatchdogMs > 0 && File.Exists(HangPath(targetName, input)))
            {
                // Known hang: skip it. AFL aborts a calibration run with a completely empty map ("No instrumentation
                // detected"), so leave one fixed byte set.
                coveragePtr[1] = 1;
                status = FaultNone;
                fatal = false;
            }
            else
            {
                _runningSinceTicks = System.Diagnostics.Stopwatch.GetTimestamp();
                _runningInput = input;
                status = ExecuteOne(targetName, execute, input, SurviveCrash, out fatal);
                _runningInput = null;
            }

            // PLANK_FUZZ_GC_EVERY=N: a compacting full GC every N executions. The shared buffer pool and LOH
            // fragmentation make a long-lived worker's heap creep up until a container memory cap fails an
            // allocation that a fresh process would survive.
            if (GcEvery > 0 && execCount % GcEvery == 0)
            {
                System.Runtime.GCSettings.LargeObjectHeapCompactionMode = System.Runtime.GCLargeObjectHeapCompactionMode.CompactOnce;
                GC.Collect(2, GCCollectionMode.Forced, blocking: true, compacting: true);
            }
            WriteU32(StFd, status);

            if (fatal)
            {
                // This process *is* the fork server, so dying here takes the
                // whole worker down and AFL aborts with "Unable to request new
                // process from fork server" (the input is already persisted by
                // ExecuteOne under its content hash).
                // FailFast exits immediately — no chance for AFL++ SIGKILL to race
                shmdt(coverageMem);
                Environment.FailFast("fuzz target crashed");
            }
        }
    }

    static string HangDirectory()
    {
        var dir = Environment.GetEnvironmentVariable("PLANK_FUZZ_HANG_DIR");
        if (!string.IsNullOrEmpty(dir)) return dir;
        var crash = Environment.GetEnvironmentVariable("PLANK_FUZZ_CRASH_DIR");
        return Path.Combine(string.IsNullOrEmpty(crash) ? "/tmp" : crash, "hangs");
    }

    static string HangPath(string targetName, byte[] input)
    {
        var hash = Convert.ToHexStringLower(System.Security.Cryptography.SHA256.HashData(input));
        return Path.Combine(HangDirectory(), $"{targetName}-{hash[..16]}.bin");
    }

    static void StartWatchdog(string targetName)
    {
        _watchdogTarget = targetName;
        var thread = new Thread(() =>
        {
            while (true)
            {
                Thread.Sleep(200);
                var input = _runningInput;
                if (input is null) continue;
                var elapsedMs = (System.Diagnostics.Stopwatch.GetTimestamp() - Volatile.Read(ref _runningSinceTicks))
                                * 1000.0 / System.Diagnostics.Stopwatch.Frequency;
                if (elapsedMs < WatchdogMs || !ReferenceEquals(input, _runningInput)) continue;
                try
                {
                    Directory.CreateDirectory(HangDirectory());
                    File.WriteAllBytes(HangPath(_watchdogTarget, input), input);
                }
                catch (IOException) { }
                catch (UnauthorizedAccessException) { }
                Environment.FailFast($"fuzz target hung (> {WatchdogMs} ms)");
            }
        }) { IsBackground = true, Name = "plank-fuzz-watchdog" };
        thread.Start();
    }

    // Runs one testcase and returns the wait-status word to report to AFL.
    //
    // PLANK_FUZZ_SURVIVE_CRASH=1 (surviveCrash): a managed exception is reported as
    // a SIGSEGV-style status (11) so AFL records a real crash with its own
    // bitmap-based uniqueness, and the loop keeps serving. Without it the worker
    // FailFasts (fatal = true), AFL only sees "Unable to communicate with fork
    // server", records nothing and re-dry-runs the whole queue on restart.
    // Native crashes (segfaults, FailFast) still kill the process either way.
    // In both modes the input is saved under PLANK_FUZZ_CRASH_DIR by content hash.
    internal static uint ExecuteOne(string targetName, Action<byte[]> execute, byte[] input, bool surviveCrash, out bool fatal)
    {
        fatal = false;
        try
        {
            if (GuardMemory.Enabled)
            {
                // PLANK_FUZZ_GUARD=end|start: an out-of-bounds access is a fatal AccessViolation (no exception to
                // catch here), so the input is written first and survives the process; the input itself is handed
                // over in a page-guarded array.
                var current = GuardCurrentPath(targetName);
                TryWriteAllBytes(current, input);
                using (GuardScope.Begin())
                    execute(GuardMemory.ToArray(input));
                TryWriteAllBytes(current, []);
                return FaultNone;
            }

            execute(input);
            return FaultNone;
        }
        catch (Exception ex)
        {
            // PLANK_FUZZ_KNOWN_FINDINGS: documented library bugs are counted, not reported, so AFL keeps exploring.
            if (KnownFindings.Match(ex, null, targetName) is { } known)
            {
                KnownFindings.Record(targetName, known);
                return FaultNone;
            }
            TryWriteAllText($"/tmp/plank-fuzz-{targetName}-last-exception.txt", ex.ToString());
            SaveCrashInput(targetName, input);
            if (surviveCrash)
                return 11;
            fatal = true;
            return FaultCrash;
        }
    }

    // If System.Private.CoreLib itself was instrumented, its injected Trace type
    // also needs the shm pointer. This is an uncommon case but handle it correctly.
    static void SetupCoreCoverage(byte* ptr)
    {
        var traceFullName = typeof(Trace).FullName;
        var coreType = typeof(object).Assembly.GetTypes()
            .FirstOrDefault(t => t.FullName == traceFullName);
        if (coreType == null) return;
        coreType.GetField("SharedMem")?.SetValue(null,
            System.Reflection.Pointer.Box(ptr, typeof(byte*)));
        coreType.GetField("PrevLocation")?.SetValue(null, 0);
    }

    // Reads the whole of fd 0. AFL++ dup2()s its .cur_input file onto our stdin
    // once, at spawn, and then rewrites that same file description for every
    // execution — so we must rewind before each read. lseek fails harmlessly
    // (ESPIPE) if stdin is a pipe, in which case the read below still works.
    static byte[] ReadTestcase()
    {
        lseek(0, 0, SEEK_SET);

        var buffer = new byte[64 * 1024];
        int length = 0;
        while (true)
        {
            if (length == buffer.Length)
                Array.Resize(ref buffer, buffer.Length * 2);

            nint got;
            fixed (byte* p = &buffer[length])
                got = read(0, p, (nuint)(buffer.Length - length));

            if (got <= 0) break;
            length += (int)got;
        }

        return buffer[..length];
    }

    const int SEEK_SET = 0;

    /// <summary>
    /// Points the SharpFuzz instrumentation at a throwaway bitmap.
    /// </summary>
    /// <remarks>
    /// Every instrumented method writes a coverage byte through Trace.SharedMem.
    /// Outside AFL that pointer is null, so any code path through the
    /// instrumented assemblies dies with an AccessViolationException that looks
    /// alarmingly like memory corruption in the library under test. Anything
    /// that runs instrumented code without a real AFL bitmap must call this
    /// first.
    /// </remarks>
    internal static void PinDummyCoverageBuffer()
    {
        if (Trace.SharedMem != null)
            return;
        var dummy = GCHandle.Alloc(new byte[MapSize], GCHandleType.Pinned);
        Trace.SharedMem = (byte*)dummy.AddrOfPinnedObject();
    }

    // PLANK_FUZZ_CRASH_DIR lets every worker on a machine funnel crashes into
    // one durable directory that outlives the AFL output dir.
    // PLANK_FUZZ_GUARD: the input being executed, emptied once it returns. One file per worker: set
    // PLANK_FUZZ_GUARD_TAG to the AFL worker name when several workers share /tmp.
    static string GuardCurrentPath(string targetName)
        => $"/tmp/plank-fuzz-{targetName}-{Environment.GetEnvironmentVariable("PLANK_FUZZ_GUARD_TAG") ?? "w"}-guard-current.bin";

    // A guard fault kills the process (AFL then only sees the fork server go away). On the restart, a non-empty
    // current-input file is that input (or one AFL killed as a hang): saved like a crash, as guard-<target>.
    static void RecoverGuardDeath(string targetName)
    {
        if (!GuardMemory.Enabled)
            return;
        var current = GuardCurrentPath(targetName);
        try
        {
            if (!File.Exists(current) || new FileInfo(current).Length == 0)
                return;
            var input = File.ReadAllBytes(current);
            Console.Error.WriteLine($"GUARD-DEATH-RECOVERED\t{targetName}\t{input.Length} bytes (guard fault or hang in the previous process)");
            SaveCrashInput($"guard-{targetName}", input);
            File.WriteAllBytes(current, []);
        }
        catch (IOException) { }
    }

    static void SaveCrashInput(string targetName, byte[] input)
    {
        var dir = Environment.GetEnvironmentVariable("PLANK_FUZZ_CRASH_DIR");
        if (string.IsNullOrEmpty(dir))
        {
            TryWriteAllBytes($"/tmp/plank-fuzz-{targetName}-crash-input.bin", input);
            return;
        }

        try
        {
            Directory.CreateDirectory(dir);
            var hash = Convert.ToHexStringLower(System.Security.Cryptography.SHA256.HashData(input));
            TryWriteAllBytes(Path.Combine(dir, $"{targetName}-{hash[..16]}.bin"), input);
        }
        catch (IOException) { }
        catch (UnauthorizedAccessException) { }
    }

    static void TryWriteAllBytes(string path, byte[] contents)
    {
        try { File.WriteAllBytes(path, contents); } catch (IOException) { } catch (UnauthorizedAccessException) { }
    }

    static void TryWriteAllText(string path, string contents)
    {
        try { File.WriteAllText(path, contents); } catch (IOException) { } catch (UnauthorizedAccessException) { }
    }

    static bool TryGetEnvInt(string name, out int value)
    {
        value = 0;
        var s = Environment.GetEnvironmentVariable(name);
        return s != null && int.TryParse(s, out value);
    }

    static void WriteU32(int fd, uint value) => write(fd, &value, 4);

    static bool ReadU32(int fd, out uint value)
    {
        uint v = 0;
        bool ok = read(fd, &v, 4) == 4;
        value = v;
        return ok;
    }
}
