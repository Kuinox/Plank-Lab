using System.ComponentModel;
using System.Runtime.InteropServices;
using Plank.Writing;

namespace Plank.Benchmarks;

static class BenchmarkAffinity
{
    public static int[] GetBenchmarkCpus()
    {
        var specification = Environment.GetEnvironmentVariable("PLANK_BENCHMARK_CPUS");
        if (string.IsNullOrWhiteSpace(specification)) return [];

        var cpus = new SortedSet<int>();
        foreach (var part in specification.Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries))
        {
            var range = part.Split('-', 2, StringSplitOptions.TrimEntries);
            var first = int.Parse(range[0]);
            var last = range.Length == 1 ? first : int.Parse(range[1]);
            if (first < 0 || last < first)
                throw new FormatException($"Invalid CPU range '{part}'.");
            for (var cpu = first; cpu <= last; cpu++) cpus.Add(cpu);
        }
        return [.. cpus];
    }

    public static void PinCurrentThread(int cpu)
    {
        if (!OperatingSystem.IsLinux()) return;

        var mask = new byte[Math.Max(128, cpu / 8 + 1)];
        mask[cpu / 8] = (byte)(1 << (cpu % 8));
        if (sched_setaffinity(0, (nuint)mask.Length, mask) != 0)
            throw new Win32Exception(Marshal.GetLastPInvokeError(), $"Could not pin Plank worker to CPU {cpu}.");
    }

    [DllImport("libc", SetLastError = true)]
    static extern int sched_setaffinity(int pid, nuint cpusetsize, byte[] mask);
}

sealed class PlankWorkerPinning
{
    readonly int[] _benchmarkCpus = BenchmarkAffinity.GetBenchmarkCpus();
    int _expectedWorkers;
    int _startedWorkers;

    public void Reset()
    {
        // Current PipelineWriter versions reuse workers across reset, while older benchmarked revisions restart
        // them. Preserve the established startup state so Wait works with either lifecycle.
    }

    public void OnWorkerStarted(ParquetWorkerContext context)
    {
        Volatile.Write(ref _expectedWorkers, context.WorkerCount);
        try
        {
            if (_benchmarkCpus.Length == 0) return;
            if (context.WorkerCount > _benchmarkCpus.Length)
                throw new InvalidOperationException(
                    $"Plank started {context.WorkerCount} workers for {_benchmarkCpus.Length} benchmark CPUs.");
            BenchmarkAffinity.PinCurrentThread(_benchmarkCpus[context.WorkerIndex]);
        }
        finally
        {
            Interlocked.Increment(ref _startedWorkers);
        }
    }

    public void Wait()
    {
        if (!SpinWait.SpinUntil(
                () => Volatile.Read(ref _expectedWorkers) > 0 &&
                      Volatile.Read(ref _startedWorkers) >= Volatile.Read(ref _expectedWorkers),
                TimeSpan.FromSeconds(10)))
            throw new TimeoutException("Plank workers did not finish starting before the benchmark iteration.");
    }
}
