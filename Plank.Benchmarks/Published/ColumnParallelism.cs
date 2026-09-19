using System.Collections.Concurrent;

namespace Plank.Benchmarks;

/// <summary>Runs independent column work with a bounded worker set and records observed threads.</summary>
static class ColumnParallelism
{
    internal sealed class Tracker
    {
        readonly ConcurrentDictionary<int, byte> _threads = new();
        int _maximum;
        int _lastObserved;

        internal int MaximumObserved => Volatile.Read(ref _maximum);
        internal int LastObserved => Volatile.Read(ref _lastObserved);

        internal int Run(int itemCount, int workerCount, Action<int> action)
        {
            ArgumentOutOfRangeException.ThrowIfNegativeOrZero(itemCount);
            ArgumentOutOfRangeException.ThrowIfNegativeOrZero(workerCount);
            ArgumentNullException.ThrowIfNull(action);
            _threads.Clear();
            Parallel.For(0, itemCount, new ParallelOptions { MaxDegreeOfParallelism = workerCount }, index =>
            {
                _threads.TryAdd(Environment.CurrentManagedThreadId, 0);
                action(index);
            });
            var observed = _threads.Count;
            Volatile.Write(ref _lastObserved, observed);
            Interlocked.Exchange(ref _maximum, Math.Max(observed, Volatile.Read(ref _maximum)));
            return observed;
        }
    }

    internal static int WorkerCount(int itemCount)
    {
        ArgumentOutOfRangeException.ThrowIfNegativeOrZero(itemCount);
        var cpus = BenchmarkAffinity.GetBenchmarkCpus();
        var available = cpus.Length == 0 ? Environment.ProcessorCount : cpus.Length;
        return Math.Max(1, Math.Min(itemCount, available));
    }

    internal static void WriteMarker(string benchmarkType, string operation, int workerCount, int observedThreads)
    {
        // Fixture preparation invokes the same cleanup methods by reflection;
        // keep those untimed worker observations out of published measurements.
        if (BenchmarkFixtures.Preparing) return;
        Console.WriteLine($"BENCHMARK_THREADS|{benchmarkType}|{operation}|{workerCount}|{observedThreads}");
    }
}
