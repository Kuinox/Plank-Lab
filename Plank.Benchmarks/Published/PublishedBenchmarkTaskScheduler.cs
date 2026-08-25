using System.Collections.Concurrent;
using System.Runtime.InteropServices;

namespace Plank.Benchmarks.Published;

/// <summary>
/// Gives each Plank benchmark worker a stable logical CPU. The machine-level
/// isolation runner supplies the allowed CPU list; ordinary quick/test runs
/// without that environment variable keep using the default task scheduler.
/// </summary>
sealed class PublishedBenchmarkTaskScheduler : TaskScheduler, IDisposable
{
    const string CpuEnvironmentVariable = "PLANK_BENCHMARK_CPUS";

    readonly BlockingCollection<Task> _tasks = new();
    readonly Thread[] _threads;
    readonly CountdownEvent _started;
    readonly ConcurrentQueue<Exception> _startupFailures = new();
    bool _disposed;

    PublishedBenchmarkTaskScheduler(ParquetExecutionOptions execution, string threadNamePrefix)
    {
        _threads = new Thread[execution.WorkerCount];
        _started = new CountdownEvent(_threads.Length);
        for (var workerIndex = 0; workerIndex < _threads.Length; workerIndex++)
        {
            var index = workerIndex;
            _threads[index] = new Thread(() => WorkerLoop(execution, index))
            {
                IsBackground = true,
                Name = $"{threadNamePrefix}-{index}"
            };
            _threads[index].Start();
        }

        _started.Wait();
        if (_startupFailures.TryPeek(out var failure))
        {
            Dispose();
            throw new InvalidOperationException("A pinned benchmark worker could not start.", failure);
        }
    }

    public static PublishedBenchmarkTaskScheduler? TryCreate(ParquetExecutionOptions execution,
        string threadNamePrefix)
    {
        var value = Environment.GetEnvironmentVariable(CpuEnvironmentVariable);
        return string.IsNullOrWhiteSpace(value)
            ? null
            : new PublishedBenchmarkTaskScheduler(execution, threadNamePrefix);
    }

    public static ParquetExecutionOptions CreateExecutionOptions(int workerCount)
    {
        var value = Environment.GetEnvironmentVariable(CpuEnvironmentVariable);
        if (string.IsNullOrWhiteSpace(value))
            return new ParquetExecutionOptions { WorkerCount = workerCount };

        var cpus = ParseCpuList(value);
        if (workerCount > cpus.Count)
            throw new InvalidOperationException(
                $"{workerCount} benchmark workers cannot be pinned to {cpus.Count} CPUs.");
        return new ParquetExecutionOptions
        {
            WorkerCount = workerCount,
            OnWorkerStarted = context => PinCurrentThread(cpus[context.WorkerIndex])
        };
    }

    internal static IReadOnlyList<int> ParseCpuList(string value)
    {
        var cpus = new SortedSet<int>();
        foreach (var part in value.Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries))
        {
            var bounds = part.Split('-', 2, StringSplitOptions.TrimEntries);
            var first = int.Parse(bounds[0], System.Globalization.CultureInfo.InvariantCulture);
            var last = bounds.Length == 1
                ? first
                : int.Parse(bounds[1], System.Globalization.CultureInfo.InvariantCulture);
            if (first < 0 || last < first)
                throw new FormatException($"Invalid CPU range '{part}' in {CpuEnvironmentVariable}.");
            for (var cpu = first; cpu <= last; cpu++)
                cpus.Add(cpu);
        }

        if (cpus.Count == 0)
            throw new FormatException($"{CpuEnvironmentVariable} contains no CPUs.");
        return cpus.ToArray();
    }

    internal static void StartWorker(ParquetExecutionOptions execution, int workerIndex, string name)
        => execution.OnWorkerStarted?.Invoke(
            new ParquetWorkerContext(workerIndex, execution.WorkerCount, name));

    protected override IEnumerable<Task>? GetScheduledTasks()
        => _tasks.ToArray();

    public override int MaximumConcurrencyLevel
        => _threads.Length;

    protected override void QueueTask(Task task)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        _tasks.Add(task);
    }

    protected override bool TryExecuteTaskInline(Task task, bool taskWasPreviouslyQueued)
        => false;

    void WorkerLoop(ParquetExecutionOptions execution, int workerIndex)
    {
        try
        {
            StartWorker(execution, workerIndex, Thread.CurrentThread.Name!);
        }
        catch (Exception ex)
        {
            _startupFailures.Enqueue(ex);
        }
        finally
        {
            _started.Signal();
        }

        if (!_startupFailures.IsEmpty)
            return;
        foreach (var task in _tasks.GetConsumingEnumerable())
            TryExecuteTask(task);
    }

    static void PinCurrentThread(int cpu)
    {
        if (!OperatingSystem.IsLinux())
            throw new PlatformNotSupportedException("Pinned published benchmarks currently require Linux.");
        var mask = new byte[cpu / 8 + 1];
        mask[cpu / 8] = (byte)(1 << (cpu % 8));
        if (sched_setaffinity(0, (nuint)mask.Length, mask) != 0)
            throw new InvalidOperationException(
                $"Could not pin benchmark worker to CPU {cpu} (errno {Marshal.GetLastPInvokeError()}).");
    }

    public void Dispose()
    {
        if (_disposed)
            return;
        _disposed = true;
        _tasks.CompleteAdding();
        foreach (var thread in _threads)
            if (thread.IsAlive)
                thread.Join();
        _tasks.Dispose();
        _started.Dispose();
    }

    [DllImport("libc", SetLastError = true)]
    static extern int sched_setaffinity(int pid, nuint cpuSetSize, byte[] mask);
}
