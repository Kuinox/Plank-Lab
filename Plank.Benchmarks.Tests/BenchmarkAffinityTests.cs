using Plank.Writing;

namespace Plank.Benchmarks.Tests;

internal sealed class BenchmarkAffinityTests
{
    [Test]
    public void WorkerStartupStateSurvivesWriterReset()
    {
        var pinning = new PlankWorkerPinning();
        pinning.Reset();
        pinning.OnWorkerStarted(new ParquetWorkerContext(0, 1, "test-worker"));
        pinning.Wait();

        pinning.Reset();
        pinning.Wait();
    }

    [Test]
    public void WorkerStartupStateAcceptsRestartCallbacks()
    {
        var pinning = new PlankWorkerPinning();
        pinning.Reset();
        pinning.OnWorkerStarted(new ParquetWorkerContext(0, 1, "first-worker"));
        pinning.Wait();

        pinning.Reset();
        pinning.OnWorkerStarted(new ParquetWorkerContext(0, 1, "restarted-worker"));
        pinning.Wait();
    }
}
