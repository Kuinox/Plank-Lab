using System.Diagnostics;
using BenchmarkDotNet.Engines;

namespace Plank.Benchmarks.Published;

// Public so BenchmarkDotNet's generated child executable can construct it.
public sealed class PrComparisonEngineFactory : IEngineFactory
{
    public IEngine CreateReadyToRun(EngineParameters engineParameters)
    {
        var engine = new EngineFactory().CreateReadyToRun(engineParameters);
        try
        {
            // These benchmarks reset readers/writers in IterationSetup and verify in
            // IterationCleanup. Run real BDN iterations; batching workload calls would
            // reuse exhausted readers and closed writers. Keep tiering/PGO enabled.
            var elapsed = Stopwatch.StartNew();
            var iterations = 0;
            do
            {
                engine.RunIteration(new IterationData(
                    IterationMode.Workload, IterationStage.Warmup, ++iterations, 1, 1));
            }
            while (iterations < 32 || elapsed.Elapsed < TimeSpan.FromSeconds(10));

            engine.WriteLine($"// PR prewarm: {iterations} iterations, {elapsed.Elapsed.TotalSeconds:F3} seconds");
            return engine;
        }
        catch
        {
            engine.Dispose();
            throw;
        }
    }
}
