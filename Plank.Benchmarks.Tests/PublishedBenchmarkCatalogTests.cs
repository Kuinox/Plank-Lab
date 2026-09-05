using BenchmarkDotNet.Attributes;
using Plank.Benchmarks.Published;
using BenchmarkDotNet.Engines;
using System.Reflection;

namespace Plank.Benchmarks.Tests;

internal sealed class PublishedBenchmarkCatalogTests
{
    [Test]
    public async Task DefaultJobPreservesFirstUseAndAllOrderedSamples()
    {
        var job = PublishedBenchmarkCommand.CreateJob();
        await Assert.That(job.Run.RunStrategy).IsEqualTo(RunStrategy.ColdStart);
        await Assert.That(job.Run.LaunchCount).IsEqualTo(1);
        await Assert.That(job.Run.WarmupCount).IsEqualTo(0);
        await Assert.That(job.Run.IterationCount).IsEqualTo(100);
        await Assert.That(job.Run.InvocationCount).IsEqualTo(1L);
        await Assert.That(job.Environment.Gc.Force).IsFalse();
        await Assert.That(job.Accuracy.EvaluateOverhead).IsFalse();
        await Assert.That(job.Accuracy.OutlierMode.ToString()).IsEqualTo("DontRemove");
    }

    [Test]
    [NotInParallel]
    public async Task AllSyntheticSetupsAreSeparatedAndSupportRepeatedOperations()
    {
        var directory = Directory.CreateTempSubdirectory("plank-fixture-test-");
        var oldDirectory = Environment.GetEnvironmentVariable(BenchmarkFixtures.DirectoryVariable);
        var oldRows = Environment.GetEnvironmentVariable("PLANK_BENCHMARK_ROWS");
        try
        {
            Environment.SetEnvironmentVariable(BenchmarkFixtures.DirectoryVariable, directory.FullName);
            Environment.SetEnvironmentVariable("PLANK_BENCHMARK_ROWS", "128");
            var types = PublishedBenchmarkCommand.GetBenchmarkTypes().Where(t => t.Name.StartsWith("Synthetic"));
            foreach (var group in types.GroupBy(t => t.Name.Replace("ParquetNetBenchmarks", "").Replace("ParquetSharpBenchmarks", "").Replace("PlankBenchmarks", "")))
            {
                await BenchmarkFixtures.Prepare(group.Key, true,
                    group.Where(t => t.GetMethod("Write") is not null).Select(t => t.Name).ToArray());
                foreach (var type in group)
                foreach (var operation in new[] { "Write", "Read" })
                {
                    if (type.GetMethod(operation) is not { } method) continue;
                    var benchmark = Activator.CreateInstance(type)!;
                    type.GetProperty("Rows")!.SetValue(benchmark, 128);
                    try
                    {
                        type.GetMethod("GlobalSetup" + operation)!.Invoke(benchmark, null);
                        var unusedField = type.GetField(operation == "Read" ? "_rows" : "_reader", BindingFlags.NonPublic | BindingFlags.Instance);
                        if (unusedField is not null) await Assert.That(unusedField.GetValue(benchmark)).IsNull();
                        object? previous = null;
                        byte[]? previousOutputBuffer = null;
                        for (var iteration = 0; iteration < 2; iteration++)
                        {
                            type.GetMethod("Setup" + operation)!.Invoke(benchmark, null);
                            try
                            {
                                if (operation == "Write")
                                {
                                    var output = (MemoryStream)type.GetField("_output", BindingFlags.NonPublic | BindingFlags.Instance)!.GetValue(benchmark)!;
                                    var buffer = output.GetBuffer();
                                    if (previousOutputBuffer is not null)
                                        await Assert.That(ReferenceEquals(buffer, previousOutputBuffer)).IsTrue();
                                    previousOutputBuffer = buffer;
                                }
                                var result = method.Invoke(benchmark, null);
                                if (result is Task task)
                                {
                                    await task;
                                    result = task.GetType().GetProperty("Result")?.GetValue(task);
                                }
                                if (iteration > 0 && operation == "Read") await Assert.That(result).IsEqualTo(previous);
                                previous = result;
                            }
                            finally { type.GetMethod("Cleanup" + operation)?.Invoke(benchmark, null); }
                        }
                    }
                    finally { type.GetMethod("Cleanup")!.Invoke(benchmark, null); }
                }
            }
        }
        finally
        {
            Environment.SetEnvironmentVariable(BenchmarkFixtures.DirectoryVariable, oldDirectory);
            Environment.SetEnvironmentVariable("PLANK_BENCHMARK_ROWS", oldRows);
            directory.Delete(recursive: true);
        }
    }

    [Test]
    [NotInParallel]
    public async Task OutputBufferCanBeReopenedAfterWriterClosesStream()
    {
        var buffer = new byte[32];
        using (var first = BenchmarkFixtures.CreateOutput(buffer))
            first.Write([1, 2, 3, 4]);

        using var second = BenchmarkFixtures.CreateOutput(buffer);
        await Assert.That(ReferenceEquals(second.GetBuffer(), buffer)).IsTrue();
        await Assert.That(second.Length).IsEqualTo(0L);
        await Assert.That(second.Position).IsEqualTo(0L);
        second.Write([5, 6]);
        await Assert.That(second.ToArray()).IsEquivalentTo(new byte[] { 5, 6 });
    }

    [Test]
    public async Task DirectCatalogContainsOnlyPerLibraryCaseClasses()
    {
        var types = PublishedBenchmarkCommand.GetBenchmarkTypes();

        await Assert.That(types).Count().IsEqualTo(121);
        await Assert.That(types.All(type =>
            type.Name.StartsWith("Real", StringComparison.Ordinal) ||
            type.Name.StartsWith("Synthetic", StringComparison.Ordinal))).IsTrue();
        var methods = types.SelectMany(type => type.GetMethods()
            .Where(method => method.IsDefined(typeof(BenchmarkAttribute), false))).ToArray();
        await Assert.That(methods).Count().IsEqualTo(229);
        await Assert.That(types.All(type => type.GetMethods()
            .Count(method => method.IsDefined(typeof(BenchmarkAttribute), false)) is 1 or 2)).IsTrue();
        await Assert.That(methods.All(method => method.Name is "Write" or "Read")).IsTrue();
    }

    [Test]
    public async Task FocusedRegressionCaseUsesSeparateLibraryMethods()
    {
        var names = PublishedBenchmarkCommand.GetBenchmarkTypes()
            .Where(type => type.Name.StartsWith("SyntheticInt32Plain", StringComparison.Ordinal))
            .Select(type => type.Name)
            .ToArray();

        await Assert.That(names).IsEquivalentTo([
            "SyntheticInt32PlainParquetNetBenchmarks",
            "SyntheticInt32PlainParquetSharpBenchmarks",
            "SyntheticInt32PlainPlankBenchmarks"
        ]);
    }
}
