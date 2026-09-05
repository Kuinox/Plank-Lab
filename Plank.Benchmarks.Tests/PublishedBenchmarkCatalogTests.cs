using BenchmarkDotNet.Attributes;
using Plank.Benchmarks.Published;

namespace Plank.Benchmarks.Tests;

internal sealed class PublishedBenchmarkCatalogTests
{
    [Test]
    public void PlankWriteLoopSupportsRepeatedWriterReset()
    {
        var benchmark = new SyntheticInt32PlainPlankBenchmarks { Rows = 128 };
        benchmark.Setup();
        try
        {
            for (var iteration = 0; iteration < 2; iteration++)
            {
                benchmark.SetupWrite();
                try { benchmark.Write(); }
                finally { benchmark.CleanupWrite(); }
            }
        }
        finally
        {
            benchmark.Cleanup();
        }
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
