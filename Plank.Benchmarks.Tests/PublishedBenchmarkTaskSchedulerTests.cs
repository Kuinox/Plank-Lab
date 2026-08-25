using Plank.Benchmarks.Published;

namespace Plank.Benchmarks.Tests;

internal sealed class PublishedBenchmarkTaskSchedulerTests
{
    [Test]
    public async Task CpuListExpandsRangesAndSortsUniqueValues()
    {
        var cpus = PublishedBenchmarkTaskScheduler.ParseCpuList("13-15,2,14,4-5");

        await Assert.That(cpus).IsEquivalentTo([2, 4, 5, 13, 14, 15]);
    }

    [Test]
    public async Task CpuListRejectsDescendingRange()
    {
        var exception = Assert.Throws<FormatException>(() =>
            PublishedBenchmarkTaskScheduler.ParseCpuList("3-1"));

        await Assert.That(exception.Message).Contains("Invalid CPU range");
    }
}
