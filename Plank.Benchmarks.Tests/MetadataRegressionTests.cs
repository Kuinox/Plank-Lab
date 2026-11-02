using System.Text.Json;
using Plank.Benchmarks.MetadataRegression;
using Plank.Reading;
using Plank.Reading.Logical;
using Plank.Reading.Physical;

namespace Plank.Benchmarks.Tests;

internal sealed class MetadataRegressionTests
{
    [Test]
    public async Task QuickFixturesExerciseMetadataAndProduceStableDigests()
    {
        var root = Path.Combine("artifacts", "metadata-tests", Guid.NewGuid().ToString("N"));
        var fixtures = Path.Combine(root, "fixtures");
        MetadataFixtures.Generate(fixtures, quick: true);
        foreach (var name in new[] { "pages-v1", "pages-v2" })
        {
            var source = new MemoryReadSource(File.ReadAllBytes(Path.Combine(fixtures, name + ".parquet")));
            using var physical = new ParquetFileReader(); physical.Reset(source);
            var chunk = physical.Metadata.ColumnChunk(0, 0);
            await Assert.That(chunk.HasBloomFilter).IsTrue();
            await Assert.That(chunk.ColumnIndexLength > 0 && chunk.OffsetIndexLength > 0).IsTrue();
            using var logical = new ParquetReader(); logical.Reset(source);
            using var pages = logical.RowGroups[0].GetColumnMetadata(0).OpenPages();
            await Assert.That(pages.Count).IsGreaterThan(10);
        }
        var a = Path.Combine(root, "a.json"); var b = Path.Combine(root, "b.json");
        var calibration = Path.Combine(root, "calibration.json");
        MetadataRegressionCommand.Run(["--fixtures", fixtures, "--output", calibration, "--calibrate", "--quick"]);
        MetadataRegressionCommand.Run(["--fixtures", fixtures, "--output", a, "--quick", "--label", "a", "--calibration", calibration]);
        MetadataRegressionCommand.Run(["--fixtures", fixtures, "--output", b, "--quick", "--label", "b", "--calibration", calibration]);
        var first = JsonSerializer.Deserialize<MetadataReport>(File.ReadAllText(a))!;
        var second = JsonSerializer.Deserialize<MetadataReport>(File.ReadAllText(b))!;
        await Assert.That(first.Cases.Count).IsGreaterThan(20);
        await Assert.That(first.Cases.Select(x => x.Digest).SequenceEqual(second.Cases.Select(x => x.Digest))).IsTrue();
        await Assert.That(first.Cases.All(x => x.Samples.Count == 3 && x.Samples.All(s => s.AllocatedBytes >= 0 && s.Operations > 0))).IsTrue();
        await Assert.That(first.Cases.Any(x => x.Samples[0].Operations > 1)).IsTrue();
        await Assert.That(MetadataRegressionCommand.Compare([a, b])).IsEqualTo(0);
        var altered = second with { Cases = second.Cases.Select((c, i) => i == 0 ? c with { Digest = "changed" } : c).ToList() };
        File.WriteAllText(b, JsonSerializer.Serialize(altered));
        await Assert.That(MetadataRegressionCommand.Compare([a, b])).IsEqualTo(1);
    }

    [Test]
    [NotInParallel]
    public async Task AllocationDeltasRemainExactFractions()
    {
        var root = Path.Combine("artifacts", "metadata-tests", Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(root);
        var a = Path.Combine(root, "a.json"); var b = Path.Combine(root, "b.json");
        MetadataReport Report(long allocated) => new("test", "revision", DateTimeOffset.UtcNow,
            [new("fixture/op", "input", "digest", [new(1, allocated, 3, 1)])]);
        File.WriteAllText(a, JsonSerializer.Serialize(Report(1)));
        File.WriteAllText(b, JsonSerializer.Serialize(Report(2)));
        var previous = Console.Out;
        using var output = new StringWriter();
        try
        {
            Console.SetOut(output);
            await Assert.That(MetadataRegressionCommand.Compare([a, b])).IsEqualTo(0);
        }
        finally { Console.SetOut(previous); }
        await Assert.That(output.ToString().Contains("1/3 (1/3..1/3 → 2/3..2/3; 3 ops/sample)")).IsTrue();
    }

    [Test]
    public async Task SummaryUsesMedianAndNearestRankP90()
    {
        await Assert.That(MetadataRegressionCommand.Median([1, 2, 3, 4])).IsEqualTo(2.5);
        await Assert.That(MetadataRegressionCommand.Percentile([1, 2, 3, 4, 5], .9)).IsEqualTo(5);
    }
}
