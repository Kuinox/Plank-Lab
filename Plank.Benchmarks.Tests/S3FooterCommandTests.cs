using System.Text.Json;
using Parquet;
using Parquet.Schema;
using Plank.Benchmarks.S3Footer;

namespace Plank.Benchmarks.Tests;

internal sealed class S3FooterCommandTests
{
    [Test]
    public async Task InvalidArgumentsAreRejectedBeforePreparingTheFixture()
    {
        string[][] invalidArguments =
        [
            ["--unknown"],
            ["--iterations"],
            ["--data-file", "--output", "unused.json"],
            ["--output", ""],
            ["--iterations", "0"],
            ["--iterations", "-1"],
            ["--iterations", "1.5"],
            ["--iterations", "2147483648"],
            ["--iterations", "1", "--iterations", "2"],
            ["--latency-ms", "-1"],
            ["--latency-ms", "NaN"],
            ["--latency-ms", "Infinity"],
            ["--latency-ms", "1e400"],
            ["--latency-ms", "1,5"],
            ["--help", "--help"],
            ["--help", "unexpected"]
        ];
        foreach (var args in invalidArguments)
            await Assert.That(await S3FooterCommand.RunAsync(args)).IsEqualTo(2);
        await Assert.That(await S3FooterCommand.RunAsync(["--help"])).IsEqualTo(0);
    }

    [Test]
    [NotInParallel]
    public async Task AllReadersReturnMatchingMetadataAndRepeatIndependentNetworkTrials()
    {
        var directory = Directory.CreateTempSubdirectory("plank-s3-command-");
        try
        {
            var input = Path.Combine(directory.FullName, "tiny.parquet");
            var output = Path.Combine(directory.FullName, "report.json");
            await CreateFixtureAsync(input);

            var exit = await S3FooterCommand.RunAsync([
                "--data-file", input, "--iterations", "2", "--latency-ms", "0", "--output", output
            ]);
            await Assert.That(exit).IsEqualTo(0);
            using var json = JsonDocument.Parse(await File.ReadAllTextAsync(output));
            var root = json.RootElement;
            await Assert.That(root.GetProperty("schemaVersion").GetInt32()).IsEqualTo(1);
            await Assert.That(root.GetProperty("dataset").GetProperty("fileSizeBytes").GetInt64())
                .IsEqualTo(new FileInfo(input).Length);
            await Assert.That(root.GetProperty("dataset").GetProperty("footerSha256").GetString()!.Length).IsEqualTo(64);
            await Assert.That(root.GetProperty("protocol").GetProperty("iterations").GetInt32()).IsEqualTo(2);
            var runs = root.GetProperty("runs").EnumerateArray().ToArray();
            await Assert.That(runs.Length).IsEqualTo(6);
            await Assert.That(runs.Select(run => run.GetProperty("library").GetString()!).ToArray())
                .IsEquivalentTo(["Plank", "Parquet.Net", "ParquetSharp", "Parquet.Net", "ParquetSharp", "Plank"]);
            await Assert.That(runs[3].GetProperty("library").GetString()).IsEqualTo("Parquet.Net");

            foreach (var run in runs)
            {
                await Assert.That(run.GetProperty("error").ValueKind).IsEqualTo(JsonValueKind.Null);
                await Assert.That(run.GetProperty("rowCount").GetInt64()).IsEqualTo(3L);
                await Assert.That(run.GetProperty("rowGroupCount").GetInt32()).IsEqualTo(2);
                await Assert.That(run.GetProperty("columnCount").GetInt32()).IsEqualTo(2);
                await Assert.That(run.GetProperty("version").GetString()!.Length > 0).IsTrue();
                var elapsedMs = run.GetProperty("elapsedMs").GetDouble();
                await Assert.That(double.IsFinite(elapsedMs) && elapsedMs > 0).IsTrue();
                var requests = run.GetProperty("requests").EnumerateArray().ToArray();
                await Assert.That(requests.Count(request => request.GetProperty("method").GetString() == "HEAD")).IsEqualTo(1);
                await Assert.That(requests[0].GetProperty("method").GetString()).IsEqualTo("HEAD");
                await Assert.That(requests[0].GetProperty("bytesReceived").GetInt64()).IsEqualTo(0L);
                await Assert.That(requests.Length > 1).IsTrue();
                foreach (var request in requests)
                {
                    await Assert.That(request.GetProperty("error").ValueKind).IsEqualTo(JsonValueKind.Null);
                    var startMs = request.GetProperty("startMs").GetDouble();
                    var durationMs = request.GetProperty("durationMs").GetDouble();
                    await Assert.That(startMs >= 0 && durationMs >= 0 && startMs + durationMs <= elapsedMs).IsTrue();
                    if (request.GetProperty("method").GetString() != "GET") continue;
                    await Assert.That(request.GetProperty("statusCode").GetInt32()).IsEqualTo(206);
                    var start = request.GetProperty("startByte").GetInt64();
                    var end = request.GetProperty("endByte").GetInt64();
                    await Assert.That(start >= 0 && end >= start && end < new FileInfo(input).Length).IsTrue();
                    await Assert.That(request.GetProperty("bytesReceived").GetInt64()).IsEqualTo(end - start + 1);
                }
            }

            foreach (var library in new[] { "Plank", "Parquet.Net", "ParquetSharp" })
            {
                var trials = runs.Where(run => run.GetProperty("library").GetString() == library).ToArray();
                await Assert.That(trials[0].GetProperty("iteration").GetInt32()).IsEqualTo(1);
                await Assert.That(trials[1].GetProperty("iteration").GetInt32()).IsEqualTo(2);
                var firstRequests = trials[0].GetProperty("requests").EnumerateArray().ToArray();
                var secondRequests = trials[1].GetProperty("requests").EnumerateArray().ToArray();
                await Assert.That(secondRequests.Length).IsEqualTo(firstRequests.Length);
                await Assert.That(secondRequests.Sum(request => request.GetProperty("bytesReceived").GetInt64()))
                    .IsEqualTo(firstRequests.Sum(request => request.GetProperty("bytesReceived").GetInt64()));
            }
        }
        finally { directory.Delete(recursive: true); }
    }

    [Test]
    [NotInParallel]
    public async Task MalformedFooterProducesFailedRunsAndANonzeroExitWithAReport()
    {
        var directory = Directory.CreateTempSubdirectory("plank-s3-failed-command-");
        try
        {
            var input = Path.Combine(directory.FullName, "corrupt.parquet");
            var output = Path.Combine(directory.FullName, "failed-report.json");
            // Valid envelope and length, deliberately invalid compact-Thrift footer.
            await File.WriteAllBytesAsync(input, [80, 65, 82, 49, 255, 1, 0, 0, 0, 80, 65, 82, 49]);
            var exit = await S3FooterCommand.RunAsync([
                "--data-file", input, "--iterations", "1", "--output", output
            ]);
            await Assert.That(exit).IsEqualTo(1);
            using var json = JsonDocument.Parse(await File.ReadAllTextAsync(output));
            var runs = json.RootElement.GetProperty("runs").EnumerateArray().ToArray();
            await Assert.That(runs.Length).IsEqualTo(3);
            foreach (var run in runs)
            {
                await Assert.That(string.IsNullOrEmpty(run.GetProperty("error").GetString())).IsFalse();
                await Assert.That(run.GetProperty("rowCount").ValueKind).IsEqualTo(JsonValueKind.Null);
                await Assert.That(run.GetProperty("rowGroupCount").ValueKind).IsEqualTo(JsonValueKind.Null);
                await Assert.That(run.GetProperty("columnCount").ValueKind).IsEqualTo(JsonValueKind.Null);
                await Assert.That(run.GetProperty("requests").GetArrayLength() > 0).IsTrue();
            }
        }
        finally { directory.Delete(recursive: true); }
    }

    [Test]
    public async Task OutputCannotOverwriteTheInputFile()
    {
        var directory = Directory.CreateTempSubdirectory("plank-s3-input-protection-");
        try
        {
            var path = Path.Combine(directory.FullName, "source.parquet");
            byte[] original = [1, 2, 3];
            await File.WriteAllBytesAsync(path, original);
            await Assert.That(await S3FooterCommand.RunAsync(["--data-file", path, "--output", path])).IsEqualTo(1);
            await Assert.That(await File.ReadAllBytesAsync(path)).IsEquivalentTo(original);
        }
        finally { directory.Delete(recursive: true); }
    }

    static async Task CreateFixtureAsync(string path)
    {
        var id = new DataField<int>("id");
        var value = new DataField<double>("value");
        await using var output = File.Create(path);
        await using var writer = await ParquetWriter.CreateAsync(new ParquetSchema(id, value), output);
        using (var group = writer.CreateRowGroup())
        {
            await group.WriteAsync<int>(id, new int[] { 1, 2 });
            await group.WriteAsync<double>(value, new double[] { 10.5, 20.5 });
        }
        using (var group = writer.CreateRowGroup())
        {
            await group.WriteAsync<int>(id, new int[] { 3 });
            await group.WriteAsync<double>(value, new double[] { 30.5 });
        }
    }
}
