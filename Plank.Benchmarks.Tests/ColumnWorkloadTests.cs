using BenchmarkDotNet.Attributes;
using Plank.Benchmarks.Published;
using System.Reflection;

namespace Plank.Benchmarks.Tests;

[NotInParallel]
internal sealed class ColumnWorkloadTests
{
    [Test]
    public async Task ColumnCatalogExactlyDoublesEverySupportedOperation()
    {
        var rows = PublishedBenchmarkCommand.GetBenchmarkTypes("row");
        var columns = PublishedBenchmarkCommand.GetBenchmarkTypes("column");
        await Assert.That(rows.Length).IsEqualTo(121);
        await Assert.That(columns.Length).IsEqualTo(197);
        foreach (var type in rows)
        {
            var counterpart = columns.Single(column => !column.Name.Contains("ColumnMulti", StringComparison.Ordinal) &&
                                                       column.Name.Replace("Column", "") == type.Name);
            var names = type.GetMethods().Where(method => method.IsDefined(typeof(BenchmarkAttribute)))
                .Select(method => method.Name).ToArray();
            await Assert.That(counterpart.GetMethods().Where(method => method.IsDefined(typeof(BenchmarkAttribute)))
                .Select(method => method.Name)).IsEquivalentTo(names);
        }
    }

    [Test]
    [TUnit.Core.Arguments(false, 128, false)]
    [TUnit.Core.Arguments(false, 45_456, true)]
    [TUnit.Core.Arguments(true, 128, false)]
    public async Task ColumnWritesAndReadsMatchRowFixtureValues(bool realWorld, int count, bool narrow)
    {
        var directory = Directory.CreateTempSubdirectory("plank-column-validation-");
        var oldDirectory = Environment.GetEnvironmentVariable(BenchmarkFixtures.DirectoryVariable);
        var oldRows = Environment.GetEnvironmentVariable("PLANK_BENCHMARK_ROWS");
        var oldTaxiRows = Environment.GetEnvironmentVariable("PLANK_BENCHMARK_TAXI_ROWS");
        var oldTaxiFile = Environment.GetEnvironmentVariable("PLANK_BENCHMARK_TAXI_FILE");
        try
        {
            Environment.SetEnvironmentVariable(BenchmarkFixtures.DirectoryVariable, directory.FullName);
            Environment.SetEnvironmentVariable("PLANK_BENCHMARK_ROWS", count.ToString());
            Environment.SetEnvironmentVariable("PLANK_BENCHMARK_TAXI_ROWS", count.ToString());
            if (realWorld && oldTaxiFile is null)
            {
                var fixture = Path.Combine(directory.FullName, "taxi-test-input.parquet");
                File.WriteAllBytes(fixture, CreateTaxiFixture(count));
                Environment.SetEnvironmentVariable("PLANK_BENCHMARK_TAXI_FILE", fixture);
            }
            foreach (var type in PublishedBenchmarkCommand.GetBenchmarkTypes("column")
                .Where(type => !type.Name.Contains("ColumnMulti", StringComparison.Ordinal))
                .Where(type => type.Name.StartsWith(narrow ? "SyntheticInt32PlainColumn" : realWorld ? "Real" : "Synthetic")))
            {
                var rowType = PublishedBenchmarkCommand.GetBenchmarkTypes("row")
                    .Single(row => type.Name.Replace("Column", "") == row.Name);
                var stem = type.Name.Replace("PlankBenchmarks", "").Replace("ParquetSharpBenchmarks", "")
                    .Replace("ParquetNetBenchmarks", "");
                await BenchmarkFixtures.Prepare(stem, true, type.GetMethod("Write") is null ? [] : [type.Name]);
                var expected = await Read(rowType, count);
                await Compare(expected, await Read(type, count));
                if (type.GetMethod("Write") is null) continue;
                var writer = Activator.CreateInstance(type)!;
                type.GetProperty("Rows")!.SetValue(writer, count);
                try
                {
                    type.GetMethod("GlobalSetupWrite")!.Invoke(writer, null);
                    type.GetMethod("SetupWrite")!.Invoke(writer, null);
                    try
                    {
                        if (type.GetMethod("Write")!.Invoke(writer, null) is Task task) await task;
                        var output = (MemoryStream)type.GetField("_output", BindingFlags.NonPublic | BindingFlags.Instance)!.GetValue(writer)!;
                        File.WriteAllBytes(Path.Combine(directory.FullName, stem[..^6] + ".parquet"), output.ToArray());
                        // Decode the column writer's output using the existing row API and column API.
                        await Compare(expected, await Read(rowType, count));
                        await Compare(expected, await Read(type, count));
                    }
                    finally { type.GetMethod("CleanupWrite")!.Invoke(writer, null); }
                }
                finally { type.GetMethod("Cleanup")!.Invoke(writer, null); }
            }
        }
        finally
        {
            Environment.SetEnvironmentVariable(BenchmarkFixtures.DirectoryVariable, oldDirectory);
            Environment.SetEnvironmentVariable("PLANK_BENCHMARK_ROWS", oldRows);
            Environment.SetEnvironmentVariable("PLANK_BENCHMARK_TAXI_ROWS", oldTaxiRows);
            Environment.SetEnvironmentVariable("PLANK_BENCHMARK_TAXI_FILE", oldTaxiFile);
            directory.Delete(true);
        }
    }

    [Test]
    public async Task MultiColumnCatalogUsesOnlySupportedLibrariesAndWideSchemas()
    {
        var multi = PublishedBenchmarkCommand.GetBenchmarkTypes("column")
            .Where(type => type.Name.Contains("ColumnMulti", StringComparison.Ordinal)).ToArray();
        await Assert.That(multi).Count().IsEqualTo(76);
        await Assert.That(multi.All(type => type.Name.EndsWith("MultiPlankBenchmarks", StringComparison.Ordinal) ||
                                             type.Name.EndsWith("MultiParquetSharpBenchmarks", StringComparison.Ordinal))).IsTrue();
        await Assert.That(multi.All(type => type.GetMethods().Any(method =>
            method.IsDefined(typeof(BenchmarkAttribute), false)))).IsTrue();
        await Assert.That(multi.Count(type => type.Name.EndsWith("MultiPlankBenchmarks", StringComparison.Ordinal)))
            .IsEqualTo(38);
        await Assert.That(multi.Count(type => type.Name.EndsWith("MultiParquetSharpBenchmarks", StringComparison.Ordinal)))
            .IsEqualTo(38);
    }

    [Test]
    [NotInParallel]
    public async Task PlankMultiColumnReadAndWriteMatchSingleColumnBytes()
    {
        const int count = 128;
        const string stem = "SyntheticInt32PlainColumn";
        const string singleName = "SyntheticInt32PlainColumnPlankBenchmarks";
        const string multiName = "SyntheticInt32PlainColumnMultiPlankBenchmarks";
        var directory = Directory.CreateTempSubdirectory("plank-column-multi-validation-");
        var oldDirectory = Environment.GetEnvironmentVariable(BenchmarkFixtures.DirectoryVariable);
        var oldRows = Environment.GetEnvironmentVariable("PLANK_BENCHMARK_ROWS");
        try
        {
            Environment.SetEnvironmentVariable(BenchmarkFixtures.DirectoryVariable, directory.FullName);
            Environment.SetEnvironmentVariable("PLANK_BENCHMARK_ROWS", count.ToString());
            // The fixture stores one output capacity per library; the multi Plank
            // writer produces the same bytes, so prepare it once and compare both
            // implementations against that capacity.
            await BenchmarkFixtures.Prepare(stem, true, [multiName]);

            var singleRead = await Read(PublishedBenchmarkCommand.GetBenchmarkTypes("column")
                .Single(type => type.Name == singleName), count);
            var multiRead = await Read(PublishedBenchmarkCommand.GetBenchmarkTypes("column")
                .Single(type => type.Name == multiName), count);
            await Compare(singleRead, multiRead);

            var singleOutput = Write(singleName, count);
            var multiOutput = Write(multiName, count);
            await Assert.That(multiOutput).IsEquivalentTo(singleOutput);
        }
        finally
        {
            Environment.SetEnvironmentVariable(BenchmarkFixtures.DirectoryVariable, oldDirectory);
            Environment.SetEnvironmentVariable("PLANK_BENCHMARK_ROWS", oldRows);
            directory.Delete(recursive: true);
        }

        static byte[] Write(string className, int rows)
        {
            var type = PublishedBenchmarkCommand.GetBenchmarkTypes("column")
                .Single(candidate => candidate.Name == className);
            var benchmark = Activator.CreateInstance(type)!;
            type.GetProperty("Rows")!.SetValue(benchmark, rows);
            try
            {
                type.GetMethod("GlobalSetupWrite")!.Invoke(benchmark, null);
                type.GetMethod("SetupWrite")!.Invoke(benchmark, null);
                try
                {
                    type.GetMethod("Write")!.Invoke(benchmark, null);
                    var output = (MemoryStream)type.GetField("_output", BindingFlags.NonPublic | BindingFlags.Instance)!
                        .GetValue(benchmark)!;
                    return output.ToArray();
                }
                finally { type.GetMethod("CleanupWrite")!.Invoke(benchmark, null); }
            }
            finally { type.GetMethod("Cleanup")!.Invoke(benchmark, null); }
        }
    }

    static byte[] CreateTaxiFixture(int count)
    {
        var rows = new RealTaxiPlainPlankRow[count];
        var properties = typeof(RealTaxiPlainPlankRow).GetProperties();
        for (var i = 0; i < count; i++)
        {
            var row = new RealTaxiPlainPlankRow();
            rows[i] = row;
            if (i % 5 == 0) continue;
            foreach (var property in properties.Where(property => property.CanWrite))
            {
                var type = Nullable.GetUnderlyingType(property.PropertyType);
                object value = type == typeof(int) ? (object)(i % 7 - 3)
                    : type == typeof(long) ? (long)(i % 11 - 5)
                    : type == typeof(double) ? i / 4d
                    : type == typeof(DateTime) ? new DateTime(2024, 1, 1, 0, 0, 0, DateTimeKind.Utc).AddSeconds(i)
                    : type == typeof(ReadOnlyMemory<byte>) ? new ReadOnlyMemory<byte>(System.Text.Encoding.UTF8.GetBytes(i % 2 == 0 ? "Y" : "é"))
                    : throw new InvalidOperationException($"Unhandled test column type: {type}.");
                property.SetValue(row, value);
            }
        }
        return RealTaxiPlainPlankRow.CreateReadFile(rows);
    }

    static async Task<object> Read(Type type, int count)
    {
        var reader = Activator.CreateInstance(type)!;
        type.GetProperty("Rows")!.SetValue(reader, count);
        try
        {
            type.GetMethod("GlobalSetupRead")!.Invoke(reader, null);
            type.GetMethod("SetupRead")!.Invoke(reader, null);
            var value = type.GetMethod("Read")!.Invoke(reader, null)!;
            if (type.Name.Contains("Column"))
            {
                var consumed = value is Task<long> consumption ? await consumption : (long)value;
                type.GetMethod("SetupRead")!.Invoke(reader, null);
                value = type.GetMethod("VerifyRead")!.Invoke(reader, null)!;
                // Timed Read also validates the exact row count times schema width.
                if (consumed <= 0) throw new InvalidDataException("No decoded values consumed.");
            }
            if (value is Task task)
            {
                await task;
                value = task.GetType().GetProperty("Result")!.GetValue(task)!;
            }
            return value;
        }
        finally { type.GetMethod("Cleanup")!.Invoke(reader, null); }
    }

    static async Task Compare(object expected, object actual)
    {
        if (expected is double left && actual is double right)
            await Assert.That(Math.Abs(left - right) <= Math.Max(1, Math.Abs(left)) * 1e-12).IsTrue();
        else
            await Assert.That(actual).IsEqualTo(expected);
    }
}
