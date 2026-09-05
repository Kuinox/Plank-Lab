using System.Diagnostics;
using System.Reflection;
using System.Text.Json;

namespace Plank.Benchmarks;

// Run-scoped artifacts, not a persistent cache. Preparation runs in separate processes,
// so it cannot warm the JIT, serializers, readers or buffer pools being measured.
internal static class BenchmarkFixtures
{
    internal const string DirectoryVariable = "PLANK_BENCHMARK_FIXTURES";
    internal static bool Preparing { get; private set; }

    static string DirectoryPath => Environment.GetEnvironmentVariable(DirectoryVariable)
        ?? throw new InvalidOperationException("Run with --published to prepare benchmark fixtures first.");

    internal static byte[] LoadReadFile(string stem)
        => File.ReadAllBytes(Path.Combine(DirectoryPath, stem + ".parquet"));

    internal static int GetOutputCapacity(string stem, string library, out long expectedBytes)
    {
        if (Preparing)
        {
            expectedBytes = -1;
            return 0;
        }
        var sizes = JsonSerializer.Deserialize<Dictionary<string, long>>(
            File.ReadAllText(Path.Combine(DirectoryPath, stem + ".json")))!;
        expectedBytes = sizes[library];
        Console.WriteLine($"BENCHMARK_FILE|{stem}|{library}|{expectedBytes}");
        return BenchmarkData.OutputCapacity(checked((int)expectedBytes));
    }

    internal static MemoryStream CreateOutput(byte[] buffer)
    {
        // Fixture preparation discovers the size with an expandable stream. Measured
        // iterations reopen the same backing array, even when a writer closes its stream.
        if (Preparing) return new MemoryStream();
        var stream = new MemoryStream(buffer, 0, buffer.Length, writable: true, publiclyVisible: true);
        stream.SetLength(0);
        return stream;
    }

    internal static void ValidateOutput(long expected, long actual)
    {
        if (expected >= 0 && expected != actual)
            throw new InvalidDataException($"Output size changed: expected {expected}, got {actual}.");
    }

    internal static long OutputLength(MemoryStream stream)
        // Plank's Complete closes the stream. TryGetBuffer remains valid after close
        // and obtains the length without copying the whole output with ToArray().
        => stream.TryGetBuffer(out var buffer) ? buffer.Count
            : throw new InvalidOperationException("Benchmark output must expose its buffer.");

    internal static void PrepareInChild(string stem, string[] writeClasses, bool read)
    {
        var start = new ProcessStartInfo("dotnet") { UseShellExecute = false };
        start.ArgumentList.Add(typeof(BenchmarkFixtures).Assembly.Location);
        start.ArgumentList.Add("--prepare-published-fixture");
        start.ArgumentList.Add(stem);
        start.ArgumentList.Add(read.ToString());
        foreach (var name in writeClasses) start.ArgumentList.Add(name);
        using var process = Process.Start(start) ?? throw new InvalidOperationException("Could not start fixture preparation.");
        try { process.WaitForExit(); }
        finally
        {
            if (!process.HasExited) process.Kill(entireProcessTree: true);
        }
        if (process.ExitCode != 0)
            throw new InvalidOperationException($"Fixture preparation failed for {stem}: exit {process.ExitCode}.");
    }

    internal static async Task Prepare(string stem, bool read, string[] writeClasses)
    {
        Preparing = true;
        try
        {
            var assembly = typeof(BenchmarkFixtures).Assembly;
            // Resolve only known schemas rather than treating CLI input as a filesystem path.
            var rowType = assembly.GetType($"Plank.Benchmarks.{stem}Row")
                ?? assembly.GetType($"Plank.Benchmarks.{stem}PlankRow", throwOnError: true)!;
            var count = stem.StartsWith("Real", StringComparison.Ordinal) ? BenchmarkData.TaxiRows : BenchmarkData.SyntheticRows;
            var rowSets = new Dictionary<Type, object>();
            object GetRows(Type type)
            {
                if (rowSets.TryGetValue(type, out var existing)) return existing;
                var value = type.GetMethod("CreateRows") is { } create ? create.Invoke(null, [count])!
                    : type.GetMethod("FromSharp") is { } convert ? convert.Invoke(null, [GetRows(convert.GetParameters()[0].ParameterType.GetElementType()!)])!
                    : typeof(BenchmarkData).GetMethod(nameof(BenchmarkData.LoadTaxiRows))!.MakeGenericMethod(type).Invoke(null, null)!;
                rowSets.Add(type, value);
                return value;
            }
            Console.WriteLine($"Preparing {stem}: {count:N0} rows, read={read}, writers={writeClasses.Length}");
            if (read)
            {
                var file = (byte[])rowType.GetMethod("CreateReadFile")!.Invoke(null, [GetRows(rowType)])!;
                File.WriteAllBytes(Path.Combine(DirectoryPath, stem + ".parquet"), file);
            }
            var sizes = new Dictionary<string, long>();
            foreach (var className in writeClasses)
            {
                var type = Published.PublishedBenchmarkCommand.GetBenchmarkTypes().Single(t => t.Name == className);
                if (!className.StartsWith(stem, StringComparison.Ordinal)) throw new ArgumentException("Fixture/schema mismatch.");
                var instance = Activator.CreateInstance(type)!;
                type.GetProperty("Rows")!.SetValue(instance, count);
                // One source-row load per schema, shared only during preparation, never in timed paths.
                var rowsField = type.GetField("_rows", BindingFlags.Instance | BindingFlags.NonPublic)!;
                rowsField.SetValue(instance, GetRows(rowsField.FieldType.GetElementType()!));
                try
                {
                    type.GetMethod("GlobalSetupWrite")!.Invoke(instance, null);
                    type.GetMethod("SetupWrite")!.Invoke(instance, null);
                    try
                    {
                        if (type.GetMethod("Write")!.Invoke(instance, null) is Task task) await task;
                        var output = (MemoryStream)type.GetField("_output", BindingFlags.Instance | BindingFlags.NonPublic)!.GetValue(instance)!;
                        var library = className.EndsWith("ParquetNetBenchmarks", StringComparison.Ordinal) ? "Parquet.Net"
                            : className.EndsWith("ParquetSharpBenchmarks", StringComparison.Ordinal) ? "ParquetSharp" : "Plank";
                        sizes.Add(library, OutputLength(output));
                    }
                    finally { type.GetMethod("CleanupWrite")!.Invoke(instance, null); }
                }
                finally { type.GetMethod("Cleanup")!.Invoke(instance, null); }
            }
            File.WriteAllText(Path.Combine(DirectoryPath, stem + ".json"), JsonSerializer.Serialize(sizes));
        }
        finally { Preparing = false; }
    }
}
