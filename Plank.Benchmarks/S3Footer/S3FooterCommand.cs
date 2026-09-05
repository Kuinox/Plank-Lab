using System.Diagnostics;
using System.Globalization;
using System.Reflection;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using System.Text.Json;
using PlankReader = Plank.Reading.Physical.ParquetFileReader;

namespace Plank.Benchmarks.S3Footer;

/// <summary>Compare footer readers through the same unbuffered HTTP range transport.</summary>
public static class S3FooterCommand
{
    static readonly string[] Libraries = ["Plank", "Parquet.Net", "ParquetSharp"];
    static readonly JsonSerializerOptions JsonOptions = new()
    {
        PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
        WriteIndented = true
    };

    const string ProtocolDescription =
        "One process; zero warmups; iteration 1 is each library's first use, not a cold process. " +
        "Libraries run sequentially in rotating order each iteration. Each trial gets a new HTTP client, " +
        "connection pool, unbuffered range stream, and reader with standard library defaults. " +
        "The stream lazily obtains object length using HEAD. Timing starts before stream and public reader " +
        "construction and includes HEAD, GETs, footer parsing, and extraction of row, row-group, and leaf-column counts. " +
        "Reader disposal, fixture preparation, JSON serialization, and cross-library validation are outside timing. " +
        "Request durations include receipt of response bodies; bytes count response bodies, excluding headers. " +
        "Injected latency applies to every emulator request, including HEAD. No transport cache or application retries; " +
        "OS caches, JIT state, and library-managed pools may persist. Footer metadata is read; no data pages are decoded.";

    public static async Task<int> RunAsync(string[] args)
    {
        Options options;
        try
        {
            options = ParseOptions(args);
        }
        catch (ArgumentException exception)
        {
            Console.Error.WriteLine(exception.Message);
            Console.Error.WriteLine("Use --s3-footer --help for options.");
            return 2;
        }

        if (options.Help)
        {
            Console.WriteLine("""
                Usage: --s3-footer [options]
                  --data-file PATH    Existing Parquet file (default: fetch NYC taxi footer metadata).
                  --iterations N      Trials per library; positive integer (default: 10).
                  --latency-ms N      Added latency per HTTP request; finite, nonnegative (default: 0).
                  --output PATH       JSON report (default: artifacts/benchmarks/s3-footer.json).
                  --help              Show this help.

                Compares Plank, Parquet.Net, and ParquetSharp using an in-process S3 range emulator.
                Exit codes: 0 success, 1 setup/read/validation/output failure, 2 invalid arguments.
                """);
            return 0;
        }

        try
        {
            var outputPath = Path.GetFullPath(options.Output);
            if (options.DataFile is { } input && SamePath(outputPath, Path.GetFullPath(input)))
                throw new ArgumentException("--output must differ from --data-file.");

            using var fixture = await TaxiFooterFixture.PrepareAsync(options.DataFile).ConfigureAwait(false);
            if (SamePath(outputPath, Path.GetFullPath(fixture.FilePath)))
                throw new ArgumentException("--output must differ from the fixture file.");

            await using var emulator = await S3Emulator.StartAsync(fixture.FilePath, options.LatencyMs)
                .ConfigureAwait(false);
            var runs = new List<S3FooterRun>();
            for (var iteration = 0; iteration < options.Iterations; iteration++)
            {
                for (var position = 0; position < Libraries.Length; position++)
                {
                    var library = Libraries[(position + iteration % Libraries.Length) % Libraries.Length];
                    var run = await RunTrialAsync(library, iteration + 1, emulator.ObjectUri).ConfigureAwait(false);
                    runs.Add(run);
                    Console.WriteLine(run.Error is null
                        ? $"{library} #{iteration + 1}: {run.ElapsedMs:F3} ms, {run.Requests.Count} requests, " +
                          $"{run.Requests.Sum(request => request.BytesReceived)} body bytes"
                        : $"{library} #{iteration + 1}: FAILED: {run.Error}");
                }
            }

            ValidateMetadata(runs);
            // Resolve assembly versions only after every reader has had its first measured invocation.
            for (var index = 0; index < runs.Count; index++)
                runs[index] = runs[index] with { Version = GetLibraryVersion(runs[index].Library) };
            var report = new S3FooterReport(1, DateTimeOffset.UtcNow,
                new S3FooterDataset(fixture.Name, fixture.SourceUrl, fixture.Mode, fixture.FileSizeBytes,
                    fixture.FooterOffset, fixture.FooterLengthBytes, fixture.FooterSha256),
                await GetEnvironmentAsync().ConfigureAwait(false),
                new S3FooterProtocol(options.Iterations, options.LatencyMs, ProtocolDescription), runs);
            await WriteReportAsync(outputPath, report).ConfigureAwait(false);
            Console.WriteLine($"Report: {outputPath}");
            return runs.Any(run => run.Error is not null) ? 1 : 0;
        }
        catch (Exception exception)
        {
            Console.Error.WriteLine($"S3 footer benchmark failed: {exception.Message}");
            return 1;
        }
    }

    static async Task<S3FooterRun> RunTrialAsync(string library, int iteration, Uri objectUri)
    {
        // These are transport/harness setup, not reader setup. Each client owns a fresh connection pool.
        using var client = new HttpClient(new SocketsHttpHandler
        {
            AllowAutoRedirect = false,
            AutomaticDecompression = System.Net.DecompressionMethods.None,
            UseProxy = false
        });
        var scope = new ReaderScope();
        MetadataSummary? metadata = null;
        string? error = null;
        var started = Stopwatch.GetTimestamp();
        using var stream = new S3RangeStream(client, objectUri, started);
        try
        {
            metadata = library switch
            {
                "Plank" => ReadPlank(stream, scope),
                "Parquet.Net" => await ReadParquetNetAsync(stream, scope).ConfigureAwait(false),
                "ParquetSharp" => ReadParquetSharp(stream, scope),
                _ => throw new ArgumentOutOfRangeException(nameof(library))
            };
        }
        catch (Exception exception)
        {
            error = $"{exception.GetType().Name}: {exception.Message}";
        }
        var elapsedMs = Stopwatch.GetElapsedTime(started).TotalMilliseconds;
        // Snapshot before cleanup so the report represents only the measured footer operation.
        var requests = stream.Requests.ToArray();
        try
        {
            await scope.DisposeAsync().ConfigureAwait(false);
        }
        catch (Exception exception)
        {
            error = AppendError(error, $"Reader disposal failed: {exception.GetType().Name}: {exception.Message}");
        }

        if (metadata is { } summary && (summary.RowCount < 0 || summary.RowGroupCount < 0 || summary.ColumnCount <= 0))
            error = AppendError(error, "Reader returned invalid metadata counts.");
        if (requests.Any(request => request.Error is not null || request.StatusCode is not (200 or 206)))
            error = AppendError(error, "One or more HTTP requests failed.");
        if (metadata is not null && !requests.Any(request => request.Method == "GET" && request.BytesReceived > 0))
            error = AppendError(error, "Reader returned metadata without receiving object bytes.");

        return new S3FooterRun(library, "unknown", iteration, elapsedMs,
            metadata?.RowCount, metadata?.RowGroupCount, metadata?.ColumnCount, error, requests);
    }

    // Keep library entrypoints out of the harness JIT: their first invocation is inside the measured span.
    [MethodImpl(MethodImplOptions.NoInlining)]
    static MetadataSummary ReadPlank(Stream stream, ReaderScope scope)
    {
        var reader = new PlankReader();
        scope.Reader = reader;
        reader.Reset(stream);
        var metadata = reader.Metadata;
        long rows = 0;
        for (var index = 0; index < metadata.RowGroupCount; index++)
            rows = checked(rows + (long)metadata.RowGroup(index).RowCount);
        return new MetadataSummary(rows, metadata.RowGroupCount, metadata.ColumnCount);
    }

    [MethodImpl(MethodImplOptions.NoInlining)]
    static async Task<MetadataSummary> ReadParquetNetAsync(Stream stream, ReaderScope scope)
    {
        var reader = await Parquet.ParquetReader.CreateAsync(stream, leaveStreamOpen: true).ConfigureAwait(false);
        scope.AsyncReader = reader;
        var metadata = reader.Metadata ?? throw new InvalidDataException("Parquet.Net returned no file metadata.");
        return new MetadataSummary(metadata.NumRows, reader.RowGroupCount, reader.Schema.GetDataFields().Length);
    }

    [MethodImpl(MethodImplOptions.NoInlining)]
    static MetadataSummary ReadParquetSharp(Stream stream, ReaderScope scope)
    {
        var reader = new ParquetSharp.ParquetFileReader(stream, leaveOpen: true);
        scope.Reader = reader;
        using var metadata = reader.FileMetaData;
        return new MetadataSummary(metadata.NumRows, metadata.NumRowGroups, metadata.NumColumns);
    }

    static void ValidateMetadata(List<S3FooterRun> runs)
    {
        var successful = runs.Where(run => run.Error is null).ToArray();
        if (successful.Select(run => (run.RowCount, run.RowGroupCount, run.ColumnCount)).Distinct().Count() <= 1)
            return;

        const string error = "Metadata counts disagree across libraries or iterations; compare rowCount, rowGroupCount, and columnCount.";
        Console.Error.WriteLine(error);
        for (var index = 0; index < runs.Count; index++)
            if (runs[index].Error is null)
                runs[index] = runs[index] with { Error = error };
    }

    static string GetLibraryVersion(string library)
    {
        var assembly = library switch
        {
            "Plank" => typeof(PlankReader).Assembly,
            "Parquet.Net" => typeof(Parquet.ParquetReader).Assembly,
            "ParquetSharp" => typeof(ParquetSharp.ParquetFileReader).Assembly,
            _ => throw new ArgumentOutOfRangeException(nameof(library))
        };
        return assembly.GetCustomAttribute<AssemblyInformationalVersionAttribute>()?.InformationalVersion
            ?? assembly.GetName().Version?.ToString() ?? "unknown";
    }

    static async Task<S3FooterEnvironment> GetEnvironmentAsync()
    {
        var root = FindLabRoot(Directory.GetCurrentDirectory()) ?? FindLabRoot(AppContext.BaseDirectory);
        var plankRoot = root is null ? null : Path.Combine(root, "library", "Plank");
        return new S3FooterEnvironment(RuntimeInformation.OSDescription, RuntimeInformation.ProcessArchitecture.ToString(),
            RuntimeInformation.FrameworkDescription, System.Environment.ProcessorCount,
            await GetGitOutputAsync(root, ["rev-parse", "HEAD"]).ConfigureAwait(false),
            await GetGitOutputAsync(plankRoot, ["rev-parse", "HEAD"]).ConfigureAwait(false),
            await GetDirtyAsync(root).ConfigureAwait(false),
            await GetDirtyAsync(plankRoot).ConfigureAwait(false));
    }

    static string? FindLabRoot(string path)
    {
        for (var directory = new DirectoryInfo(path); directory is not null; directory = directory.Parent)
            if (File.Exists(Path.Combine(directory.FullName, "Plank.Benchmarks", "Plank.Benchmarks.csproj")))
                return directory.FullName;
        return null;
    }

    static async Task<bool?> GetDirtyAsync(string? path)
    {
        var status = await GetGitOutputAsync(path, ["status", "--porcelain", "--untracked-files=normal"])
            .ConfigureAwait(false);
        return status is null ? null : status.Length != 0;
    }

    static async Task<string?> GetGitOutputAsync(string? path, string[] arguments)
    {
        if (path is null || !Directory.Exists(path)) return null;
        try
        {
            using var process = new Process
            {
                StartInfo = new ProcessStartInfo("git")
                {
                    WorkingDirectory = path,
                    RedirectStandardOutput = true,
                    RedirectStandardError = true,
                    UseShellExecute = false
                }
            };
            foreach (var argument in arguments) process.StartInfo.ArgumentList.Add(argument);
            process.Start();
            var output = process.StandardOutput.ReadToEndAsync();
            var errors = process.StandardError.ReadToEndAsync();
            using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(3));
            try { await process.WaitForExitAsync(timeout.Token).ConfigureAwait(false); }
            catch (OperationCanceledException) { process.Kill(entireProcessTree: true); return null; }
            await errors.ConfigureAwait(false);
            return process.ExitCode == 0 ? (await output.ConfigureAwait(false)).Trim() : null;
        }
        catch (Exception) { return null; }
    }

    static async Task WriteReportAsync(string path, S3FooterReport report)
    {
        Directory.CreateDirectory(Path.GetDirectoryName(path)!);
        var temporaryPath = path + "." + Guid.NewGuid().ToString("N") + ".tmp";
        try
        {
            await using (var output = File.Create(temporaryPath))
                await JsonSerializer.SerializeAsync(output, report, JsonOptions).ConfigureAwait(false);
            File.Move(temporaryPath, path, overwrite: true);
        }
        finally { if (File.Exists(temporaryPath)) File.Delete(temporaryPath); }
    }

    static Options ParseOptions(string[] args)
    {
        var options = new Options();
        var seen = new HashSet<string>(StringComparer.Ordinal);
        for (var index = 0; index < args.Length; index++)
        {
            var option = args[index];
            if (option is not ("--help" or "--data-file" or "--iterations" or "--latency-ms" or "--output"))
                throw new ArgumentException($"Unknown option: {option}");
            if (!seen.Add(option)) throw new ArgumentException($"Duplicate option: {option}");
            if (option == "--help") { options.Help = true; continue; }
            if (++index >= args.Length || args[index].StartsWith("--", StringComparison.Ordinal) || string.IsNullOrWhiteSpace(args[index]))
                throw new ArgumentException($"Missing value for {option}.");
            var value = args[index];
            switch (option)
            {
                case "--data-file": options.DataFile = value; break;
                case "--output": options.Output = value; break;
                case "--iterations":
                    if (!int.TryParse(value, NumberStyles.None, CultureInfo.InvariantCulture, out var iterations) || iterations <= 0)
                        throw new ArgumentException("--iterations must be a positive integer.");
                    options.Iterations = iterations;
                    break;
                case "--latency-ms":
                    if (!double.TryParse(value, NumberStyles.Float, CultureInfo.InvariantCulture, out var latency) ||
                        !double.IsFinite(latency) || latency < 0)
                        throw new ArgumentException("--latency-ms must be finite and nonnegative.");
                    options.LatencyMs = latency;
                    break;
            }
        }
        return options;
    }

    static bool SamePath(string left, string right)
        => string.Equals(left, right, OperatingSystem.IsWindows() ? StringComparison.OrdinalIgnoreCase : StringComparison.Ordinal);

    static string AppendError(string? existing, string error) => existing is null ? error : existing + " " + error;

    sealed class Options
    {
        public string? DataFile { get; set; }
        public int Iterations { get; set; } = 10;
        public double LatencyMs { get; set; }
        public string Output { get; set; } = "artifacts/benchmarks/s3-footer.json";
        public bool Help { get; set; }
    }

    readonly record struct MetadataSummary(long RowCount, int RowGroupCount, int ColumnCount);

    sealed class ReaderScope : IAsyncDisposable
    {
        public IDisposable? Reader { get; set; }
        public IAsyncDisposable? AsyncReader { get; set; }
        public async ValueTask DisposeAsync()
        {
            Reader?.Dispose();
            if (AsyncReader is not null) await AsyncReader.DisposeAsync().ConfigureAwait(false);
        }
    }
}
