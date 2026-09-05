using BenchmarkDotNet.Attributes;
using BenchmarkDotNet.Configs;
using BenchmarkDotNet.Jobs;
using BenchmarkDotNet.Running;
using BenchmarkDotNet.Engines;
using Perfolizer.Mathematics.OutlierDetection;
using BenchmarkDotNet.ConsoleArguments;
using BenchmarkDotNet.Loggers;

namespace Plank.Benchmarks.Published;

public static class PublishedBenchmarkCommand
{
    static readonly string[] s_librarySuffixes =
    [
        "PlankBenchmarks",
        "ParquetSharpBenchmarks",
        "ParquetNetBenchmarks"
    ];

    public static void Run(string[] args, string? method = null)
    {
        var arguments = args.ToList();
        var quick = arguments.Remove("--quick");
        var rows = ReadIntOption(arguments, "--rows", quick ? 4_096 : 1_000_000);
        var taxiRows = ReadIntOption(arguments, "--taxi-rows", quick ? 4_096 : 2_964_624);
        var taxiFile = ReadStringOption(arguments, "--data-file") ?? DefaultTaxiFile();

        if (method is not null)
        {
            if (arguments.Contains("--filter", StringComparer.Ordinal))
                throw new ArgumentException(
                    $"Use --published with a combined filter when filtering the {method} alias.");
            arguments.Add("--filter");
            arguments.Add($"*.{method}");
        }

        Environment.SetEnvironmentVariable("PLANK_BENCHMARK_ROWS", rows.ToString());
        Environment.SetEnvironmentVariable("PLANK_BENCHMARK_TAXI_ROWS", taxiRows.ToString());
        Environment.SetEnvironmentVariable("PLANK_BENCHMARK_TAXI_FILE", taxiFile);

        var job = CreateJob(quick);
        var config = ManualConfig.Create(DefaultConfig.Instance).AddJob(job);
        if (arguments.Any(a => a is "--help" or "--info" or "--list" or "--version"))
        {
            BenchmarkSwitcher.FromTypes(GetBenchmarkTypes()).Run([.. arguments], config);
            return;
        }

        // Explicit selection prevents an interactive prompt after expensive fixture preparation.
        if (!arguments.Contains("--filter") && !arguments.Contains("-f"))
            arguments.AddRange(["--filter", "*"]);
        var (parsed, cliConfig, _) = ConfigParser.Parse([.. arguments], ConsoleLogger.Default, config);
        if (!parsed) throw new ArgumentException("Invalid benchmark arguments.");
        // Use BDN's own selection rules, including category, attribute and parameter filters.
        var effectiveConfig = ManualConfig.Union(config, cliConfig);
        var selected = GetBenchmarkTypes().SelectMany(type => BenchmarkConverter.TypeToBenchmarks(type, effectiveConfig).BenchmarksCases)
            .Select(b => (Type: b.Descriptor.Type, Method: b.Descriptor.WorkloadMethod.Name))
            .Distinct().ToArray();
        if (selected.Length == 0) throw new ArgumentException("No benchmark cases match the supplied filters.");
        var previousFixtures = Environment.GetEnvironmentVariable(BenchmarkFixtures.DirectoryVariable);
        var fixtures = Directory.CreateTempSubdirectory("plank-benchmark-fixtures-");
        try
        {
            Environment.SetEnvironmentVariable(BenchmarkFixtures.DirectoryVariable, fixtures.FullName);
            foreach (var group in selected.GroupBy(x => s_librarySuffixes.Aggregate(x.Type.Name,
                         (name, suffix) => name.EndsWith(suffix, StringComparison.Ordinal) ? name[..^suffix.Length] : name)))
                BenchmarkFixtures.PrepareInChild(group.Key,
                    group.Where(x => x.Method == "Write").Select(x => x.Type.Name).ToArray(),
                    group.Any(x => x.Method == "Read"));
            var summaries = BenchmarkSwitcher.FromTypes(GetBenchmarkTypes()).Run([.. arguments], config).ToArray();
            if (summaries.Length == 0 || summaries.Any(s => s.HasCriticalValidationErrors || s.Reports.Any(r => !r.Success)))
                throw new InvalidOperationException("Benchmark run failed; see the preceding log.");
        }
        finally
        {
            Environment.SetEnvironmentVariable(BenchmarkFixtures.DirectoryVariable, previousFixtures);
            fixtures.Delete(recursive: true);
        }
    }

    internal static Job CreateJob(bool quick = false) => Job.Default
        .WithStrategy(RunStrategy.ColdStart)
        .WithLaunchCount(1)
        .WithWarmupCount(0)
        .WithIterationCount(quick ? 1 : 100)
        .WithInvocationCount(1)
        .WithUnrollFactor(1)
        .WithGcForce(false)
        .WithEvaluateOverhead(false)
        .WithOutlierMode(OutlierMode.DontRemove);

    internal static Type[] GetBenchmarkTypes()
        => typeof(PublishedBenchmarkCommand).Assembly.GetTypes()
            .Where(type => type.IsClass && type.IsPublic &&
                           s_librarySuffixes.Any(suffix => type.Name.EndsWith(suffix, StringComparison.Ordinal)) &&
                           type.GetMethods().Any(method => method.IsDefined(typeof(BenchmarkAttribute), false)))
            .OrderBy(type => type.Name, StringComparer.Ordinal)
            .ToArray();

    internal static string FindRepositoryRoot()
    {
        for (var directory = new DirectoryInfo(Environment.CurrentDirectory); directory is not null;
             directory = directory.Parent)
        {
            var marker = Path.Combine(directory.FullName, ".git");
            if (Directory.Exists(marker) || File.Exists(marker))
                return directory.FullName;
        }

        throw new DirectoryNotFoundException("Could not find the Plank-Lab repository root.");
    }

    internal static string? ReadValue(string[] args, string name)
    {
        var index = Array.IndexOf(args, name);
        if (index < 0) return null;
        if (index == args.Length - 1)
            throw new ArgumentException($"{name} requires a value.");
        return args[index + 1];
    }

    static int ReadIntOption(List<string> arguments, string option, int defaultValue)
    {
        var value = ReadStringOption(arguments, option);
        if (value is null) return defaultValue;
        if (!int.TryParse(value, out var parsed) || parsed <= 0)
            throw new ArgumentException($"{option} must be a positive integer.");
        return parsed;
    }

    static string? ReadStringOption(List<string> arguments, string option)
    {
        var index = arguments.IndexOf(option);
        if (index < 0) return null;
        if (index + 1 == arguments.Count)
            throw new ArgumentException($"Missing value after {option}.");
        var value = arguments[index + 1];
        arguments.RemoveRange(index, 2);
        return value;
    }

    static string DefaultTaxiFile()
        => Path.GetFullPath(Path.Combine(AppContext.BaseDirectory, "..", "..", "..", "nyc-data",
            "yellow_tripdata_2024-01.parquet"));
}
