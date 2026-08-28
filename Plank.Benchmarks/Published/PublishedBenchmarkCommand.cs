using BenchmarkDotNet.Attributes;
using BenchmarkDotNet.Configs;
using BenchmarkDotNet.Jobs;
using BenchmarkDotNet.Running;

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

        var job = Job.Default
            .WithWarmupCount(quick ? 8 : 80)
            .WithIterationCount(quick ? 1 : 100)
            .WithInvocationCount(1)
            .WithUnrollFactor(1);
        var config = ManualConfig.Create(DefaultConfig.Instance).AddJob(job);
        BenchmarkSwitcher.FromTypes(GetBenchmarkTypes()).Run([.. arguments], config);
    }

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
