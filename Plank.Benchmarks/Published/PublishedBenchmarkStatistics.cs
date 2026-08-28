namespace Plank.Benchmarks.Published;

public static class PublishedBenchmarkStatistics
{
    public static Summary Summarize(IReadOnlyList<double> samples)
    {
        ArgumentOutOfRangeException.ThrowIfZero(samples.Count);
        var ordered = samples.Order().ToArray();
        var median = Percentile(ordered, 0.5);
        var p25 = Percentile(ordered, 0.25);
        var p75 = Percentile(ordered, 0.75);
        return new Summary(median, p25, p75, median == 0 ? 0 : (p75 - p25) / median * 100);
    }

    static double Percentile(double[] ordered, double percentile)
    {
        if (ordered.Length == 1) return ordered[0];
        var position = (ordered.Length - 1) * percentile;
        var lower = (int)Math.Floor(position);
        var upper = (int)Math.Ceiling(position);
        if (lower == upper) return ordered[lower];
        return ordered[lower] + (ordered[upper] - ordered[lower]) * (position - lower);
    }

    public readonly record struct Summary(double Median, double P25, double P75, double VariationPercent);
}
