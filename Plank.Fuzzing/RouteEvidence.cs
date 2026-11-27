using System.Collections.Concurrent;

namespace Plank.Fuzzing;

/// <summary>
/// Proof that a branch of a route actually ran: routes call <see cref="Hit"/> with a descriptive key, and with
/// PLANK_ORACLE_COUNTERS=1 the totals are printed when the process exits (one `EVIDENCE key count` line each).
/// A branch that should be reachable but never shows up in the output is a silent coverage hole.
/// </summary>
internal static class RouteEvidence
{
    static readonly ConcurrentDictionary<string, long> Counts = new();

    static RouteEvidence()
    {
        if (Environment.GetEnvironmentVariable("PLANK_ORACLE_COUNTERS") == "1")
            AppDomain.CurrentDomain.ProcessExit += (_, _) =>
            {
                foreach (var (key, count) in Counts.OrderBy(static p => p.Key, StringComparer.Ordinal))
                    Console.Error.WriteLine($"EVIDENCE {key} {count}");
            };
    }

    internal static void Hit(string key)
        => Counts.AddOrUpdate(key, 1, static (_, count) => count + 1);
}
