using System.Security.Cryptography;
using System.Text;
using System.Text.RegularExpressions;

namespace Plank.Fuzzing.Reader.Target;

/// <summary>
/// Records reader-acceptance disagreements and unexpected Plank exceptions
/// without stopping the fuzzer.
/// </summary>
/// <remarks>
/// The persistent harness is its own fork server, so every thrown finding
/// costs a full .NET restart plus recalibration of the whole seed corpus. With
/// a couple of dozen reachable disagreement kinds, a fleet that crashed on each
/// one spent all its time restarting and never accumulated coverage. Acceptance
/// disagreements are therefore bucketed by their normalised diagnostic and a
/// few examples per bucket are kept for triage. Decoded-value mismatches are
/// recorded the same way but under a VALUE-MISMATCH prefix, since Plank
/// returning different data is the finding this oracle exists for.
/// </remarks>
static partial class DisagreementLog
{
    const int ExamplesPerBucket = 5;
    static readonly Dictionary<string, int> Seen = [];
    static readonly string? Root = Environment.GetEnvironmentVariable("PLANK_FUZZ_DISAGREEMENT_DIR");

    public static bool TryRecord(Exception error, ReadOnlySpan<byte> input)
    {
        var key = error is ReaderAcceptanceMismatchException mismatch
            ? (IsDecodedValueMismatch(mismatch) ? "VALUE-MISMATCH " : "") + BucketKey(mismatch)
            : UnexpectedKey(error);
        return Record(key, error, input);
    }

    static bool Record(string key, Exception error, ReadOnlySpan<byte> input)
    {
        Seen.TryGetValue(key, out var count);
        Seen[key] = count + 1;
        if (count >= ExamplesPerBucket || string.IsNullOrEmpty(Root)) return true;

        try
        {
            var bucket = Path.Combine(Root, Convert.ToHexStringLower(SHA256.HashData(Encoding.UTF8.GetBytes(key)))[..16]);
            Directory.CreateDirectory(bucket);
            var description = Path.Combine(bucket, "bucket.txt");
            if (!File.Exists(description)) File.WriteAllText(description, key + "\n\n" + error + "\n");
            var name = Convert.ToHexStringLower(SHA256.HashData(input))[..16] + ".bin";
            File.WriteAllBytes(Path.Combine(bucket, name), input.ToArray());
        }
        catch (IOException) { }
        catch (UnauthorizedAccessException) { }
        return true;
    }

    static bool IsDecodedValueMismatch(Exception error)
    {
        for (var e = error; e != null; e = e.InnerException)
            if (e.Message.Contains("Decoded value mismatch", StringComparison.Ordinal)) return true;
        return false;
    }

    static string BucketKey(ReaderAcceptanceMismatchException error)
    {
        var inner = error.InnerException;
        var message = inner?.Message ?? "";
        var newline = message.IndexOf('\n');
        if (newline >= 0) message = message[..newline];
        message = Digits().Replace(message, "#");
        if (message.Length > 200) message = message[..200];
        return $"{error.Message} | {inner?.GetType().FullName} | {message}";
    }

    // An exception Plank did not translate into one of its own format errors
    // is a Plank bug however the oracle would have judged the file. Bucket by
    // type and throwing frame so each distinct bug is kept once, not per input.
    static string UnexpectedKey(Exception error)
    {
        var frame = error.StackTrace?.Split('\n').Select(l => l.Trim()).FirstOrDefault(l => l.StartsWith("at Plank.", StringComparison.Ordinal)) ?? "?";
        var paren = frame.IndexOf('(');
        if (paren > 0) frame = frame[..paren];
        return $"PLANK-UNEXPECTED {error.GetType().FullName} {frame}";
    }

    [GeneratedRegex("[0-9]+")]
    private static partial Regex Digits();
}
