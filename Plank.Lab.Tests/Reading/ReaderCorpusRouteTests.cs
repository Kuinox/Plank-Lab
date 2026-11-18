using Plank.Fuzzing;

namespace Plank.Tests.Reading;

internal sealed class ReaderCorpusRouteTests
{
    [Test]
    public void GeneratedSeedsExerciseNonBorrowingAndAlternateReaderRoutes()
    {
        var directory = Path.Combine(Path.GetTempPath(), $"plank-reader-seeds-{Guid.NewGuid():N}");
        try
        {
            CorpusGenerator.Generate(directory);
            foreach (var (name, selector) in new (string, byte)[]
            {
                ("gen-stream-i32-none.bin", 0x40),
                ("gen-stream-i32-snappy.bin", 0x40),
                ("gen-stream-i32-opt-none-v1.bin", 0x40),
                ("gen-stream-crc-i32-opt-snappy-v2.bin", 0x50),
                ("gen-nonstrict-i32-none.bin", 0x20),
                ("gen-rowapi-bin-none.bin", 0x02)
            })
            {
                var input = File.ReadAllBytes(Path.Combine(directory, name));
                if (input[0] != selector)
                    throw new InvalidOperationException($"{name} selected 0x{input[0]:X2}, expected 0x{selector:X2}.");
                if (PlankReaderFuzzTarget.GetHandledException(input) is { } error)
                    throw new InvalidOperationException($"{name} failed before exercising its reader route.", error);
            }
        }
        finally
        {
            if (Directory.Exists(directory))
                Directory.Delete(directory, recursive: true);
        }
    }

    [Test]
    public void CorruptedOpeningMagicIsNotCompared()
    {
        var directory = Path.Combine(Path.GetTempPath(), $"plank-reader-magic-{Guid.NewGuid():N}");
        try
        {
            CorpusGenerator.Generate(directory);
            var input = File.ReadAllBytes(Path.Combine(directory, "gen-i32-dict-none-v1.bin"));
            input[3] ^= 0x10; // PAR1 -> PAB1, after the fuzzer's selector byte.

            // Plank may accept this or reject it directly. A differing policy
            // about the opening marker must not become an oracle finding.
            PlankReaderFuzzTarget.Execute(input);
        }
        finally
        {
            if (Directory.Exists(directory))
                Directory.Delete(directory, recursive: true);
        }
    }
}
