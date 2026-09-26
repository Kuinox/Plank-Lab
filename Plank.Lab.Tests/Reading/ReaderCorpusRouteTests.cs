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
}
