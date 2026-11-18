using System.Collections.Immutable;
using Plank.Schema;
using Plank.Writing;

namespace Plank.Fuzzing;

internal static class ImportValidationCoverageCases
{
    internal static void Execute(ReadOnlySpan<byte> input)
    {
        if (input.IsEmpty)
            return;

        var caseId = input[0];
        var parquetBytes = input[1..];
        var schema = new ParquetSchema([
            ColumnDefinition.RequiredLeaf("c", ParquetPhysicalType.Int32,
                new ColumnOptions(encodings: ImmutableArray.Create(EncodingKind.Plain)))
        ]);

        Exception? observed = null;
        try
        {
            using var stream = new MemoryStream();
            stream.Write(parquetBytes);
            stream.Position = 0;
            using var writer = schema.CreateAppender(stream, new ParquetAppendOptions
            {
                WriterOptions = new ParquetWriterOptions
                {
                    Compression = CompressionKind.None,
                    SortingColumns = []
                }
            });
            writer.CloseFile();
        }
        catch (CorruptParquetException error)
        {
            observed = error;
        }
        catch (NotSupportedException error)
        {
            observed = error;
        }

        var expected = caseId switch
        {
            0 or 5 => null,
            1 or 2 => "Column data page offset is outside its column chunk.",
            3 => "Column dictionary page offset is outside its column chunk.",
            4 => "Expected a non-negative i32 value no greater than 4294967295 but got -1.",
            _ => null
        };
        if (expected is null)
        {
            if (caseId is not (0 or 5) || observed is not null)
                throw new InvalidOperationException(
                    $"Unexpected import validation outcome for case {caseId}: '{observed?.Message}'.");
            return;
        }

        if (observed?.Message != expected)
            throw new InvalidOperationException(
                $"Expected import validation '{expected}', got '{observed?.Message}'.");
    }
}
