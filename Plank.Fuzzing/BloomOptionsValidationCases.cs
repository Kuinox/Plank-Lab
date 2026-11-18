using Plank.Schema;
using Plank.Writing;

namespace Plank.Fuzzing;

// Public Bloom options validation and bitset-sizing boundaries. Keep each
// boundary as an independent input so a failure names the responsible case.
internal static class BloomOptionsValidationCases
{
    internal const int Count = 9;

    internal static void Execute(byte selector)
    {
        var mode = selector % Count;
        var bloom = mode switch
        {
            0 => new ParquetBloomFilterOptions { FalsePositiveProbability = double.NaN },
            1 => new ParquetBloomFilterOptions { FalsePositiveProbability = 0 },
            2 => new ParquetBloomFilterOptions { FalsePositiveProbability = 1 },
            3 => new ParquetBloomFilterOptions { ExpectedDistinctValueCount = 0 },
            4 => new ParquetBloomFilterOptions { MaximumBytes = 0 },
            5 => new ParquetBloomFilterOptions { MaximumBytes = 128u * 1024 * 1024 + 1 },
            6 => new ParquetBloomFilterOptions { MaximumBytes = 33 },
            7 => new ParquetBloomFilterOptions
            {
                FalsePositiveProbability = double.Epsilon,
                MaximumBytes = 32
            },
            _ => new ParquetBloomFilterOptions
            {
                ExpectedDistinctValueCount = 1000,
                MaximumBytes = 32
            }
        };

        if (mode <= 6)
        {
            var expected = mode switch
            {
                <= 2 => nameof(ParquetBloomFilterOptions.FalsePositiveProbability),
                3 => nameof(ParquetBloomFilterOptions.ExpectedDistinctValueCount),
                _ => nameof(ParquetBloomFilterOptions.MaximumBytes)
            };
            try
            {
                _ = new ColumnOptions(bloomFilter: bloom);
            }
            catch (ArgumentOutOfRangeException exception) when (exception.ParamName == expected)
            {
                return;
            }
            throw new InvalidOperationException($"Invalid Bloom option {expected} was accepted.");
        }

        var schema = new ParquetSchema([
            ColumnDefinition.RequiredLeaf("bloom-size", ParquetPhysicalType.Int32,
                new ColumnOptions(bloomFilter: bloom))
        ]);
        using var output = new MemoryStream();
        using var writer = schema.CreateWriter(output,
            new ParquetWriterOptions { Compression = CompressionKind.None });
        var column = writer.CreateSerializedColumn<int>(schema.LeafColumns[0]);
        column.Serialize([1]);
        writer.StartRowGroup().Write(column);
        writer.CloseFile();
    }
}
