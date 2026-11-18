using System.Collections.Immutable;
using Plank.Schema;
using Plank.Writing;

namespace Plank.Fuzzing;

// Keep invalid public writer options as separate, replayable inputs. Each case
// reaches one validation guard after all preceding guards have passed.
internal static class WriterOptionsValidationCases
{
    internal const int Count = 14;

    internal static void Execute(byte selector)
    {
        var mode = selector % Count;
        var options = mode switch
        {
            0 => new ParquetWriterOptions { BufferChunkSizeBytes = 0 },
            1 => new ParquetWriterOptions { InitialPageBufferBytes = 0 },
            2 => new ParquetWriterOptions { InitialColumnBufferBytes = 0 },
            3 => new ParquetWriterOptions { TargetDataPageSizeBytes = 0 },
            4 => new ParquetWriterOptions { TargetDataPageSizeBytes = uint.MaxValue },
            5 => new ParquetWriterOptions { RowApiInitialRowCapacity = 0 },
            6 => new ParquetWriterOptions { TargetRowGroupSizeBytes = 0 },
            7 => new ParquetWriterOptions { TargetFileSizeBytes = 0 },
            8 => new ParquetWriterOptions { SortingColumns = default(ImmutableArray<ParquetSortingColumn>) },
            9 => new ParquetWriterOptions { FileVersion = (ParquetFileVersion)255 },
            10 => new ParquetWriterOptions { DataPageVersion = (ParquetDataPageVersion)255 },
            11 => new ParquetWriterOptions { KeyValueMetadata = [new ParquetKeyValueMetadata("", "value")] },
            12 => new ParquetWriterOptions { RowApiMaxParallelism = 2 },
            _ => new ParquetWriterOptions()
        };

        if (mode >= 12)
        {
            var actual = options.RowApiMaxParallelism;
            if (actual != (mode == 12 ? 2u : (uint)options.Execution.WorkerCount))
                throw new InvalidOperationException("Writer parallelism was resolved incorrectly.");
            return;
        }

        var expected = mode switch
        {
            0 => nameof(ParquetWriterOptions.BufferChunkSizeBytes),
            1 => nameof(ParquetWriterOptions.InitialPageBufferBytes),
            2 => nameof(ParquetWriterOptions.InitialColumnBufferBytes),
            3 or 4 => nameof(ParquetWriterOptions.TargetDataPageSizeBytes),
            5 => nameof(ParquetWriterOptions.RowApiInitialRowCapacity),
            6 => nameof(ParquetWriterOptions.TargetRowGroupSizeBytes),
            7 => nameof(ParquetWriterOptions.TargetFileSizeBytes),
            8 => nameof(ParquetWriterOptions.SortingColumns),
            9 => nameof(ParquetWriterOptions.FileVersion),
            10 => nameof(ParquetWriterOptions.DataPageVersion),
            _ => nameof(ParquetWriterOptions.KeyValueMetadata)
        };

        var schema = new ParquetSchema([ColumnDefinition.Leaf("value", ParquetPhysicalType.Int32)]);
        using var stream = new MemoryStream();
        try
        {
            using var writer = schema.CreateWriter(stream, options);
        }
        catch (ArgumentException exception) when (exception.ParamName == expected)
        {
            return;
        }
        throw new InvalidOperationException($"Writer accepted invalid option {expected}.");
    }
}
