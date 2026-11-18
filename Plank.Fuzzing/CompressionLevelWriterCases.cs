using System.Collections.Immutable;
using Plank.Schema;
using Plank.Writing;
using ZstdSharp;
using PlankColumn = Plank.Schema.ColumnDefinition;
using PlankWriterTarget = Plank.Fuzzing.PlankWriterFuzzTarget;

namespace Plank.Fuzzing;

/// <summary>Validates explicit codec level boundaries and writes each supported codec.</summary>
internal static class CompressionLevelWriterCases
{
    enum FailureKind
    {
        None,
        CompressionLevel,
        CompressionKind,
        LegacyLz4
    }

    readonly record struct LevelCase(CompressionKind Compression, int Level, FailureKind Failure)
    {
        internal bool IsValid => Failure == FailureKind.None;
    }

    static readonly LevelCase[] Cases =
    [
        new(CompressionKind.Gzip, 0, FailureKind.None),
        new(CompressionKind.Gzip, 9, FailureKind.None),
        new(CompressionKind.Zstd, Compressor.MinCompressionLevel, FailureKind.None),
        new(CompressionKind.Zstd, Compressor.MaxCompressionLevel, FailureKind.None),
        new(CompressionKind.Lz4, 0, FailureKind.None),
        new(CompressionKind.Lz4, 3, FailureKind.None),
        new(CompressionKind.Lz4, 12, FailureKind.None),
        new(CompressionKind.Brotli, 0, FailureKind.None),
        new(CompressionKind.Brotli, 11, FailureKind.None),
        new(CompressionKind.Gzip, -1, FailureKind.CompressionLevel),
        new(CompressionKind.Gzip, 10, FailureKind.CompressionLevel),
        new(CompressionKind.Zstd, Compressor.MinCompressionLevel - 1, FailureKind.CompressionLevel),
        new(CompressionKind.Zstd, Compressor.MaxCompressionLevel + 1, FailureKind.CompressionLevel),
        new(CompressionKind.Lz4, 1, FailureKind.CompressionLevel),
        new(CompressionKind.Lz4, 13, FailureKind.CompressionLevel),
        new(CompressionKind.Brotli, -1, FailureKind.CompressionLevel),
        new(CompressionKind.Brotli, 12, FailureKind.CompressionLevel),
        new(CompressionKind.None, 0, FailureKind.CompressionLevel),
        new(CompressionKind.Snappy, 0, FailureKind.CompressionLevel),
        new((CompressionKind)byte.MaxValue, 0, FailureKind.CompressionKind),
        new(CompressionKind.Lz4Legacy, 0, FailureKind.LegacyLz4)
    ];

    internal static void Execute(byte selector)
    {
        var testCase = Cases[selector % Cases.Length];
        if (!testCase.IsValid)
        {
            AssertRejected(testCase);
            return;
        }

        PlankWriterTarget.Validate(Create(testCase));
    }

    static PlankWriterTarget.FuzzCase Create(LevelCase testCase)
    {
        var column = PlankColumn.Leaf("compression-level", ParquetPhysicalType.Int32,
            new ColumnOptions(encodings: ImmutableArray.Create(EncodingKind.Plain)));
        var values = Enumerable.Range(-32, 65).Select(static value => value * 7919).ToArray();
        return new PlankWriterTarget.FuzzCase(
            [new PlankWriterTarget.ColumnSpec(column, typeof(int))], [[values]], testCase.Compression,
            new PlankWriterTarget.WriterSettings(ParquetDataPageVersion.V2, WritePageCrc: true,
                WritePageIndexes: true, FileVersion: ParquetFileVersion.V1,
                TargetDataPageSizeBytes: 64, BufferChunkSizeBytes: 128, WithKeyValueMetadata: false,
                CompressionLevel: testCase.Level));
    }

    static void AssertRejected(LevelCase testCase)
    {
        var schema = new ParquetSchema([PlankColumn.Leaf("compression-level", ParquetPhysicalType.Int32)]);
        using var stream = new MemoryStream();
        try
        {
            schema.CreateWriter(stream, new ParquetWriterOptions
            {
                Compression = testCase.Compression,
                CompressionLevel = testCase.Level
            });
        }
        catch (ArgumentOutOfRangeException ex) when
            (testCase.Failure == FailureKind.CompressionLevel && ex.ParamName == "CompressionLevel" ||
             testCase.Failure == FailureKind.CompressionKind && ex.ParamName == "Compression")
        {
            return;
        }
        catch (NotSupportedException) when (testCase.Failure == FailureKind.LegacyLz4)
        {
            return;
        }

        throw new InvalidOperationException(
            $"Writer did not reject {testCase.Compression} with the expected {testCase.Failure} failure.");
    }
}
