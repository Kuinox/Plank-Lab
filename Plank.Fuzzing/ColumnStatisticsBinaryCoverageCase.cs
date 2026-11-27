using System.Collections.Immutable;
using Plank.Reading;
using Plank.Schema;
using Plank.Writing;

namespace Plank.Fuzzing;

/// <summary>Reaches reusable binary statistics through public writer routes with decimal ordering.</summary>
internal static class ColumnStatisticsBinaryCoverageCase
{
    static readonly ColumnOptions Plain = new(encodings: ImmutableArray.Create(EncodingKind.Plain), bloomFilter: null);

    internal static void Execute(byte selector)
    {
        switch (selector % 3)
        {
            case 0:
                ExerciseByteArrays();
                break;
            case 1:
                ExerciseMemory();
                break;
            default:
                ExerciseEmptyRequiredByteArray();
                break;
        }
    }

    static void ExerciseByteArrays()
    {
        var requiredDefinition = ColumnDefinition.RequiredLeaf("required-binary-stats",
            ParquetPhysicalType.ByteArray, Plain, new LogicalType.Decimal(9, 0));
        var optionalDefinition = ColumnDefinition.OptionalLeaf("binary-stats", ParquetPhysicalType.ByteArray, Plain,
            new LogicalType.Decimal(9, 0));
        var allNullDefinition = ColumnDefinition.OptionalLeaf("all-null-binary-stats",
            ParquetPhysicalType.ByteArray, Plain, new LogicalType.Decimal(9, 0));
        var schema = new ParquetSchema([requiredDefinition, optionalDefinition, allNullDefinition]);
        byte[][] required = [Array.Empty<byte>(), [0x00], [0x00, 0x7f], [0xff, 0x7f], [0x00, 0x80], [0x00, 0x80]];
        byte[]?[] optional = [null, [0x00, 0x7f], [0xff, 0x7f], [0x00, 0x80], Array.Empty<byte>(), null];
        using var stream = new MemoryStream();
        var writer = schema.CreateWriter(stream, new ParquetWriterOptions { Compression = CompressionKind.None });
        var rowGroup = writer.StartRowGroup();
        var requiredColumn = rowGroup.CreateSerializedColumn<byte[]>(schema.LeafColumns[0]);
        requiredColumn.Serialize(required);
        rowGroup.Write(requiredColumn);
        var optionalColumn = rowGroup.CreateSerializedColumn<byte[]?>(schema.LeafColumns[1]);
        optionalColumn.Serialize(optional);
        rowGroup.Write(optionalColumn);
        var allNullColumn = rowGroup.CreateSerializedColumn<byte[]?>(schema.LeafColumns[2]);
        allNullColumn.Serialize(new byte[]?[6]);
        rowGroup.Write(allNullColumn);
        writer.CloseFile();

        using var source = FullValueOracle.Source(stream.ToArray());
        using var reader = schema.CreateReader(source);
        var requiredStatistics = reader.RowGroups[0].GetColumnMetadata(0).Statistics;
        var optionalStatistics = reader.RowGroups[0].GetColumnMetadata(1).Statistics;
        var allNullStatistics = reader.RowGroups[0].GetColumnMetadata(2).Statistics;
        if (!requiredStatistics.HasMinimum || !requiredStatistics.HasMaximum
            || !requiredStatistics.Minimum.SequenceEqual(new byte[] { 0xff, 0x7f })
            || !requiredStatistics.Maximum.SequenceEqual(new byte[] { 0x00, 0x80 })
            || !optionalStatistics.HasMinimum || !optionalStatistics.HasMaximum || optionalStatistics.NullCount != 2
            || !optionalStatistics.Minimum.SequenceEqual(new byte[] { 0xff, 0x7f })
            || !optionalStatistics.Maximum.SequenceEqual(new byte[] { 0x00, 0x80 })
            || allNullStatistics.HasMinimum || allNullStatistics.HasMaximum || allNullStatistics.NullCount != 6)
            throw new InvalidOperationException("Binary statistics coverage case changed.");
    }

    static void ExerciseEmptyRequiredByteArray()
    {
        var definition = ColumnDefinition.RequiredLeaf("empty-binary-stats", ParquetPhysicalType.ByteArray, Plain,
            new LogicalType.Decimal(9, 0));
        var schema = new ParquetSchema([definition]);
        using var stream = new MemoryStream();
        var writer = schema.CreateWriter(stream, new ParquetWriterOptions { Compression = CompressionKind.None });
        var rowGroup = writer.StartRowGroup();
        var column = rowGroup.CreateSerializedColumn<byte[]>(schema.LeafColumns[0]);
        column.Serialize(Array.Empty<byte[]>());
        rowGroup.Write(column);
        writer.CloseFile();

        using var source = FullValueOracle.Source(stream.ToArray());
        using var reader = schema.CreateReader(source);
        var statistics = reader.RowGroups[0].GetColumnMetadata(0).Statistics;
        if (statistics.HasMinimum || statistics.HasMaximum)
            throw new InvalidOperationException("Empty binary statistics coverage case changed.");
    }

    static void ExerciseMemory()
    {
        var requiredDefinition = ColumnDefinition.RequiredLeaf("memory-stats", ParquetPhysicalType.ByteArray, Plain,
            new LogicalType.Decimal(9, 0));
        var optionalDefinition = ColumnDefinition.OptionalLeaf("nullable-memory-stats", ParquetPhysicalType.ByteArray,
            Plain, new LogicalType.Decimal(9, 0));
        var schema = new ParquetSchema([requiredDefinition, optionalDefinition]);
        ReadOnlyMemory<byte>[] required = [new byte[] { 0x00, 0x7f }, new byte[] { 0xff, 0x7f }, new byte[] { 0x00, 0x80 }, new byte[] { 0x00, 0x7f }, new byte[] { 0xff, 0x7f }];
        ReadOnlyMemory<byte>?[] optional = [null, new byte[] { 0x00, 0x7f }, new byte[] { 0xff, 0x7f }, new byte[] { 0x00, 0x80 }, null];
        using var stream = new MemoryStream();
        var writer = schema.CreateWriter(stream, new ParquetWriterOptions { Compression = CompressionKind.None });
        var rowGroup = writer.StartRowGroup();
        var requiredColumn = rowGroup.CreateSerializedColumn<ReadOnlyMemory<byte>>(schema.LeafColumns[0]);
        requiredColumn.Serialize(required);
        rowGroup.Write(requiredColumn);
        var optionalColumn = rowGroup.CreateSerializedColumn<ReadOnlyMemory<byte>?>(schema.LeafColumns[1]);
        optionalColumn.Serialize(optional);
        rowGroup.Write(optionalColumn);
        writer.CloseFile();

        using var source = FullValueOracle.Source(stream.ToArray());
        using var reader = schema.CreateReader(source);
        var requiredStatistics = reader.RowGroups[0].GetColumnMetadata(0).Statistics;
        var optionalStatistics = reader.RowGroups[0].GetColumnMetadata(1).Statistics;
        if (!requiredStatistics.HasMinimum || !requiredStatistics.HasMaximum
            || !requiredStatistics.Minimum.SequenceEqual(new byte[] { 0xff, 0x7f })
            || !requiredStatistics.Maximum.SequenceEqual(new byte[] { 0x00, 0x80 })
            || !optionalStatistics.HasMinimum || !optionalStatistics.HasMaximum || optionalStatistics.NullCount != 2
            || !optionalStatistics.Minimum.SequenceEqual(new byte[] { 0xff, 0x7f })
            || !optionalStatistics.Maximum.SequenceEqual(new byte[] { 0x00, 0x80 }))
            throw new InvalidOperationException("Memory binary statistics coverage case changed.");
    }
}
