using System.Collections.Immutable;
using Plank.Reading;
using Plank.Schema;
using Plank.Writing;
using PlankColumn = Plank.Schema.ColumnDefinition;
using PlankWriterTarget = Plank.Fuzzing.PlankWriterFuzzTarget;

namespace Plank.Fuzzing;

/// <summary>Valid writer cases for logical annotations absent from the generic plan decoder.</summary>
internal static class LogicalMetadataWriterCases
{
    internal static void Execute(byte selector)
    {
        if ((selector & 0x1f) == 7)
        {
            ExerciseVariant(selector);
            return;
        }

        PlankWriterTarget.Validate(Create(selector));
    }

    internal static PlankWriterTarget.FuzzCase Create(byte selector)
    {
        var hasFieldId = (selector & 0x40) != 0;
        var fieldId = hasFieldId ? 37 : (int?)null;
        var index = selector & 0x1f;
        if (index >= 7)
            return CreateMetadataOnly(index, fieldId, selector);

        byte[][] data = [[0x01, 0x02], [0x7f, 0x80], [0xff]];
        (ParquetPhysicalType PhysicalType, uint TypeLength, LogicalType LogicalType) type = index switch
        {
            0 => (ParquetPhysicalType.ByteArray, 0u, new LogicalType.Bson()),
            1 => (ParquetPhysicalType.ByteArray, 0u, new LogicalType.Enum()),
            2 => (ParquetPhysicalType.FixedLenByteArray, 2u, new LogicalType.Float16()),
            3 => (ParquetPhysicalType.FixedLenByteArray, 12u, new LogicalType.Interval()),
            4 => (ParquetPhysicalType.ByteArray, 0u, new LogicalType.Geometry((selector & 0x80) == 0 ? null : "EPSG:4326")),
            5 => (ParquetPhysicalType.ByteArray, 0u, new LogicalType.Geography(
                (selector & 0x80) == 0 ? null : "EPSG:4326",
                (selector & 0x20) == 0 ? null : EdgeInterpolationAlgorithm.Karney)),
            _ => (ParquetPhysicalType.ByteArray, 0u, new LogicalType.Unknown())
        };

        if (type.TypeLength > 0)
            data = new[] { 0, 1, 2 }.Select(seed => Enumerable.Range(0, checked((int)type.TypeLength))
                .Select(offset => (byte)(seed * 31 + offset)).ToArray()).ToArray();

        var options = new ColumnOptions(
            repetition: type.LogicalType is LogicalType.Unknown ? ParquetRepetition.Optional : ParquetRepetition.Unspecified,
            encodings: ImmutableArray.Create(EncodingKind.Plain), typeLength: type.TypeLength);
        var column = type.LogicalType is LogicalType.Unknown
            ? ColumnDefinition.OptionalLeaf("logical-metadata", type.PhysicalType, options, type.LogicalType)
            : fieldId is { } id
                ? ColumnDefinition.Leaf("logical-metadata", type.PhysicalType, id, options, type.LogicalType)
                : ColumnDefinition.Leaf("logical-metadata", type.PhysicalType, options, type.LogicalType);

        if (type.LogicalType is LogicalType.Unknown)
            data = [null!, null!, null!];

        var pageVersion = (selector & 1) == 0
            ? ParquetDataPageVersion.V1
            : ParquetDataPageVersion.V2;
        var fuzzCase = new PlankWriterTarget.FuzzCase(
            [new PlankWriterTarget.ColumnSpec(column, typeof(byte[]))], [[data]], CompressionKind.None,
            new PlankWriterTarget.WriterSettings(pageVersion, WritePageCrc: true,
                WritePageIndexes: false, FileVersion: ParquetFileVersion.V1,
                TargetDataPageSizeBytes: 64, BufferChunkSizeBytes: 128, WithKeyValueMetadata: false));
        return fuzzCase;
    }

    static PlankWriterTarget.FuzzCase CreateMetadataOnly(int index, int? fieldId, byte selector)
    {
        var logical = index switch
        {
            7 => throw new InvalidOperationException("Variant is validated through its dedicated group route."),
            8 => (Column: Leaf(ParquetPhysicalType.Int32, new LogicalType.Time(TimeUnit.Millis, false), fieldId), Type: typeof(int)),
            9 => (Column: Leaf(ParquetPhysicalType.Int64, new LogicalType.Time(TimeUnit.Nanos, true), fieldId), Type: typeof(long)),
            10 => (Column: Leaf(ParquetPhysicalType.Int64, new LogicalType.Timestamp(TimeUnit.Millis, false), fieldId), Type: typeof(long)),
            11 => (Column: Leaf(ParquetPhysicalType.Int64, new LogicalType.Timestamp(TimeUnit.Nanos, true), fieldId), Type: typeof(long)),
            12 => (Column: Leaf(ParquetPhysicalType.Int32, new LogicalType.Int(8, true), fieldId), Type: typeof(int)),
            13 => (Column: Leaf(ParquetPhysicalType.Int32, new LogicalType.Int(16, true), fieldId), Type: typeof(int)),
            14 => (Column: Leaf(ParquetPhysicalType.Int32, new LogicalType.Int(32, true), fieldId), Type: typeof(int)),
            15 => (Column: Leaf(ParquetPhysicalType.Int64, new LogicalType.Int(64, true), fieldId), Type: typeof(long)),
            16 => (Column: Leaf(ParquetPhysicalType.Int32, new LogicalType.Int(8, false), fieldId), Type: typeof(int)),
            17 => (Column: Leaf(ParquetPhysicalType.Int32, new LogicalType.Int(16, false), fieldId), Type: typeof(int)),
            18 => (Column: Leaf(ParquetPhysicalType.Int32, new LogicalType.Int(32, false), fieldId), Type: typeof(int)),
            19 => (Column: Leaf(ParquetPhysicalType.Int64, new LogicalType.Int(64, false), fieldId), Type: typeof(long)),
            20 => (Column: Leaf(ParquetPhysicalType.Int32, new LogicalType.Date(), fieldId), Type: typeof(int)),
            21 => (Column: Leaf(ParquetPhysicalType.ByteArray, new LogicalType.String(), fieldId), Type: typeof(byte[])),
            22 => (Column: Leaf(ParquetPhysicalType.ByteArray, new LogicalType.Json(), fieldId), Type: typeof(byte[])),
            23 => (Column: Leaf(ParquetPhysicalType.Int32, new LogicalType.Decimal(9, 2), fieldId), Type: typeof(int)),
            24 => (Column: Leaf(ParquetPhysicalType.FixedLenByteArray, new LogicalType.Uuid(), fieldId, 16), Type: typeof(byte[])),
            25 => (Column: Leaf(ParquetPhysicalType.Int64, new LogicalType.Time(TimeUnit.Micros, true), fieldId), Type: typeof(long)),
            _ => (Column: Leaf(ParquetPhysicalType.Int64, new LogicalType.Timestamp(TimeUnit.Micros, false), fieldId), Type: typeof(long))
        };
        return new PlankWriterTarget.FuzzCase(
            [new PlankWriterTarget.ColumnSpec(logical.Column, logical.Type)], [], CompressionKind.None,
            new PlankWriterTarget.WriterSettings(ParquetDataPageVersion.V2, WritePageCrc: false,
                WritePageIndexes: false, FileVersion: ParquetFileVersion.V1,
                TargetDataPageSizeBytes: 64, BufferChunkSizeBytes: 128, WithKeyValueMetadata: false));
    }

    static void ExerciseVariant(byte selector)
    {
        var schema = new ParquetSchema([ColumnDefinition.RequiredGroup("logical-variant",
            new LogicalType.Variant((sbyte?)((selector & 0x20) == 0 ? null : 1)),
            ColumnDefinition.RequiredLeaf("metadata", ParquetPhysicalType.ByteArray),
            ColumnDefinition.RequiredLeaf("value", ParquetPhysicalType.ByteArray))]);
        using var stream = new MemoryStream();
        schema.CreateWriter(stream, new ParquetWriterOptions { Compression = CompressionKind.None }).CloseFile();
        using var reader = schema.CreateReader(FullValueOracle.Source(stream.ToArray()));
        if (reader.RowGroups.Count != 0)
            throw new InvalidOperationException("Variant metadata route unexpectedly wrote a row group.");
    }

    static PlankColumn Leaf(ParquetPhysicalType physical, LogicalType logical, int? fieldId, uint length = 0)
    {
        var options = new ColumnOptions(typeLength: length,
            encodings: ImmutableArray.Create(EncodingKind.Plain));
        return fieldId is { } id
            ? ColumnDefinition.Leaf("logical-metadata", physical, id, options, logical)
            : ColumnDefinition.Leaf("logical-metadata", physical, options, logical);
    }
}
