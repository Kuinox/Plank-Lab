using Plank.Reading;
using Plank.Schema;
using Plank.Writing;

namespace Plank.Fuzzing;

/// <summary>Focused public-writer samples for flat and nested repeated-row dispatch.</summary>
internal static class RepeatedRowsCoverageCases
{
    internal static void Execute(byte selector)
    {
        switch (selector & 7)
        {
            case 0:
                ExerciseFlatRepeatedPhysicalTypes(selector);
                break;
            case 1:
                ExerciseNestedRepeatedRows(selector);
                break;
            case 2:
                ExerciseReadOnlyMemoryRepeatedRows(selector);
                break;
            case 3:
                ExerciseOptionalReadOnlyMemoryRejection();
                break;
            case 4:
                ExerciseUnknownFlatPhysicalType();
                break;
            default:
                ExerciseUnknownNestedPhysicalType();
                break;
        }
    }

    static void ExerciseFlatRepeatedPhysicalTypes(byte selector)
    {
        WriteAndCheck(
            ColumnDefinition.List("required-bool", ColumnDefinition.RequiredLeaf("element", ParquetPhysicalType.Boolean)),
            new[] { new[] { true, false }, Array.Empty<bool>(), new[] { true } }, selector);
        WriteAndCheck(
            ColumnDefinition.List("optional-bool", ColumnDefinition.OptionalLeaf("element", ParquetPhysicalType.Boolean)),
            new[] { new bool?[] { true, null, false }, Array.Empty<bool?>(), new bool?[] { null } }, selector);
        WriteAndCheck(
            ColumnDefinition.List("required-i32", ColumnDefinition.RequiredLeaf("element", ParquetPhysicalType.Int32)),
            new[] { new[] { int.MinValue, 0 }, Array.Empty<int>(), new[] { int.MaxValue } }, selector);
        WriteAndCheck(
            ColumnDefinition.List("optional-i32", ColumnDefinition.OptionalLeaf("element", ParquetPhysicalType.Int32)),
            new[] { new int?[] { int.MinValue, null, 0 }, Array.Empty<int?>(), new int?[] { int.MaxValue } }, selector);
        WriteAndCheck(
            ColumnDefinition.List("required-i64", ColumnDefinition.RequiredLeaf("element", ParquetPhysicalType.Int64)),
            new[] { new[] { long.MinValue, 0L }, Array.Empty<long>(), new[] { long.MaxValue } }, selector);
        WriteAndCheck(
            ColumnDefinition.List("optional-i64", ColumnDefinition.OptionalLeaf("element", ParquetPhysicalType.Int64)),
            new[] { new long?[] { long.MinValue, null, 0L }, Array.Empty<long?>(), new long?[] { long.MaxValue } }, selector);
        WriteAndCheck(
            ColumnDefinition.List("required-float", ColumnDefinition.RequiredLeaf("element", ParquetPhysicalType.Float)),
            new[] { new[] { float.MinValue, 0f }, Array.Empty<float>(), new[] { float.MaxValue } }, selector);
        WriteAndCheck(
            ColumnDefinition.List("optional-float", ColumnDefinition.OptionalLeaf("element", ParquetPhysicalType.Float)),
            new[] { new float?[] { float.MinValue, null, 0f }, Array.Empty<float?>(), new float?[] { float.MaxValue } }, selector);
        WriteAndCheck(
            ColumnDefinition.List("required-double", ColumnDefinition.RequiredLeaf("element", ParquetPhysicalType.Double)),
            new[] { new[] { double.MinValue, 0d }, Array.Empty<double>(), new[] { double.MaxValue } }, selector);
        WriteAndCheck(
            ColumnDefinition.List("optional-double", ColumnDefinition.OptionalLeaf("element", ParquetPhysicalType.Double)),
            new[] { new double?[] { double.MinValue, null, 0d }, Array.Empty<double?>(), new double?[] { double.MaxValue } }, selector);
        WriteAndCheck(
            ColumnDefinition.List("required-binary", ColumnDefinition.RequiredLeaf("element", ParquetPhysicalType.ByteArray)),
            new[] { new[] { "alpha"u8.ToArray(), Array.Empty<byte>() }, Array.Empty<byte[]>(), new[] { "omega"u8.ToArray() } }, selector);
        WriteAndCheck(
            ColumnDefinition.List("optional-binary", ColumnDefinition.OptionalLeaf("element", ParquetPhysicalType.ByteArray)),
            new[] { new byte[]?[] { "alpha"u8.ToArray(), null, Array.Empty<byte>() }, Array.Empty<byte[]?>(), new byte[]?[] { "omega"u8.ToArray() } }, selector);
    }

    static void ExerciseNestedRepeatedRows(byte selector)
    {
        int[][][] requiredRows =
        [
            [[int.MinValue, 0], [], [int.MaxValue]],
            [],
            [[-17], [42, 99]]
        ];
        var requiredSchema = new ParquetSchema([
            ColumnDefinition.List("outer",
                ColumnDefinition.List("inner", ColumnDefinition.RequiredLeaf("element", ParquetPhysicalType.Int32)))
        ]);
        WriteAndCheck(requiredSchema, requiredRows, selector);

        double?[][][] optionalRows =
        [
            [[double.MinValue, null], [], [double.MaxValue]],
            [],
            [[-17d], [null, 42d]]
        ];
        var optionalSchema = new ParquetSchema([
            ColumnDefinition.List("outer",
                ColumnDefinition.List("inner", ColumnDefinition.OptionalLeaf("element", ParquetPhysicalType.Double)))
        ]);
        WriteAndCheck(optionalSchema, optionalRows, selector);
    }

    static void ExerciseReadOnlyMemoryRepeatedRows(byte selector)
    {
        // Plank 80578da (#224) added ReadOnlyMemory<byte>[] rows for single-level repeated binary
        // columns (SerializedColumn.SerializeRepeated); they used to be rejected. They must now
        // encode exactly what the same rows as byte[][] encode: same levels, same values.
        var backing = "xalphaomegay"u8.ToArray();
        ReadOnlyMemory<byte>[][] rows =
        [
            [backing.AsMemory(1, 5), ReadOnlyMemory<byte>.Empty],
            [],
            [backing.AsMemory(6, 5)]
        ];
        var schema = new ParquetSchema([
            ColumnDefinition.List("required-memory",
                ColumnDefinition.RequiredLeaf("element", ParquetPhysicalType.ByteArray))
        ]);
        var memoryTrace = WriteAndReadNestedBinary(schema, rows, selector);
        var arrayTrace = WriteAndReadNestedBinary(schema,
            rows.Select(static row => row.Select(static value => value.ToArray()).ToArray()).ToArray(), selector);
        if (!memoryTrace.Definitions.SequenceEqual(arrayTrace.Definitions)
            || !memoryTrace.Repetitions.SequenceEqual(arrayTrace.Repetitions)
            || memoryTrace.Values.Count != arrayTrace.Values.Count
            || memoryTrace.Values.Zip(arrayTrace.Values).Any(static pair => !pair.First.AsSpan().SequenceEqual(pair.Second)))
            throw new InvalidOperationException("Repeated ReadOnlyMemory rows encoded differently from the same byte[] rows.");
        if (arrayTrace.Values.Count != 3 || !arrayTrace.Values[0].AsSpan().SequenceEqual("alpha"u8)
            || arrayTrace.Values[1].Length != 0 || !arrayTrace.Values[2].AsSpan().SequenceEqual("omega"u8))
            throw new InvalidOperationException("Repeated binary rows did not round-trip their values.");
    }

    static (List<int> Definitions, List<int> Repetitions, List<byte[]> Values) WriteAndReadNestedBinary<T>(
        ParquetSchema schema, T[] rows, byte selector)
    {
        using var stream = new MemoryStream();
        var writer = schema.CreateWriter(stream, new ParquetWriterOptions
        {
            Compression = CompressionKind.None,
            DataPageVersion = (selector & 2) == 0 ? ParquetDataPageVersion.V1 : ParquetDataPageVersion.V2
        });
        var serialized = writer.CreateSerializedColumn<T>(schema.LeafColumns[0]);
        serialized.Serialize(rows);
        writer.StartRowGroup().Write(serialized);
        writer.CloseFile();

        using var reader = schema.CreateReader(FullValueOracle.Source(stream.ToArray()));
        if (reader.RowGroups.Count != 1 || reader.RowGroups[0].RowCount != (ulong)rows.Length)
            throw new InvalidOperationException("Repeated binary rows changed the row-group shape.");
        var definitions = new List<int>();
        var repetitions = new List<int>();
        var values = new List<byte[]>();
        foreach (var page in reader.RowGroups[0].NestedColumn<byte>(schema.LeafColumns[0]))
        {
            definitions.AddRange(page.DefinitionLevels.ToArray());
            repetitions.AddRange(page.RepetitionLevels.ToArray());
            for (var i = 0; i < page.Values.Count; i++)
                values.Add(page.Values.GetValue(i).ToArray());
        }
        return (definitions, repetitions, values);
    }

    static void ExerciseOptionalReadOnlyMemoryRejection()
    {
        ReadOnlyMemory<byte>[][] rows = [["alpha"u8.ToArray()], []];
        var schema = new ParquetSchema([
            ColumnDefinition.List("optional-memory",
                ColumnDefinition.OptionalLeaf("element", ParquetPhysicalType.ByteArray))
        ]);
        // ReadOnlyMemory<byte> cannot carry a null element; message from Plank 80578da (#224).
        ExpectEncodingFailure(schema, rows, "has optional list elements; use a nullable row element type");
    }

    static void ExerciseUnknownFlatPhysicalType()
    {
        var unknownType = (ParquetPhysicalType)255;
        var schema = new ParquetSchema([
            ColumnDefinition.List("unknown-flat",
                ColumnDefinition.RequiredLeaf("element", unknownType))
        ]);
        ExpectEncodingFailure(schema, new[] { new[] { 1, 2 }, Array.Empty<int>() },
            "Unsupported repeated physical type '255'");
    }

    static void ExerciseUnknownNestedPhysicalType()
    {
        var unknownType = (ParquetPhysicalType)255;
        var schema = new ParquetSchema([
            ColumnDefinition.List("outer",
                ColumnDefinition.List("inner", ColumnDefinition.RequiredLeaf("element", unknownType)))
        ]);
        int[][][] rows = [[[1, 2], []], [], [[3]]];
        // Since Plank 80578da (#224) the physical-type switch rejects it before any nesting check.
        ExpectEncodingFailure(schema, rows, "Unsupported repeated physical type '255'");
    }

    static void ExpectEncodingFailure<T>(ParquetSchema schema, T[] rows, string expectedMessage)
    {
        try
        {
            using var stream = new MemoryStream();
            var writer = schema.CreateWriter(stream, new ParquetWriterOptions { Compression = CompressionKind.None });
            var serialized = writer.CreateSerializedColumn<T>(schema.LeafColumns[0]);
            serialized.Serialize(rows);
        }
        catch (InvalidOperationException error) when (error.Message.Contains(expectedMessage, StringComparison.Ordinal))
        {
            return;
        }

        throw new InvalidOperationException($"Repeated writer did not reject the expected input: {expectedMessage}");
    }

    static void WriteAndCheck<T>(ColumnDefinition definition, T[] rows, byte selector)
    {
        var schema = new ParquetSchema([definition]);
        WriteAndCheck(schema, rows, selector);
    }

    static void WriteAndCheck<T>(ParquetSchema schema, T[] rows, byte selector)
    {
        using var stream = new MemoryStream();
        var writer = schema.CreateWriter(stream, new ParquetWriterOptions
        {
            Compression = CompressionKind.None,
            DataPageVersion = (selector & 2) == 0 ? ParquetDataPageVersion.V1 : ParquetDataPageVersion.V2,
            WritePageCrc = (selector & 4) != 0,
            TargetDataPageSizeBytes = 64,
            BufferChunkSizeBytes = 128
        });
        var serialized = writer.CreateSerializedColumn<T>(schema.LeafColumns[0]);
        serialized.Serialize(rows);
        writer.StartRowGroup().Write(serialized);
        writer.CloseFile();

        using var reader = schema.CreateReader(FullValueOracle.Source(stream.ToArray()));
        if (reader.RowGroups.Count != 1 || reader.RowGroups[0].RowCount != (ulong)rows.Length)
            throw new InvalidOperationException("Repeated-row encoding changed the row-group shape.");
        using var pages = reader.RowGroups[0].GetColumnMetadata(schema.LeafColumns[0]).OpenPages();
        if (rows.Length != 0 && pages.Count == 0)
            throw new InvalidOperationException("Repeated-row encoding omitted its data page.");
    }

}
