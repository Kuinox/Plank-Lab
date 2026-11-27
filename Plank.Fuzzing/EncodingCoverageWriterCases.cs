using System.Buffers.Binary;
using System.Collections.Immutable;
using Plank.Reading;
using Plank.Schema;
using Plank.Writing;
using Plank.Writing.PageStrategy;

namespace Plank.Fuzzing;

/// <summary>Deliberate writer-only cases for encoding paths beyond the general corpus limits.</summary>
internal static class EncodingCoverageWriterCases
{
    internal static void Execute(ReadOnlySpan<byte> controls)
    {
        var caseId = controls.IsEmpty ? (byte)0 : controls[0];
        if (caseId == 0)
        {
            WriteDelta13BitAllMiniBlocks();
            return;
        }

        if (caseId is >= 1 and <= 6)
        {
            WriteWideDictionary(caseId + 7);
            return;
        }

        if (caseId is >= 7 and <= 12)
        {
            WriteForcedRequiredByteArrayDictionary(caseId);
            return;
        }

        if (caseId == 13)
        {
            WriteOptionalDoubleDictionaryAfterUnsortedRowGroup();
            return;
        }

        if (caseId == 14)
        {
            WriteBooleanRunShapesAndByteStreamSplit();
            return;
        }

        if (caseId == 15)
        {
            WriteInt96PlainPayloads();
            return;
        }

        if (caseId == 16)
        {
            WriteOptionalSingleByteMemoryPayloads();
            return;
        }

        if (caseId == 17)
        {
            WriteNullableTemporalValues();
            return;
        }

        if (caseId == 18)
        {
            WriteOptionalDoubleDictionarySignedZeroAndNaN();
            return;
        }

        if (caseId == 19)
        {
            WriteOptionalSingleByteMemoryPayloadsWithNullRuns();
            return;
        }

        if (caseId == 20)
        {
            WriteRequiredInt32DictionaryDropCheckpoint();
            return;
        }

        if (caseId == 21)
        {
            WriteAlpFloatAndDoubleExceptions();
            return;
        }

        if (caseId == 23)
        {
            WriteFixedBinaryByteStreamSplitGuidAndDecimal();
            return;
        }

        if (caseId == 24)
        {
            WriteRequiredReadOnlyMemoryDictionary();
            return;
        }

        if (caseId == 25)
        {
            WriteDeltaLengthByteArrayReadOnlyMemoryShapes();
            WriteRequiredDeltaLengthByteArrayNullRejection();
            return;
        }

        if (caseId == 26)
        {
            WriteFixedWidthPlainTargetPages();
            return;
        }

        if (caseId == 27)
        {
            WriteOptionalInt32PlainTargetPages();
            return;
        }

        if (caseId == 28)
        {
            WriteOptionalInt32ForcedDictionaryRangeFallback();
            return;
        }

        if (caseId == 29)
        {
            WriteOptionalFixedBinaryPlainPayloads(useRowCountStrategy: false);
            return;
        }

        if (caseId == 30)
        {
            WriteOptionalFixedBinaryPlainPayloads(useRowCountStrategy: true);
            return;
        }

        if (caseId == 31)
        {
            WriteAlternateNumericEncodingInputs();
            return;
        }

        if (caseId == 32)
        {
            ProbeOptionalFixedMemoryPayloads();
            return;
        }

        if (caseId == 33)
        {
            ProbeOptionalFixedByteArrayWrongWidth();
            return;
        }

        if (caseId == 34)
        {
            ProbeFixedBssInvalidPayloads();
            return;
        }

        if (caseId == 35)
        {
            WriteOptionalReadOnlyMemoryDictionaryDecisionPaths();
            return;
        }

        if (caseId == 36)
        {
            WriteDeltaByteArrayReadOnlyMemoryShapes();
            return;
        }

        if (caseId == 37)
        {
            WriteOptionalByteArrayTargetPages();
            return;
        }

        if (caseId == 38)
        {
            WriteSerializedColumnOptionalBranches();
            return;
        }

        if (caseId == 39)
        {
            WriteDeltaInt32GenericDispatchInputs();
            return;
        }

        if (caseId == 40)
        {
            WriteOptionalDoubleDictionarySmallIndexPaths();
            return;
        }

        if (caseId == 43)
        {
            WriteEmptyOptionalStructAndReferenceColumns();
            return;
        }

        if (caseId == 45)
        {
            WriteNullableInt32StatisticsBloomPath();
            return;
        }

        if (caseId == 47)
        {
            WriteAllNullOptionalInt32Statistics();
            return;
        }

        if (caseId == 48)
        {
            WriteAllNullOptionalInt64Statistics();
            return;
        }

        if (caseId == 41)
        {
            WriteEmptyRequiredReadOnlyMemory();
            return;
        }

        if (caseId == 42)
        {
            WriteOptionalPlainInt64ValidationAndEmptyCases();
            return;
        }

        if (caseId == 44)
        {
            WriteOptionalDeltaInt64ValidationAndPublicControl();
            return;
        }

        if (caseId == 46)
        {
            WriteOptionalMemoryTargetPageDecisionPaths();
            return;
        }

        if (caseId == 49)
        {
            WriteRequiredDeltaByteArrayPrecomputedPages();
            return;
        }

        if (caseId == 50)
        {
            WriteOptionalDateTimePredicateMatrix();
            return;
        }

        if (caseId == 51)
        {
            WriteByteArrayCountPresentMatrix();
            return;
        }

        if (caseId == 53)
        {
            WriteForcedOptionalInt32DictionaryGuardMatrix();
            return;
        }

        if (caseId == 52)
        {
            WriteFixedByteStreamSplitReadOnlyMemory();
            return;
        }

        if (caseId == 54)
        {
            WriteForcedOptionalInt64DictionaryNestedProjectionRejection();
            return;
        }

        if (caseId == 56)
        {
            WriteForcedOptionalInt64DictionaryRequiredCarrierRejection();
            return;
        }

        if (caseId == 58)
        {
            WriteFloatAndDecimalDictionarySortComparisons();
            return;
        }

        if (caseId == 55)
        {
            WritePlainInt32DecimalCarrier();
            return;
        }

        if (caseId == 57)
        {
            WriteForcedRequiredByteArrayDictionarySortTransitions();
            return;
        }

        if (caseId == 59)
        {
            WriteForcedRequiredByteArrayDictionaryMapNullFailures();
            return;
        }


        // AFL mutations can alter the selector; unknown cases are intentionally inert.
    }

    static void WriteFixedWidthPlainTargetPages()
    {
        const int count = 19;
        var ints = Enumerable.Range(0, count).Select(i => unchecked(i * 7919 - 12345)).ToArray();
        var bools = Enumerable.Range(0, count).Select(i => (i % 5) is 1 or 2).ToArray();
        var schema = new ParquetSchema([
            ColumnDefinition.Leaf("fixed-page-int32", ParquetPhysicalType.Int32),
            ColumnDefinition.Leaf("fixed-page-bool", ParquetPhysicalType.Boolean)
        ]);
        var stream = new MemoryStream();
        var writer = schema.CreateWriter(stream, new ParquetWriterOptions
        {
            Compression = CompressionKind.None,
            TargetDataPageSizeBytes = 300_000_000
        });
        var rowGroup = writer.StartRowGroup();
        var intColumn = rowGroup.CreateSerializedColumn<int>(schema.LeafColumns[0]);
        intColumn.Serialize(ints);
        rowGroup.Write(intColumn);
        var boolColumn = rowGroup.CreateSerializedColumn<bool>(schema.LeafColumns[1]);
        boolColumn.Serialize(bools);
        rowGroup.Write(boolColumn);
        writer.CloseFile();

        using var reader = schema.CreateReader(FullValueOracle.Source(stream.ToArray()));
        AssertReadBack(reader, 0, ints);
        AssertReadBack(reader, 1, bools);
    }

    static void WriteAlternateNumericEncodingInputs()
    {
        const int count = 300;
        var byteValues = Enumerable.Range(0, count).Select(i => (byte)(i % 251)).ToArray();
        var ushortValues = Enumerable.Range(0, count).Select(i => (ushort)(i * 17)).ToArray();
        var uintValues = Enumerable.Range(0, count).Select(i => unchecked((uint)(i * 65_537))).ToArray();
        var ulongValues = Enumerable.Range(0, count).Select(i => unchecked((ulong)i * 0x01020304050607UL)).ToArray();
        var decimalValues = Enumerable.Range(0, count).Select(i => (decimal)(i - 150) / 100m).ToArray();
        var floatValues = Enumerable.Range(0, count).Select(i => (float)i / 8f).ToArray();
        var doubleValues = Enumerable.Range(0, count).Select(i => (double)i / 16d).ToArray();
        var delta = ImmutableArray.Create(EncodingKind.DeltaBinaryPacked);
        var split = ImmutableArray.Create(EncodingKind.ByteStreamSplit);
        var schema = new ParquetSchema(
        [
            ColumnDefinition.Leaf("bss-ushort", ParquetPhysicalType.Int32,
                new ColumnOptions(encodings: split)),
            ColumnDefinition.Leaf("bss-uint", ParquetPhysicalType.Int32,
                new ColumnOptions(encodings: split)),
            ColumnDefinition.Leaf("bss-decimal32", ParquetPhysicalType.Int32,
                new ColumnOptions(encodings: split), new LogicalType.Decimal(9, 2)),
            ColumnDefinition.Leaf("bss-ulong", ParquetPhysicalType.Int64,
                new ColumnOptions(encodings: split)),
            ColumnDefinition.Leaf("bss-decimal64", ParquetPhysicalType.Int64,
                new ColumnOptions(encodings: split), new LogicalType.Decimal(18, 2)),
            ColumnDefinition.Leaf("bss-float", ParquetPhysicalType.Float,
                new ColumnOptions(encodings: split)),
            ColumnDefinition.Leaf("bss-double", ParquetPhysicalType.Double,
                new ColumnOptions(encodings: split)),
            ColumnDefinition.Leaf("delta-byte", ParquetPhysicalType.Int32,
                new ColumnOptions(encodings: delta)),
            ColumnDefinition.Leaf("delta-ushort", ParquetPhysicalType.Int32,
                new ColumnOptions(encodings: delta)),
            ColumnDefinition.Leaf("delta-uint", ParquetPhysicalType.Int32,
                new ColumnOptions(encodings: delta)),
            ColumnDefinition.Leaf("delta-decimal32", ParquetPhysicalType.Int32,
                new ColumnOptions(encodings: delta), new LogicalType.Decimal(9, 2)),
            ColumnDefinition.Leaf("delta-ulong", ParquetPhysicalType.Int64,
                new ColumnOptions(encodings: delta)),
            ColumnDefinition.Leaf("delta-decimal64", ParquetPhysicalType.Int64,
                new ColumnOptions(encodings: delta), new LogicalType.Decimal(18, 2)),
            ColumnDefinition.Leaf("delta-byte-array", ParquetPhysicalType.ByteArray,
                new ColumnOptions(encodings: ImmutableArray.Create(EncodingKind.DeltaByteArray))),
            ColumnDefinition.Leaf("delta-width-9", ParquetPhysicalType.Int32,
                new ColumnOptions(encodings: delta)),
            ColumnDefinition.Leaf("delta-width-10", ParquetPhysicalType.Int32,
                new ColumnOptions(encodings: delta)),
            ColumnDefinition.Leaf("delta-width-11", ParquetPhysicalType.Int32,
                new ColumnOptions(encodings: delta)),
            ColumnDefinition.Leaf("delta-width-12", ParquetPhysicalType.Int32,
                new ColumnOptions(encodings: delta)),
            ColumnDefinition.Leaf("bss-fixed-bytes", ParquetPhysicalType.FixedLenByteArray,
                new ColumnOptions(typeLength: 4, encodings: split)),
            ColumnDefinition.Leaf("bss-fixed-large-decimal", ParquetPhysicalType.FixedLenByteArray,
                new ColumnOptions(typeLength: 300, encodings: split), new LogicalType.Decimal(28, 6)),
            ColumnDefinition.Leaf("delta-width-64", ParquetPhysicalType.Int64,
                new ColumnOptions(encodings: delta))
        ]);

        using var stream = new MemoryStream();
        var writer = schema.CreateWriter(stream, new ParquetWriterOptions { Compression = CompressionKind.None });
        var rowGroup = writer.StartRowGroup();
        var bssUShort = rowGroup.CreateSerializedColumn<ushort>(schema.LeafColumns[0]);
        bssUShort.Serialize(ushortValues);
        rowGroup.Write(bssUShort);
        var bssUInt = rowGroup.CreateSerializedColumn<uint>(schema.LeafColumns[1]);
        bssUInt.Serialize(uintValues);
        rowGroup.Write(bssUInt);
        var bssDecimal32 = rowGroup.CreateSerializedColumn<decimal>(schema.LeafColumns[2]);
        bssDecimal32.Serialize(decimalValues);
        rowGroup.Write(bssDecimal32);
        var bssULong = rowGroup.CreateSerializedColumn<ulong>(schema.LeafColumns[3]);
        bssULong.Serialize(ulongValues);
        rowGroup.Write(bssULong);
        var bssDecimal64 = rowGroup.CreateSerializedColumn<decimal>(schema.LeafColumns[4]);
        bssDecimal64.Serialize(decimalValues);
        rowGroup.Write(bssDecimal64);
        var bssFloat = rowGroup.CreateSerializedColumn<float>(schema.LeafColumns[5]);
        bssFloat.Serialize(floatValues);
        rowGroup.Write(bssFloat);
        var bssDouble = rowGroup.CreateSerializedColumn<double>(schema.LeafColumns[6]);
        bssDouble.Serialize(doubleValues);
        rowGroup.Write(bssDouble);
        var deltaByte = rowGroup.CreateSerializedColumn<byte>(schema.LeafColumns[7]);
        deltaByte.Serialize(byteValues);
        rowGroup.Write(deltaByte);
        var deltaUShort = rowGroup.CreateSerializedColumn<ushort>(schema.LeafColumns[8]);
        deltaUShort.Serialize(ushortValues);
        rowGroup.Write(deltaUShort);
        var deltaUInt = rowGroup.CreateSerializedColumn<uint>(schema.LeafColumns[9]);
        deltaUInt.Serialize(uintValues);
        rowGroup.Write(deltaUInt);
        var deltaDecimal32 = rowGroup.CreateSerializedColumn<decimal>(schema.LeafColumns[10]);
        deltaDecimal32.Serialize(decimalValues);
        rowGroup.Write(deltaDecimal32);
        var deltaULong = rowGroup.CreateSerializedColumn<ulong>(schema.LeafColumns[11]);
        deltaULong.Serialize(ulongValues);
        rowGroup.Write(deltaULong);
        var deltaDecimal64 = rowGroup.CreateSerializedColumn<decimal>(schema.LeafColumns[12]);
        deltaDecimal64.Serialize(decimalValues);
        rowGroup.Write(deltaDecimal64);
        var byteArrayValues = Enumerable.Range(0, count)
            .Select(i => System.Text.Encoding.ASCII.GetBytes($"shared-prefix-{i / 8:D3}-{i:D4}"))
            .ToArray();
        var deltaByteArray = rowGroup.CreateSerializedColumn<byte[]>(schema.LeafColumns[13]);
        deltaByteArray.Serialize(byteArrayValues);
        rowGroup.Write(deltaByteArray);
        for (var bitWidth = 9; bitWidth <= 12; bitWidth++)
        {
            var widthValues = new int[count];
            for (var i = 1; i < widthValues.Length; i++)
                widthValues[i] = checked(widthValues[i - 1] + 1 + ((i & 1) == 0 ? 1 << (bitWidth - 1) : 0));
            var column = rowGroup.CreateSerializedColumn<int>(schema.LeafColumns[14 + bitWidth - 9]);
            column.Serialize(widthValues);
            rowGroup.Write(column);
        }
        var fixedByteValues = Enumerable.Range(0, count)
            .Select(i => new[] { (byte)i, (byte)(i >> 1), (byte)(i >> 2), (byte)(i >> 3) })
            .ToArray();
        var fixedBytes = rowGroup.CreateSerializedColumn<byte[]>(schema.LeafColumns[18]);
        fixedBytes.Serialize(fixedByteValues);
        rowGroup.Write(fixedBytes);
        var largeFixedDecimals = rowGroup.CreateSerializedColumn<decimal>(schema.LeafColumns[19]);
        largeFixedDecimals.Serialize(decimalValues);
        rowGroup.Write(largeFixedDecimals);
        var wideDeltas = rowGroup.CreateSerializedColumn<long>(schema.LeafColumns[20]);
        wideDeltas.Serialize(Enumerable.Range(0, count)
            .Select(static i => (i & 1) == 0 ? 0L : long.MaxValue).ToArray());
        rowGroup.Write(wideDeltas);
        writer.CloseFile();
    }

    static void WriteDeltaInt32GenericDispatchInputs()
    {
        var ints = new[] { -9, 0, 4, 19, 27 };
        var bytes = new byte[] { 1, 2, 7, 11, 255 };
        var ushorts = new ushort[] { 2, 256, 1024, 4096, 65535 };
        var uints = new uint[] { 0, 1, 65536, 1_000_000, uint.MaxValue };
        var decimals = new[] { -1.25m, 0m, 0.01m, 4.56m, 99.99m };
        var delta = ImmutableArray.Create(EncodingKind.DeltaBinaryPacked);
        var schema = new ParquetSchema([
            ColumnDefinition.Leaf("delta-int32-int", ParquetPhysicalType.Int32,
                new ColumnOptions(encodings: delta)),
            ColumnDefinition.Leaf("delta-int32-byte", ParquetPhysicalType.Int32,
                new ColumnOptions(encodings: delta)),
            ColumnDefinition.Leaf("delta-int32-ushort", ParquetPhysicalType.Int32,
                new ColumnOptions(encodings: delta)),
            ColumnDefinition.Leaf("delta-int32-uint", ParquetPhysicalType.Int32,
                new ColumnOptions(encodings: delta)),
            ColumnDefinition.Leaf("delta-int32-decimal", ParquetPhysicalType.Int32,
                new ColumnOptions(encodings: delta), new LogicalType.Decimal(9, 2))
        ]);

        using var stream = new MemoryStream();
        var writer = schema.CreateWriter(stream,
            new ParquetWriterOptions { Compression = CompressionKind.None });
        var rowGroup = writer.StartRowGroup();
        Write(0, ints);
        Write(1, bytes);
        Write(2, ushorts);
        Write(3, uints);
        Write(4, decimals);
        writer.CloseFile();

        using var reader = schema.CreateReader(FullValueOracle.Source(stream.ToArray()));
        AssertReadBack(reader, 0, ints);
        AssertReadBack(reader, 1, bytes);
        AssertReadBack(reader, 2, ushorts);
        AssertReadBack(reader, 3, uints);
        AssertReadBack(reader, 4, decimals);

        void Write<T>(int index, T[] values) where T : notnull
        {
            var column = rowGroup.CreateSerializedColumn<T>(schema.LeafColumns[index]);
            column.Serialize(values);
            rowGroup.Write(column);
        }
    }

    static void ProbeOptionalFixedMemoryPayloads()
    {
        ReadOnlyMemory<byte>?[] fixedValues =
        [
            new byte[] { 0x10, 0x20, 0x30, 0x40 },
            null,
            new byte[] { 0x50, 0x60, 0x70, 0x80 }
        ];
        ReadOnlyMemory<byte>?[] int96Values =
        [
            Enumerable.Range(0, 12).Select(static i => (byte)i).ToArray(),
            null,
            Enumerable.Range(12, 12).Select(static i => (byte)i).ToArray()
        ];
        byte[]?[] expectedFixed = [[0x10, 0x20, 0x30, 0x40], null, [0x50, 0x60, 0x70, 0x80]];
        byte[]?[] expectedInt96 =
        [
            Enumerable.Range(0, 12).Select(static i => (byte)i).ToArray(),
            null,
            Enumerable.Range(12, 12).Select(static i => (byte)i).ToArray()
        ];
        var schema = new ParquetSchema(
        [
            ColumnDefinition.OptionalLeaf("fixed-memory-plain", ParquetPhysicalType.FixedLenByteArray,
                new ColumnOptions(ParquetRepetition.Optional, typeLength: 4,
                    encodings: ImmutableArray.Create(EncodingKind.Plain))),
            ColumnDefinition.OptionalLeaf("int96-memory-plain", ParquetPhysicalType.Int96,
                new ColumnOptions(ParquetRepetition.Optional,
                    encodings: ImmutableArray.Create(EncodingKind.Plain)))
        ]);
        using var stream = new MemoryStream();
        var writer = schema.CreateWriter(stream, new ParquetWriterOptions { Compression = CompressionKind.None });
        var rowGroup = writer.StartRowGroup();
        var fixedColumn = rowGroup.CreateSerializedColumn<ReadOnlyMemory<byte>?>(schema.LeafColumns[0]);
        fixedColumn.Serialize(fixedValues);
        rowGroup.Write(fixedColumn);
        var int96Column = rowGroup.CreateSerializedColumn<ReadOnlyMemory<byte>?>(schema.LeafColumns[1]);
        int96Column.Serialize(int96Values);
        rowGroup.Write(int96Column);
        writer.CloseFile();

        using var reader = schema.CreateReader(FullValueOracle.Source(stream.ToArray()));
        AssertBinaryReadBack(reader, 0, expectedFixed);
        AssertBinaryReadBack(reader, 1, expectedInt96);
    }

    static void ProbeOptionalFixedByteArrayWrongWidth()
    {
        var schema = new ParquetSchema(
        [
            ColumnDefinition.OptionalLeaf("fixed-byte-array-wrong-width", ParquetPhysicalType.FixedLenByteArray,
                new ColumnOptions(ParquetRepetition.Optional, typeLength: 4,
                    encodings: ImmutableArray.Create(EncodingKind.Plain)))
        ]);
        using var stream = new MemoryStream();
        var writer = schema.CreateWriter(stream, new ParquetWriterOptions { Compression = CompressionKind.None });
        var column = writer.CreateSerializedColumn<byte[]>(schema.LeafColumns[0]);
        try
        {
            column.Serialize([[0x01, 0x02, 0x03], null!, [0x04, 0x05, 0x06, 0x07]]);
            writer.StartRowGroup().Write(column);
        }
        catch (InvalidOperationException error) when (
            error.Message.Contains("expects fixed-length values of 4 bytes, but got 3", StringComparison.Ordinal))
        {
            return;
        }

        throw new InvalidOperationException("Optional fixed-length PLAIN accepted a three-byte value for width four.");
    }

    static void ProbeFixedBssInvalidPayloads()
    {
        ExpectFixedBssRejection([null!, [0x01, 0x02, 0x03, 0x04]], "does not support null values");
        ExpectFixedBssRejection([[0x01, 0x02, 0x03], [0x04, 0x05, 0x06, 0x07]],
            "expects fixed-length values of 4 bytes, but got 3");
    }

    static void ExpectFixedBssRejection(byte[][] values, string expectedMessage)
    {
        var schema = new ParquetSchema(
        [
            ColumnDefinition.RequiredLeaf("fixed-bss-invalid", ParquetPhysicalType.FixedLenByteArray,
                new ColumnOptions(typeLength: 4, encodings: ImmutableArray.Create(EncodingKind.ByteStreamSplit)))
        ]);
        using var stream = new MemoryStream();
        var writer = schema.CreateWriter(stream, new ParquetWriterOptions { Compression = CompressionKind.None });
        var column = writer.CreateSerializedColumn<byte[]>(schema.LeafColumns[0]);
        try
        {
            column.Serialize(values);
            writer.StartRowGroup().Write(column);
            writer.CloseFile();
        }
        catch (InvalidOperationException error) when (error.Message.Contains(expectedMessage, StringComparison.Ordinal))
        {
            return;
        }

        throw new InvalidOperationException($"Fixed-width BSS did not reject input containing '{expectedMessage}'.");
    }

    static void WriteOptionalInt32PlainTargetPages()
    {
        int?[] allPresent = [17, -9, int.MaxValue, int.MinValue, 0, 17, 23, -11, 42];
        int?[] withNulls = [null, 17, -9, null, int.MaxValue, int.MinValue, 0, null, 17];
        var schema = new ParquetSchema([
            ColumnDefinition.OptionalLeaf("optional-int32-plain-all-present", ParquetPhysicalType.Int32,
                new ColumnOptions(ParquetRepetition.Optional,
                    encodings: ImmutableArray.Create(EncodingKind.Plain))),
            ColumnDefinition.OptionalLeaf("optional-int32-plain-with-nulls", ParquetPhysicalType.Int32,
                new ColumnOptions(ParquetRepetition.Optional,
                    encodings: ImmutableArray.Create(EncodingKind.Plain)))
        ]);
        using var stream = new MemoryStream();
        var writer = schema.CreateWriter(stream, new ParquetWriterOptions
        {
            Compression = CompressionKind.None,
            TargetDataPageSizeBytes = 300_000_000
        });
        var allPresentColumn = writer.CreateSerializedColumn<int?>(schema.LeafColumns[0]);
        allPresentColumn.Serialize(allPresent);
        var nullColumn = writer.CreateSerializedColumn<int?>(schema.LeafColumns[1]);
        nullColumn.Serialize(withNulls);
        var rowGroup = writer.StartRowGroup();
        rowGroup.Write(allPresentColumn);
        rowGroup.Write(nullColumn);
        writer.CloseFile();

        using var reader = schema.CreateReader(FullValueOracle.Source(stream.ToArray()));
        AssertNullableInt32ReadBack(reader, 0, allPresent);
        AssertNullableInt32ReadBack(reader, 1, withNulls);
    }

    static void WriteOptionalInt32ForcedDictionaryRangeFallback()
    {
        int?[] values =
        [
            null, 0, 511, 512, -1, int.MinValue, int.MaxValue, 512, null, 0, -1
        ];
        var schema = new ParquetSchema([
            ColumnDefinition.OptionalLeaf("optional-int32-forced-dictionary-range", ParquetPhysicalType.Int32,
                new ColumnOptions(ParquetRepetition.Optional,
                    encodings: ImmutableArray.Create(EncodingKind.RleDictionary)),
                pageStrategy: ForceDictionaryPageStrategy.Shared)
        ]);
        using var stream = new MemoryStream();
        var writer = schema.CreateWriter(stream, new ParquetWriterOptions
        {
            Compression = CompressionKind.None,
            WritePageIndexes = false
        });
        var column = writer.CreateSerializedColumn<int?>(schema.LeafColumns[0]);
        column.Serialize(values);
        writer.StartRowGroup().Write(column);
        writer.CloseFile();

        using var reader = schema.CreateReader(FullValueOracle.Source(stream.ToArray()));
        AssertNullableInt32ReadBack(reader, 0, values);
    }

    static void AssertNullableInt32ReadBack(Plank.Reading.Logical.ParquetReader reader, int columnIndex,
        int?[] expected)
    {
        var actual = new List<int?>(expected.Length);
        foreach (var buffer in reader.RowGroups[0].Column<int?>(columnIndex))
            actual.AddRange(buffer.Values);
        if (!actual.SequenceEqual(expected))
            throw new InvalidOperationException("Optional Int32 encoding case changed values or null positions.");
    }

    static void WriteBooleanRunShapesAndByteStreamSplit()
    {
        const int valueCount = 128;
        bool[][] booleanValues =
        [
            Enumerable.Range(0, valueCount).Select(i => (i & 1) != 0).ToArray(),
            Enumerable.Repeat(true, valueCount).ToArray(),
            Enumerable.Range(0, valueCount).Select(i => i is >= 1 and < 9 || i is >= 20 and < 27).ToArray(),
            Enumerable.Range(0, valueCount).Select(i => i < 3 || (i is >= 3 and < 11) || i is >= 20 and < 33).ToArray(),
            Enumerable.Range(0, valueCount).Select(i => i < 7 || (i is >= 7 and < 15) || (i is >= 16 and < 24) || i >= 30).ToArray(),
            Enumerable.Range(0, valueCount).Select(i => (i % 19) < 8).ToArray(),
            // Eight alternating literal values end exactly at a byte boundary before this repeat.
            Enumerable.Range(0, valueCount).Select(i => i < 8 && (i & 1) != 0).ToArray()
        ];
        var int32Values = Enumerable.Range(0, valueCount)
            .Select(i => unchecked(i * 7919 - 1_000_003)).ToArray();
        var int64Values = Enumerable.Range(0, valueCount)
            .Select(i => unchecked((long)i * 0x01020304050607L - 0x0123456789ABCDEFL)).ToArray();

        var definitions = new List<ColumnDefinition>
        {
            ColumnDefinition.Leaf("bss-int32", ParquetPhysicalType.Int32,
                new ColumnOptions(encodings: ImmutableArray.Create(EncodingKind.ByteStreamSplit))),
            ColumnDefinition.Leaf("bss-int64", ParquetPhysicalType.Int64,
                new ColumnOptions(encodings: ImmutableArray.Create(EncodingKind.ByteStreamSplit)))
        };
        for (var i = 0; i < booleanValues.Length; i++)
            definitions.Add(ColumnDefinition.Leaf($"rle-bool-{i}", ParquetPhysicalType.Boolean,
                new ColumnOptions(encodings: ImmutableArray.Create(EncodingKind.Rle))));

        var schema = new ParquetSchema([.. definitions]);
        using var stream = new MemoryStream();
        var writer = schema.CreateWriter(stream, new ParquetWriterOptions { Compression = CompressionKind.None });
        var rowGroup = writer.StartRowGroup();

        var int32Column = rowGroup.CreateSerializedColumn<int>(schema.LeafColumns[0]);
        int32Column.Serialize(int32Values);
        rowGroup.Write(int32Column);

        var int64Column = rowGroup.CreateSerializedColumn<long>(schema.LeafColumns[1]);
        int64Column.Serialize(int64Values);
        rowGroup.Write(int64Column);

        for (var i = 0; i < booleanValues.Length; i++)
        {
            var column = rowGroup.CreateSerializedColumn<bool>(schema.LeafColumns[i + 2]);
            column.Serialize(booleanValues[i]);
            rowGroup.Write(column);
        }
        writer.CloseFile();

        using var reader = schema.CreateReader(FullValueOracle.Source(stream.ToArray()));
        if (reader.RowGroups.Count != 1 || reader.RowGroups[0].RowCount != valueCount)
            throw new InvalidOperationException("RLE boolean/BSS case changed the row-group shape.");
        AssertReadBack(reader, 0, int32Values);
        AssertReadBack(reader, 1, int64Values);
        for (var i = 0; i < booleanValues.Length; i++)
            AssertReadBack(reader, i + 2, booleanValues[i]);
    }

    static void WriteOptionalSingleByteMemoryPayloadsWithNullRuns()
    {
        ReadOnlyMemory<byte>?[] values =
        [
            null,
            new byte[] { 0x11 },
            null,
            new byte[] { 0xA5 },
            null,
            new byte[] { 0x5C }
        ];
        byte[]?[] expected = [null, [0x11], null, [0xA5], null, [0x5C]];
        var schema = new ParquetSchema([
            ColumnDefinition.OptionalLeaf("optional-single-byte-memory-null-runs", ParquetPhysicalType.ByteArray,
                new ColumnOptions(ParquetRepetition.Optional,
                    encodings: ImmutableArray.Create(EncodingKind.Plain)))
        ]);
        using var stream = new MemoryStream();
        var writer = schema.CreateWriter(stream, new ParquetWriterOptions { Compression = CompressionKind.None });
        var column = writer.CreateSerializedColumn<ReadOnlyMemory<byte>?>(schema.LeafColumns[0]);
        column.Serialize(values);
        writer.StartRowGroup().Write(column);
        writer.CloseFile();

        using var source = FullValueOracle.Source(stream.ToArray());
        using var reader = schema.CreateReader(source);
        if (reader.RowGroups.Count != 1 || reader.RowGroups[0].RowCount != (ulong)values.Length)
            throw new InvalidOperationException("Optional single-byte memory null-run case changed the row-group shape.");
        AssertBinaryReadBack(reader, 0, expected);
    }

    static void WriteRequiredInt32DictionaryDropCheckpoint()
    {
        const int uniqueCount = 16_384;
        var values = new int[uniqueCount * 2];
        for (var i = 0; i < values.Length; i++)
            values[i] = i % uniqueCount;

        var schema = new ParquetSchema([
            ColumnDefinition.Leaf("dictionary-drop-checkpoint", ParquetPhysicalType.Int32,
                new ColumnOptions(encodings: ImmutableArray.Create(EncodingKind.RleDictionary)))
        ]);
        using var stream = new MemoryStream();
        var writer = schema.CreateWriter(stream, new ParquetWriterOptions
        {
            Compression = CompressionKind.None,
            WritePageIndexes = true
        });
        var serialized = writer.CreateSerializedColumn<int>(schema.LeafColumns[0]);
        serialized.Serialize(values);
        writer.StartRowGroup().Write(serialized);
        writer.CloseFile();

        using var source = FullValueOracle.Source(stream.ToArray());
        using var reader = schema.CreateReader(source);
        if (reader.RowGroups.Count != 1 || reader.RowGroups[0].RowCount != (ulong)values.Length)
            throw new InvalidOperationException("Dictionary drop-checkpoint case changed the row-group shape.");

        var offset = 0;
        foreach (var buffer in reader.RowGroups[0].Column<int>(schema.LeafColumns[0]))
            foreach (var value in buffer.Values)
            {
                if (offset >= values.Length || value != values[offset])
                    throw new InvalidOperationException($"Dictionary drop-checkpoint case changed value {offset}.");
                offset++;
            }
        if (offset != values.Length)
            throw new InvalidOperationException("Dictionary drop-checkpoint case changed the value count.");
    }

    static void WriteInt96PlainPayloads()
    {
        var values = new byte[3][];
        for (var row = 0; row < values.Length; row++)
        {
            values[row] = new byte[12];
            for (var index = 0; index < values[row].Length; index++)
                values[row][index] = (byte)(row * 29 + index * 17);
        }

        var schema = new ParquetSchema([
            ColumnDefinition.RequiredLeaf("plain-int96", ParquetPhysicalType.Int96,
                new ColumnOptions(encodings: ImmutableArray.Create(EncodingKind.Plain)))
        ]);
        using var stream = new MemoryStream();
        var writer = schema.CreateWriter(stream, new ParquetWriterOptions { Compression = CompressionKind.None });
        var rowGroup = writer.StartRowGroup();
        var column = rowGroup.CreateSerializedColumn<byte[]>(schema.LeafColumns[0]);
        column.Serialize(values);
        rowGroup.Write(column);
        writer.CloseFile();

        using var source = FullValueOracle.Source(stream.ToArray());
        using var reader = schema.CreateReader(source);
        if (reader.RowGroups.Count != 1 || reader.RowGroups[0].RowCount != (ulong)values.Length)
            throw new InvalidOperationException("INT96 PLAIN case changed the row-group shape.");
        AssertBinaryReadBack(reader, 0, values);
    }

    static void WriteOptionalFixedBinaryPlainPayloads(bool useRowCountStrategy)
    {
        byte[][] fixedValues = [[0x01, 0x02, 0x03, 0x04], null!, [0x11, 0x12, 0x13, 0x14]];
        byte[][] int96Values = [null!, Enumerable.Range(0, 12).Select(static value => (byte)value).ToArray(),
            Enumerable.Range(12, 12).Select(static value => (byte)value).ToArray()];
        byte[][] byteArrayValues = [null!, [], [0x21, 0x22]];
        IPageStrategy? pageStrategy = useRowCountStrategy ? SinglePageNoTargetStrategy.Shared : null;
        var schema = new ParquetSchema([
            ColumnDefinition.OptionalLeaf("optional-fixed-plain", ParquetPhysicalType.FixedLenByteArray,
                new ColumnOptions(ParquetRepetition.Optional, typeLength: 4,
                    encodings: ImmutableArray.Create(EncodingKind.Plain)), pageStrategy: pageStrategy),
            ColumnDefinition.OptionalLeaf("optional-int96-plain", ParquetPhysicalType.Int96,
                new ColumnOptions(ParquetRepetition.Optional,
                    encodings: ImmutableArray.Create(EncodingKind.Plain)), pageStrategy: pageStrategy),
            ColumnDefinition.OptionalLeaf("optional-byte-array-plain", ParquetPhysicalType.ByteArray,
                new ColumnOptions(ParquetRepetition.Optional,
                    encodings: ImmutableArray.Create(EncodingKind.Plain)), pageStrategy: pageStrategy)
        ]);
        using var stream = new MemoryStream();
        var writer = schema.CreateWriter(stream, new ParquetWriterOptions { Compression = CompressionKind.None });
        var rowGroup = writer.StartRowGroup();
        var fixedColumn = rowGroup.CreateSerializedColumn<byte[]>(schema.LeafColumns[0]);
        fixedColumn.Serialize(fixedValues);
        rowGroup.Write(fixedColumn);
        var int96Column = rowGroup.CreateSerializedColumn<byte[]>(schema.LeafColumns[1]);
        int96Column.Serialize(int96Values);
        rowGroup.Write(int96Column);
        var byteArrayColumn = rowGroup.CreateSerializedColumn<byte[]>(schema.LeafColumns[2]);
        byteArrayColumn.Serialize(byteArrayValues);
        rowGroup.Write(byteArrayColumn);
        writer.CloseFile();

        using var reader = schema.CreateReader(FullValueOracle.Source(stream.ToArray()));
        AssertBinaryReadBack(reader, 0, fixedValues);
        AssertBinaryReadBack(reader, 1, int96Values);
        AssertBinaryReadBack(reader, 2, byteArrayValues);
    }

    sealed class SinglePageNoTargetStrategy : IPageStrategy
    {
        internal static readonly SinglePageNoTargetStrategy Shared = new();

        public DictionaryMode GetDictionaryMode() => DictionaryMode.Disabled;

        public bool ShouldDropDictionary(uint uniqueCount, uint totalRowCount, uint rowsSeen) => false;

        public uint GetNextDataPageRowCount(uint totalRowCount, uint rowsWritten)
            => totalRowCount - rowsWritten;
    }

    static void WriteOptionalByteArrayTargetPages()
    {
        byte[]?[] arrays = [null, null, null, null, null, null, [0x11], [0x22], [0x33], [0x44, 0x55]];
        ReadOnlyMemory<byte>?[] memories =
        [
            null, null, null, null, null, null,
            new byte[] { 0x11 }, new byte[] { 0x22 }, new byte[] { 0x33 }, new byte[] { 0x44, 0x55 }
        ];
        byte[]?[] expected = [null, null, null, null, null, null, [0x11], [0x22], [0x33], [0x44, 0x55]];
        var plain = ImmutableArray.Create(EncodingKind.Plain);
        byte[]?[] dictionaryValues = [null, null, null, null, null, null, [0x10], [0x20], [0x10], [0x30]];
        var dictionaryExpected = dictionaryValues;
        var schema = new ParquetSchema([
            ColumnDefinition.OptionalLeaf("target-byte-array", ParquetPhysicalType.ByteArray,
                new ColumnOptions(ParquetRepetition.Optional, encodings: plain)),
            ColumnDefinition.OptionalLeaf("target-memory", ParquetPhysicalType.ByteArray,
                new ColumnOptions(ParquetRepetition.Optional, encodings: plain)),
            ColumnDefinition.OptionalLeaf("dictionary-byte-array", ParquetPhysicalType.ByteArray,
                new ColumnOptions(ParquetRepetition.Optional,
                    encodings: ImmutableArray.Create(EncodingKind.RleDictionary, EncodingKind.Plain)),
                pageStrategy: ForceDictionaryPageStrategy.Shared)
        ]);
        using var stream = new MemoryStream();
        var writer = schema.CreateWriter(stream, new ParquetWriterOptions
        {
            Compression = CompressionKind.None,
            TargetDataPageSizeBytes = 6
        });
        var rowGroup = writer.StartRowGroup();
        var arrayColumn = rowGroup.CreateSerializedColumn<byte[]>(schema.LeafColumns[0]);
        arrayColumn.Serialize(arrays);
        rowGroup.Write(arrayColumn);
        WriteOptionalMemoryColumn(rowGroup, schema, 1, memories);
        var dictionaryColumn = rowGroup.CreateSerializedColumn<byte[]>(schema.LeafColumns[2]);
        dictionaryColumn.Serialize(dictionaryValues);
        rowGroup.Write(dictionaryColumn);
        writer.CloseFile();

        using var reader = schema.CreateReader(FullValueOracle.Source(stream.ToArray()));
        if (reader.RowGroups.Count != 1 || reader.RowGroups[0].RowCount != (ulong)expected.Length)
            throw new InvalidOperationException("Optional byte-array target-page case changed the row-group shape.");
        AssertBinaryReadBack(reader, 0, expected);
        AssertBinaryReadBack(reader, 1, expected);
        AssertBinaryReadBack(reader, 2, dictionaryExpected);
    }

    static void WriteSerializedColumnOptionalBranches()
    {
        const int count = 10;
        var plain = ImmutableArray.Create(EncodingKind.Plain);
        var dictionary = ImmutableArray.Create(EncodingKind.RleDictionary, EncodingKind.Plain);
        var delta = ImmutableArray.Create(EncodingKind.DeltaBinaryPacked);
        var schema = new ParquetSchema([
            ColumnDefinition.OptionalLeaf("optional-plain-int32", ParquetPhysicalType.Int32,
                new ColumnOptions(ParquetRepetition.Optional, encodings: plain)),
            ColumnDefinition.OptionalLeaf("optional-dictionary-int32", ParquetPhysicalType.Int32,
                new ColumnOptions(ParquetRepetition.Optional, encodings: dictionary),
                pageStrategy: ForceDictionaryPageStrategy.Shared),
            ColumnDefinition.OptionalLeaf("optional-delta-int64", ParquetPhysicalType.Int64,
                new ColumnOptions(ParquetRepetition.Optional, encodings: delta)),
            ColumnDefinition.OptionalLeaf("optional-dictionary-int64", ParquetPhysicalType.Int64,
                new ColumnOptions(ParquetRepetition.Optional, encodings: dictionary),
                pageStrategy: ForceDictionaryPageStrategy.Shared),
            ColumnDefinition.OptionalLeaf("optional-dictionary-double", ParquetPhysicalType.Double,
                new ColumnOptions(ParquetRepetition.Optional, encodings: dictionary),
                pageStrategy: ForceDictionaryPageStrategy.Shared),
            ColumnDefinition.OptionalLeaf("all-null-memory", ParquetPhysicalType.ByteArray,
                new ColumnOptions(ParquetRepetition.Optional, encodings: plain)),
            ColumnDefinition.OptionalLeaf("decimal-memory", ParquetPhysicalType.ByteArray,
                new ColumnOptions(ParquetRepetition.Optional, encodings: plain), new LogicalType.Decimal(9, 0)),
            ColumnDefinition.OptionalLeaf("dictionary-memory-no-minmax", ParquetPhysicalType.ByteArray,
                new ColumnOptions(ParquetRepetition.Optional, encodings: dictionary),
                pageStrategy: ForceDictionaryPageStrategy.Shared),
            ColumnDefinition.OptionalLeaf("decimal-byte-array", ParquetPhysicalType.ByteArray,
                new ColumnOptions(ParquetRepetition.Optional, encodings: plain), new LogicalType.Decimal(9, 0)),
            ColumnDefinition.OptionalLeaf("all-null-byte-array", ParquetPhysicalType.ByteArray,
                new ColumnOptions(ParquetRepetition.Optional, encodings: plain)),
            ColumnDefinition.OptionalLeaf("dictionary-byte-array-no-minmax", ParquetPhysicalType.ByteArray,
                new ColumnOptions(ParquetRepetition.Optional, encodings: dictionary),
                pageStrategy: ForceDictionaryPageStrategy.Shared)
        ]);
        using var stream = new MemoryStream();
        var writer = schema.CreateWriter(stream, new ParquetWriterOptions
        {
            Compression = CompressionKind.None,
            TargetDataPageSizeBytes = 6,
            WritePageIndexes = false
        });
        var rowGroup = writer.StartRowGroup();

        var plainInts = Enumerable.Range(0, count).Select(static i => (int?)(i % 3 == 0 ? null : i * 7)).ToArray();
        var plainIntColumn = rowGroup.CreateSerializedColumn<int?>(schema.LeafColumns[0]);
        plainIntColumn.Serialize(plainInts);
        try
        {
            plainIntColumn.Serialize(plainInts);
            throw new InvalidOperationException("Optional typed SerializedColumn accepted duplicate pending serialization.");
        }
        catch (InvalidOperationException exception) when (exception.Message.Contains("already contains pending data"))
        {
        }
        rowGroup.Write(plainIntColumn);

        var intDictionaryColumn = rowGroup.CreateSerializedColumn<int?>(schema.LeafColumns[1]);
        intDictionaryColumn.Serialize(Enumerable.Range(0, count).Select(static i => (int?)(i % 3)).ToArray());
        rowGroup.Write(intDictionaryColumn);

        var deltaLongColumn = rowGroup.CreateSerializedColumn<long?>(schema.LeafColumns[2]);
        deltaLongColumn.Serialize(Enumerable.Range(0, count).Select(static i => (long?)(i * 17 - 20)).ToArray());
        rowGroup.Write(deltaLongColumn);

        var longDictionaryColumn = rowGroup.CreateSerializedColumn<long?>(schema.LeafColumns[3]);
        longDictionaryColumn.Serialize(Enumerable.Range(0, count).Select(static i => (long?)(i % 4)).ToArray());
        rowGroup.Write(longDictionaryColumn);

        var doubleDictionaryColumn = rowGroup.CreateSerializedColumn<double?>(schema.LeafColumns[4]);
        doubleDictionaryColumn.Serialize(Enumerable.Range(0, count).Select(static i => (double?)(i % 3)).ToArray());
        rowGroup.Write(doubleDictionaryColumn);

        var memoryColumn = rowGroup.CreateSerializedColumn<ReadOnlyMemory<byte>?>(schema.LeafColumns[5]);
        ReadOnlyMemory<byte>?[] allNullMemory = new ReadOnlyMemory<byte>?[count];
        memoryColumn.Serialize(allNullMemory);
        rowGroup.Write(memoryColumn);

        var decimalMemoryColumn = rowGroup.CreateSerializedColumn<ReadOnlyMemory<byte>?>(schema.LeafColumns[6]);
        ReadOnlyMemory<byte>?[] decimalMemory = Enumerable.Range(0, count)
            .Select(static i => (ReadOnlyMemory<byte>?)new byte[] { 0, (byte)(i + 1) }).ToArray();
        decimalMemoryColumn.Serialize(decimalMemory);
        rowGroup.Write(decimalMemoryColumn);

        var dictionaryMemoryColumn = rowGroup.CreateSerializedColumn<ReadOnlyMemory<byte>?>(schema.LeafColumns[7]);
        ReadOnlyMemory<byte>?[] dictionaryMemory = Enumerable.Range(0, count)
            .Select(static i => (ReadOnlyMemory<byte>?)new byte[] { (byte)(i % 3) }).ToArray();
        dictionaryMemoryColumn.Serialize(dictionaryMemory);
        rowGroup.Write(dictionaryMemoryColumn);

        var decimalByteArrayColumn = rowGroup.CreateSerializedColumn<byte[]?>(schema.LeafColumns[8]);
        byte[]?[] decimalByteArrays = Enumerable.Range(0, count)
            .Select(static i => new byte[] { 0, (byte)(i + 1) }).ToArray();
        decimalByteArrayColumn.Serialize(decimalByteArrays);
        try
        {
            decimalByteArrayColumn.Serialize(decimalByteArrays);
            throw new InvalidOperationException("Optional reference SerializedColumn accepted duplicate pending serialization.");
        }
        catch (InvalidOperationException exception) when (exception.Message.Contains("already contains pending data"))
        {
        }
        rowGroup.Write(decimalByteArrayColumn);

        var allNullByteArrayColumn = rowGroup.CreateSerializedColumn<byte[]?>(schema.LeafColumns[9]);
        allNullByteArrayColumn.Serialize(new byte[]?[count]);
        rowGroup.Write(allNullByteArrayColumn);

        var dictionaryByteArrayColumn = rowGroup.CreateSerializedColumn<byte[]?>(schema.LeafColumns[10]);
        byte[]?[] dictionaryByteArrays = Enumerable.Range(0, count)
            .Select(static i => new byte[] { (byte)(i % 3) }).ToArray();
        dictionaryByteArrayColumn.Serialize(dictionaryByteArrays);
        rowGroup.Write(dictionaryByteArrayColumn);
        writer.CloseFile();

        using var reader = schema.CreateReader(FullValueOracle.Source(stream.ToArray()));
        if (reader.RowGroups.Count != 1 || reader.RowGroups[0].RowCount != (ulong)count)
            throw new InvalidOperationException("SerializedColumn optional branch case changed the row-group shape.");
    }

    static void WriteEmptyRequiredReadOnlyMemory()
    {
        var schema = new ParquetSchema([
            ColumnDefinition.RequiredLeaf("empty-required-memory", ParquetPhysicalType.ByteArray,
                new ColumnOptions(encodings: ImmutableArray.Create(EncodingKind.Plain)))
        ]);
        using var stream = new MemoryStream();
        var writer = schema.CreateWriter(stream, new ParquetWriterOptions { Compression = CompressionKind.None });
        var rowGroup = writer.StartRowGroup();
        var column = rowGroup.CreateSerializedColumn<ReadOnlyMemory<byte>>(schema.LeafColumns[0]);
        column.Serialize(Array.Empty<ReadOnlyMemory<byte>>());
        rowGroup.Write(column);
        writer.CloseFile();

        using var reader = schema.CreateReader(FullValueOracle.Source(stream.ToArray()));
        if (reader.RowGroups.Count != 1 || reader.RowGroups[0].RowCount != 0)
            throw new InvalidOperationException("Empty required-memory case changed the row-group shape.");
    }

    static void WriteOptionalPlainInt64ValidationAndEmptyCases()
    {
        var plain = new ColumnOptions(encodings: ImmutableArray.Create(EncodingKind.Plain));

        var requiredSchema = new ParquetSchema([
            ColumnDefinition.RequiredLeaf("required-int64", ParquetPhysicalType.Int64, plain)
        ]);
        using (var stream = new MemoryStream())
        using (var writer = requiredSchema.CreateWriter(stream))
        {
            var rowGroup = writer.StartRowGroup();
            var column = rowGroup.CreateSerializedColumn<long?>(requiredSchema.LeafColumns[0]);
            try
            {
                column.Serialize([1L]);
                throw new InvalidOperationException("Optional Int64 carrier unexpectedly accepted by required column.");
            }
            catch (InvalidOperationException exception) when (
                exception.Message.Contains("must be an optional INT64 column"))
            {
            }
        }

        var nestedSchema = new ParquetSchema([
            ColumnDefinition.OptionalGroup("nested-int64", ColumnDefinition.OptionalLeaf("element",
                ParquetPhysicalType.Int64, plain))
        ]);
        using (var stream = new MemoryStream())
        using (var writer = nestedSchema.CreateWriter(stream))
        {
            var rowGroup = writer.StartRowGroup();
            var column = rowGroup.CreateSerializedColumn<long?>(nestedSchema.LeafColumns[0]);
            try
            {
                column.Serialize([1L]);
                throw new InvalidOperationException("Flat optional Int64 carrier unexpectedly accepted for nested leaf.");
            }
            catch (NotSupportedException exception) when (
                exception.Message.Contains("requires a single optional leaf"))
            {
            }
        }

        var optionalSchema = new ParquetSchema([
            ColumnDefinition.OptionalLeaf("optional-int64", ParquetPhysicalType.Int64, plain)
        ]);
        using var output = new MemoryStream();
        var optionalWriter = optionalSchema.CreateWriter(output, new ParquetWriterOptions
        {
            Compression = CompressionKind.None,
            TargetDataPageSizeBytes = 64
        });
        var optionalRowGroup = optionalWriter.StartRowGroup();
        var optionalColumn = optionalRowGroup.CreateSerializedColumn<long?>(optionalSchema.LeafColumns[0]);
        optionalColumn.Serialize(Array.Empty<long?>());
        optionalRowGroup.Write(optionalColumn);
        optionalWriter.CloseFile();

        using var reader = optionalSchema.CreateReader(FullValueOracle.Source(output.ToArray()));
        if (reader.RowGroups.Count != 1 || reader.RowGroups[0].RowCount != 0)
            throw new InvalidOperationException("Empty optional Int64 case changed the row-group shape.");
    }

    static void WriteOptionalDeltaInt64ValidationAndPublicControl()
    {
        var delta = new ColumnOptions(encodings: ImmutableArray.Create(EncodingKind.DeltaBinaryPacked));

        var requiredSchema = new ParquetSchema([
            ColumnDefinition.RequiredLeaf("required-delta-int64", ParquetPhysicalType.Int64, delta)
        ]);
        using (var stream = new MemoryStream())
        using (var writer = requiredSchema.CreateWriter(stream))
        {
            var rowGroup = writer.StartRowGroup();
            var column = rowGroup.CreateSerializedColumn<long?>(requiredSchema.LeafColumns[0]);
            try
            {
                column.Serialize([1L]);
                throw new InvalidOperationException("Optional Delta Int64 carrier unexpectedly accepted by required column.");
            }
            catch (InvalidOperationException exception) when (
                exception.Message.Contains("is not an optional INT64 column"))
            {
            }
        }

        var nestedSchema = new ParquetSchema([
            ColumnDefinition.OptionalGroup("nested-delta-int64", ColumnDefinition.OptionalLeaf("element",
                ParquetPhysicalType.Int64, delta))
        ]);
        using (var stream = new MemoryStream())
        using (var writer = nestedSchema.CreateWriter(stream))
        {
            var rowGroup = writer.StartRowGroup();
            var column = rowGroup.CreateSerializedColumn<long?>(nestedSchema.LeafColumns[0]);
            try
            {
                column.Serialize([1L]);
                throw new InvalidOperationException("Flat optional Delta Int64 carrier unexpectedly accepted for nested leaf.");
            }
            catch (NotSupportedException exception) when (
                exception.Message.Contains("requires a single optional leaf"))
            {
            }
        }

        var optionalSchema = new ParquetSchema([
            ColumnDefinition.OptionalLeaf("optional-delta-int64", ParquetPhysicalType.Int64, delta)
        ]);
        using var output = new MemoryStream();
        var optionalWriter = optionalSchema.CreateWriter(output, new ParquetWriterOptions
        {
            Compression = CompressionKind.None,
            TargetDataPageSizeBytes = 64
        });
        var optionalRowGroup = optionalWriter.StartRowGroup();
        var optionalColumn = optionalRowGroup.CreateSerializedColumn<long?>(optionalSchema.LeafColumns[0]);
        long?[] values = [1, null, 4, -2];
        optionalColumn.Serialize(values);
        optionalRowGroup.Write(optionalColumn);
        optionalWriter.CloseFile();

        using var reader = optionalSchema.CreateReader(FullValueOracle.Source(output.ToArray()));
        if (reader.RowGroups.Count != 1 || reader.RowGroups[0].RowCount != (ulong)values.Length)
            throw new InvalidOperationException("Optional Delta INT64 control changed the row-group shape.");
    }

    static void WriteOptionalMemoryTargetPageDecisionPaths()
    {
        var schema = new ParquetSchema([
            ColumnDefinition.OptionalLeaf("descending-plain-memory", ParquetPhysicalType.ByteArray,
                new ColumnOptions(ParquetRepetition.Optional, encodings: ImmutableArray.Create(EncodingKind.Plain))),
            ColumnDefinition.OptionalLeaf("dictionary-memory-page-budget", ParquetPhysicalType.ByteArray,
                new ColumnOptions(ParquetRepetition.Optional,
                    encodings: ImmutableArray.Create(EncodingKind.RleDictionary, EncodingKind.Plain)))
        ]);
        ReadOnlyMemory<byte>?[] descending =
        [
            new byte[] { 0x90 }, null,
            new byte[] { 0x80 }, new byte[] { 0x70 }, new byte[] { 0x60 }, new byte[] { 0x50 },
            new byte[] { 0x40 }, new byte[] { 0x30 }, new byte[] { 0x20 }, new byte[] { 0x10 }
        ];
        ReadOnlyMemory<byte>?[] dictionaryValues =
        [
            new byte[] { 0x01 }, new byte[] { 0x02 }, new byte[] { 0x01 }, null,
            new byte[] { 0x02 }, new byte[] { 0x03 }, new byte[] { 0x01 }, new byte[] { 0x03 },
            new byte[] { 0x02 }, new byte[] { 0x01 }
        ];
        using var stream = new MemoryStream();
        var writer = schema.CreateWriter(stream, new ParquetWriterOptions
        {
            Compression = CompressionKind.None,
            TargetDataPageSizeBytes = 6
        });
        var rowGroup = writer.StartRowGroup();
        var plainColumn = rowGroup.CreateSerializedColumn<ReadOnlyMemory<byte>?>(schema.LeafColumns[0]);
        plainColumn.Serialize(descending);
        rowGroup.Write(plainColumn);
        var dictionaryColumn = rowGroup.CreateSerializedColumn<ReadOnlyMemory<byte>?>(schema.LeafColumns[1]);
        dictionaryColumn.Serialize(dictionaryValues);
        rowGroup.Write(dictionaryColumn);
        writer.CloseFile();

        using var reader = schema.CreateReader(FullValueOracle.Source(stream.ToArray()));
        if (reader.RowGroups.Count != 1 || reader.RowGroups[0].RowCount != (ulong)descending.Length)
            throw new InvalidOperationException("Optional memory page-budget case changed the row-group shape.");
    }

    static void WriteRequiredDeltaByteArrayPrecomputedPages()
    {
        var delta = ImmutableArray.Create(EncodingKind.DeltaByteArray);
        byte[][] values =
        [
            "shared-prefix/alpha"u8.ToArray(), "shared-prefix/alpine"u8.ToArray(),
            "shared-prefix/azure"u8.ToArray(), "shared-prefix/azure"u8.ToArray()
        ];

        var sizedSchema = new ParquetSchema([
            ColumnDefinition.RequiredLeaf("sized-delta-byte-array", ParquetPhysicalType.ByteArray,
                new ColumnOptions(encodings: delta))
        ]);
        using var sizedStream = new MemoryStream();
        var sizedWriter = sizedSchema.CreateWriter(sizedStream, new ParquetWriterOptions
        {
            Compression = CompressionKind.None,
            TargetDataPageSizeBytes = 128
        });
        var sizedRowGroup = sizedWriter.StartRowGroup();
        var sizedColumn = sizedRowGroup.CreateSerializedColumn<byte[]>(sizedSchema.LeafColumns[0]);
        sizedColumn.Serialize(values);
        sizedRowGroup.Write(sizedColumn);
        sizedWriter.CloseFile();
        using (var reader = sizedSchema.CreateReader(FullValueOracle.Source(sizedStream.ToArray())))
            AssertBinaryReadBack(reader, 0, values);

        var strategySchema = new ParquetSchema([
            ColumnDefinition.RequiredLeaf("rowcount-delta-byte-array", ParquetPhysicalType.ByteArray,
                new ColumnOptions(encodings: delta), pageStrategy: SinglePageNoTargetStrategy.Shared)
        ]);
        using var strategyStream = new MemoryStream();
        var strategyWriter = strategySchema.CreateWriter(strategyStream,
            new ParquetWriterOptions { Compression = CompressionKind.None });
        var strategyRowGroup = strategyWriter.StartRowGroup();
        var strategyColumn = strategyRowGroup.CreateSerializedColumn<byte[]>(strategySchema.LeafColumns[0]);
        strategyColumn.Serialize(values);
        strategyRowGroup.Write(strategyColumn);
        strategyWriter.CloseFile();
        using var strategyReader = strategySchema.CreateReader(FullValueOracle.Source(strategyStream.ToArray()));
        AssertBinaryReadBack(strategyReader, 0, values);
    }

    static void WriteOptionalDateTimePredicateMatrix()
    {
        var plain = new ColumnOptions(encodings: ImmutableArray.Create(EncodingKind.Plain));
        var timestamp = new LogicalType.Timestamp(TimeUnit.Micros, IsAdjustedToUtc: false);
        DateTime?[] values =
        [
            new DateTime(1960, 1, 2, 3, 4, 5, DateTimeKind.Unspecified),
            null,
            new DateTime(2026, 7, 8, 9, 10, 11, DateTimeKind.Unspecified)
        ];

        var requiredSchema = new ParquetSchema([
            ColumnDefinition.RequiredLeaf("required-timestamp", ParquetPhysicalType.Int64, plain, timestamp)
        ]);
        using (var stream = new MemoryStream())
        using (var writer = requiredSchema.CreateWriter(stream))
        {
            var rowGroup = writer.StartRowGroup();
            var column = rowGroup.CreateSerializedColumn<DateTime?>(requiredSchema.LeafColumns[0]);
            try
            {
                column.Serialize(values);
                throw new InvalidOperationException("Nullable DateTime unexpectedly accepted by required timestamp.");
            }
            catch (InvalidOperationException exception) when (
                exception.Message.Contains("does not support null values"))
            {
            }
        }

        var nestedSchema = new ParquetSchema([
            ColumnDefinition.OptionalGroup("timestamp-group",
                ColumnDefinition.OptionalLeaf("timestamp", ParquetPhysicalType.Int64, plain, timestamp))
        ]);
        using (var stream = new MemoryStream())
        using (var writer = nestedSchema.CreateWriter(stream))
        {
            var rowGroup = writer.StartRowGroup();
            var column = rowGroup.CreateSerializedColumn<DateTime?>(nestedSchema.LeafColumns[0]);
            try
            {
                column.Serialize(values);
                throw new InvalidOperationException("Flat nullable DateTime unexpectedly accepted for nested timestamp.");
            }
            catch (NotSupportedException exception) when (
                exception.Message.Contains("requires a single optional leaf"))
            {
            }
        }

        var deltaSchema = new ParquetSchema([
            ColumnDefinition.OptionalLeaf("delta-timestamp", ParquetPhysicalType.Int64,
                new ColumnOptions(ParquetRepetition.Optional,
                    encodings: ImmutableArray.Create(EncodingKind.DeltaBinaryPacked)), timestamp)
        ]);
        WriteDateTimeColumn(deltaSchema, values);

        var rowCountSchema = new ParquetSchema([
            ColumnDefinition.OptionalLeaf("rowcount-timestamp", ParquetPhysicalType.Int64, plain, timestamp,
                pageStrategy: SinglePageNoTargetStrategy.Shared)
        ]);
        WriteDateTimeColumn(rowCountSchema, values);

        var dictionarySchema = new ParquetSchema([
            ColumnDefinition.OptionalLeaf("dictionary-timestamp", ParquetPhysicalType.Int64,
                new ColumnOptions(ParquetRepetition.Optional,
                    encodings: ImmutableArray.Create(EncodingKind.RleDictionary, EncodingKind.Plain)), timestamp)
        ]);
        WriteDateTimeColumn(dictionarySchema, values);

        var plainSchema = new ParquetSchema([
            ColumnDefinition.OptionalLeaf("plain-timestamp", ParquetPhysicalType.Int64, plain, timestamp)
        ]);
        WriteDateTimeColumn(plainSchema, values);
    }

    static void WriteDateTimeColumn(ParquetSchema schema, DateTime?[] values)
    {
        using var stream = new MemoryStream();
        var writer = schema.CreateWriter(stream, new ParquetWriterOptions
        {
            Compression = CompressionKind.None,
            TargetDataPageSizeBytes = 64
        });
        var rowGroup = writer.StartRowGroup();
        var column = rowGroup.CreateSerializedColumn<DateTime?>(schema.LeafColumns[0]);
        column.Serialize(values);
        rowGroup.Write(column);
        writer.CloseFile();
        using var reader = schema.CreateReader(FullValueOracle.Source(stream.ToArray()));
        if (reader.RowGroups.Count != 1 || reader.RowGroups[0].RowCount != (ulong)values.Length)
            throw new InvalidOperationException("Optional DateTime predicate case changed the row-group shape.");
    }

    static void WriteByteArrayCountPresentMatrix()
    {
        var delta = ImmutableArray.Create(EncodingKind.DeltaByteArray);
        var schema = new ParquetSchema([
            ColumnDefinition.RequiredLeaf("required-delta-bytes", ParquetPhysicalType.ByteArray,
                new ColumnOptions(encodings: delta)),
            ColumnDefinition.OptionalLeaf("optional-delta-byte-arrays", ParquetPhysicalType.ByteArray,
                new ColumnOptions(ParquetRepetition.Optional, encodings: delta)),
            ColumnDefinition.OptionalLeaf("optional-delta-memory", ParquetPhysicalType.ByteArray,
                new ColumnOptions(ParquetRepetition.Optional, encodings: delta)),
            ColumnDefinition.OptionalLeaf("optional-fixed-byte-arrays", ParquetPhysicalType.FixedLenByteArray,
                new ColumnOptions(ParquetRepetition.Optional, typeLength: 2,
                    encodings: ImmutableArray.Create(EncodingKind.Plain)))
        ]);
        byte[][] required = ["alpha"u8.ToArray(), "alpine"u8.ToArray(), "beta"u8.ToArray()];
        byte[]?[] optional = ["alpha"u8.ToArray(), null, "alpine"u8.ToArray()];
        ReadOnlyMemory<byte>?[] memory = [new byte[] { 0x10 }, null, new byte[] { 0x20 }];
        byte[]?[] fixedValues = [[0x01, 0x02], null, [0x03, 0x04]];

        using var stream = new MemoryStream();
        var writer = schema.CreateWriter(stream, new ParquetWriterOptions { Compression = CompressionKind.None });
        var rowGroup = writer.StartRowGroup();
        var requiredColumn = rowGroup.CreateSerializedColumn<byte[]>(schema.LeafColumns[0]);
        requiredColumn.Serialize(required);
        rowGroup.Write(requiredColumn);
        var optionalColumn = rowGroup.CreateSerializedColumn<byte[]?>(schema.LeafColumns[1]);
        optionalColumn.Serialize(optional);
        rowGroup.Write(optionalColumn);
        var memoryColumn = rowGroup.CreateSerializedColumn<ReadOnlyMemory<byte>?>(schema.LeafColumns[2]);
        memoryColumn.Serialize(memory);
        rowGroup.Write(memoryColumn);
        var fixedColumn = rowGroup.CreateSerializedColumn<byte[]?>(schema.LeafColumns[3]);
        fixedColumn.Serialize(fixedValues);
        rowGroup.Write(fixedColumn);
        writer.CloseFile();

        using var reader = schema.CreateReader(FullValueOracle.Source(stream.ToArray()));
        if (reader.RowGroups.Count != 1 || reader.RowGroups[0].RowCount != (ulong)required.Length)
            throw new InvalidOperationException("Byte-array CountPresent case changed the row-group shape.");
    }

    static void WriteForcedOptionalInt32DictionaryGuardMatrix()
    {
        var dictionary = ImmutableArray.Create(EncodingKind.RleDictionary);
        int?[] values = [null, -12, 0, 1, 500, -12, null, int.MinValue, int.MaxValue];
        var requiredSchema = new ParquetSchema([
            ColumnDefinition.RequiredLeaf("forced-dictionary-required-int32", ParquetPhysicalType.Int32,
                new ColumnOptions(encodings: dictionary), pageStrategy: ForceDictionaryPageStrategy.Shared)
        ]);
        using (var stream = new MemoryStream())
        using (var writer = requiredSchema.CreateWriter(stream,
                   new ParquetWriterOptions { Compression = CompressionKind.None, WritePageIndexes = false }))
        {
            var column = writer.StartRowGroup().CreateSerializedColumn<int?>(requiredSchema.LeafColumns[0]);
            try
            {
                column.Serialize(values);
                throw new InvalidOperationException("Nullable values unexpectedly accepted by required INT32.");
            }
            catch (InvalidOperationException exception) when (
                exception.Message.Contains("does not support null values"))
            {
            }
        }

        var nestedSchema = new ParquetSchema([
            ColumnDefinition.OptionalGroup("forced-dictionary-group",
                ColumnDefinition.OptionalLeaf("int32", ParquetPhysicalType.Int32,
                    new ColumnOptions(ParquetRepetition.Optional, encodings: dictionary),
                    pageStrategy: ForceDictionaryPageStrategy.Shared))
        ]);
        using (var stream = new MemoryStream())
        using (var writer = nestedSchema.CreateWriter(stream,
                   new ParquetWriterOptions { Compression = CompressionKind.None, WritePageIndexes = false }))
        {
            var column = writer.StartRowGroup().CreateSerializedColumn<int?>(nestedSchema.LeafColumns[0]);
            try
            {
                column.Serialize(values);
                throw new InvalidOperationException("Flat nullable values unexpectedly accepted by nested INT32.");
            }
            catch (NotSupportedException exception) when (
                exception.Message.Contains("requires a single optional leaf"))
            {
            }
        }

        var schema = new ParquetSchema([
            ColumnDefinition.OptionalLeaf("forced-dictionary-int32", ParquetPhysicalType.Int32,
                new ColumnOptions(ParquetRepetition.Optional, encodings: dictionary),
                pageStrategy: ForceDictionaryPageStrategy.Shared)
        ]);
        using var output = new MemoryStream();
        using var outputWriter = schema.CreateWriter(output,
            new ParquetWriterOptions { Compression = CompressionKind.None, WritePageIndexes = false });
        var rowGroup = outputWriter.StartRowGroup();
        var successfulColumn = rowGroup.CreateSerializedColumn<int?>(schema.LeafColumns[0]);
        successfulColumn.Serialize(values);
        rowGroup.Write(successfulColumn);
        outputWriter.CloseFile();
        using var reader = schema.CreateReader(FullValueOracle.Source(output.ToArray()));
        AssertNullableInt32ReadBack(reader, 0, values);
    }

    static void WritePlainInt32DecimalCarrier()
    {
        decimal[] values = [12.34m, -56.78m, 0m, 901.23m];
        var schema = new ParquetSchema([
            ColumnDefinition.RequiredLeaf("plain-int32-decimal-carrier", ParquetPhysicalType.Int32,
                new ColumnOptions(encodings: ImmutableArray.Create(EncodingKind.Plain)),
                new LogicalType.Decimal(9, 2))
        ]);
        using var stream = new MemoryStream();
        var writer = schema.CreateWriter(stream, new ParquetWriterOptions { Compression = CompressionKind.None });
        var rowGroup = writer.StartRowGroup();
        var column = rowGroup.CreateSerializedColumn<decimal>(schema.LeafColumns[0]);
        column.Serialize(values);
        rowGroup.Write(column);
        writer.CloseFile();

        using var reader = schema.CreateReader(FullValueOracle.Source(stream.ToArray()));
        if (reader.RowGroups.Count != 1 || reader.RowGroups[0].RowCount != (ulong)values.Length)
            throw new InvalidOperationException("Plain INT32 decimal case changed the row-group shape.");
        var actual = new List<decimal>();
        foreach (var buffer in reader.RowGroups[0].Column<decimal>(schema.LeafColumns[0]))
            actual.AddRange(buffer.Values.ToArray());
        if (!actual.SequenceEqual(values))
            throw new InvalidOperationException("Plain INT32 decimal case changed the values.");

        var invalidSchema = new ParquetSchema([
            ColumnDefinition.RequiredLeaf("plain-int32-invalid-bool", ParquetPhysicalType.Int32,
                new ColumnOptions(encodings: ImmutableArray.Create(EncodingKind.Plain)))
        ]);
        using var invalidStream = new MemoryStream();
        using var invalidWriter = invalidSchema.CreateWriter(invalidStream,
            new ParquetWriterOptions { Compression = CompressionKind.None });
        var invalidColumn = invalidWriter.StartRowGroup().CreateSerializedColumn<bool>(invalidSchema.LeafColumns[0]);
        try
        {
            invalidColumn.Serialize([true]);
            throw new InvalidOperationException("Boolean carrier unexpectedly accepted by plain INT32.");
        }
        catch (InvalidOperationException exception) when (
            exception.Message.Contains("expects 'Int32' values") && exception.Message.Contains("System.Boolean"))
        {
        }
    }

    static void WriteForcedRequiredByteArrayDictionarySortTransitions()
    {
        byte[][][] descendingGroups =
        [
            ["zulu"u8.ToArray(), "mike"u8.ToArray(), "alpha"u8.ToArray()],
            ["zulu"u8.ToArray(), "mike"u8.ToArray(), "yankee"u8.ToArray()],
            ["bravo"u8.ToArray(), "delta"u8.ToArray(), "omega"u8.ToArray()]
        ];
        byte[][][] ascendingGroups =
        [
            ["alpha"u8.ToArray(), "mike"u8.ToArray(), "zulu"u8.ToArray()],
            ["alpha"u8.ToArray(), "mike"u8.ToArray(), "bravo"u8.ToArray()],
            ["bravo"u8.ToArray(), "delta"u8.ToArray(), "omega"u8.ToArray()]
        ];
        var schema = new ParquetSchema([
            ColumnDefinition.RequiredLeaf("forced-required-byte-array-sort", ParquetPhysicalType.ByteArray,
                new ColumnOptions(encodings: ImmutableArray.Create(EncodingKind.RleDictionary)),
                pageStrategy: ForceDictionaryPageStrategy.Shared),
            ColumnDefinition.RequiredLeaf("forced-required-byte-array-ascending", ParquetPhysicalType.ByteArray,
                new ColumnOptions(encodings: ImmutableArray.Create(EncodingKind.RleDictionary)),
                pageStrategy: ForceDictionaryPageStrategy.Shared)
        ]);
        using var stream = new MemoryStream();
        var writer = schema.CreateWriter(stream,
            new ParquetWriterOptions { Compression = CompressionKind.None, WritePageIndexes = false });
        for (var groupIndex = 0; groupIndex < descendingGroups.Length; groupIndex++)
        {
            var rowGroup = writer.StartRowGroup();
            var descendingColumn = rowGroup.CreateSerializedColumn<byte[]>(schema.LeafColumns[0]);
            descendingColumn.Serialize(descendingGroups[groupIndex]);
            rowGroup.Write(descendingColumn);
            var ascendingColumn = rowGroup.CreateSerializedColumn<byte[]>(schema.LeafColumns[1]);
            ascendingColumn.Serialize(ascendingGroups[groupIndex]);
            rowGroup.Write(ascendingColumn);
        }
        writer.CloseFile();

        using var reader = schema.CreateReader(FullValueOracle.Source(stream.ToArray()));
        if (reader.RowGroups.Count != descendingGroups.Length)
            throw new InvalidOperationException("Forced required BYTE_ARRAY groups were not all written.");
        for (var groupIndex = 0; groupIndex < descendingGroups.Length; groupIndex++)
        {
            AssertRequiredBinaryGroup(reader, groupIndex, 0, descendingGroups[groupIndex]);
            AssertRequiredBinaryGroup(reader, groupIndex, 1, ascendingGroups[groupIndex]);
        }

        var singletonSchema = new ParquetSchema([
            ColumnDefinition.RequiredLeaf("forced-required-byte-array-singleton", ParquetPhysicalType.ByteArray,
                new ColumnOptions(encodings: ImmutableArray.Create(EncodingKind.RleDictionary)),
                pageStrategy: ForceDictionaryPageStrategy.Shared)
        ]);
        using var singletonStream = new MemoryStream();
        var singletonWriter = singletonSchema.CreateWriter(singletonStream,
            new ParquetWriterOptions { Compression = CompressionKind.None, WritePageIndexes = false });
        var singletonRowGroup = singletonWriter.StartRowGroup();
        var singletonColumn = singletonRowGroup.CreateSerializedColumn<byte[]>(singletonSchema.LeafColumns[0]);
        byte[][] singletonValues = ["one"u8.ToArray()];
        singletonColumn.Serialize(singletonValues);
        singletonRowGroup.Write(singletonColumn);
        singletonWriter.CloseFile();
        using var singletonReader = singletonSchema.CreateReader(FullValueOracle.Source(singletonStream.ToArray()));
        AssertRequiredBinaryGroup(singletonReader, 0, 0, singletonValues);
    }

    static void AssertRequiredBinaryGroup(Plank.Reading.Logical.ParquetReader reader, int groupIndex,
        int columnIndex, byte[][] expected)
    {
        var actual = new List<byte[]>();
        foreach (var buffer in reader.RowGroups[groupIndex].Column<byte>(columnIndex))
            for (var index = 0; index < buffer.Count; index++)
                actual.Add(buffer.GetValue(index).ToArray());
        if (actual.Count != expected.Length)
            throw new InvalidOperationException("Forced required BYTE_ARRAY dictionary changed row count.");
        for (var index = 0; index < actual.Count; index++)
            if (!actual[index].AsSpan().SequenceEqual(expected[index]))
                throw new InvalidOperationException("Forced required BYTE_ARRAY dictionary changed values.");
    }

    static void WriteForcedRequiredByteArrayDictionaryMapNullFailures()
    {
        var unsortedSchema = CreateForcedRequiredByteArrayDictionarySchema("map-entry-null");
        using (var stream = new MemoryStream())
        using (var writer = unsortedSchema.CreateWriter(stream,
                   new ParquetWriterOptions { Compression = CompressionKind.None, WritePageIndexes = false }))
        {
            var firstGroup = writer.StartRowGroup();
            var firstColumn = firstGroup.CreateSerializedColumn<byte[]>(unsortedSchema.LeafColumns[0]);
            firstColumn.Serialize(["bravo"u8.ToArray(), "charlie"u8.ToArray(), "alpha"u8.ToArray()]);
            firstGroup.Write(firstColumn);

            var nullGroup = writer.StartRowGroup();
            var nullColumn = nullGroup.CreateSerializedColumn<byte[]>(unsortedSchema.LeafColumns[0]);
            byte[][] nullAtMapEntry = [null!, "present"u8.ToArray()];
            ExpectRequiredByteArrayDictionaryNull(nullColumn, nullAtMapEntry);
        }

        var cycleSchema = CreateForcedRequiredByteArrayDictionarySchema("cycle-close-null");
        byte[][] cycleCloseNull = ["alpha"u8.ToArray(), "bravo"u8.ToArray(), "alpha"u8.ToArray(), null!];
        ExpectRequiredByteArrayDictionaryNull(cycleSchema, cycleCloseNull);

        var tailSchema = CreateForcedRequiredByteArrayDictionarySchema("cycle-tail-null");
        byte[][] cycleTailNull =
        [
            "alpha"u8.ToArray(), "bravo"u8.ToArray(), "alpha"u8.ToArray(), "charlie"u8.ToArray(), null!
        ];
        ExpectRequiredByteArrayDictionaryNull(tailSchema, cycleTailNull);
    }

    static ParquetSchema CreateForcedRequiredByteArrayDictionarySchema(string name)
        => new([
            ColumnDefinition.RequiredLeaf(name, ParquetPhysicalType.ByteArray,
                new ColumnOptions(encodings: ImmutableArray.Create(EncodingKind.RleDictionary)),
                pageStrategy: ForceDictionaryPageStrategy.Shared)
        ]);

    static void ExpectRequiredByteArrayDictionaryNull(ParquetSchema schema, byte[][] values)
    {
        using var stream = new MemoryStream();
        using var writer = schema.CreateWriter(stream,
            new ParquetWriterOptions { Compression = CompressionKind.None, WritePageIndexes = false });
        var column = writer.StartRowGroup().CreateSerializedColumn<byte[]>(schema.LeafColumns[0]);
        ExpectRequiredByteArrayDictionaryNull(column, values);
    }

    static void ExpectRequiredByteArrayDictionaryNull(SerializedColumn<byte[]> column, byte[][] values)
    {
        try
        {
            column.Serialize(values);
            throw new InvalidOperationException("Null value unexpectedly accepted by required BYTE_ARRAY dictionary.");
        }
        catch (InvalidOperationException exception) when (
            exception.Message.Contains("A required byte-array dictionary does not support null values."))
        {
        }
    }

    static void WriteForcedOptionalInt64DictionaryNestedProjectionRejection()
    {
        var dictionary = ImmutableArray.Create(EncodingKind.RleDictionary);
        var schema = new ParquetSchema([
            ColumnDefinition.OptionalGroup("forced-dictionary-group",
                ColumnDefinition.OptionalLeaf("int64", ParquetPhysicalType.Int64,
                    new ColumnOptions(ParquetRepetition.Optional, encodings: dictionary),
                    pageStrategy: ForceDictionaryPageStrategy.Shared))
        ]);
        using var stream = new MemoryStream();
        using var writer = schema.CreateWriter(stream,
            new ParquetWriterOptions { Compression = CompressionKind.None, WritePageIndexes = false });
        var column = writer.StartRowGroup().CreateSerializedColumn<long?>(schema.LeafColumns[0]);

        Exception? observed = null;
        try
        {
            column.Serialize([1L, null, 2L]);
        }
        catch (NotSupportedException error)
        {
            observed = error;
        }

        if (observed is null || !observed.Message.EndsWith(
            "optional flat encoding requires a single optional leaf.", StringComparison.Ordinal))
            throw new InvalidOperationException(
                $"Expected the nested forced INT64 projection rejection, got '{observed?.Message}'.");
    }

    static void WriteForcedOptionalInt64DictionaryRequiredCarrierRejection()
    {
        var schema = new ParquetSchema([
            ColumnDefinition.RequiredLeaf("required-int64", ParquetPhysicalType.Int64,
                new ColumnOptions(encodings: ImmutableArray.Create(EncodingKind.RleDictionary)),
                pageStrategy: ForceDictionaryPageStrategy.Shared)
        ]);
        using var stream = new MemoryStream();
        using var writer = schema.CreateWriter(stream,
            new ParquetWriterOptions { Compression = CompressionKind.None, WritePageIndexes = false });
        var column = writer.StartRowGroup().CreateSerializedColumn<long?>(schema.LeafColumns[0]);

        Exception? observed = null;
        try
        {
            column.Serialize([1L, null, 2L]);
        }
        catch (InvalidOperationException error)
        {
            observed = error;
        }

        if (observed is null || observed.Message != "Column 'required-int64' does not support null values.")
            throw new InvalidOperationException(
                $"Expected the required forced INT64 rejection, got '{observed?.Message}'.");
    }

    static void WriteFloatAndDecimalDictionarySortComparisons()
    {
        var dictionary = ImmutableArray.Create(EncodingKind.RleDictionary, EncodingKind.Plain);
        var schema = new ParquetSchema([
            ColumnDefinition.RequiredLeaf("float-sort", ParquetPhysicalType.Float,
                new ColumnOptions(encodings: dictionary)),
            ColumnDefinition.RequiredLeaf("decimal-sort", ParquetPhysicalType.ByteArray,
                new ColumnOptions(encodings: dictionary), new LogicalType.Decimal(9, 2))
        ]);
        float[] expectedFloats = [-3.5f, 0.25f, 17f];
        decimal[] expectedDecimals = [-12.34m, 0m, 56.78m];
        using var stream = new MemoryStream();
        using var writer = schema.CreateWriter(stream, new ParquetWriterOptions
        {
            Compression = CompressionKind.None,
            WritePageIndexes = false
        });
        var rowGroup = writer.StartRowGroup();
        var floatColumn = rowGroup.CreateSerializedColumn<float>(schema.LeafColumns[0]);
        floatColumn.Serialize(expectedFloats);
        rowGroup.Write(floatColumn);
        var decimalColumn = rowGroup.CreateSerializedColumn<decimal>(schema.LeafColumns[1]);
        decimalColumn.Serialize(expectedDecimals);
        rowGroup.Write(decimalColumn);
        writer.CloseFile();

        using var reader = schema.CreateReader(FullValueOracle.Source(stream.ToArray()));
        var actualFloats = new List<float>();
        foreach (var buffer in reader.RowGroups[0].Column<float>(schema.LeafColumns[0]))
            actualFloats.AddRange(buffer.Values.ToArray());
        var actualDecimals = new List<decimal>();
        foreach (var buffer in reader.RowGroups[0].Column<decimal>(schema.LeafColumns[1]))
            actualDecimals.AddRange(buffer.Values.ToArray());
        if (!actualFloats.SequenceEqual(expectedFloats) || !actualDecimals.SequenceEqual(expectedDecimals))
            throw new InvalidOperationException("FLOAT/decimal dictionary comparison changed public values.");
    }

    static void WriteOptionalSingleByteMemoryPayloads()
    {
        ReadOnlyMemory<byte>?[] values =
        [
            new byte[] { 0x11 },
            null,
            new byte[] { 0xA5 },
            null
        ];
        byte[]?[] expected = [[0x11], null, [0xA5], null];
        var schema = new ParquetSchema([
            ColumnDefinition.OptionalLeaf("optional-single-byte-memory", ParquetPhysicalType.ByteArray,
                new ColumnOptions(ParquetRepetition.Optional,
                    encodings: ImmutableArray.Create(EncodingKind.Plain)))
        ]);
        using var stream = new MemoryStream();
        var writer = schema.CreateWriter(stream, new ParquetWriterOptions { Compression = CompressionKind.None });
        var rowGroup = writer.StartRowGroup();
        var column = rowGroup.CreateSerializedColumn<ReadOnlyMemory<byte>?>(schema.LeafColumns[0]);
        column.Serialize(values);
        rowGroup.Write(column);
        writer.CloseFile();

        using var source = FullValueOracle.Source(stream.ToArray());
        using var reader = schema.CreateReader(source);
        if (reader.RowGroups.Count != 1 || reader.RowGroups[0].RowCount != (ulong)values.Length)
            throw new InvalidOperationException("Optional single-byte memory case changed the row-group shape.");
        AssertBinaryReadBack(reader, 0, expected);
    }

    static void WriteNullableTemporalValues()
    {
        var plain = ImmutableArray.Create(EncodingKind.Plain);
        DateOnly?[] dates = [new(1969, 12, 31), null, new(2026, 7, 27)];
        TimeOnly?[] times = [new(1, 2, 3), null, new(22, 33, 44)];
        DateTimeOffset?[] instants =
        [
            DateTimeOffset.UnixEpoch.AddTicks(-120),
            null,
            DateTimeOffset.UnixEpoch.AddTicks(750)
        ];

        WriteNullableTemporalColumn(
            ColumnDefinition.OptionalLeaf("nullable-date", ParquetPhysicalType.Int32,
                new ColumnOptions(ParquetRepetition.Optional, encodings: plain), new LogicalType.Date()),
            dates, static (reader, column) => ReadAllNullable<DateOnly>(reader, column),
            "nullable DateOnly", EncodeInt32(-1), EncodeInt32(
                new DateOnly(2026, 7, 27).DayNumber - new DateOnly(1970, 1, 1).DayNumber));
        WriteNullableTemporalColumn(
            ColumnDefinition.OptionalLeaf("nullable-time", ParquetPhysicalType.Int64,
                new ColumnOptions(ParquetRepetition.Optional, encodings: plain),
                new LogicalType.Time(TimeUnit.Micros, IsAdjustedToUtc: false)),
            times, static (reader, column) => ReadAllNullable<TimeOnly>(reader, column),
            "nullable TimeOnly", EncodeInt64(3_723_000_000), EncodeInt64(81_224_000_000));
        WriteNullableTemporalColumn(
            ColumnDefinition.OptionalLeaf("nullable-instant", ParquetPhysicalType.Int64,
                new ColumnOptions(ParquetRepetition.Optional, encodings: plain),
                new LogicalType.Timestamp(TimeUnit.Nanos, IsAdjustedToUtc: true)),
            instants, static (reader, column) => ReadAllNullable<DateTimeOffset>(reader, column),
            "nullable DateTimeOffset", EncodeInt64(-12_000), EncodeInt64(75_000));
    }

    static void WriteOptionalDoubleDictionarySignedZeroAndNaN()
    {
        double?[] expected = [-0.0, 0.0, double.NaN, null, double.NaN];
        var schema = new ParquetSchema([
            ColumnDefinition.OptionalLeaf("optional-double-dictionary-zero-nan", ParquetPhysicalType.Double,
                new ColumnOptions(ParquetRepetition.Optional,
                    encodings: ImmutableArray.Create(EncodingKind.RleDictionary)),
                pageStrategy: ForceDictionaryPageStrategy.Shared)
        ]);
        using var stream = new MemoryStream();
        var writer = schema.CreateWriter(stream, new ParquetWriterOptions
        {
            Compression = CompressionKind.None,
            WritePageIndexes = false
        });
        var serialized = writer.CreateSerializedColumn<double?>(schema.LeafColumns[0]);
        serialized.Serialize(expected);
        writer.StartRowGroup().Write(serialized);
        writer.CloseFile();

        using var source = FullValueOracle.Source(stream.ToArray());
        using var reader = schema.CreateReader(source);
        if (reader.RowGroups.Count != 1 || reader.RowGroups[0].RowCount != (ulong)expected.Length)
            throw new InvalidOperationException("Optional DOUBLE dictionary case changed the row-group shape.");
        var actual = new List<double?>(expected.Length);
        foreach (var buffer in reader.RowGroups[0].Column<double?>(schema.LeafColumns[0]))
            actual.AddRange(buffer.Values);
        if (actual.Count != expected.Length)
            throw new InvalidOperationException("Optional DOUBLE dictionary case changed the value count.");
        for (var i = 0; i < expected.Length; i++)
        {
            if (expected[i] is not { } expectedValue)
            {
                if (actual[i].HasValue)
                    throw new InvalidOperationException($"Optional DOUBLE dictionary case changed null row {i}.");
                continue;
            }
            if (actual[i] is not { } actualValue
                || BitConverter.DoubleToInt64Bits(actualValue) != BitConverter.DoubleToInt64Bits(expectedValue))
                throw new InvalidOperationException($"Optional DOUBLE dictionary case changed value {i}.");
        }
    }

    static void WriteOptionalReadOnlyMemoryDictionaryDecisionPaths()
    {
        const int count = 32_768;
        var maybeRetained = new ReadOnlyMemory<byte>?[count];
        var maybeDropped = new ReadOnlyMemory<byte>?[count];
        var forced = new ReadOnlyMemory<byte>?[count];
        for (var i = 0; i < count; i++)
        {
            maybeRetained[i] = new byte[] { (byte)(i % 97) };
            maybeDropped[i] = BitConverter.GetBytes(i);
            forced[i] = new byte[] { (byte)(i % 11) };
        }
        maybeRetained[0] = null;
        maybeRetained[1] = null;
        maybeDropped[0] = null;
        maybeDropped[1] = null;
        forced[0] = null;
        forced[1] = null;

        var dictionary = ImmutableArray.Create(EncodingKind.RleDictionary);
        var schema = new ParquetSchema(
        [
            ColumnDefinition.OptionalLeaf("maybe-retained", ParquetPhysicalType.ByteArray,
                new ColumnOptions(ParquetRepetition.Optional, encodings: dictionary)),
            ColumnDefinition.OptionalLeaf("maybe-dropped", ParquetPhysicalType.ByteArray,
                new ColumnOptions(ParquetRepetition.Optional, encodings: dictionary)),
            ColumnDefinition.OptionalLeaf("forced", ParquetPhysicalType.ByteArray,
                new ColumnOptions(ParquetRepetition.Optional, encodings: dictionary),
                pageStrategy: ForceDictionaryPageStrategy.Shared)
        ]);

        using var stream = new MemoryStream();
        var writer = schema.CreateWriter(stream, new ParquetWriterOptions
        {
            Compression = CompressionKind.None,
            WritePageIndexes = false
        });
        var rowGroup = writer.StartRowGroup();
        WriteOptionalMemoryColumn(rowGroup, schema, 0, maybeRetained);
        WriteOptionalMemoryColumn(rowGroup, schema, 1, maybeDropped);
        WriteOptionalMemoryColumn(rowGroup, schema, 2, forced);
        writer.CloseFile();

        using var reader = schema.CreateReader(FullValueOracle.Source(stream.ToArray()));
        AssertBinaryReadBack(reader, 0, maybeRetained.Select(static value => value?.ToArray()).ToArray());
        AssertBinaryReadBack(reader, 1, maybeDropped.Select(static value => value?.ToArray()).ToArray());
        AssertBinaryReadBack(reader, 2, forced.Select(static value => value?.ToArray()).ToArray());
    }

    static void WriteOptionalMemoryColumn(RowGroupWriter rowGroup, ParquetSchema schema, int columnIndex,
        ReadOnlyMemory<byte>?[] values)
    {
        var column = rowGroup.CreateSerializedColumn<ReadOnlyMemory<byte>?>(schema.LeafColumns[columnIndex]);
        column.Serialize(values);
        rowGroup.Write(column);
    }

    static void WriteNullableTemporalColumn<T>(ColumnDefinition definition, T?[] expected,
        Func<Plank.Reading.Logical.ParquetReader, int, T?[]> read, string name,
        ReadOnlySpan<byte> expectedMinimum, ReadOnlySpan<byte> expectedMaximum)
        where T : struct
    {
        var schema = new ParquetSchema([definition]);
        using var stream = new MemoryStream();
        var writer = schema.CreateWriter(stream, new ParquetWriterOptions { Compression = CompressionKind.None });
        var rowGroup = writer.StartRowGroup();
        var column = rowGroup.CreateSerializedColumn<T?>(schema.LeafColumns[0]);
        column.Serialize(expected);
        rowGroup.Write(column);
        writer.CloseFile();

        using var source = FullValueOracle.Source(stream.ToArray());
        using var reader = schema.CreateReader(source);
        if (reader.RowGroups.Count != 1 || reader.RowGroups[0].RowCount != (ulong)expected.Length)
            throw new InvalidOperationException($"{name} case changed the row-group shape.");
        var actual = read(reader, 0);
        if (!actual.AsSpan().SequenceEqual(expected))
            throw new InvalidOperationException($"{name} case changed values or null positions.");

        var statistics = reader.RowGroups[0].GetColumnMetadata(0).Statistics;
        if (statistics.NullCount != 1 || !statistics.HasMinimum || !statistics.HasMaximum
            || !statistics.IsMinimumExact || !statistics.IsMaximumExact
            || !statistics.Minimum.SequenceEqual(expectedMinimum)
            || !statistics.Maximum.SequenceEqual(expectedMaximum))
            throw new InvalidOperationException($"{name} case changed exact footer statistics.");
    }

    static T?[] ReadAllNullable<T>(Plank.Reading.Logical.ParquetReader reader, int columnIndex)
        where T : struct
    {
        var values = new List<T?>();
        foreach (var buffer in reader.RowGroups[0].Column<T?>(columnIndex))
            values.AddRange(buffer.Values);
        return values.ToArray();
    }

    static byte[] EncodeInt32(int value)
    {
        var bytes = new byte[sizeof(int)];
        BinaryPrimitives.WriteInt32LittleEndian(bytes, value);
        return bytes;
    }

    static byte[] EncodeInt64(long value)
    {
        var bytes = new byte[sizeof(long)];
        BinaryPrimitives.WriteInt64LittleEndian(bytes, value);
        return bytes;
    }

    static void AssertBinaryReadBack(Plank.Reading.Logical.ParquetReader reader, int columnIndex,
        byte[]?[] expected)
    {
        var actual = new List<byte[]?>(expected.Length);
        foreach (var buffer in reader.RowGroups[0].Column<byte>(columnIndex))
            for (var index = 0; index < buffer.Count; index++)
                actual.Add(buffer.IsNull(index) ? null : buffer.GetValue(index).ToArray());

        if (actual.Count != expected.Length)
            throw new InvalidOperationException(
                $"Binary encoding case changed row count: expected {expected.Length}, read {actual.Count}.");
        for (var index = 0; index < expected.Length; index++)
            if (expected[index] is { } expectedValue)
            {
                if (actual[index] is not { } actualValue || !actualValue.AsSpan().SequenceEqual(expectedValue))
                    throw new InvalidOperationException($"Binary encoding case changed value {index}.");
            }
            else if (actual[index] is not null)
            {
                throw new InvalidOperationException($"Binary encoding case changed null value {index}.");
            }
    }

    static void AssertReadBack<T>(Plank.Reading.Logical.ParquetReader reader, int columnIndex, T[] expected)
        where T : notnull
    {
        var actual = new List<T>(expected.Length);
        foreach (var buffer in reader.RowGroups[0].Column<T>(columnIndex))
            actual.AddRange(buffer.Values);
        if (!actual.SequenceEqual(expected))
            throw new InvalidOperationException(
                $"RLE boolean/BSS case changed column {columnIndex}: expected {expected.Length} values, "
                + $"read {actual.Count}.");
    }

    static void WriteDelta13BitAllMiniBlocks()
    {
        // Produce 128 deltas (four 32-value mini-blocks), each with a zero residual
        // and one 8191 residual. All four encoded widths are therefore exactly 13.
        var values = new int[129];
        var value = 0;
        for (var block = 0; block < 4; block++)
        {
            var start = block * 32;
            for (var i = 0; i < 32; i++)
            {
                if (i == 1)
                    value += 8191;
                values[start + i + 1] = value;
            }
        }

        Write("delta-13-all-miniblocks", values, EncodingKind.DeltaBinaryPacked, forceDictionary: false);
    }

    static void WriteWideDictionary(int bitWidth)
    {
        var paletteSize = 1 << bitWidth;
        var values = new int[paletteSize * 2];
        for (var i = 0; i < values.Length; i++)
            values[i] = i % paletteSize;

        Write($"dictionary-index-width-{bitWidth}", values, EncodingKind.RleDictionary, forceDictionary: true);
    }

    static void WriteForcedRequiredByteArrayDictionary(int caseId)
    {
        var values = new byte[384][];
        var palette = new byte[][] { [0], [1], [2], [3] };
        for (var i = 0; i < values.Length; i++)
        {
            var value = caseId switch
            {
                7 => i / 3,
                8 => (values.Length - 1 - i) / 3,
                9 => i < 192 ? i / 3 : (values.Length - 1 - i) / 3,
                10 => i % 4,
                11 => i < 16 ? i % 4 : (i + 1) % 4,
                _ => 0
            };
            values[i] = caseId is 10 or 12
                ? palette[value]
                : caseId == 11 ? [(byte)value] : [(byte)value, (byte)(value >> 8)];
        }

        var column = ColumnDefinition.Leaf("required-binary-dictionary", ParquetPhysicalType.ByteArray,
            new ColumnOptions(encodings: ImmutableArray.Create(EncodingKind.RleDictionary)),
            pageStrategy: ForceDictionaryPageStrategy.Shared);
        var schema = new ParquetSchema([column]);
        using var stream = new MemoryStream();
        var writer = schema.CreateWriter(stream, new ParquetWriterOptions
        {
            Compression = CompressionKind.None,
            DataPageVersion = ParquetDataPageVersion.V2,
            WritePageIndexes = false,
            TargetDataPageSizeBytes = caseId >= 10 ? 1024 * 1024U : 128U,
            BufferChunkSizeBytes = 128
        });
        var rowGroup = writer.StartRowGroup();
        var serialized = rowGroup.CreateSerializedColumn<byte[]>(schema.LeafColumns[0]);
        serialized.Serialize(values);
        rowGroup.Write(serialized);
        writer.CloseFile();

        using var source = FullValueOracle.Source(stream.ToArray());
        using var reader = schema.CreateReader(source);
        if (reader.RowGroups.Count != 1 || reader.RowGroups[0].RowCount != (ulong)values.Length)
            throw new InvalidOperationException("Forced binary dictionary changed the row-group shape.");
        var offset = 0;
        foreach (var buffer in reader.RowGroups[0].Column<byte>(schema.LeafColumns[0]))
            for (var i = 0; i < buffer.Count; i++)
            {
                if (offset >= values.Length || buffer.IsNull(i)
                    || !buffer.GetValue(i).SequenceEqual(values[offset]))
                    throw new InvalidOperationException($"Forced binary dictionary changed value {offset}.");
                offset++;
            }
        if (offset != values.Length)
            throw new InvalidOperationException("Forced binary dictionary changed the value count.");
    }

    static void WriteOptionalDoubleDictionaryAfterUnsortedRowGroup()
    {
        double?[] firstValues = [0, 10, 1, 10, 2, 0, 2, 1];

        var secondValues = new double?[801];
        secondValues[0] = null;
        var offset = 1;
        for (var value = 0; value < 200; value++)
            secondValues[offset++] = value;
        secondValues[offset++] = 0;
        for (var value = 200; value < 600; value++)
            secondValues[offset++] = value;
        for (var value = 0; value < 199; value++)
            secondValues[offset++] = value;
        if (offset != secondValues.Length)
            throw new InvalidOperationException("Optional double dictionary case constructed the wrong second-group length.");

        var thirdValues = new double?[601];
        thirdValues[0] = null;
        for (var value = 1; value < thirdValues.Length; value++)
            thirdValues[value] = 10_000 + value;

        var column = ColumnDefinition.OptionalLeaf("optional-double-dictionary", ParquetPhysicalType.Double,
            new ColumnOptions(ParquetRepetition.Optional,
                encodings: ImmutableArray.Create(EncodingKind.RleDictionary)));
        var schema = new ParquetSchema([column]);
        using var stream = new MemoryStream();
        var writer = schema.CreateWriter(stream, new ParquetWriterOptions
        {
            Compression = CompressionKind.None,
            WritePageIndexes = true,
            TargetDataPageSizeBytes = 128
        });
        var serialized = writer.CreateSerializedColumn<double?>(schema.LeafColumns[0]);

        serialized.Serialize(firstValues);
        writer.StartRowGroup().Write(serialized);
        serialized.Serialize(secondValues);
        writer.StartRowGroup().Write(serialized);
        serialized.Serialize(thirdValues);
        writer.StartRowGroup().Write(serialized);
        writer.CloseFile();

        var expected = firstValues.Concat(secondValues).Concat(thirdValues).ToArray();
        using var source = FullValueOracle.Source(stream.ToArray());
        using var reader = schema.CreateReader(source);
        if (reader.RowGroups.Count != 3)
            throw new InvalidOperationException(
                $"Optional double dictionary case produced {reader.RowGroups.Count} row groups; expected 3.");

        int[] expectedRowsPerGroup = [firstValues.Length, secondValues.Length, thirdValues.Length];
        var actual = new List<double?>(expected.Length);
        for (var rowGroupIndex = 0; rowGroupIndex < expectedRowsPerGroup.Length; rowGroupIndex++)
        {
            var rowGroup = reader.RowGroups[rowGroupIndex];
            if (rowGroup.RowCount != (ulong)expectedRowsPerGroup[rowGroupIndex])
                throw new InvalidOperationException(
                    $"Optional double dictionary row group {rowGroupIndex} has {rowGroup.RowCount} rows; "
                    + $"expected {expectedRowsPerGroup[rowGroupIndex]}.");

            foreach (var buffer in rowGroup.Column<double?>(schema.LeafColumns[0]))
                actual.AddRange(buffer.Values.ToArray());
        }

        if (expected.Length != 1_410 || actual.Count != expected.Length
            || !actual.SequenceEqual(expected))
            throw new InvalidOperationException(
                $"Optional double dictionary case changed its 1,410-value sequence: expected {expected.Length}, "
                + $"read {actual.Count}.");
    }

    static void WriteOptionalDoubleDictionarySmallIndexPaths()
    {
        double?[] firstValues = [0, 10, 1, 10, 2, 0, 2, 1];
        var secondValuesList = new List<double?>(525);
        for (var i = 0; i < 10; i++)
            secondValuesList.Add(i);
        secondValuesList.Add(0);
        for (var i = 10; i < 520; i++)
            secondValuesList.Add(i);
        secondValuesList.AddRange([0, 519, 17, 0]);
        var secondValues = secondValuesList.ToArray();

        var schema = new ParquetSchema([
            ColumnDefinition.OptionalLeaf("optional-double-small-index", ParquetPhysicalType.Double,
                new ColumnOptions(ParquetRepetition.Optional,
                    encodings: ImmutableArray.Create(EncodingKind.RleDictionary)))
        ]);
        using var stream = new MemoryStream();
        var writer = schema.CreateWriter(stream, new ParquetWriterOptions
        {
            Compression = CompressionKind.None,
            WritePageIndexes = true,
            TargetDataPageSizeBytes = 128
        });
        var serialized = writer.CreateSerializedColumn<double?>(schema.LeafColumns[0]);
        serialized.Serialize(firstValues);
        writer.StartRowGroup().Write(serialized);
        serialized.Serialize(secondValues);
        writer.StartRowGroup().Write(serialized);
        writer.CloseFile();

        using var reader = schema.CreateReader(FullValueOracle.Source(stream.ToArray()));
        double?[][] expected = [firstValues, secondValues];
        if (reader.RowGroups.Count != expected.Length)
            throw new InvalidOperationException("Optional double small-index case changed row-group count.");
        for (var groupIndex = 0; groupIndex < expected.Length; groupIndex++)
        {
            var actual = new List<double?>();
            foreach (var buffer in reader.RowGroups[groupIndex].Column<double?>(schema.LeafColumns[0]))
                actual.AddRange(buffer.Values);
            if (!actual.SequenceEqual(expected[groupIndex]))
                throw new InvalidOperationException(
                    $"Optional double small-index case changed row group {groupIndex} values.");
        }
    }

    static void WriteEmptyOptionalStructAndReferenceColumns()
    {
        var schema = new ParquetSchema([
            ColumnDefinition.OptionalLeaf("empty-optional-int32", ParquetPhysicalType.Int32),
            ColumnDefinition.OptionalLeaf("empty-optional-byte-array", ParquetPhysicalType.ByteArray)
        ]);
        using var stream = new MemoryStream();
        var writer = schema.CreateWriter(stream, new ParquetWriterOptions
        {
            Compression = CompressionKind.None
        });
        var rowGroup = writer.StartRowGroup();
        var numbers = writer.CreateSerializedColumn<int?>(schema.LeafColumns[0]);
        numbers.Serialize(Array.Empty<int?>());
        rowGroup.Write(numbers);
        var binary = writer.CreateSerializedColumn<byte[]>(schema.LeafColumns[1]);
        binary.Serialize(Array.Empty<byte[]>());
        rowGroup.Write(binary);
        writer.CloseFile();

        using var reader = schema.CreateReader(FullValueOracle.Source(stream.ToArray()));
        if (reader.RowGroups.Count != 1 || reader.RowGroups[0].RowCount != 0)
            throw new InvalidOperationException("Empty optional columns changed the row-group shape.");

        var requiredSchema = new ParquetSchema([
            ColumnDefinition.RequiredLeaf("required-int32", ParquetPhysicalType.Int32)
        ]);
        using var requiredStream = new MemoryStream();
        using (var requiredWriter = requiredSchema.CreateWriter(requiredStream))
        {
            var required = requiredWriter.CreateSerializedColumn<int?>(requiredSchema.LeafColumns[0]);
            AssertExpectedWriterException(() => required.Serialize(new int?[] { 1 }),
                typeof(InvalidOperationException), "does not support null values");
        }

        var nestedSchemas = new[]
        {
            new ParquetSchema([
                ColumnDefinition.OptionalGroup("outer",
                    ColumnDefinition.OptionalLeaf("inner", ParquetPhysicalType.Int32))
            ])
        };
        foreach (var nestedSchema in nestedSchemas)
        {
            using var nestedStream = new MemoryStream();
            using var nestedWriter = nestedSchema.CreateWriter(nestedStream);
            var nested = nestedWriter.CreateSerializedColumn<int?>(nestedSchema.LeafColumns[0]);
            AssertExpectedWriterException(() => nested.Serialize(new int?[] { 1, null }),
                typeof(NotSupportedException), "optional flat encoding requires a single optional leaf");
        }

        var repeatedSchema = new ParquetSchema([
            ColumnDefinition.List("items", ColumnDefinition.OptionalLeaf("element", ParquetPhysicalType.Int32))
        ]);
        using var repeatedStream = new MemoryStream();
        using (var repeatedWriter = repeatedSchema.CreateWriter(repeatedStream))
        {
            var repeated = repeatedWriter.CreateSerializedColumn<int?>(repeatedSchema.LeafColumns[0]);
            AssertExpectedWriterException(() => repeated.Serialize(new int?[] { 1, null }),
                // Message from Plank 80578da (#224), which rewrote repeated-row flattening.
                typeof(InvalidOperationException),
                "Array type 'System.Nullable`1[System.Int32]' is incompatible with column 'items.list.element'");
        }
    }

    static void WriteNullableInt32StatisticsBloomPath()
    {
        int?[] expected = [null, 20, -5, 50, 11, null];
        var schema = new ParquetSchema([
            ColumnDefinition.OptionalLeaf("nullable-int32-statistics", ParquetPhysicalType.Int32,
                new ColumnOptions(ParquetRepetition.Optional,
                    encodings: ImmutableArray.Create(EncodingKind.Plain),
                    bloomFilter: new ParquetBloomFilterOptions
                    {
                        FalsePositiveProbability = 0.001,
                        MaximumBytes = 256
                    }))
        ]);
        using var stream = new MemoryStream();
        var writer = schema.CreateWriter(stream, new ParquetWriterOptions
        {
            Compression = CompressionKind.None,
            WritePageIndexes = false
        });
        var column = writer.CreateSerializedColumn<int?>(schema.LeafColumns[0]);
        column.Serialize(expected);
        writer.StartRowGroup().Write(column);
        writer.CloseFile();

        using var reader = schema.CreateReader(FullValueOracle.Source(stream.ToArray()));
        if (reader.RowGroups.Count != 1 || reader.RowGroups[0].RowCount != (ulong)expected.Length)
            throw new InvalidOperationException("Nullable INT32 statistics case changed the row-group shape.");
        var actual = new List<int?>();
        foreach (var buffer in reader.RowGroups[0].Column<int?>(schema.LeafColumns[0]))
            actual.AddRange(buffer.Values);
        if (!actual.SequenceEqual(expected))
            throw new InvalidOperationException("Nullable INT32 statistics case changed values.");
    }

    static void WriteAllNullOptionalInt32Statistics()
    {
        int?[] expected = [null, null, null];
        var schema = new ParquetSchema([
            ColumnDefinition.OptionalLeaf("all-null-int32-statistics", ParquetPhysicalType.Int32,
                new ColumnOptions(ParquetRepetition.Optional,
                    encodings: ImmutableArray.Create(EncodingKind.Plain)))
        ]);
        using var stream = new MemoryStream();
        var writer = schema.CreateWriter(stream, new ParquetWriterOptions
        {
            Compression = CompressionKind.None
        });
        var column = writer.CreateSerializedColumn<int?>(schema.LeafColumns[0]);
        column.Serialize(expected);
        writer.StartRowGroup().Write(column);
        writer.CloseFile();

        using var reader = schema.CreateReader(FullValueOracle.Source(stream.ToArray()));
        if (reader.RowGroups.Count != 1 || reader.RowGroups[0].RowCount != (ulong)expected.Length)
            throw new InvalidOperationException("All-null optional INT32 case changed row-group shape.");
        var actual = new List<int?>();
        foreach (var buffer in reader.RowGroups[0].Column<int?>(schema.LeafColumns[0]))
            actual.AddRange(buffer.Values);
        if (!actual.SequenceEqual(expected))
            throw new InvalidOperationException("All-null optional INT32 case changed values.");
    }

    static void WriteAllNullOptionalInt64Statistics()
    {
        long?[] expected = [null, null, null];
        var schema = new ParquetSchema([
            ColumnDefinition.OptionalLeaf("all-null-int64-statistics", ParquetPhysicalType.Int64,
                new ColumnOptions(ParquetRepetition.Optional,
                    encodings: ImmutableArray.Create(EncodingKind.Plain),
                    bloomFilter: new ParquetBloomFilterOptions
                    {
                        FalsePositiveProbability = 0.001,
                        MaximumBytes = 256
                    }))
        ]);
        using var stream = new MemoryStream();
        var writer = schema.CreateWriter(stream, new ParquetWriterOptions
        {
            Compression = CompressionKind.None
        });
        var column = writer.CreateSerializedColumn<long?>(schema.LeafColumns[0]);
        column.Serialize(expected);
        writer.StartRowGroup().Write(column);
        writer.CloseFile();

        using var reader = schema.CreateReader(FullValueOracle.Source(stream.ToArray()));
        if (reader.RowGroups.Count != 1 || reader.RowGroups[0].RowCount != (ulong)expected.Length)
            throw new InvalidOperationException("All-null optional INT64 case changed row-group shape.");
        var actual = new List<long?>();
        foreach (var buffer in reader.RowGroups[0].Column<long?>(schema.LeafColumns[0]))
            actual.AddRange(buffer.Values);
        if (!actual.SequenceEqual(expected))
            throw new InvalidOperationException("All-null optional INT64 case changed values.");
    }

    static void AssertExpectedWriterException(Action action, Type expectedType, string messageFragment)
    {
        Exception? observed = null;
        try
        {
            action();
        }
        catch (Exception error)
        {
            observed = error;
        }

        if (observed is null || observed.GetType() != expectedType ||
            !observed.Message.Contains(messageFragment, StringComparison.Ordinal))
            throw new InvalidOperationException(
                $"Expected {expectedType.Name} containing '{messageFragment}', got " +
                $"'{observed?.GetType().Name}: {observed?.Message}'.");
    }

    static void Write(string name, int[] values, EncodingKind encoding, bool forceDictionary)
    {
        var column = ColumnDefinition.Leaf(name, ParquetPhysicalType.Int32,
            new ColumnOptions(encodings: ImmutableArray.Create(encoding)),
            pageStrategy: forceDictionary ? ForceDictionaryPageStrategy.Shared : null);
        var schema = new ParquetSchema([column]);
        using var stream = new MemoryStream();
        var writer = schema.CreateWriter(stream, new ParquetWriterOptions
        {
            Compression = CompressionKind.None,
            DataPageVersion = ParquetDataPageVersion.V2,
            WritePageIndexes = false,
            TargetDataPageSizeBytes = 1024 * 1024,
            BufferChunkSizeBytes = 128
        });
        var rowGroup = writer.StartRowGroup();
        var serialized = rowGroup.CreateSerializedColumn<int>(schema.LeafColumns[0]);
        serialized.Serialize(values);
        rowGroup.Write(serialized);
        writer.CloseFile();

        var bytes = stream.ToArray();
        using var source = FullValueOracle.Source(bytes);
        using var reader = schema.CreateReader(source);
        if (reader.RowGroups.Count != 1 || reader.RowGroups[0].RowCount != (ulong)values.Length)
            throw new InvalidOperationException($"Encoding case '{name}' changed the row-group shape.");

        var actual = new int[values.Length];
        var offset = 0;
        foreach (var buffer in reader.RowGroups[0].Column<int>(schema.LeafColumns[0]))
            foreach (var value in buffer.Values)
                actual[offset++] = value;
        if (offset != values.Length || !actual.AsSpan().SequenceEqual(values))
            throw new InvalidOperationException($"Encoding case '{name}' changed values during readback.");
    }

    static void WriteAlpFloatAndDoubleExceptions()
    {
        var floatValues = Enumerable.Range(0, 1_024)
            .Select(i => i switch
            {
                101 => float.NaN,
                203 => float.PositiveInfinity,
                307 => float.NegativeInfinity,
                409 => -0.0f,
                503 => float.MaxValue,
                _ => i * 0.25f
            }).ToArray();
        var doubleValues = Enumerable.Range(0, 1_024)
            .Select(i => i switch
            {
                107 => double.NaN,
                211 => double.PositiveInfinity,
                313 => double.NegativeInfinity,
                419 => -0.0d,
                521 => double.MaxValue,
                _ => i * 0.125d
            }).ToArray();
        var schema = new ParquetSchema(
        [
            ColumnDefinition.Leaf("alp-float-exceptions", ParquetPhysicalType.Float,
                new ColumnOptions(encodings: ImmutableArray.Create(EncodingKind.Alp))),
            ColumnDefinition.Leaf("alp-double-exceptions", ParquetPhysicalType.Double,
                new ColumnOptions(encodings: ImmutableArray.Create(EncodingKind.Alp)))
        ]);
        using var stream = new MemoryStream();
        var writer = schema.CreateWriter(stream, new ParquetWriterOptions
        {
            Compression = CompressionKind.None,
            WritePageIndexes = false,
            TargetDataPageSizeBytes = 1024 * 1024
        });
        var rowGroup = writer.StartRowGroup();
        var floatColumn = rowGroup.CreateSerializedColumn<float>(schema.LeafColumns[0]);
        floatColumn.Serialize(floatValues);
        rowGroup.Write(floatColumn);
        var doubleColumn = rowGroup.CreateSerializedColumn<double>(schema.LeafColumns[1]);
        doubleColumn.Serialize(doubleValues);
        rowGroup.Write(doubleColumn);
        writer.CloseFile();

        using var source = FullValueOracle.Source(stream.ToArray());
        using var reader = schema.CreateReader(source);
        if (reader.RowGroups.Count != 1 || reader.RowGroups[0].RowCount != 1_024)
            throw new InvalidOperationException("ALP exception case changed the row-group shape.");
        var actualFloats = new List<float>();
        foreach (var buffer in reader.RowGroups[0].Column<float>(schema.LeafColumns[0]))
            actualFloats.AddRange(buffer.Values.ToArray());
        var actualDoubles = new List<double>();
        foreach (var buffer in reader.RowGroups[0].Column<double>(schema.LeafColumns[1]))
            actualDoubles.AddRange(buffer.Values.ToArray());
        if (!SameFloatBits(floatValues, actualFloats) || !SameDoubleBits(doubleValues, actualDoubles))
            throw new InvalidOperationException("ALP exception case changed a float or double bit pattern.");
    }

    static void WriteFixedBinaryByteStreamSplitGuidAndDecimal()
    {
        Guid[] guids =
        [
            Guid.Empty,
            Guid.Parse("00112233-4455-6677-8899-aabbccddeeff"),
            Guid.Parse("ffeeddcc-bbaa-9988-7766-554433221100")
        ];
        decimal[] decimals = [0m, 1.234567m, -1.234567m];
        var schema = new ParquetSchema(
        [
            ColumnDefinition.RequiredLeaf("bss-guid", ParquetPhysicalType.FixedLenByteArray,
                new ColumnOptions(typeLength: 16, encodings: ImmutableArray.Create(EncodingKind.ByteStreamSplit)),
                new LogicalType.Uuid()),
            ColumnDefinition.RequiredLeaf("bss-decimal", ParquetPhysicalType.FixedLenByteArray,
                new ColumnOptions(typeLength: 16, encodings: ImmutableArray.Create(EncodingKind.ByteStreamSplit)),
                new LogicalType.Decimal(28, 6))
        ]);
        using var stream = new MemoryStream();
        var writer = schema.CreateWriter(stream, new ParquetWriterOptions { Compression = CompressionKind.None });
        var rowGroup = writer.StartRowGroup();
        var guidColumn = rowGroup.CreateSerializedColumn<Guid>(schema.LeafColumns[0]);
        guidColumn.Serialize(guids);
        rowGroup.Write(guidColumn);
        var decimalColumn = rowGroup.CreateSerializedColumn<decimal>(schema.LeafColumns[1]);
        decimalColumn.Serialize(decimals);
        rowGroup.Write(decimalColumn);
        writer.CloseFile();

        using var reader = schema.CreateReader(FullValueOracle.Source(stream.ToArray()));
        if (reader.RowGroups.Count != 1 || reader.RowGroups[0].RowCount != (ulong)guids.Length)
            throw new InvalidOperationException("Fixed-binary BSS changed the row-group shape.");
        var actualGuids = new List<byte[]>();
        foreach (var buffer in reader.RowGroups[0].Column<byte>(schema.LeafColumns[0]))
            for (var i = 0; i < buffer.Count; i++)
                actualGuids.Add(buffer.GetValue(i).ToArray());
        var actualDecimals = new List<decimal>();
        foreach (var buffer in reader.RowGroups[0].Column<decimal>(schema.LeafColumns[1]))
            actualDecimals.AddRange(buffer.Values.ToArray());
        Span<byte> expectedGuid = stackalloc byte[16];
        var guidsMatch = actualGuids.Count == guids.Length;
        for (var i = 0; guidsMatch && i < guids.Length; i++)
        {
            guids[i].TryWriteBytes(expectedGuid, bigEndian: true, out _);
            guidsMatch = actualGuids[i].AsSpan().SequenceEqual(expectedGuid);
        }
        if (!guidsMatch || !actualDecimals.SequenceEqual(decimals))
            throw new InvalidOperationException("Fixed-binary BSS changed UUID or Decimal values.");
    }

    // Plank 2ecda7b (#229, "Support fixed-width binary memory values in all encodings") made
    // ReadOnlyMemory<byte> a supported carrier for FIXED_LEN_BYTE_ARRAY under every encoding; this
    // used to expect the BYTE_STREAM_SPLIT rejection. Now the values must round-trip, including a
    // slice that does not start at offset 0 of its array.
    static void WriteFixedByteStreamSplitReadOnlyMemory()
    {
        var schema = new ParquetSchema([
            ColumnDefinition.RequiredLeaf("fixed-bss-memory", ParquetPhysicalType.FixedLenByteArray,
                new ColumnOptions(typeLength: 3, encodings: ImmutableArray.Create(EncodingKind.ByteStreamSplit)))
        ]);
        var backing = new byte[] { 9, 1, 2, 3, 4, 5, 6, 9 };
        ReadOnlyMemory<byte>[] values = [backing.AsMemory(1, 3), backing.AsMemory(4, 3), new byte[] { 0xff, 0, 0x80 }];
        using var stream = new MemoryStream();
        var writer = schema.CreateWriter(stream, new ParquetWriterOptions
        {
            Compression = CompressionKind.None
        });
        var column = writer.CreateSerializedColumn<ReadOnlyMemory<byte>>(schema.LeafColumns[0]);
        column.Serialize(values);
        writer.StartRowGroup().Write(column);
        writer.CloseFile();

        using var reader = schema.CreateReader(FullValueOracle.Source(stream.ToArray()));
        if (reader.RowGroups.Count != 1 || reader.RowGroups[0].RowCount != (ulong)values.Length)
            throw new InvalidOperationException("Fixed BSS ReadOnlyMemory changed the row-group shape.");
        var actual = new List<byte[]>();
        foreach (var buffer in reader.RowGroups[0].Column<byte>(schema.LeafColumns[0]))
            for (var i = 0; i < buffer.Count; i++)
                actual.Add(buffer.GetValue(i).ToArray());
        if (actual.Count != values.Length)
            throw new InvalidOperationException("Fixed BSS ReadOnlyMemory changed the value count.");
        for (var i = 0; i < values.Length; i++)
            if (!actual[i].AsSpan().SequenceEqual(values[i].Span))
                throw new InvalidOperationException($"Fixed BSS ReadOnlyMemory changed value {i}.");
    }

    static void WriteRequiredReadOnlyMemoryDictionary()
    {
        ReadOnlyMemory<byte>[] values =
        [
            new byte[] { 0x10, 0x20 },
            new byte[] { 0x30 },
            new byte[] { 0x10, 0x20 },
            new byte[] { 0x40, 0x50, 0x60 },
            new byte[] { 0x30 }
        ];
        var expected = values.Select(value => value.ToArray()).ToArray();
        var schema = new ParquetSchema([
            ColumnDefinition.RequiredLeaf("dictionary-rom", ParquetPhysicalType.ByteArray,
                new ColumnOptions(encodings: ImmutableArray.Create(EncodingKind.RleDictionary)))
        ]);
        using var stream = new MemoryStream();
        var writer = schema.CreateWriter(stream, new ParquetWriterOptions { Compression = CompressionKind.None });
        var column = writer.CreateSerializedColumn<ReadOnlyMemory<byte>>(schema.LeafColumns[0]);
        column.Serialize(values);
        writer.StartRowGroup().Write(column);
        writer.CloseFile();

        using var reader = schema.CreateReader(FullValueOracle.Source(stream.ToArray()));
        var actual = new List<byte[]>();
        foreach (var buffer in reader.RowGroups[0].Column<byte>(schema.LeafColumns[0]))
            for (var i = 0; i < buffer.Count; i++)
                actual.Add(buffer.GetValue(i).ToArray());
        if (actual.Count != expected.Length || actual.Where((value, index) => !value.AsSpan().SequenceEqual(expected[index])).Any())
            throw new InvalidOperationException("ReadOnlyMemory dictionary changed values or insertion order.");
    }

    static void WriteDeltaLengthByteArrayReadOnlyMemoryShapes()
    {
        ReadOnlyMemory<byte>[] required =
        [
            ReadOnlyMemory<byte>.Empty,
            new byte[] { 0x10, 0x20 },
            new byte[] { 0x30 }
        ];
        ReadOnlyMemory<byte>?[] optional =
        [
            null,
            ReadOnlyMemory<byte>.Empty,
            new byte[] { 0xA0, 0xB0 }
        ];
        ReadOnlyMemory<byte>?[] emptyPayloads =
        [
            null,
            ReadOnlyMemory<byte>.Empty,
            null
        ];
        ReadOnlyMemory<byte>[] requiredEmptyPayloads =
        [
            ReadOnlyMemory<byte>.Empty,
            ReadOnlyMemory<byte>.Empty,
            ReadOnlyMemory<byte>.Empty
        ];
        byte[][] requiredByteArrays = [[], [0x60, 0x70], [0x80]];
        byte[][] requiredEmptyByteArrays = [[], [], []];
        byte[]?[] optionalByteArrays = [null, [0x55], []];
        byte[]?[][] expected =
        [
            required.Select(value => value.ToArray()).ToArray(),
            [null, [], [0xA0, 0xB0]],
            [null, [], null],
            requiredEmptyPayloads.Select(value => value.ToArray()).ToArray(),
            requiredByteArrays,
            requiredEmptyByteArrays,
            [null, [0x55], []]
        ];
        var deltaLength = ImmutableArray.Create(EncodingKind.DeltaLengthByteArray);
        var schema = new ParquetSchema(
        [
            ColumnDefinition.RequiredLeaf("required-delta-length-rom", ParquetPhysicalType.ByteArray,
                new ColumnOptions(encodings: deltaLength)),
            ColumnDefinition.OptionalLeaf("optional-delta-length-rom", ParquetPhysicalType.ByteArray,
                new ColumnOptions(ParquetRepetition.Optional, encodings: deltaLength)),
            ColumnDefinition.OptionalLeaf("empty-delta-length-rom", ParquetPhysicalType.ByteArray,
                new ColumnOptions(ParquetRepetition.Optional, encodings: deltaLength)),
            ColumnDefinition.RequiredLeaf("zero-payload-delta-length-rom", ParquetPhysicalType.ByteArray,
                new ColumnOptions(encodings: deltaLength)),
            ColumnDefinition.RequiredLeaf("required-delta-length-byte-array", ParquetPhysicalType.ByteArray,
                new ColumnOptions(encodings: deltaLength)),
            ColumnDefinition.RequiredLeaf("zero-payload-delta-length-byte-array", ParquetPhysicalType.ByteArray,
                new ColumnOptions(encodings: deltaLength)),
            ColumnDefinition.OptionalLeaf("optional-delta-length-byte-array", ParquetPhysicalType.ByteArray,
                new ColumnOptions(ParquetRepetition.Optional, encodings: deltaLength))
        ]);

        using var stream = new MemoryStream();
        var writer = schema.CreateWriter(stream, new ParquetWriterOptions { Compression = CompressionKind.None });
        var rowGroup = writer.StartRowGroup();
        var requiredColumn = rowGroup.CreateSerializedColumn<ReadOnlyMemory<byte>>(schema.LeafColumns[0]);
        requiredColumn.Serialize(required);
        rowGroup.Write(requiredColumn);
        var optionalColumn = rowGroup.CreateSerializedColumn<ReadOnlyMemory<byte>?>(schema.LeafColumns[1]);
        optionalColumn.Serialize(optional);
        rowGroup.Write(optionalColumn);
        var emptyColumn = rowGroup.CreateSerializedColumn<ReadOnlyMemory<byte>?>(schema.LeafColumns[2]);
        emptyColumn.Serialize(emptyPayloads);
        rowGroup.Write(emptyColumn);
        var zeroPayloadColumn = rowGroup.CreateSerializedColumn<ReadOnlyMemory<byte>>(schema.LeafColumns[3]);
        zeroPayloadColumn.Serialize(requiredEmptyPayloads);
        rowGroup.Write(zeroPayloadColumn);
        var requiredByteArrayColumn = rowGroup.CreateSerializedColumn<byte[]>(schema.LeafColumns[4]);
        requiredByteArrayColumn.Serialize(requiredByteArrays);
        rowGroup.Write(requiredByteArrayColumn);
        var requiredEmptyByteArrayColumn = rowGroup.CreateSerializedColumn<byte[]>(schema.LeafColumns[5]);
        requiredEmptyByteArrayColumn.Serialize(requiredEmptyByteArrays);
        rowGroup.Write(requiredEmptyByteArrayColumn);
        var optionalByteArrayColumn = rowGroup.CreateSerializedColumn<byte[]>(schema.LeafColumns[6]);
        optionalByteArrayColumn.Serialize(optionalByteArrays);
        rowGroup.Write(optionalByteArrayColumn);
        writer.CloseFile();

        using var reader = schema.CreateReader(FullValueOracle.Source(stream.ToArray()));
        if (reader.RowGroups.Count != 1 || reader.RowGroups[0].RowCount != (ulong)required.Length)
            throw new InvalidOperationException("DELTA_LENGTH_BYTE_ARRAY ReadOnlyMemory case changed the row-group shape.");
        AssertBinaryReadBack(reader, 0, expected[0]);
        AssertBinaryReadBack(reader, 1, expected[1]);
        AssertBinaryReadBack(reader, 2, expected[2]);
        AssertBinaryReadBack(reader, 3, expected[3]);
        AssertBinaryReadBack(reader, 4, expected[4]);
        AssertBinaryReadBack(reader, 5, expected[5]);
        AssertBinaryReadBack(reader, 6, expected[6]);
    }

    static void WriteDeltaByteArrayReadOnlyMemoryShapes()
    {
        ReadOnlyMemory<byte>[] required =
        [
            "prefix/one"u8.ToArray(),
            "prefix/two"u8.ToArray(),
            "prefix/two"u8.ToArray(),
            ReadOnlyMemory<byte>.Empty
        ];
        ReadOnlyMemory<byte>?[] optional =
        [
            null,
            "prefix/one"u8.ToArray(),
            "prefix/two"u8.ToArray(),
            "prefix/two"u8.ToArray()
        ];
        ReadOnlyMemory<byte>[] requiredEmpty =
        [
            ReadOnlyMemory<byte>.Empty,
            ReadOnlyMemory<byte>.Empty,
            ReadOnlyMemory<byte>.Empty,
            ReadOnlyMemory<byte>.Empty
        ];
        ReadOnlyMemory<byte>?[] optionalEmpty = [null, null, null, null];
        var deltaByteArray = ImmutableArray.Create(EncodingKind.DeltaByteArray);
        var schema = new ParquetSchema(
        [
            ColumnDefinition.RequiredLeaf("required-delta-byte-array-rom", ParquetPhysicalType.ByteArray,
                new ColumnOptions(encodings: deltaByteArray)),
            ColumnDefinition.OptionalLeaf("optional-delta-byte-array-rom", ParquetPhysicalType.ByteArray,
                new ColumnOptions(ParquetRepetition.Optional, encodings: deltaByteArray)),
            ColumnDefinition.RequiredLeaf("empty-delta-byte-array-rom", ParquetPhysicalType.ByteArray,
                new ColumnOptions(encodings: deltaByteArray)),
            ColumnDefinition.OptionalLeaf("empty-optional-delta-byte-array-rom", ParquetPhysicalType.ByteArray,
                new ColumnOptions(ParquetRepetition.Optional, encodings: deltaByteArray))
        ]);

        using var stream = new MemoryStream();
        using var writer = schema.CreateWriter(stream, new ParquetWriterOptions { Compression = CompressionKind.None });
        var rowGroup = writer.StartRowGroup();
        var requiredColumn = rowGroup.CreateSerializedColumn<ReadOnlyMemory<byte>>(schema.LeafColumns[0]);
        requiredColumn.Serialize(required);
        rowGroup.Write(requiredColumn);
        var optionalColumn = rowGroup.CreateSerializedColumn<ReadOnlyMemory<byte>?>(schema.LeafColumns[1]);
        optionalColumn.Serialize(optional);
        rowGroup.Write(optionalColumn);
        var emptyColumn = rowGroup.CreateSerializedColumn<ReadOnlyMemory<byte>>(schema.LeafColumns[2]);
        emptyColumn.Serialize(requiredEmpty);
        rowGroup.Write(emptyColumn);
        var optionalEmptyColumn = rowGroup.CreateSerializedColumn<ReadOnlyMemory<byte>?>(schema.LeafColumns[3]);
        optionalEmptyColumn.Serialize(optionalEmpty);
        rowGroup.Write(optionalEmptyColumn);
        writer.CloseFile();

        using var reader = schema.CreateReader(FullValueOracle.Source(stream.ToArray()));
        AssertBinaryReadBack(reader, 0, required.Select(static value => value.ToArray()).ToArray());
        AssertBinaryReadBack(reader, 1,
            optional.Select(static value => value?.ToArray()).ToArray());
        AssertBinaryReadBack(reader, 2, [[], [], [], []]);
        AssertBinaryReadBack(reader, 3, [null, null, null, null]);
    }

    static void WriteRequiredDeltaLengthByteArrayNullRejection()
    {
        var schema = new ParquetSchema([
            ColumnDefinition.RequiredLeaf("required-delta-length-byte-array-null", ParquetPhysicalType.ByteArray,
                new ColumnOptions(encodings: ImmutableArray.Create(EncodingKind.DeltaLengthByteArray)))
        ]);
        using var stream = new MemoryStream();
        using var writer = schema.CreateWriter(stream, new ParquetWriterOptions { Compression = CompressionKind.None });
        var column = writer.CreateSerializedColumn<byte[]>(schema.LeafColumns[0]);
        try
        {
            column.Serialize([null!]);
        }
        catch (InvalidOperationException error) when (error.Message.Contains("does not support null values", StringComparison.Ordinal))
        {
            return;
        }

        throw new InvalidOperationException("Required DELTA_LENGTH_BYTE_ARRAY accepted a null byte array.");
    }

    static bool SameFloatBits(float[] expected, List<float> actual)
    {
        if (expected.Length != actual.Count)
            return false;
        for (var i = 0; i < expected.Length; i++)
            if (BitConverter.SingleToInt32Bits(expected[i]) != BitConverter.SingleToInt32Bits(actual[i]))
                return false;
        return true;
    }

    static bool SameDoubleBits(double[] expected, List<double> actual)
    {
        if (expected.Length != actual.Count)
            return false;
        for (var i = 0; i < expected.Length; i++)
            if (BitConverter.DoubleToInt64Bits(expected[i]) != BitConverter.DoubleToInt64Bits(actual[i]))
                return false;
        return true;
    }
}
