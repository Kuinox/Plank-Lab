using System.Text;
using Plank.RowApi;
using Plank.Writing;

namespace Plank.Fuzzing;

/// <summary>
/// Writes rows through the generated row-oriented writer, then reads them back
/// through the generated row reader and checks they survived.
/// </summary>
/// <remarks>
/// The row API's write half was entirely unfuzzed, and not for want of trying:
/// it cannot be driven without generated code. RowWriterBase&lt;TSlot&gt; is
/// abstract over four methods the generator emits, and RowGroupWriterCore&lt;TSlot&gt;
/// is generic over a generated slot type, so a fuzzer has nothing to instantiate.
/// The writer fuzz target drives the columnar writer only, and the reader target
/// drives RowReaderCore directly — which covers the read states but never the
/// write pipeline. RowBufferSlot, RowValueSizeEstimator, PipelineRowWriterBase,
/// RowApiColumnWriteState and RowWriterBase all measured zero.
///
/// This closes that by giving the fuzzing project its own [ParquetSchema] row
/// types (see RowFuzzSchemas) and driving the generated pipeline over values the
/// fuzzer chooses. It is a round trip, so a value that comes back wrong is a
/// finding and not just a crash — the same standard the columnar writer target
/// holds itself to.
/// </remarks>
public static partial class PlankRowApiFuzzTarget
{
    // Rows are cheap but each one costs a write and a read-back, and AFL wants
    // many small executions rather than few large ones.
    const int MaxRows = 48;
    const int MaxNestedRows = 16;
    const int MaxBinaryLength = 24;
    static ReadOnlySpan<byte> NestedRowMagic => "NRW1"u8;
    static ReadOnlySpan<byte> NullableBinaryMagic => "RBN1"u8;
    static ReadOnlySpan<byte> PipelineControlMagic => "RWP1"u8;
    static ReadOnlySpan<byte> DirectRowGroupMagic => "RWG1"u8;
    static ReadOnlySpan<byte> WideMagic => "RWW1"u8;
    static ReadOnlySpan<byte> WideNullableMagic => "RWN1"u8;
    static ReadOnlySpan<byte> WideDatasetMagic => "RDW1"u8;
    static ReadOnlySpan<byte> WideNullableDatasetMagic => "RDN1"u8;
    static ReadOnlySpan<byte> WideMergeMagic => "RMW1"u8;
    static ReadOnlySpan<byte> WideNullableMergeMagic => "RMN1"u8;

    public static void Execute(ReadOnlySpan<byte> data)
    {
        if (data.IsEmpty)
            return;

        // No expected-exception filter: every route below is valid API usage over bytes the
        // writer produced itself, so any exception (including InvalidOperationException,
        // NotSupportedException and CorruptParquetException) is a library finding.
        if (data.StartsWith(WideMagic))
        {
            var wideCursor = new Cursor(data[WideMagic.Length..]);
            RowFuzzWideRoutes.Run(ref wideCursor);
            return;
        }

        if (data.StartsWith(WideDatasetMagic))
        {
            var datasetCursor = new Cursor(data[WideDatasetMagic.Length..]);
            RowFuzzWideRoutes.RunDataset(ref datasetCursor);
            return;
        }

        if (data.StartsWith(WideNullableDatasetMagic))
        {
            var datasetCursor = new Cursor(data[WideNullableDatasetMagic.Length..]);
            RowFuzzWideNullableRoutes.RunDataset(ref datasetCursor);
            return;
        }

        if (data.StartsWith(WideMergeMagic))
        {
            var mergeCursor = new Cursor(data[WideMergeMagic.Length..]);
            RowFuzzWideRoutes.RunMerge(ref mergeCursor);
            return;
        }

        if (data.StartsWith(WideNullableMergeMagic))
        {
            var mergeCursor = new Cursor(data[WideNullableMergeMagic.Length..]);
            RowFuzzWideNullableRoutes.RunMerge(ref mergeCursor);
            return;
        }

        if (data.StartsWith(WideNullableMagic))
        {
            var wideCursor = new Cursor(data[WideNullableMagic.Length..]);
            RowFuzzWideNullableRoutes.Run(ref wideCursor);
            return;
        }

        if (data.StartsWith(NullableBinaryMagic))
        {
            RunNullableBinary();
            return;
        }

        if (data.StartsWith(DirectRowGroupMagic))
        {
            var directCursor = new Cursor(data[DirectRowGroupMagic.Length..]);
            RunDirectRowGroups(ref directCursor);
            return;
        }

        if (data.StartsWith(PipelineControlMagic))
        {
            var pipelineCursor = new Cursor(data[PipelineControlMagic.Length..]);
            RunPipelineControls(ref pipelineCursor);
            return;
        }

        if (data.StartsWith(NestedRowMagic))
        {
            var nestedCursor = new Cursor(data[NestedRowMagic.Length..]);
            RunNested(ref nestedCursor);
            return;
        }

        var cursor = new Cursor(data[1..]);
        switch (data[0] % 3)
        {
            case 0: RunFixed(ref cursor); break;
            case 1: RunNullable(ref cursor); break;
            default: RunBinary(ref cursor); break;
        }
    }

    static void RunFixed(ref Cursor cursor)
    {
        var count = cursor.NextInt(1, MaxRows + 1);
        var expected = new (bool Flag, int Id, long Sequence, double Measure)[count];
        for (var i = 0; i < count; i++)
            expected[i] = (cursor.NextInt(0, 2) == 0, cursor.NextInt32(), cursor.NextInt64(), cursor.NextDouble());

        using var stream = new MemoryStream();
        var writer = RowFuzzFixed.CreateRowWriter(stream, WriterOptions(ref cursor));
        foreach (var (flag, id, sequence, measure) in expected)
        {
            var row = writer.GetRow();
            row.Flag = flag;
            row.Id = id;
            row.Sequence = sequence;
            row.Measure = measure;
        }

        writer.Complete();

        var index = 0;
        using var reader = RowFuzzFixed.CreateRowReader(new MemoryStream(stream.ToArray(), writable: false),
            options: ReaderOptions(ref cursor));
        while (reader.MoveNext())
        {
            var row = reader.Current;
            var want = expected[index];
            Check(row.Flag == want.Flag, "Flag", index);
            Check(row.Id == want.Id, "Id", index);
            Check(row.Sequence == want.Sequence, "Sequence", index);
            // Compared bitwise so NaN matches NaN, which equality does not.
            Check(BitConverter.DoubleToInt64Bits(row.Measure) == BitConverter.DoubleToInt64Bits(want.Measure),
                "Measure", index);
            index++;
        }

        Check(index == count, "row count", index);
    }

    static void RunNullable(ref Cursor cursor)
    {
        var count = cursor.NextInt(1, MaxRows + 1);
        var expected = new (int? Id, long? Sequence, double? Measure, bool? Flag)[count];
        for (var i = 0; i < count; i++)
            expected[i] = (
                cursor.NextInt(0, 4) == 0 ? null : cursor.NextInt32(),
                cursor.NextInt(0, 4) == 0 ? null : cursor.NextInt64(),
                cursor.NextInt(0, 4) == 0 ? null : cursor.NextDouble(),
                cursor.NextInt(0, 4) == 0 ? null : cursor.NextInt(0, 2) == 0);

        using var stream = new MemoryStream();
        var writer = RowFuzzNullable.CreateRowWriter(stream, WriterOptions(ref cursor));
        foreach (var (id, sequence, measure, flag) in expected)
        {
            var row = writer.GetRow();
            row.Id = id;
            row.Sequence = sequence;
            row.Measure = measure;
            row.Flag = flag;
        }

        writer.Complete();

        var index = 0;
        using var reader = RowFuzzNullable.CreateRowReader(new MemoryStream(stream.ToArray(), writable: false),
            options: ReaderOptions(ref cursor));
        while (reader.MoveNext())
        {
            var row = reader.Current;
            var want = expected[index];
            Check(row.Id == want.Id, "Id", index);
            Check(row.Sequence == want.Sequence, "Sequence", index);
            Check(row.Flag == want.Flag, "Flag", index);
            Check(NullableDoubleMatches(row.Measure, want.Measure), "Measure", index);
            index++;
        }

        Check(index == count, "row count", index);
    }

    static void RunBinary(ref Cursor cursor)
    {
        var count = cursor.NextInt(1, MaxRows + 1);
        var expected = new (int Id, byte[] Payload, string Label)[count];
        for (var i = 0; i < count; i++)
            expected[i] = (cursor.NextInt32(), cursor.NextBytes(MaxBinaryLength), cursor.NextLabel());

        using var stream = new MemoryStream();
        var writer = RowFuzzBinary.CreateRowWriter(stream, WriterOptions(ref cursor));
        foreach (var (id, payload, label) in expected)
        {
            var row = writer.GetRow();
            row.Id = id;
            row.Payload = payload;
            row.Label = label;
        }

        writer.Complete();

        var index = 0;
        using var reader = RowFuzzBinary.CreateRowReader(new MemoryStream(stream.ToArray(), writable: false),
            options: ReaderOptions(ref cursor));
        while (reader.MoveNext())
        {
            var row = reader.Current;
            var want = expected[index];
            Check(row.Id == want.Id, "Id", index);
            Check(row.Payload.Value.SequenceEqual(want.Payload), "Payload", index);
            Check(string.Equals(row.Label, want.Label, StringComparison.Ordinal), "Label", index);
            index++;
        }

        Check(index == count, "row count", index);
    }

    static void RunNullableBinary()
    {
        byte[]?[] expected = [null, [], [0, 1, 255]];
        var options = new ParquetWriterOptions
        {
            TargetRowGroupSizeBytes = 1,
            RowApiInitialRowCapacity = expected.Length
        };
        using var stream = new MemoryStream();
        using (var writer = RowFuzzNullableBinary.CreateRowWriter(stream, options))
        {
            foreach (var payload in expected)
                writer.GetRow().Payload = payload;
            writer.Complete();
        }

        using var reader = RowFuzzNullableBinary.CreateRowReader(
            new MemoryStream(stream.ToArray(), writable: false));
        var index = 0;
        while (reader.MoveNext())
        {
            Check(index < expected.Length, "nullable binary extra row", index);
            var actual = reader.Current.Payload;
            var want = expected[index];
            Check(want is null ? actual.IsNull : !actual.IsNull && actual.Value.SequenceEqual(want),
                "nullable binary Payload", index);
            index++;
        }

        Check(index == expected.Length, "nullable binary row count", index);
    }

    static void RunNested(ref Cursor cursor)
    {
        var count = cursor.NextInt(4, MaxNestedRows + 1);
        var shapeOffset = cursor.NextInt(0, 4);
        var writerOptions = WriterOptions(ref cursor);
        var expected = new RowFuzzNested[count];
        for (var i = 0; i < count; i++)
            expected[i] = CreateNestedRow(ref cursor, i, (i + shapeOffset) % 4);

        using var stream = new MemoryStream();
        var writer = RowFuzzNested.CreateRowWriter(stream, writerOptions);
        foreach (var want in expected)
        {
            var row = writer.GetRow();
            row.Sequence = want.Sequence;
            row.CorrelationId = want.CorrelationId;
            row.Label = want.Label;
            row.Values = want.Values;
            row.Scores = want.Scores;
            row.Location = want.Location;
            row.Items = want.Items;
            row.Names = want.Names;
            row.Identifiers = want.Identifiers;
            row.Dates = want.Dates;
            row.Times = want.Times;
            row.Timestamps = want.Timestamps;
            row.Instants = want.Instants;
        }
        writer.Complete();

        var index = 0;
        using var reader = RowFuzzNested.CreateRowReader(new MemoryStream(stream.ToArray(), writable: false),
            options: ReaderOptions(ref cursor));
        while (reader.MoveNext())
        {
            var row = reader.Current;
            var want = expected[index];
            Check(row.Sequence == want.Sequence, "Sequence", index);
            Check(row.CorrelationId == want.CorrelationId, "CorrelationId", index);
            Check(string.Equals(row.Label, want.Label, StringComparison.Ordinal), "Label", index);
            Check(NestedValuesMatch(row.Values, want.Values), "Values", index);
            Check(NestedScoresMatch(row.Scores, want.Scores), "Scores", index);
            Check(row.Location == want.Location, "Location", index);
            Check(NestedItemsMatch(row.Items, want.Items), "Items", index);
            Check(NestedListMatches(row.Names, want.Names), "Names", index);
            Check(NestedListMatches(row.Identifiers, want.Identifiers), "Identifiers", index);
            Check(NestedListMatches(row.Dates, want.Dates), "Dates", index);
            Check(NestedListMatches(row.Times, want.Times), "Times", index);
            Check(NestedListMatches(row.Timestamps, want.Timestamps), "Timestamps", index);
            Check(NestedListMatches(row.Instants, want.Instants), "Instants", index);
            index++;
        }

        Check(index == count, "row count", index);
    }

    // The ordinary routes use stream writers only. Keep these controls behind an
    // exact marker so AFL can discover the public rolling-file, reset, and
    // callback overloads without changing how existing row-api seeds decode.
    // Each route is deliberately small and checks every value through the
    // generated reader before returning.
    static void RunPipelineControls(ref Cursor cursor)
    {
        var count = cursor.NextInt(3, 7);
        var baseId = cursor.NextInt32() & 0x0FFF_FFFF;
        var rollingExpected = CreatePipelineRows(ref cursor, baseId, count, "roll");
        var store = new InMemoryFileStore();
        var file = new InMemoryDatasetFile(store);
        var paths = Enumerable.Range(0, count + 1)
            .Select(static i => Encoding.UTF8.GetBytes($"row-api-rolling-{i:D2}.parquet"))
            .ToArray();
        ParquetFilePath selectPath = (ulong fileIndex, IParquetBufferPool _, out ParquetBuffer? allocation) =>
        {
            allocation = null;
            return paths[checked((int)fileIndex)];
        };

        using (file)
        using (var writer = RowFuzzBinary.CreateRowWriter(selectPath, file, PipelineWriterOptions(targetFileSizeBytes: 1)))
        {
            foreach (var want in rollingExpected)
            {
                var row = writer.GetRow();
                row.Id = want.Id;
                row.Label = want.Label;
                row.Payload = want.Payload;
            }
            writer.Complete();
        }

        if (store.Files.Count != count)
            throw new RowApiRoundTripException($"Rolling writer produced {store.Files.Count} files for {count} row groups.");

        var rollingActual = new Dictionary<int, (string Label, byte[] Payload)>();
        foreach (var (path, stream) in store.Files)
        {
            if (stream.Length == 0)
                throw new RowApiRoundTripException($"Rolling writer produced an empty file at '{path}'.");
            foreach (var (id, value) in ReadBinaryRows(stream.ToArray()))
                if (!rollingActual.TryAdd(id, value))
                    throw new RowApiRoundTripException($"Rolling writer duplicated row {id} across files.");
        }
        CheckBinaryRows(rollingActual, rollingExpected, "rolling row writer");

        var firstStream = new MemoryStream();
        var resetStream = new MemoryStream();
        var firstExpected = CreatePipelineRows(ref cursor, baseId + 1024, 1, "before-reset");
        var resetExpected = CreatePipelineRows(ref cursor, baseId + 2048, 2, "after-reset");
        using (var writer = RowFuzzBinary.CreateRowWriter(firstStream, PipelineWriterOptions()))
        {
            WriteBinaryRows(writer, firstExpected);
            writer.Complete();
            writer.Reset(resetStream);
            WriteBinaryRows(writer, resetExpected);
            writer.Complete();
        }
        CheckBinaryRows(ReadBinaryRows(firstStream.ToArray()), firstExpected, "row writer before reset");
        CheckBinaryRows(ReadBinaryRows(resetStream.ToArray()), resetExpected, "row writer after reset");

        var callbackStream = new MemoryStream();
        var callbackExpected = CreatePipelineRows(ref cursor, baseId + 3072, count, "callback");
        var callbackRows = 0;
        var callbackCount = 0;
        using (var writer = RowFuzzBinary.CreateRowWriter(callbackStream, flushedRows =>
        {
            if (flushedRows <= 0)
                throw new RowApiRoundTripException($"Row writer flush callback received {flushedRows} rows.");
            callbackRows += flushedRows;
            callbackCount++;
        }, PipelineWriterOptions()))
        {
            WriteBinaryRows(writer, callbackExpected);
            writer.Complete();
        }
        if (callbackRows != count || callbackCount != count)
            throw new RowApiRoundTripException(
                $"Row writer reported {callbackRows} rows in {callbackCount} flushes; expected {count} of each.");
        CheckBinaryRows(ReadBinaryRows(callbackStream.ToArray()), callbackExpected, "row writer flush callback");

        RunFixedAdvanceControl();
    }

    // Keep TargetRowGroupSizeBytes above the fixed row's 21-byte size so the
    // generated fixed-width writer takes both false arms of TryAdvanceBefore.
    // The ordinary fuzz options cap this value at three bytes and only reach
    // its row-group boundary path.
    static void RunFixedAdvanceControl()
    {
        const int count = 2;
        var options = new ParquetWriterOptions
        {
            TargetRowGroupSizeBytes = 64,
            RowApiInitialRowCapacity = 4
        };
        var expected = new (bool Flag, int Id, long Sequence, double Measure)[]
        {
            (true, 17, 23, 1.5),
            (false, 29, 31, -2.25)
        };

        using var stream = new MemoryStream();
        using var writer = RowFuzzFixed.CreateRowWriter(stream, options);
        foreach (var want in expected)
        {
            var row = writer.GetRow();
            row.Flag = want.Flag;
            row.Id = want.Id;
            row.Sequence = want.Sequence;
            row.Measure = want.Measure;
        }
        writer.Complete();

        using var reader = RowFuzzFixed.CreateRowReader(new MemoryStream(stream.ToArray(), writable: false));
        for (var i = 0; i < count; i++)
        {
            if (!reader.MoveNext())
                throw new RowApiRoundTripException($"Fixed advance control lost row {i}.");
            var actual = reader.Current;
            var want = expected[i];
            Check(actual.Flag == want.Flag, "fixed advance Flag", i);
            Check(actual.Id == want.Id, "fixed advance Id", i);
            Check(actual.Sequence == want.Sequence, "fixed advance Sequence", i);
            Check(BitConverter.DoubleToInt64Bits(actual.Measure) == BitConverter.DoubleToInt64Bits(want.Measure),
                "fixed advance Measure", i);
        }
        Check(!reader.MoveNext(), "fixed advance trailing row", count);
    }

    static RowApiPipelineValue[] CreatePipelineRows(ref Cursor cursor, int baseId, int count, string prefix)
    {
        var rows = new RowApiPipelineValue[count];
        for (var i = 0; i < rows.Length; i++)
        {
            var labelSuffix = unchecked((uint)cursor.NextInt32()).ToString("x8");
            rows[i] = new RowApiPipelineValue(
                baseId + i,
                $"{prefix}-{i}-{labelSuffix}",
                cursor.NextBytes(MaxBinaryLength));
        }
        return rows;
    }

    // Exercise the generated row writer that targets a caller-owned RowGroupWriter,
    // alongside the pipeline writer routes above. The explicit second empty group
    // covers Write() when no row is pending and is checked in the generated reader's
    // row-group metadata as well as its row stream.
    //
    // The row count and RowApiInitialRowCapacity are drawn independently: tying the
    // capacity to the row count (as this route first did) means the direct writer
    // never has to grow, which hid a heap overrun when GetRow() ran past capacity.
    // Every call sequence here is valid API usage, so an InvalidOperationException
    // is a finding rather than a rejected input.
    static void RunDirectRowGroups(ref Cursor cursor)
    {
        try
        {
            RunDirectRowGroupsCore(ref cursor);
        }
        catch (InvalidOperationException ex)
        {
            throw new RowApiRoundTripException($"Direct row-group writer rejected valid usage: {ex.Message}");
        }
    }

    static void RunDirectRowGroupsCore(ref Cursor cursor)
    {
        var count = cursor.NextInt(1, MaxRows + 1);
        var fixedCapacity = cursor.NextInt(1, 9);
        var binaryCapacity = cursor.NextInt(1, 9);
        var fixedExpected = new (bool Flag, int Id, long Sequence, double Measure)[count];
        for (var i = 0; i < count; i++)
            fixedExpected[i] = (cursor.NextInt(0, 2) != 0, cursor.NextInt32(), cursor.NextInt64(), cursor.NextDouble());

        var fixedOptions = new ParquetWriterOptions { RowApiInitialRowCapacity = fixedCapacity };
        using var fixedStream = new MemoryStream();
        using (var parquetWriter = RowFuzzFixed.Schema.CreateWriter(fixedStream, fixedOptions))
        {
            var rowGroupWriter = RowFuzzFixed.CreateRowWriter(parquetWriter.StartRowGroup(), fixedOptions);
            foreach (var want in fixedExpected)
            {
                var row = rowGroupWriter.GetRow();
                row.Flag = want.Flag;
                row.Id = want.Id;
                row.Sequence = want.Sequence;
                row.Measure = want.Measure;
            }
            rowGroupWriter.Write();

            var emptyGroupWriter = RowFuzzFixed.CreateRowWriter(parquetWriter.StartRowGroup(), fixedOptions);
            emptyGroupWriter.Write();
            parquetWriter.CloseFile();
        }

        var fixedBytes = fixedStream.ToArray();
        using (var metadataReader = RowFuzzFixed.Schema.CreateReader(new MemoryStream(fixedBytes, writable: false)))
        {
            Check(metadataReader.RowGroups.Count == 2, "direct fixed row-group count", 0);
            Check(metadataReader.RowGroups[0].RowCount == (ulong)count, "direct fixed row count", 0);
            Check(metadataReader.RowGroups[1].RowCount == 0, "direct empty row group", 0);
        }

        using (var reader = RowFuzzFixed.CreateRowReader(new MemoryStream(fixedBytes, writable: false)))
        {
            var index = 0;
            while (reader.MoveNext())
            {
                Check(index < fixedExpected.Length, "direct fixed extra row", index);
                var row = reader.Current;
                var want = fixedExpected[index];
                Check(row.Flag == want.Flag, "direct fixed Flag", index);
                Check(row.Id == want.Id, "direct fixed Id", index);
                Check(row.Sequence == want.Sequence, "direct fixed Sequence", index);
                Check(BitConverter.DoubleToInt64Bits(row.Measure) == BitConverter.DoubleToInt64Bits(want.Measure),
                    "direct fixed Measure", index);
                index++;
            }
            Check(index == count, "direct fixed row count", index);
        }

        var binaryExpected = new (int Id, byte[] Payload, string Label)[count];
        for (var i = 0; i < count; i++)
            binaryExpected[i] = (cursor.NextInt32(), cursor.NextBytes(MaxBinaryLength), cursor.NextLabel());

        var binaryOptions = new ParquetWriterOptions { RowApiInitialRowCapacity = binaryCapacity };
        using var binaryStream = new MemoryStream();
        using (var parquetWriter = RowFuzzBinary.Schema.CreateWriter(binaryStream, binaryOptions))
        {
            var rowGroupWriter = RowFuzzBinary.CreateRowWriter(parquetWriter.StartRowGroup(), binaryOptions);
            foreach (var want in binaryExpected)
            {
                var row = rowGroupWriter.GetRow();
                row.Id = want.Id;
                row.Payload = want.Payload;
                row.Label = want.Label;
            }
            rowGroupWriter.Write();
            parquetWriter.CloseFile();
        }

        var binaryBytes = binaryStream.ToArray();
        using (var metadataReader = RowFuzzBinary.Schema.CreateReader(new MemoryStream(binaryBytes, writable: false)))
        {
            Check(metadataReader.RowGroups.Count == 1, "direct binary row-group count", 0);
            Check(metadataReader.RowGroups[0].RowCount == (ulong)count, "direct binary metadata row count", 0);
        }

        using var binaryReader = RowFuzzBinary.CreateRowReader(new MemoryStream(binaryBytes, writable: false));
        var binaryIndex = 0;
        while (binaryReader.MoveNext())
        {
            Check(binaryIndex < binaryExpected.Length, "direct binary extra row", binaryIndex);
            var row = binaryReader.Current;
            var want = binaryExpected[binaryIndex];
            Check(row.Id == want.Id, "direct binary Id", binaryIndex);
            Check(row.Payload.Value.SequenceEqual(want.Payload), "direct binary Payload", binaryIndex);
            Check(string.Equals(row.Label, want.Label, StringComparison.Ordinal), "direct binary Label", binaryIndex);
            binaryIndex++;
        }
        Check(binaryIndex == count, "direct binary row count", binaryIndex);
    }

    static void WriteBinaryRows(RowFuzzBinary.PipelineWriter writer, RowApiPipelineValue[] rows)
    {
        foreach (var want in rows)
        {
            var row = writer.GetRow();
            row.Id = want.Id;
            row.Label = want.Label;
            row.Payload = want.Payload;
        }
    }

    static Dictionary<int, (string Label, byte[] Payload)> ReadBinaryRows(byte[] bytes)
    {
        var rows = new Dictionary<int, (string Label, byte[] Payload)>();
        using var reader = RowFuzzBinary.CreateRowReader(new MemoryStream(bytes, writable: false));
        while (reader.MoveNext())
        {
            var row = reader.Current;
            if (!rows.TryAdd(row.Id, (row.Label, row.Payload.Value.ToArray())))
                throw new RowApiRoundTripException($"Row API readback duplicated row {row.Id}.");
        }
        return rows;
    }

    static void CheckBinaryRows(Dictionary<int, (string Label, byte[] Payload)> actual,
        RowApiPipelineValue[] expected, string route)
    {
        if (actual.Count != expected.Length)
            throw new RowApiRoundTripException($"{route} read back {actual.Count} rows; expected {expected.Length}.");
        foreach (var want in expected)
            if (!actual.TryGetValue(want.Id, out var got)
                || !string.Equals(got.Label, want.Label, StringComparison.Ordinal)
                || !got.Payload.AsSpan().SequenceEqual(want.Payload))
                throw new RowApiRoundTripException($"{route} did not preserve row {want.Id} exactly.");
    }

    static ParquetWriterOptions PipelineWriterOptions(ulong targetFileSizeBytes = ulong.MaxValue)
        => new()
        {
            TargetRowGroupSizeBytes = 1,
            TargetFileSizeBytes = targetFileSizeBytes,
            RowApiInitialRowCapacity = 1,
            RowApiMaxParallelism = 1
        };

    readonly record struct RowApiPipelineValue(int Id, string Label, byte[] Payload);

    static RowFuzzNested CreateNestedRow(ref Cursor cursor, int row, int shape)
    {
        var valueSeed = cursor.NextInt32();
        var entrySeed = cursor.NextInt32();
        var guid = cursor.NextGuid();
        var label = cursor.NextLabel();
        return new RowFuzzNested
        {
            Sequence = cursor.NextInt32(),
            CorrelationId = guid,
            Label = label,
            Values = shape switch
            {
                0 => null,
                1 => [],
                2 => [[valueSeed, null], []],
                _ => [[valueSeed + 1]]
            },
            Scores = shape switch
            {
                0 => null,
                1 => [],
                2 => new Dictionary<int, int?> { [row] = valueSeed, [row + 1] = null },
                _ => new Dictionary<int, int?> { [row] = valueSeed }
            },
            Location = row % 3 == 0 ? null : new RowFuzzAddress
            {
                Zip = 10000 + row,
                Rank = unchecked((byte)valueSeed),
                City = label,
                Token = cursor.NextGuid()
            },
            Items = shape switch
            {
                0 => null,
                1 => [],
                2 => [new RowFuzzEntry { Id = entrySeed, Amount = entrySeed * 100L }],
                _ =>
                [
                    new RowFuzzEntry { Id = entrySeed, Amount = entrySeed * 100L },
                    new RowFuzzEntry { Id = entrySeed + 1, Amount = (entrySeed + 1) * 100L }
                ]
            },
            Names = shape switch
            {
                0 => null,
                1 => [],
                2 => [label, null],
                _ => [label]
            },
            Identifiers = shape switch
            {
                0 => null,
                1 => [],
                2 => [guid, null],
                _ => [guid]
            },
            Dates = shape switch
            {
                0 => null,
                1 => [],
                2 => [new DateOnly(2026, 1, 1).AddDays(row), null],
                _ => [new DateOnly(2026, 1, 1).AddDays(row)]
            },
            Times = shape switch
            {
                0 => null,
                1 => [],
                2 => [new TimeOnly(1, 2, 3).AddMinutes(row), null],
                _ => [new TimeOnly(1, 2, 3).AddMinutes(row)]
            },
            Timestamps = shape switch
            {
                0 => null,
                1 => [],
                2 => [DateTime.UnixEpoch.AddMinutes(row), null],
                _ => [DateTime.UnixEpoch.AddMinutes(row)]
            },
            Instants = shape switch
            {
                0 => null,
                1 => [],
                2 => [CreateInstant(row), null],
                _ => [CreateInstant(row)]
            }
        };
    }

    static DateTimeOffset CreateInstant(int row)
        => new DateTimeOffset(2026, 1, 1, 0, 0, 0, TimeSpan.FromHours(2)).AddMinutes(row);

    static bool NestedValuesMatch(int?[][]? actual, int?[][]? expected)
    {
        if (actual is null || expected is null)
            return actual is null && expected is null;
        if (actual.Length != expected.Length)
            return false;
        for (var i = 0; i < actual.Length; i++)
        {
            if (actual[i] is null || expected[i] is null)
            {
                if (actual[i] is not null || expected[i] is not null)
                    return false;
            }
            else if (!actual[i].AsSpan().SequenceEqual(expected[i]))
                return false;
        }
        return true;
    }

    static bool NestedScoresMatch(Dictionary<int, int?>? actual, Dictionary<int, int?>? expected)
    {
        if (actual is null || expected is null)
            return actual is null && expected is null;
        if (actual.Count != expected.Count)
            return false;
        foreach (var pair in expected)
            if (!actual.TryGetValue(pair.Key, out var value) || value != pair.Value)
                return false;
        return true;
    }

    static bool NestedItemsMatch(List<RowFuzzEntry>? actual, List<RowFuzzEntry>? expected)
    {
        if (actual is null || expected is null)
            return actual is null && expected is null;
        return actual.SequenceEqual(expected);
    }

    static bool NestedListMatches<T>(List<T>? actual, List<T>? expected)
    {
        if (actual is null || expected is null)
            return actual is null && expected is null;
        return actual.SequenceEqual(expected);
    }

    static bool NullableDoubleMatches(double? actual, double? expected)
    {
        if (actual is null || expected is null)
            return actual is null && expected is null;
        return BitConverter.DoubleToInt64Bits(actual.Value) == BitConverter.DoubleToInt64Bits(expected.Value);
    }

    // Tiny row-group targets make the generated file contain several groups,
    // allowing RowReaderCore's parallel prefetch and read-ahead paths to run.
    static ParquetWriterOptions WriterOptions(ref Cursor cursor)
        => new()
        {
            TargetRowGroupSizeBytes = (ulong)cursor.NextInt(1, 4),
            RowApiInitialRowCapacity = cursor.NextInt(1, 9),
            RowApiMaxParallelism = 1
        };

    static RowReaderOptions ReaderOptions(ref Cursor cursor)
    {
        var workers = cursor.NextInt(1, 5);
        return new RowReaderOptions
        {
            MaxReadAheadRowGroups = cursor.NextInt(0, 2),
            Execution = new ParquetExecutionOptions { WorkerCount = workers }
        };
    }

    // A round-trip mismatch is a correctness bug, not corrupt input: the bytes
    // were produced by the writer moments earlier. It has to escape the target's
    // expected-exception filter to be recorded, so it is not one of those types.
    static void Check(bool condition, string what, int row)
    {
        if (!condition)
            throw new RowApiRoundTripException($"Row API round trip lost '{what}' at row {row}.");
    }

    /// <summary>Signals that a written row did not read back as written.</summary>
    public sealed class RowApiRoundTripException(string message) : Exception(message);

    // Deliberately not the writer target's ByteCursor: that one is private to it
    // and shaped for column specs. Running out of input yields zeros rather than
    // throwing, so a truncated case stays a valid smaller case.
    internal ref partial struct Cursor(ReadOnlySpan<byte> data)
    {
        readonly ReadOnlySpan<byte> _data = data;
        int _offset;

        internal byte NextByte()
            => _offset < _data.Length ? _data[_offset++] : (byte)0;

        internal int NextInt(int minInclusive, int maxExclusive)
        {
            var range = maxExclusive - minInclusive;
            return range <= 0 ? minInclusive : minInclusive + (NextByte() % range);
        }

        internal int NextInt32()
            => (NextByte() << 24) | (NextByte() << 16) | (NextByte() << 8) | NextByte();

        internal long NextInt64()
            => ((long)NextInt32() << 32) | (uint)NextInt32();

        internal Guid NextGuid()
            => new(NextInt32(), unchecked((short)NextInt32()), unchecked((short)NextInt32()),
                NextByte(), NextByte(), NextByte(), NextByte(), NextByte(), NextByte(), NextByte(), NextByte());

        // Bit patterns rather than a numeric range, so NaN, the infinities and
        // the denormals all come up.
        internal double NextDouble()
            => BitConverter.Int64BitsToDouble(NextInt64());

        internal byte[] NextBytes(int maxLength)
        {
            var bytes = new byte[NextInt(0, maxLength + 1)];
            for (var i = 0; i < bytes.Length; i++)
                bytes[i] = NextByte();
            return bytes;
        }

        // Built from scalar values rather than raw bytes: an unpaired surrogate
        // is not round-trippable through UTF-8 by any encoder, so comparing it
        // back would report a defect that is not one.
        internal string NextLabel()
        {
            var length = NextInt(0, 9);
            var builder = new StringBuilder(length);
            for (var i = 0; i < length; i++)
            {
                var pick = NextByte();
                builder.Append(pick switch
                {
                    < 0x40 => (char)('a' + (pick % 26)),      // ASCII
                    < 0x80 => (char)(0x00A1 + (pick % 0x40)), // two-byte UTF-8
                    < 0xC0 => (char)(0x0800 + (pick % 0x40)), // three-byte UTF-8
                    _ => '�'
                });
            }

            return builder.ToString();
        }
    }
}
