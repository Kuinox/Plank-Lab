using System.Collections.Immutable;
using Plank.Reading;
using Plank.Reading.Logical;
using Plank.RowApi;
using Plank.Schema;

namespace Plank.Fuzzing;

public static class PlankReaderFuzzTarget
{
    static readonly ParquetSchema[] Schemas = BuildSchemas();

    public static void Execute(ReadOnlySpan<byte> data)
    {
        try
        {
            Run(data.IsEmpty ? (byte)0 : data[0], data.IsEmpty ? [] : data[1..].ToArray());
        }
        catch (Exception ex) when (ex is CorruptParquetException or NotSupportedException or InvalidOperationException) { }
    }

    public static Exception? GetHandledException(byte[] data)
    {
        ArgumentNullException.ThrowIfNull(data);
        try
        {
            Run(data.Length == 0 ? (byte)0 : data[0], data.Length == 0 ? [] : data[1..]);
            return null;
        }
        catch (Exception ex) when (ex is CorruptParquetException or NotSupportedException or InvalidOperationException)
        {
            return ex;
        }
    }

    static void Run(byte selector, byte[] fileBytes)
    {
        // Bit 7 routes the input to a decompressor instead of the Parquet reader.
        // It is a separate target sharing this one's harness and corpus, because
        // the codecs cannot be reached through a file: the corpus can only
        // contain codecs the writer can produce, and it cannot produce Lz4Legacy.
        // Checked before anything else so the payload is untouched by the
        // reader's own selector bits.
        if ((selector & 0x80) != 0)
        {
            PlankDecompressorFuzzTarget.Execute(fileBytes);
            return;
        }

        // Bit 6 picks the read source, and it decides more than the 54 lines of
        // StreamReadSource. ParquetFileReader.TryBorrowSource hard-tests for
        // MemoryReadSource, so with the memory source every page read borrows a
        // span straight out of the input — and the other side of both borrow
        // branches in ParquetPageCursor, the ones that rent a buffer and copy
        // into it, had never run. A stream source is also the only one that can
        // fail a read part-way, which is a different failure mode from a span
        // that is simply too short.
        using var source = (selector & 0x40) != 0
            ? new StreamReadSource(new MemoryStream(fileBytes, writable: false))
            : (IParquetReadSource)new MemoryReadSource(fileBytes);

        // Bits 4 and 5 pick the reader options. Both were pinned to their
        // defaults, and both defaults skip code:
        //
        // VerifyPageCrc defaults off, and with it off the reader never hashes a
        // page — ParquetCrc32 measured 0/54 lines, and the mismatch diagnostic
        // had never run either. The corpus now carries CRC-bearing seeds
        // (gen-crc-*), which are inert unless verification is on.
        //
        // Strict defaults on. Non-strict binding is a separate matching pass
        // over the requested schema against the file's, so half the projection
        // cases now take it.
        var options = new ParquetReaderOptions
        {
            VerifyPageCrc = (selector & 0x10) != 0,
            Strict = (selector & 0x20) == 0
        };

        // A quarter of the inputs go through the row-oriented API. It is a
        // separate public reader with its own buffering and projection, and it
        // measured 0% over a 14k-input corpus — neither fuzz target drove it.
        if ((selector & 3) == 2)
        {
            DrainRowApi(source, options.VerifyPageCrc, selector);
            return;
        }

        // Of the rest, half bind the file's own schema. Reading through a fixed
        // requested schema — the only thing this target used to do — can never
        // reach a decoder for a type that schema does not name, so FLOAT, INT96,
        // FIXED_LEN_BYTE_ARRAY, every logical type and every compression codec
        // the file declares were unreachable no matter how long it ran. The
        // other half keeps exercising the strict projection path, which is where
        // the requested schema is matched against the file's.
        using var reader = (selector & 1) == 0
            ? OpenWithFileSchema(source, options)
            : Schemas[(selector >> 1) % Schemas.Length].CreateReader(source, options);

        // Parquet.Net's generic reader is a useful second opinion for simple
        // flat columns, but its handling of newer encodings and nested shapes
        // differs. Do not treat unsupported features as file rejections.
        var canCompareWithParquetNet = (selector & 1) == 0
            && reader.Schema.LeafColumns.Length > 0
            && reader.Schema.LeafColumns.All(static column =>
                column.MaxDefinitionLevel == 0 && column.MaxRepetitionLevel == 0
                && column.LogicalType is null
                && column.PhysicalType is ParquetPhysicalType.Boolean or ParquetPhysicalType.Int32
                    or ParquetPhysicalType.Int64 or ParquetPhysicalType.Float or ParquetPhysicalType.Double);

        var decodedColumns = new List<Array>();
        // Only the file-schema route reads every column with the file's own
        // types, so only it can be compared value-for-value with Arrow.
        var traces = (selector & 1) == 0 ? new List<ColumnTrace?[]>() : null;
        if ((selector & 1) == 0)
            DrainFileMetadata(reader);
        foreach (var group in reader.RowGroups)
        {
            if (group.RowCount > 4096)
                canCompareWithParquetNet = false;
            var groupTraces = traces is null ? null : new ColumnTrace?[reader.Schema.LeafColumns.Length];
            traces?.Add(groupTraces!);
            for (var columnIndex = 0; columnIndex < reader.Schema.LeafColumns.Length; columnIndex++)
            {
                var column = reader.Schema.LeafColumns[columnIndex];
                DrainMetadata(group, column);
                if (canCompareWithParquetNet)
                    foreach (var encoding in group.GetColumnMetadata(column).Encodings)
                        if (encoding is not (EncodingKind.Plain or EncodingKind.Rle
                            or EncodingKind.PlainDictionary or EncodingKind.RleDictionary))
                            canCompareWithParquetNet = false;

                // The trace reads the physical values, which is the level Arrow
                // can be compared at. An API refusal (not a file rejection) just
                // leaves this column uncompared.
                if (groupTraces is not null)
                {
                    try
                    {
                        groupTraces[columnIndex] = ColumnTrace.CapturePlank(group, column);
                    }
                    catch (InvalidOperationException) { }
                }

                if (canCompareWithParquetNet)
                    decodedColumns.Add(DrainFlatColumnForComparison(group, column));
                // Annotated columns still go through their logical CLR type, so
                // the conversions (decimal, timestamps, ...) keep being fuzzed.
                else if (groupTraces?[columnIndex] is null || column.LogicalType is not null)
                    DrainColumn(group, column);

                // Bit 2 (file-schema route only; bits 2-3 are otherwise unused
                // there) reads the column a second time with the opposite
                // nullability. See CrossCheckReadPaths.
                if ((selector & 4) != 0 && (selector & 1) == 0)
                    CrossCheckReadPaths(group, column);
            }
        }

        // Bit 3 (file-schema route) reads the file again through a page pruner.
        // See CrossCheckPrunedReads.
        if ((selector & 8) != 0 && (selector & 1) == 0)
            CrossCheckPrunedReads(fileBytes, options);

        // Only the file-schema route has read every column in the file. A
        // projection can succeed while the columns it omitted are corrupt.
        // The row API and decompressor routes return above this point.
        if ((selector & 1) == 0 && ReaderAcceptanceOracle.HasParquetHeader(fileBytes))
        {
            ReaderAcceptanceOracle.VerifyWithParquetSharp(fileBytes, traces);
            if (canCompareWithParquetNet)
            {
                var types = new ParquetPhysicalType[reader.Schema.LeafColumns.Length];
                for (var i = 0; i < types.Length; i++)
                    types[i] = reader.Schema.LeafColumns[i].PhysicalType;
                ReaderAcceptanceOracle.VerifyWithParquetNet(fileBytes, types, decodedColumns);
            }
        }
    }

    // Draining values only ever exercised the value decoders. Everything a
    // caller reaches through the metadata APIs — page index, offset index,
    // column statistics, bloom filters — parses offsets and lengths straight
    // out of the footer and was never executed at all: PageMetadataReader and
    // BloomFilterReader measured 0% over a 14k-input corpus.
    // Footer metadata that nothing reads unless asked: key/value pairs, sorting
    // columns, created_by, schema node names, CRS strings and the geospatial
    // statistics, which are parsed lazily on request. ParquetKeyValueMetadataInfo,
    // ParquetSortingColumn and ParquetGeospatialStatistics.Read measured 0%
    // because the harness never asked.
    static void DrainFileMetadata(ParquetReader reader)
    {
        var metadata = reader.PhysicalReader.Metadata;
        _ = metadata.FileVersion + (long)metadata.FooterOffset + metadata.FooterLength;
        if (metadata.HasCreatedBy)
            Consume(metadata.CreatedByUtf8);
        for (var i = 0; i < metadata.KeyValueMetadataCount; i++)
        {
            Consume(metadata.KeyValueMetadataKeyUtf8(i));
            Consume(metadata.KeyValueMetadataValueUtf8(i));
        }
        foreach (var sorting in metadata.SortingColumns)
            _ = sorting.ColumnOrdinal + (sorting.Descending ? 1 : 0) + (sorting.NullsFirst ? 2 : 0);
        for (var node = 0; node < metadata.SchemaNodeCount; node++)
        {
            Consume(metadata.SchemaNodeNameUtf8(node));
            Consume(metadata.SchemaNodeLogicalTypeCrsUtf8(node));
        }
        for (var column = 0; column < metadata.ColumnCount; column++)
        {
            var schema = metadata.ColumnSchema(column);
            for (var segment = 0; segment < schema.PathSegmentCount; segment++)
                Consume(metadata.ColumnPathSegmentUtf8(column, segment));
            Consume(metadata.ColumnLogicalTypeCrsUtf8(column));
        }
        for (var group = 0; group < metadata.RowGroupCount; group++)
        {
            foreach (var sorting in metadata.RowGroupSortingColumns(group))
                _ = sorting.ColumnOrdinal;
            for (var column = 0; column < metadata.ColumnCount; column++)
            {
                _ = metadata.ColumnChunk(group, column);
                if (metadata.ReadGeospatialStatistics(group, column) is not { } geo)
                    continue;
                if (geo.BoundingBox is { } box)
                    _ = box.XMin + box.XMax + box.YMin + box.YMax + (box.ZMin ?? 0) + (box.ZMax ?? 0)
                        + (box.MMin ?? 0) + (box.MMax ?? 0);
                if (geo.GeospatialTypes is { } types)
                    foreach (var type in types)
                        _ = type;
            }
        }
    }

    static void DrainMetadata(RowGroup rowGroup, LeafColumn column)
    {
        var metadata = rowGroup.GetColumnMetadata(column);
        _ = metadata.ValueCount;
        _ = metadata.Compression;
        foreach (var encoding in metadata.Encodings)
            _ = encoding;

        var statistics = metadata.Statistics;
        Consume(statistics.Minimum);
        Consume(statistics.Maximum);
        _ = statistics.NullCount;

        using (var pages = metadata.OpenPages())
            for (var i = 0; i < pages.Count; i++)
            {
                var page = pages[i];
                _ = page.Offset;
                _ = page.CompressedSize;
                _ = page.FirstRowIndex;
                _ = page.RowCount;
                _ = page.IsNullPage;
                Consume(page.Statistics.Minimum);
                Consume(page.Statistics.Maximum);
            }

        if (!metadata.HasBloomFilter)
            return;
        var bloom = metadata.OpenBloomFilter();
        _ = bloom.BitsetSizeBytes;
        Consume(bloom.Bitset);
        _ = bloom.MightContain(0);
        _ = bloom.MightContain(long.MaxValue);
    }

    static void Consume(ReadOnlySpan<byte> bytes)
    {
        for (var i = 0; i < bytes.Length; i++)
            _ = bytes[i];
    }

    // RowReaderCore is normally reached through source-generated row types, but
    // it is public and takes the schema and descriptors directly, so the fuzzer
    // can drive it over whatever schema the file declares.
    static void DrainRowApi(IParquetReadSource source, bool verifyPageCrc, byte selector)
    {
        ParquetSchema schema;
        using (var probe = new ParquetReader())
        {
            probe.Reset(source);
            schema = probe.Schema;
        }

        var descriptors = new RowApiColumnDescriptor[schema.LeafColumns.Length];
        for (var i = 0; i < descriptors.Length; i++)
        {
            var descriptor = CreateRowApiDescriptor(schema.LeafColumns[i], i);
            // A leaf the fuzzer cannot describe (nesting deeper than two levels,
            // or a repeated binary leaf) would otherwise abort the whole file:
            // RowReaderCore requires one descriptor per leaf, in leaf order, so
            // there is no way to describe the rest of the columns without it.
            if (descriptor is null)
                return;
            descriptors[i] = descriptor;
        }

        // The row reader has its own page cursor and so its own CRC call sites,
        // separate from the columnar reader's.
        //
        // The worker pool stays off (WorkerCount 1). Its default,
        // Environment.ProcessorCount, honours CPU affinity, so it is already off
        // on a pinned worker; turning it on made several threads run
        // instrumented code at once, and SharpFuzz's previous-location state is
        // shared, so the edge map scrambled and AFL's stability fell from 92% to
        // 55%. Thread interleavings are not something this fuzzer explores well.
        //
        // Bit 3 resets the reader onto the same file and reads it again, as a
        // caller reusing one reader would; the second pass must return exactly
        // what the first did, which catches state carried across Reset.
        var rowOptions = new RowReaderOptions
        {
            VerifyPageCrc = verifyPageCrc,
            Execution = new ParquetExecutionOptions { WorkerCount = 1 }
        };
        var compareAfterReset = (selector & 8) != 0;
        using var rows = new RowReaderCore(source, schema, descriptors, projection: null,
            rowOptions, schemaEvolution: null);
        var first = ReadAllRows(rows, descriptors, compareAfterReset);
        if (!compareAfterReset)
            return;

        rows.Reset(source, projection: null);
        List<string>? second;
        try
        {
            second = ReadAllRows(rows, descriptors, record: true);
        }
        catch (CorruptParquetException error)
        {
            throw new ReaderAcceptanceMismatchException(
                "Plank row reader rejected a file after Reset that it read in full before.", error);
        }
        if (first!.Count != second!.Count)
            throw new ReaderAcceptanceMismatchException(
                $"Decoded value mismatch (Plank row reader reset) — {first.Count} values before Reset, {second.Count} after.");
        for (var i = 0; i < first.Count; i++)
            if (first[i] != second[i])
                throw new ReaderAcceptanceMismatchException(
                    $"Decoded value mismatch (Plank row reader reset) — value {i} differs: before {first[i]}, after {second[i]}.");
    }

    static List<string>? ReadAllRows(RowReaderCore rows, RowApiColumnDescriptor[] descriptors, bool record)
    {
        var values = record ? new List<string>() : null;
        while (rows.MoveNext())
            for (var i = 0; i < descriptors.Length; i++)
            {
                var value = ReadCurrent(rows, descriptors[i]);
                values?.Add(FormatRowValue(value));
            }
        return values;
    }

    static string FormatRowValue(object? value) => value switch
    {
        null => "null",
        byte[] bytes => Convert.ToHexString(bytes),
        Array array => "[" + string.Join(",", array.Cast<object?>().Select(FormatRowValue)) + "]",
        IFormattable formattable => formattable.ToString(null, System.Globalization.CultureInfo.InvariantCulture),
        _ => value.ToString() ?? ""
    };

    // Returns null when the leaf has no describable shape, which the caller
    // treats as "skip this file's row-API pass".
    static RowApiColumnDescriptor? CreateRowApiDescriptor(LeafColumn leaf, int index)
    {
        var name = $"p{index}";

        // A repeated leaf needs a nested descriptor; a flat one is rejected, and
        // that rejection is an InvalidOperationException the target swallows —
        // which is why every nested file silently skipped its row-API pass and
        // RowApiNestedColumnReadState measured 0/282 lines.
        if (leaf.MaxRepetitionLevel > 0)
            return CreateNestedDescriptor(leaf, name);

        // Binary leaves require the variable-length read state. A descriptor
        // of byte reaches the fixed-width state, which cannot decode BYTE_ARRAY
        // pages and used to abort this fuzz case before any binary values ran.
        return leaf.PhysicalType switch
        {
            ParquetPhysicalType.Boolean => new RowApiColumnDescriptor<bool>(name, leaf),
            ParquetPhysicalType.Int32 => new RowApiColumnDescriptor<int>(name, leaf),
            ParquetPhysicalType.Int64 => new RowApiColumnDescriptor<long>(name, leaf),
            ParquetPhysicalType.Float => new RowApiColumnDescriptor<float>(name, leaf),
            ParquetPhysicalType.Double => new RowApiColumnDescriptor<double>(name, leaf),
            _ => new RowApiColumnDescriptor<byte[]>(name, leaf)
        };
    }

    // The generated code computes its collection thresholds from the row type it
    // was generated for; the fuzzer only has the leaf, so it reconstructs them:
    // the innermost collection has an element at the leaf's maximum definition
    // level, and each enclosing one sits a level above. That is the correct
    // reading for the shapes the corpus generates, and for anything else it is
    // still a well-formed descriptor — a corrupt file can present any levels it
    // likes, which is the point.
    static RowApiColumnDescriptor? CreateNestedDescriptor(LeafColumn leaf, string name)
    {
        var repetition = leaf.MaxRepetitionLevel;
        var definition = leaf.MaxDefinitionLevel;

        // TShape has to be a closed generic, so only the depths spelled out here
        // are reachable. One and two cover every shape the corpus writes.
        if (repetition is not (1 or 2) || definition < repetition)
            return null;

        var levels = new RowApiCollectionLevel[repetition];
        for (var i = 0; i < repetition; i++)
        {
            var element = definition - (repetition - 1 - i);
            levels[i] = new RowApiCollectionLevel(i + 1, element - 1, element);
        }

        // A nested binary leaf decodes into byte[] dense elements — the read
        // state requires exactly that type and rejects anything else.
        return repetition == 1
            ? leaf.PhysicalType switch
            {
                ParquetPhysicalType.Boolean => new RowApiNestedColumnDescriptor<bool?[], bool>(name, leaf, levels),
                ParquetPhysicalType.Int32 => new RowApiNestedColumnDescriptor<int?[], int>(name, leaf, levels),
                ParquetPhysicalType.Int64 => new RowApiNestedColumnDescriptor<long?[], long>(name, leaf, levels),
                ParquetPhysicalType.Float => new RowApiNestedColumnDescriptor<float?[], float>(name, leaf, levels),
                ParquetPhysicalType.Double => new RowApiNestedColumnDescriptor<double?[], double>(name, leaf, levels),
                _ => new RowApiNestedColumnDescriptor<byte[][], byte[]>(name, leaf, levels)
            }
            : leaf.PhysicalType switch
            {
                ParquetPhysicalType.Boolean => new RowApiNestedColumnDescriptor<bool?[][], bool>(name, leaf, levels),
                ParquetPhysicalType.Int32 => new RowApiNestedColumnDescriptor<int?[][], int>(name, leaf, levels),
                ParquetPhysicalType.Int64 => new RowApiNestedColumnDescriptor<long?[][], long>(name, leaf, levels),
                ParquetPhysicalType.Float => new RowApiNestedColumnDescriptor<float?[][], float>(name, leaf, levels),
                ParquetPhysicalType.Double => new RowApiNestedColumnDescriptor<double?[][], double>(name, leaf, levels),
                _ => new RowApiNestedColumnDescriptor<byte[][][], byte[]>(name, leaf, levels)
            };
    }

    static object? ReadCurrent(RowReaderCore rows, RowApiColumnDescriptor descriptor)
    {
        switch (descriptor)
        {
            case RowApiColumnDescriptor<bool> typed: return rows.GetCurrent(typed);
            case RowApiColumnDescriptor<int> typed: return rows.GetCurrent(typed);
            case RowApiColumnDescriptor<long> typed: return rows.GetCurrent(typed);
            case RowApiColumnDescriptor<float> typed: return rows.GetCurrent(typed);
            case RowApiColumnDescriptor<double> typed: return rows.GetCurrent(typed);
            case RowApiColumnDescriptor<byte[]> typed:
            {
                // A span into the reader's buffer: touch it, and copy it only
                // because the caller may keep the value past the next row.
                var current = rows.GetCurrentBinary(typed);
                var span = current.Value;
                for (var i = 0; i < span.Length; i++)
                    _ = span[i];
                return current.IsNull ? null : span.ToArray();
            }

            // The materialized shape is what the repetition-level bookkeeping
            // produces, so walking it is what checks that bookkeeping.
            case RowApiNestedColumnDescriptor<bool?[], bool> typed: { var value = rows.GetCurrentNested(typed); Consume(value); return value; }
            case RowApiNestedColumnDescriptor<int?[], int> typed: { var value = rows.GetCurrentNested(typed); Consume(value); return value; }
            case RowApiNestedColumnDescriptor<long?[], long> typed: { var value = rows.GetCurrentNested(typed); Consume(value); return value; }
            case RowApiNestedColumnDescriptor<float?[], float> typed: { var value = rows.GetCurrentNested(typed); Consume(value); return value; }
            case RowApiNestedColumnDescriptor<double?[], double> typed: { var value = rows.GetCurrentNested(typed); Consume(value); return value; }

            case RowApiNestedColumnDescriptor<bool?[][], bool> typed: { var value = rows.GetCurrentNested(typed); Consume(value); return value; }
            case RowApiNestedColumnDescriptor<int?[][], int> typed: { var value = rows.GetCurrentNested(typed); Consume(value); return value; }
            case RowApiNestedColumnDescriptor<long?[][], long> typed: { var value = rows.GetCurrentNested(typed); Consume(value); return value; }
            case RowApiNestedColumnDescriptor<float?[][], float> typed: { var value = rows.GetCurrentNested(typed); Consume(value); return value; }
            case RowApiNestedColumnDescriptor<double?[][], double> typed: { var value = rows.GetCurrentNested(typed); Consume(value); return value; }

            case RowApiNestedColumnDescriptor<byte[][], byte[]> typed: { var value = rows.GetCurrentNested(typed); ConsumeBinaryShape(value); return value; }
            case RowApiNestedColumnDescriptor<byte[][][], byte[]> typed:
            {
                var shape = rows.GetCurrentNested(typed);
                if (shape is not null)
                    for (var i = 0; i < shape.Length; i++)
                        ConsumeBinaryShape(shape[i]);
                return shape;
            }
        }
        return null;
    }

    static void ConsumeBinaryShape(byte[][]? shape)
    {
        if (shape is null)
            return;
        for (var i = 0; i < shape.Length; i++)
            Consume(shape[i]);
    }

    static void Consume(byte[]? value)
    {
        if (value is null)
            return;
        for (var i = 0; i < value.Length; i++)
            _ = value[i];
    }

    static void Consume<T>(T?[]? shape) where T : struct
    {
        if (shape is null)
            return;
        for (var i = 0; i < shape.Length; i++)
            _ = shape[i];
    }

    static void Consume<T>(T?[][]? shape) where T : struct
    {
        if (shape is null)
            return;
        for (var i = 0; i < shape.Length; i++)
            Consume(shape[i]);
    }

    // Acceptance alone does not catch two readers successfully decoding the
    // same bytes to different values. The Parquet.Net route is deliberately
    // limited to required, flat, unannotated primitive columns, so their CLR
    // representations and row layout are unambiguous.
    static Array DrainFlatColumnForComparison(RowGroup rowGroup, LeafColumn column)
        => column.PhysicalType switch
        {
            ParquetPhysicalType.Boolean => DrainValues<bool>(rowGroup.Column<bool>(column)),
            ParquetPhysicalType.Int32 => DrainValues<int>(rowGroup.Column<int>(column)),
            ParquetPhysicalType.Int64 => DrainValues<long>(rowGroup.Column<long>(column)),
            ParquetPhysicalType.Float => DrainValues<float>(rowGroup.Column<float>(column)),
            ParquetPhysicalType.Double => DrainValues<double>(rowGroup.Column<double>(column)),
            _ => throw new InvalidOperationException("The decoded-value oracle received an unsupported column.")
        };

    static T[] DrainValues<T>(RowGroupColumn<T> buffers)
    {
        var values = new List<T>();
        foreach (var buffer in buffers)
            foreach (var value in buffer.Values)
                values.Add(value);
        return values.ToArray();
    }

    static ParquetReader OpenWithFileSchema(IParquetReadSource source, ParquetReaderOptions options)
    {
        var reader = new ParquetReader(options);
        reader.Reset(source);
        return reader;
    }

    // Every physical type has to be drained through the CLR type the reader
    // accepts for it, and an optional column has to be read as a nullable, or
    // the reader rejects the call before decoding anything. Missing cases here
    // are silent: the column is skipped and its decoder never runs, which is how
    // FLOAT, INT96 and FIXED_LEN_BYTE_ARRAY went unfuzzed.
    static void DrainColumn(RowGroup rowGroup, LeafColumn column)
    {
        // A converter column only reads as its converted type.
        switch (column.Converter)
        {
            case IntBoxConverter:
                if (column.MaxDefinitionLevel > 0) DrainBuffers(rowGroup.Column<IntBox?>(column));
                else DrainBuffers(rowGroup.Column<IntBox>(column));
                return;
            case LongBoxConverter:
                if (column.MaxDefinitionLevel > 0) DrainBuffers(rowGroup.Column<LongBox?>(column));
                else DrainBuffers(rowGroup.Column<LongBox>(column));
                return;
            case DoubleBoxConverter:
                if (column.MaxDefinitionLevel > 0) DrainBuffers(rowGroup.Column<DoubleBox?>(column));
                else DrainBuffers(rowGroup.Column<DoubleBox>(column));
                return;
        }

        // A repeated leaf has to go through NestedColumn<T>; the flat API refuses
        // it. Skipping them left the repetition-level decoding — the fiddliest
        // bookkeeping in the format — entirely unexercised.
        if (column.MaxRepetitionLevel > 0)
        {
            DrainNestedColumn(rowGroup, column);
            return;
        }

        // Reading an annotated column as its physical type skips the conversion
        // entirely — that is why seeding logical-type files changed nothing on
        // its own, and why ParquetDecimalConverter stayed at 0% with decimal
        // files in the corpus. The logical type has to pick the CLR type.
        if (column.LogicalType is not null && TryDrainLogicalColumn(rowGroup, column))
            return;

        // A non-zero max definition level means the value can be absent, whether
        // because the leaf itself is optional or because an ancestor group is.
        var optional = column.MaxDefinitionLevel > 0;
        switch (column.PhysicalType)
        {
            case ParquetPhysicalType.Boolean:
                if (optional) DrainBuffers(rowGroup.Column<bool?>(column));
                else DrainBuffers(rowGroup.Column<bool>(column));
                break;
            case ParquetPhysicalType.Int32:
                if (optional) DrainBuffers(rowGroup.Column<int?>(column));
                else DrainBuffers(rowGroup.Column<int>(column));
                break;
            case ParquetPhysicalType.Int64:
                if (optional) DrainBuffers(rowGroup.Column<long?>(column));
                else DrainBuffers(rowGroup.Column<long>(column));
                break;
            case ParquetPhysicalType.Float:
                if (optional) DrainBuffers(rowGroup.Column<float?>(column));
                else DrainBuffers(rowGroup.Column<float>(column));
                break;
            case ParquetPhysicalType.Double:
                if (optional) DrainBuffers(rowGroup.Column<double?>(column));
                else DrainBuffers(rowGroup.Column<double>(column));
                break;
            // ByteArray, FixedLenByteArray and Int96 are all read as spans of bytes.
            case ParquetPhysicalType.ByteArray:
            case ParquetPhysicalType.FixedLenByteArray:
            case ParquetPhysicalType.Int96:
                DrainBinaryBuffers(rowGroup.Column<byte>(column));
                break;
        }
    }

    // Returns false when the annotation has no distinct CLR representation, so
    // the caller falls back to the physical type. A mismatch between the
    // annotation and the physical type is a corrupt file rather than a target
    // bug, so those surface as the exceptions the harness already expects.
    static bool TryDrainLogicalColumn(RowGroup rowGroup, LeafColumn column)
    {
        var optional = column.MaxDefinitionLevel > 0;
        switch (column.LogicalType)
        {
            case LogicalType.Date:
                if (optional) DrainBuffers(rowGroup.Column<DateOnly?>(column));
                else DrainBuffers(rowGroup.Column<DateOnly>(column));
                return true;
            case LogicalType.Time:
                if (optional) DrainBuffers(rowGroup.Column<TimeOnly?>(column));
                else DrainBuffers(rowGroup.Column<TimeOnly>(column));
                return true;
            case LogicalType.Timestamp:
                if (optional) DrainBuffers(rowGroup.Column<DateTime?>(column));
                else DrainBuffers(rowGroup.Column<DateTime>(column));
                return true;
            case LogicalType.Decimal:
                if (optional) DrainBuffers(rowGroup.Column<decimal?>(column));
                else DrainBuffers(rowGroup.Column<decimal>(column));
                return true;
            case LogicalType.Uuid:
                if (optional) DrainBuffers(rowGroup.Column<Guid?>(column));
                else DrainBuffers(rowGroup.Column<Guid>(column));
                return true;
            case LogicalType.Int { BitWidth: 8, IsSigned: false }:
                if (optional) DrainBuffers(rowGroup.Column<byte?>(column));
                else DrainBuffers(rowGroup.Column<byte>(column));
                return true;
            case LogicalType.Int { BitWidth: 16, IsSigned: false }:
                if (optional) DrainBuffers(rowGroup.Column<ushort?>(column));
                else DrainBuffers(rowGroup.Column<ushort>(column));
                return true;
            case LogicalType.Int { BitWidth: 32, IsSigned: false }:
                if (optional) DrainBuffers(rowGroup.Column<uint?>(column));
                else DrainBuffers(rowGroup.Column<uint>(column));
                return true;
            case LogicalType.Int { BitWidth: 64, IsSigned: false }:
                if (optional) DrainBuffers(rowGroup.Column<ulong?>(column));
                else DrainBuffers(rowGroup.Column<ulong>(column));
                return true;
            default:
                // String, Json, Bson, Enum and the rest stay byte spans, which
                // the physical path already drains.
                return false;
        }
    }

    // Plank decodes a page through one of two families: the batched decoders
    // (TryStartFixedWidthPageBatches / TryStartEncodedPageBatches) and the
    // whole-page "IntoNative" decoders they fall back to. Reading with the
    // column's natural type always takes the batched side for flat columns,
    // so the whole-page decoders for every logical type and every encoding
    // (hundreds of lines, e.g. TryDecodeByteStreamSplitIntoNative) only ever
    // ran for nested columns. Asking for the other nullability (T? from a
    // required column, T from an optional one) routes the same pages through
    // the other family. The two are separate implementations of the same
    // decoding, so they must agree: same values for the rows both return, and
    // the same verdict on whether the page is corrupt. Either disagreement is a
    // Plank bug, reported like an oracle mismatch.
    static void CrossCheckReadPaths(RowGroup rowGroup, LeafColumn column)
    {
        if (column.MaxRepetitionLevel > 0)
            return;
        switch (column.LogicalType)
        {
            case LogicalType.Date: CrossCheck<DateOnly>(rowGroup, column); return;
            case LogicalType.Time: CrossCheck<TimeOnly>(rowGroup, column); return;
            case LogicalType.Timestamp: CrossCheck<DateTime>(rowGroup, column); return;
            case LogicalType.Decimal: CrossCheck<decimal>(rowGroup, column); return;
            case LogicalType.Uuid: CrossCheck<Guid>(rowGroup, column); return;
            case LogicalType.Int { BitWidth: 8, IsSigned: false }: CrossCheck<byte>(rowGroup, column); return;
            case LogicalType.Int { BitWidth: 16, IsSigned: false }: CrossCheck<ushort>(rowGroup, column); return;
            case LogicalType.Int { BitWidth: 32, IsSigned: false }: CrossCheck<uint>(rowGroup, column); return;
            case LogicalType.Int { BitWidth: 64, IsSigned: false }: CrossCheck<ulong>(rowGroup, column); return;
        }
        switch (column.PhysicalType)
        {
            case ParquetPhysicalType.Boolean: CrossCheck<bool>(rowGroup, column); return;
            case ParquetPhysicalType.Int32: CrossCheck<int>(rowGroup, column); return;
            case ParquetPhysicalType.Int64: CrossCheck<long>(rowGroup, column); return;
            case ParquetPhysicalType.Float: CrossCheck<float>(rowGroup, column); return;
            case ParquetPhysicalType.Double: CrossCheck<double>(rowGroup, column); return;
        }
    }

    static void CrossCheck<T>(RowGroup rowGroup, LeafColumn column) where T : struct
    {
        // A null from the T? path is a row the T path cannot represent, so it is
        // skipped rather than compared.
        RequireSameReads($"{typeof(T).Name} column '{column.Path}'",
            "T? path", TryReadPath(() => Array.ConvertAll(DrainValues(rowGroup.Column<T?>(column)), static v => (object?)v)),
            "T path", TryReadPath(() => Array.ConvertAll(DrainValues(rowGroup.Column<T>(column)), static v => (object?)v)),
            skipNullsOfFirst: true);
    }

    // Two Plank read paths over the same column must give the same verdict on
    // corruption and the same values for the rows both return. The natural read
    // already ran, so a corrupt page has been reported by now; this only checks
    // that the paths agree with each other.
    static void RequireSameReads(string what,
        string firstName, (object?[]? Values, Exception? Error) first,
        string secondName, (object?[]? Values, Exception? Error) second,
        bool skipNullsOfFirst = false, bool secondMayRejectMore = false)
    {
        if ((first.Error is CorruptParquetException) != (second.Error is CorruptParquetException)
            && !(secondMayRejectMore && second.Error is CorruptParquetException))
            throw new ReaderAcceptanceMismatchException(
                $"Plank read paths disagree on corruption for {what}: " +
                $"{firstName} {Describe(first.Error)}, {secondName} {Describe(second.Error)}.",
                first.Error ?? second.Error!);
        if (first.Values is not { } a || second.Values is not { } b)
            return;
        if (a.Length != b.Length)
            throw new ReaderAcceptanceMismatchException(
                $"Decoded value mismatch (Plank read paths) — entry count differs for {what}: " +
                $"{firstName} {a.Length}, {secondName} {b.Length}.");
        for (var i = 0; i < a.Length; i++)
            if (!(skipNullsOfFirst && a[i] is null) && !Equals(a[i], b[i]))
                throw new ReaderAcceptanceMismatchException(
                    $"Decoded value mismatch (Plank read paths) — value differs for {what} at row {i}: " +
                    $"{firstName} {a[i]}, {secondName} {b[i]}.");
    }

    // A pruned scan (ParquetReader.Reset with a ParquetPagePruner) is a separate
    // cursor: it walks the page metadata (offset index, or a header scan when
    // there is none) and seeks to the pages the callback accepts, where the
    // plain scan just walks the chunk. ParquetPageCursor.MoveNextPruned and the
    // page-metadata handle had never run. A pruner that accepts every page must
    // return exactly what the plain scan returns, with the same verdict on
    // corruption. A pruner that skips every other page has no reference to
    // compare with, but it reaches the seek-past-a-page branches and must not
    // fail in any way other than rejecting the file.
    static readonly ParquetPagePruner AcceptAllPages = static (in ParquetDataPageMetadata _) => true;
    static readonly ParquetPagePruner AcceptEvenPages =
        static (in ParquetDataPageMetadata page) => page.PageOrdinal % 2 == 0;

    static void CrossCheckPrunedReads(byte[] fileBytes, ParquetReaderOptions options)
    {
        using var plain = new ParquetReader(options);
        plain.Reset(new MemoryReadSource(fileBytes));
        using var pruned = new ParquetReader(options);
        pruned.Reset(new MemoryReadSource(fileBytes), AcceptAllPages);
        using var sparse = new ParquetReader(options);
        sparse.Reset(new MemoryReadSource(fileBytes), AcceptEvenPages);

        for (var groupIndex = 0; groupIndex < plain.RowGroups.Count; groupIndex++)
        {
            // Each reader owns its LeafColumn instances; another reader's are refused.
            for (var columnIndex = 0; columnIndex < plain.Schema.LeafColumns.Length; columnIndex++)
            {
                var column = plain.Schema.LeafColumns[columnIndex];
                if (column.MaxRepetitionLevel > 0)
                    continue;
                RequireSameReads($"column '{column.Path}'",
                    "plain scan", TryReadPath(() => ReadPhysical(plain.RowGroups[groupIndex], column)),
                    "pruned scan", TryReadPath(() =>
                        ReadPhysical(pruned.RowGroups[groupIndex], pruned.Schema.LeafColumns[columnIndex])),
                    // The pruned scan reads the offset index and the plain scan
                    // does not, so an inconsistent index is the pruned scan's to
                    // reject. Returning different data silently is still a bug.
                    secondMayRejectMore: true);
                _ = TryReadPath(() => ReadPhysical(sparse.RowGroups[groupIndex], sparse.Schema.LeafColumns[columnIndex]));
            }
        }
    }

    static object?[] ReadPhysical(RowGroup rowGroup, LeafColumn column)
    {
        var optional = column.MaxDefinitionLevel > 0;
        return column.PhysicalType switch
        {
            ParquetPhysicalType.Boolean => optional ? Box(rowGroup.Column<bool?>(column)) : Box(rowGroup.Column<bool>(column)),
            ParquetPhysicalType.Int32 => optional ? Box(rowGroup.Column<int?>(column)) : Box(rowGroup.Column<int>(column)),
            ParquetPhysicalType.Int64 => optional ? Box(rowGroup.Column<long?>(column)) : Box(rowGroup.Column<long>(column)),
            ParquetPhysicalType.Float => optional ? Box(rowGroup.Column<float?>(column)) : Box(rowGroup.Column<float>(column)),
            ParquetPhysicalType.Double => optional ? Box(rowGroup.Column<double?>(column)) : Box(rowGroup.Column<double>(column)),
            _ => BoxBinary(rowGroup.Column<byte>(column))
        };
    }

    static object?[] Box<T>(RowGroupColumn<T> buffers)
        => Array.ConvertAll(DrainValues(buffers), static value => (object?)value);

    // Binary values are compared as hex so the comparison is by content.
    static object?[] BoxBinary(RowGroupColumn<byte> buffers)
    {
        var values = new List<object?>();
        foreach (var buffer in buffers)
            for (var i = 0; i < buffer.Count; i++)
                values.Add(buffer.IsNull(i) ? null : Convert.ToHexString(buffer.GetValue(i)));
        return values.ToArray();
    }

    // An API refusal (asking for T from a column that holds nulls, a type the
    // column cannot convert to) just means that path has nothing to compare.
    // Anything else is a verdict on the file and is returned to the caller.
    static (TValue[]? Values, Exception? Error) TryReadPath<TValue>(Func<TValue[]> read)
    {
        try { return (read(), null); }
        catch (CorruptParquetException error) { return (null, error); }
        catch (Exception error) when (error is InvalidOperationException or NotSupportedException
            or ArgumentException or InvalidCastException) { return (null, null); }
    }

    static string Describe(Exception? error)
        => error is null ? "read it" : $"rejected it ({error.GetType().Name})";

    static void DrainNestedColumn(RowGroup rowGroup, LeafColumn column)
    {
        switch (column.PhysicalType)
        {
            case ParquetPhysicalType.Boolean: DrainNested(rowGroup.NestedColumn<bool>(column)); break;
            case ParquetPhysicalType.Int32: DrainNested(rowGroup.NestedColumn<int>(column)); break;
            case ParquetPhysicalType.Int64: DrainNested(rowGroup.NestedColumn<long>(column)); break;
            case ParquetPhysicalType.Float: DrainNested(rowGroup.NestedColumn<float>(column)); break;
            case ParquetPhysicalType.Double: DrainNested(rowGroup.NestedColumn<double>(column)); break;
            case ParquetPhysicalType.ByteArray:
            case ParquetPhysicalType.FixedLenByteArray:
            case ParquetPhysicalType.Int96:
                DrainNested(rowGroup.NestedColumn<byte>(column));
                break;
        }
    }

    // The levels are the point: they are what says which row a value belongs to
    // and how deeply it nests, and they are decoded from the page rather than
    // the schema, so a corrupt file controls them.
    static void DrainNested<T>(NestedRowGroupColumn<T> buffers)
    {
        foreach (var buffer in buffers)
        {
            _ = buffer.RowCount;
            _ = buffer.StartsWithContinuation;
            var repetition = buffer.RepetitionLevels;
            for (var i = 0; i < repetition.Length; i++)
                _ = repetition[i];
            var definition = buffer.DefinitionLevels;
            for (var i = 0; i < definition.Length; i++)
                _ = definition[i];
            var values = buffer.Values.Values;
            for (var i = 0; i < values.Length; i++)
                _ = values[i];
        }
    }

    static void DrainBuffers<T>(RowGroupColumn<T> buffers)
    {
        foreach (var buffer in buffers)
        {
            var span = buffer.Values;
            for (var i = 0; i < span.Length; i++)
                _ = span[i];
        }
    }

    // Variable-length byte[] columns are read as RowGroupColumn<byte>: one span
    // per row rather than one flat value span per buffer. Touching every byte
    // is what exercises the offset/length bookkeeping we want fuzzed.
    static void DrainBinaryBuffers(RowGroupColumn<byte> buffers)
    {
        foreach (var buffer in buffers)
            for (var i = 0; i < buffer.Count; i++)
            {
                if (buffer.IsNull(i)) continue;
                var value = buffer.GetValue(i);
                for (var j = 0; j < value.Length; j++)
                    _ = value[j];
            }
    }

    static ParquetSchema[] BuildSchemas()
        =>
        [
            // 0: single int32 plain
            Schema(Col("c0", ParquetPhysicalType.Int32, EncodingKind.Plain)),
            // 1: single byte[] plain
            Schema(Col("c0", ParquetPhysicalType.ByteArray, EncodingKind.Plain)),
            // 2: int32 + bool
            Schema(Col("c0", ParquetPhysicalType.Int32, EncodingKind.DeltaBinaryPacked),
                   Col("c1", ParquetPhysicalType.Boolean, EncodingKind.Plain)),
            // 3: int64 + double
            Schema(Col("c0", ParquetPhysicalType.Int64, EncodingKind.Plain),
                   Col("c1", ParquetPhysicalType.Double, EncodingKind.Plain)),
            // 4: int32 rle-dict
            Schema(Col("c0", ParquetPhysicalType.Int32, EncodingKind.RleDictionary)),
            // 5: byte[] delta-length
            Schema(Col("c0", ParquetPhysicalType.ByteArray, EncodingKind.DeltaLengthByteArray)),
            // 6: all five types, plain
            Schema(Col("c0", ParquetPhysicalType.Boolean, EncodingKind.Plain),
                   Col("c1", ParquetPhysicalType.Int32, EncodingKind.Plain),
                   Col("c2", ParquetPhysicalType.Int64, EncodingKind.Plain),
                   Col("c3", ParquetPhysicalType.Double, EncodingKind.Plain),
                   Col("c4", ParquetPhysicalType.ByteArray, EncodingKind.Plain)),
            // 7: byte[] delta-byte-array
            Schema(Col("c0", ParquetPhysicalType.ByteArray, EncodingKind.DeltaByteArray)),
            // 8: custom value converters. The converted decode family
            // (TryDecodeConvertedRequired*, ParquetValueConverter's span
            // conversions) only runs for a column that carries a converter, and
            // no requested schema had one. c1 is requested optional, which also
            // reads a required file through the nullable conversion.
            Schema(ColumnDefinition.RequiredLeaf("c0", ParquetPhysicalType.Int32, converter: new IntBoxConverter()),
                   ColumnDefinition.OptionalLeaf("c1", ParquetPhysicalType.Int64, converter: new LongBoxConverter()),
                   ColumnDefinition.RequiredLeaf("c2", ParquetPhysicalType.Double, converter: new DoubleBoxConverter())),
        ];

    static ParquetSchema Schema(params ColumnDefinition[] columns)
        => new(columns.ToImmutableArray());

    static ColumnDefinition Col(string name, ParquetPhysicalType type, EncodingKind encoding)
        => ColumnDefinition.Leaf(name, type, new ColumnOptions(encodings: ImmutableArray.Create(encoding)));
}

// Value types that exist only to give schema 8 something to convert to.
readonly record struct IntBox(int Value);
readonly record struct LongBox(long Value);
readonly record struct DoubleBox(double Value);

sealed class IntBoxConverter : ParquetValueConverter<IntBox, int>
{
    public override int ConvertToPhysical(IntBox value) => value.Value;
    public override IntBox ConvertFromPhysical(int value) => new(value);
}

sealed class LongBoxConverter : ParquetValueConverter<LongBox, long>
{
    public override long ConvertToPhysical(LongBox value) => value.Value;
    public override LongBox ConvertFromPhysical(long value) => new(value);
}

sealed class DoubleBoxConverter : ParquetValueConverter<DoubleBox, double>
{
    public override double ConvertToPhysical(DoubleBox value) => value.Value;
    public override DoubleBox ConvertFromPhysical(double value) => new(value);
}
