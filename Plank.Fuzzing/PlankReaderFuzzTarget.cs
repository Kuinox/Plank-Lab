using System.Collections.Immutable;
using System.IO;
using System.Security.Cryptography;
using Plank.Reading;
using Plank.Reading.Logical;
using Plank.RowApi;
using Plank.Schema;

namespace Plank.Fuzzing;

public static class PlankReaderFuzzTarget
{
    internal const byte SignedIntegerStrictProbeSelector = 0x26;
    internal const byte SignedIntegerWidthMismatchProbeSelector = 0x2E;
    internal const byte RowApiProjectionProbeSelector = 0x22;
    internal const byte PageIndexBloomProbeSelector = 0x1A;
    internal const byte PageMetadataEnumeratorProbeSelector = 0x1C;
    internal const byte FileReadSourceProbeSelector = 0x04;
    internal const byte BufferRetentionProbeSelector = 0x0A;
    internal const byte RowApiStreamResetProbeSelector = 0x6A;
    internal const byte RowGroupTypeValidationProbeSelector = 0x6C;
    internal const byte PhysicalMetadataOrdinalProbeSelector = 0x6E;
    internal const byte RowApiNullLeafShapeProbeSelector = 0x70;
    internal const byte ColumnBufferConstructorProbeSelector = 0x74;
    internal const byte EncodedDecoderKindProbeSelector = 0x76;
    internal const byte NestedByteStreamSplitLogicalProbeSelector = 0x76;
    internal const byte ByteStreamSplitSliceProbeSelector = 0x78;
    internal const byte FixedDeltaByteArrayProbeSelector = 0x7A;
    internal const byte PageIndexBloomValidFilterRoute = 0;
    internal const byte PageIndexBloomNoFilterRoute = 1;
    internal const byte PageIndexBloomOversizedFilterRoute = 2;
    internal static ReadOnlySpan<byte> LogicalTypeProbeMarker => "RAPI"u8;
    internal static ReadOnlySpan<byte> ProjectionProbeMarker => "RPRJ"u8;
    internal static ReadOnlySpan<byte> PageIndexBloomProbeMarker => "BFPR"u8;
    internal static ReadOnlySpan<byte> PageMetadataEnumeratorProbeMarker => "PMEN"u8;
    internal static ReadOnlySpan<byte> FileReadSourceProbeMarker => "PRFS"u8;
    internal static ReadOnlySpan<byte> BufferRetentionProbeMarker => "RBUF"u8;
    internal static ReadOnlySpan<byte> RowApiStreamResetProbeMarker => "RSTR"u8;
    internal static ReadOnlySpan<byte> RowGroupTypeValidationProbeMarker => "RGVT"u8;
    internal static ReadOnlySpan<byte> RowGroupUnsupportedClrProbeMarker => "RGVU"u8;
    internal static ReadOnlySpan<byte> PhysicalMetadataOrdinalProbeMarker => "PMOR"u8;
    internal static ReadOnlySpan<byte> RowApiNullLeafShapeProbeMarker => "RNSH"u8;
    internal static ReadOnlySpan<byte> ColumnBufferConstructorProbeMarker => "CBCV"u8;
    internal static ReadOnlySpan<byte> EncodedDecoderKindProbeMarker => "EDKI"u8;
    internal static ReadOnlySpan<byte> NestedByteStreamSplitLogicalProbeMarker => "BSSO"u8;
    internal static ReadOnlySpan<byte> ByteStreamSplitSliceProbeMarker => "BSSL"u8;
    internal static ReadOnlySpan<byte> FixedDeltaByteArrayProbeMarker => "FDBA"u8;
    internal static ReadOnlySpan<byte> FixedDeltaByteArrayNullableProbeMarker => "FDBO"u8;
    static ReadOnlySpan<byte> NestedByteStreamSplitLogicalProbeFileHash =>
    [
        0x98, 0x2A, 0x45, 0x7F, 0xB0, 0x9F, 0xF1, 0xAB,
        0xD9, 0x55, 0x36, 0x3A, 0xAD, 0x3C, 0x65, 0xA7,
        0xC8, 0xC8, 0x15, 0x03, 0xD8, 0x27, 0x2B, 0x59,
        0x98, 0xD8, 0x8A, 0x6B, 0xA0, 0x8B, 0x5E, 0xEE
    ];

    const int MaxPageMetadataEnumeratorProbeFileSize = 64 * 1024;
    const int MaxFileReadSourceProbeFileSize = 8 * 1024;
    const int MaxBufferRetentionProbeFileSize = 8 * 1024;
    const int MaxRowApiStreamResetProbeFileSize = 8 * 1024;
    const int MaxRowGroupTypeValidationProbeFileSize = 8 * 1024;
    const int MaxPhysicalMetadataOrdinalProbeFileSize = 8 * 1024;
    const int MaxRowApiNullLeafShapeProbeFileSize = 8 * 1024;
    static ReadOnlySpan<byte> PageMetadataEnumeratorProbeFileHash =>
    [
        0x1C, 0xE4, 0x98, 0x3F, 0x54, 0xE5, 0x86, 0x87,
        0x51, 0x0D, 0xD8, 0x09, 0x65, 0x30, 0x73, 0x0D,
        0xE1, 0x54, 0xE2, 0x6B, 0xF5, 0x51, 0x2E, 0x2E,
        0xFB, 0x72, 0x9E, 0xC3, 0x42, 0xEE, 0x3F, 0xA5
    ];
    static ReadOnlySpan<byte> RowApiNullLeafShapeProbeFileHash =>
    [
        0x24, 0x06, 0x93, 0x7F, 0x40, 0x25, 0x46, 0xC2,
        0x09, 0x23, 0xFA, 0x1C, 0x06, 0x88, 0x2B, 0x3D,
        0xCF, 0xFD, 0xA4, 0x6B, 0x90, 0xAC, 0xBA, 0x65,
        0x4A, 0xD3, 0x13, 0x64, 0x93, 0xA0, 0xD2, 0x95
    ];

    static readonly ParquetSchema[] Schemas = BuildSchemas();

    public static void Execute(ReadOnlySpan<byte> data)
        => Execute(data, DefaultParquetBufferPool.Shared);

    // Persistent AFL repeats the same testcase during calibration. A process-wide
    // adaptive buffer pool changes allocation/reuse branches between those runs,
    // so the AFL entry point uses one pool per testcase. Replay keeps Execute's
    // shared-pool behavior for normal coverage and validation.
    public static void ExecuteWithFreshBufferPool(ReadOnlySpan<byte> data)
    {
        using var bufferPool = new DefaultParquetBufferPool();
        Execute(data, bufferPool);
    }

    static void Execute(ReadOnlySpan<byte> data, IParquetBufferPool bufferPool)
    {
        try
        {
            Run(data.IsEmpty ? (byte)0 : data[0], data.IsEmpty ? [] : data[1..].ToArray(), bufferPool);
        }
        catch (Exception ex) when (ex is CorruptParquetException or NotSupportedException or InvalidOperationException) { }
    }

    public static Exception? GetHandledException(byte[] data)
    {
        ArgumentNullException.ThrowIfNull(data);
        try
        {
            Run(data.Length == 0 ? (byte)0 : data[0], data.Length == 0 ? [] : data[1..],
                DefaultParquetBufferPool.Shared);
            return null;
        }
        catch (Exception ex) when (ex is CorruptParquetException or NotSupportedException or InvalidOperationException)
        {
            return ex;
        }
    }

    static void Run(byte selector, byte[] fileBytes, IParquetBufferPool bufferPool,
        IParquetReadSource? injectedSource = null)
    {
        if (selector == EncodedDecoderKindProbeSelector
            && fileBytes.AsSpan().StartsWith(EncodedDecoderKindProbeMarker))
        {
            EncodedDecoderKindCoverageCases.Run(bufferPool);
            return;
        }

        if (selector == ColumnBufferConstructorProbeSelector
            && fileBytes.AsSpan().StartsWith(ColumnBufferConstructorProbeMarker))
        {
            ColumnBufferConstructorCoverageCases.Run(bufferPool);
            return;
        }

        // Keep the public RowGroup.Column<T> type-rejection probe on a known,
        // valid nullable DATE fixture. The marker and schema/value checks make
        // fuzz mutations exercise the API boundary only while the payload still
        // represents the exact row shape under test; ordinary inputs keep their
        // existing selector behavior.
        if (selector == RowGroupTypeValidationProbeSelector
            && fileBytes.AsSpan().StartsWith(RowGroupTypeValidationProbeMarker))
        {
            var payload = fileBytes.AsSpan(RowGroupTypeValidationProbeMarker.Length);
            if (payload.IsEmpty || payload.Length > MaxRowGroupTypeValidationProbeFileSize)
                return;
            RunRowGroupTypeValidationProbe(payload.ToArray(), bufferPool);
            return;
        }

        // Exercise the public generic-type mapper failure independently from
        // the early variable-length type guard in the RGVT probe.
        if (selector == RowGroupTypeValidationProbeSelector
            && fileBytes.AsSpan().StartsWith(RowGroupUnsupportedClrProbeMarker))
        {
            var payload = fileBytes.AsSpan(RowGroupUnsupportedClrProbeMarker.Length);
            if (payload.IsEmpty || payload.Length > MaxRowGroupTypeValidationProbeFileSize)
                return;
            RunRowGroupUnsupportedClrProbe(payload.ToArray(), bufferPool);
            return;
        }

        // Exercise the public physical metadata API's ordinal guard using a
        // valid footer, then send the same file through strict logical readback.
        if (selector == PhysicalMetadataOrdinalProbeSelector
            && fileBytes.AsSpan().StartsWith(PhysicalMetadataOrdinalProbeMarker))
        {
            var payload = fileBytes.AsSpan(PhysicalMetadataOrdinalProbeMarker.Length);
            if (payload.IsEmpty || payload.Length > MaxPhysicalMetadataOrdinalProbeFileSize)
                return;
            RunPhysicalMetadataOrdinalProbe(payload.ToArray(), bufferPool);
            return;
        }

        // Keep a concrete public nested projection for the BSS DateTimeOffset
        // decoder arm. Ordinary nested fuzzing intentionally reads physical CLR
        // types, while this leaf's logical projection is what reaches it.
        if (selector == NestedByteStreamSplitLogicalProbeSelector
            && fileBytes.AsSpan().StartsWith(NestedByteStreamSplitLogicalProbeMarker))
        {
            var payload = fileBytes.AsSpan(NestedByteStreamSplitLogicalProbeMarker.Length);
            if (payload.IsEmpty || payload.Length > 8 * 1024 ||
                !SHA256.HashData(payload).AsSpan().SequenceEqual(NestedByteStreamSplitLogicalProbeFileHash))
                return;
            RunNestedByteStreamSplitDateTimeOffsetProbe(payload.ToArray(), bufferPool);
            return;
        }

        // A concrete public-schema Guid projection drives the fixed-width BSS
        // slice decoder's FixedLenByteArray branches. File-schema reads retain
        // the physical byte projection for UUID columns, so this marker keeps
        // the requested Guid converter explicit and stable for replay.
        if (selector == ByteStreamSplitSliceProbeSelector
            && fileBytes.AsSpan().StartsWith(ByteStreamSplitSliceProbeMarker))
        {
            var payload = fileBytes.AsSpan(ByteStreamSplitSliceProbeMarker.Length);
            if (payload.IsEmpty || payload.Length > 8 * 1024)
                return;
            ByteStreamSplitSliceProbe.Run(payload.ToArray(), bufferPool);
            return;
        }

        // Keep a public Guid projection available for FIXED_LEN_BYTE_ARRAY
        // DELTA_BYTE_ARRAY pages. File-schema reads intentionally expose UUID
        // values as bytes unless a converter is supplied by the requested schema.
        if (selector == FixedDeltaByteArrayProbeSelector
            && fileBytes.AsSpan().StartsWith(FixedDeltaByteArrayProbeMarker))
        {
            var payload = fileBytes.AsSpan(FixedDeltaByteArrayProbeMarker.Length);
            if (payload.IsEmpty || payload.Length > 8 * 1024)
                return;
            FixedDeltaByteArrayProbe.Run(payload.ToArray(), bufferPool);
            return;
        }
        if (selector == FixedDeltaByteArrayProbeSelector
            && fileBytes.AsSpan().StartsWith(FixedDeltaByteArrayNullableProbeMarker))
        {
            var payload = fileBytes.AsSpan(FixedDeltaByteArrayNullableProbeMarker.Length);
            if (payload.IsEmpty || payload.Length > 8 * 1024)
                return;
            FixedDeltaByteArrayProbe.RunNullable(payload.ToArray(), bufferPool);
            return;
        }

        // This exact-file route distinguishes a valid optional nested leaf from
        // a caller-selected non-nullable CLR array shape. Only the nullable
        // descriptor reads values successfully; the non-nullable descriptor
        // must report its precise null-leaf materialization rejection.
        if (selector == RowApiNullLeafShapeProbeSelector
            && fileBytes.AsSpan().StartsWith(RowApiNullLeafShapeProbeMarker))
        {
            var payload = fileBytes.AsSpan(RowApiNullLeafShapeProbeMarker.Length);
            if (payload.IsEmpty || payload.Length > MaxRowApiNullLeafShapeProbeFileSize
                || !SHA256.HashData(payload).AsSpan().SequenceEqual(RowApiNullLeafShapeProbeFileHash))
                return;
            RunRowApiNullLeafShapeProbe(payload.ToArray(), bufferPool);
            return;
        }

        // A dedicated valid seed drives the public reader's caller-type errors.
        // Keep this before the selector's ordinary routing bits; 0xFF is
        // otherwise the decompressor selector.
        if (selector == 0xFF)
        {
            RunVariableBytesTypeMismatchRoute(fileBytes, bufferPool);
            return;
        }

        // A bounded exact marker routes one small file through the public buffer
        // retention API. Its fixture uses a borrowable required PLAIN INT32 page
        // and a nested binary page; retained values and levels must survive both
        // enumerator advancement and reader disposal.
        if (selector == BufferRetentionProbeSelector
            && fileBytes.AsSpan().StartsWith(BufferRetentionProbeMarker))
        {
            var payload = fileBytes.AsSpan(BufferRetentionProbeMarker.Length);
            if (payload.IsEmpty || payload.Length > MaxBufferRetentionProbeFileSize)
                return;
            RunBufferRetentionProbe(payload, bufferPool);
            return;
        }

        // Drive the public RowReaderCore stream constructor and Reset(Stream)
        // overload over one small known-shape fixture. Exact selector and marker
        // gating keep mutated ordinary inputs on their existing route.
        if (selector == RowApiStreamResetProbeSelector
            && fileBytes.AsSpan().StartsWith(RowApiStreamResetProbeMarker))
        {
            var payload = fileBytes.AsSpan(RowApiStreamResetProbeMarker.Length);
            if (payload.IsEmpty || payload.Length > MaxRowApiStreamResetProbeFileSize)
                return;
            var parquetBytes = payload.ToArray();
            RunRowApiStreamResetProbe(parquetBytes, bufferPool);
            if (Environment.GetEnvironmentVariable("PLANK_FUZZ_ENABLE_ROW_WORKERS") == "1")
                RunRowApiReadAheadProbe(parquetBytes, bufferPool);
            return;
        }

        // The ordinary fuzz routes use memory and stream sources. A dedicated
        // marker gates this small file-backed probe so file IO stays off the
        // normal hot path. The marker is stripped before parsing, and the
        // reader follows the same strict file-schema/oracle checks below.
        if (selector == FileReadSourceProbeSelector
            && fileBytes.AsSpan().StartsWith(FileReadSourceProbeMarker))
        {
            var payload = fileBytes.AsSpan(FileReadSourceProbeMarker.Length);
            if (payload.IsEmpty || payload.Length > MaxFileReadSourceProbeFileSize)
                return;
            RunFileReadSourceProbe(selector, payload.ToArray(), bufferPool);
            return;
        }

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

        // This narrow route exercises public page-metadata foreach enumeration.
        // The selector and marker keep ordinary inputs on their existing routes,
        // and the size cap bounds marker-preserving AFL mutations before parsing.
        if (selector == PageMetadataEnumeratorProbeSelector
            && fileBytes.AsSpan().StartsWith(PageMetadataEnumeratorProbeMarker))
        {
            var payload = fileBytes.AsSpan(PageMetadataEnumeratorProbeMarker.Length);
            if (payload.IsEmpty || payload.Length > MaxPageMetadataEnumeratorProbeFileSize)
                return;
            RunPageMetadataEnumeratorProbe(payload, bufferPool);
            return;
        }

        // Focused page-index/Bloom probes must carry a four-byte magic after
        // their selector. Inputs that merely collide on selector 0x1A retain
        // their ordinary row-API behavior.
        var pageIndexBloomProbe = selector == PageIndexBloomProbeSelector
            && fileBytes.AsSpan().StartsWith(PageIndexBloomProbeMarker);
        if (pageIndexBloomProbe)
        {
            var payloadOffset = PageIndexBloomProbeMarker.Length;
            if (fileBytes.Length <= payloadOffset)
                return;
            var route = fileBytes[payloadOffset];
            RunPageIndexBloomProbe(route, fileBytes.AsSpan(payloadOffset + 1));
            return;
        }

        // Dedicated schema-evolution probes carry a reserved marker before the
        // Parquet bytes. Ordinary files that happen to share their selectors
        // keep the normal reader behavior.
        var logicalTypeProbe = (selector is SignedIntegerStrictProbeSelector
                or SignedIntegerWidthMismatchProbeSelector)
            && fileBytes.AsSpan().StartsWith(LogicalTypeProbeMarker);
        var projectionProbe = selector == RowApiProjectionProbeSelector
            && fileBytes.AsSpan().StartsWith(ProjectionProbeMarker);
        if (logicalTypeProbe)
            fileBytes = fileBytes[LogicalTypeProbeMarker.Length..];
        else if (projectionProbe)
            fileBytes = fileBytes[ProjectionProbeMarker.Length..];

        // Bit 6 picks the read source, and it decides more than the 54 lines of
        // StreamReadSource. ParquetFileReader.TryBorrowSource hard-tests for
        // MemoryReadSource, so with the memory source every page read borrows a
        // span straight out of the input — and the other side of both borrow
        // branches in ParquetPageCursor, the ones that rent a buffer and copy
        // into it, had never run. A stream source is also the only one that can
        // fail a read part-way, which is a different failure mode from a span
        // that is simply too short.
        using var source = injectedSource ?? ((selector & 0x40) != 0
            ? new StreamReadSource((selector & 0x20) != 0
                ? new FragmentedReadStream(fileBytes, 1 + (selector & 7))
                : new MemoryStream(fileBytes, writable: false))
            : new MemoryReadSource(fileBytes));

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
            BufferPool = bufferPool,
            VerifyPageCrc = (selector & 0x10) != 0,
            Strict = (selector & 0x20) == 0
        };

        // A quarter of the inputs go through the row-oriented API. It is a
        // separate public reader with its own buffering and projection, and it
        // measured 0% over a 14k-input corpus — neither fuzz target drove it.
        if ((selector & 3) == 2)
        {
            DrainRowApi(source, fileBytes, options.VerifyPageCrc, selector, bufferPool, logicalTypeProbe,
                projectionProbe);
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

                // Bit 2 (file-schema route only; bits 2-3 are otherwise unused
                // there) reads the column with both nullabilities and requires
                // them to agree. It runs before the natural read on purpose: when
                // the natural read rejects a corrupt page, the input ends there,
                // and the other path was never asked whether it rejects it too.
                // Reading T from an optional column once returned garbage for
                // definition levels that T? (and Arrow) reject, unseen for days.
                // See CrossCheckReadPaths.
                if ((selector & 4) != 0 && (selector & 1) == 0)
                    CrossCheckReadPaths(group, column);

                // Drain optional flat and variable-length values before the
                // trace warms the shared buffer pool. The first owned binary
                // batch can then exercise its value-boundary split path.
                var drainNativeBeforeTrace = column.MaxDefinitionLevel > 0 && column.MaxRepetitionLevel == 0
                    || column.PhysicalType is ParquetPhysicalType.ByteArray
                        or ParquetPhysicalType.FixedLenByteArray or ParquetPhysicalType.Int96;
                if (drainNativeBeforeTrace)
                    DrainColumn(group, column);

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

                // Logical values are checked against the specification's conversion of
                // the physical values the trace just captured. See LogicalOracle.
                if (groupTraces?[columnIndex] is { } trace && column.LogicalType is not null)
                    LogicalOracle.Check(group, column, trace);

                if (canCompareWithParquetNet)
                    decodedColumns.Add(DrainFlatColumnForComparison(group, column));
                // Annotated columns still go through their logical CLR type, so
                // the conversions (decimal, timestamps, ...) keep being fuzzed.
                else if (!drainNativeBeforeTrace &&
                    (groupTraces?[columnIndex] is null || column.LogicalType is not null))
                    DrainColumn(group, column);

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

    static void RunRowGroupTypeValidationProbe(byte[] parquetBytes, IParquetBufferPool bufferPool)
    {
        using (var source = new MemoryReadSource(parquetBytes))
        using (var reader = new ParquetReader(new ParquetReaderOptions { BufferPool = bufferPool, Strict = true }))
        {
            reader.Reset(source);
            if (reader.Schema.LeafColumns.Length != 1 || reader.RowGroups.Count != 1)
                return;

            var column = reader.Schema.LeafColumns[0];
            var group = reader.RowGroups[0];
            if (column.Path != "Date" || column.PhysicalType != ParquetPhysicalType.Int32 ||
                column.LogicalType is not LogicalType.Date ||
                column.Options.Repetition != ParquetRepetition.Optional || group.RowCount != 3)
                return;

            DateOnly?[] expected = [new DateOnly(2020, 1, 2), null, new DateOnly(2020, 1, 4)];
            var row = 0;
            foreach (var buffer in group.Column<DateOnly?>(0))
            {
                foreach (var value in buffer.Values)
                {
                    if (row >= expected.Length || value != expected[row])
                        throw new InvalidDataException(
                            $"The nullable DATE type-probe value {row} was {value?.ToString() ?? "null"}.");
                    row++;
                }
            }
            if (row != expected.Length)
                throw new InvalidDataException("The nullable DATE type-probe row count changed.");

            var rejected = false;
            try
            {
                _ = group.Column<ReadOnlyMemory<byte>?>(0);
            }
            catch (NotSupportedException error)
                when (error.Message.Contains("variable-length bytes", StringComparison.Ordinal))
            {
                // Expected caller-type rejection; preserve the successful
                // logical read and normal strict/oracle pass below.
                rejected = true;
            }
            catch (Exception error)
            {
                throw new InvalidDataException("The RowGroup type probe changed its rejection classification.", error);
            }
            if (!rejected)
                throw new InvalidDataException("RowGroup.Column accepted a variable-byte type for the DATE column.");
        }

        // Also run the ordinary strict file-schema path and independent Arrow
        // checks for every marker-preserving mutation that retains this schema.
        Run(0, parquetBytes, bufferPool);
    }

    static void RunRowGroupUnsupportedClrProbe(byte[] parquetBytes, IParquetBufferPool bufferPool)
    {
        using (var source = new MemoryReadSource(parquetBytes))
        using (var reader = new ParquetReader(new ParquetReaderOptions { BufferPool = bufferPool, Strict = true }))
        {
            reader.Reset(source);
            if (reader.Schema.LeafColumns.Length != 1 || reader.RowGroups.Count != 1)
                return;

            var column = reader.Schema.LeafColumns[0];
            var group = reader.RowGroups[0];
            if (column.Path != "Date" || column.PhysicalType != ParquetPhysicalType.Int32 ||
                column.LogicalType is not LogicalType.Date ||
                column.Options.Repetition != ParquetRepetition.Optional || group.RowCount != 3)
                return;

            var rejected = false;
            try
            {
                _ = group.Column<object>(0);
            }
            catch (NotSupportedException)
            {
                rejected = true;
            }
            catch (Exception error)
            {
                throw new InvalidDataException($"The unsupported CLR type probe changed its rejection classification: {error.GetType().Name}: {error.Message}", error);
            }
            if (!rejected)
                throw new InvalidDataException("RowGroup.Column accepted object as a DATE value type.");
        }

        Run(0, parquetBytes, bufferPool);
    }

    static void RunPhysicalMetadataOrdinalProbe(byte[] parquetBytes, IParquetBufferPool bufferPool)
    {
        using (var source = new MemoryReadSource(parquetBytes))
        using (var reader = new Plank.Reading.Physical.ParquetFileReader())
        {
            reader.Reset(source);
            var metadata = reader.Metadata;
            var count = metadata.ColumnCount;
            if (count == 0)
                throw new InvalidDataException("Physical metadata ordinal fixture must have a column.");

            var rejectedOutOfRange = false;
            try
            {
                _ = metadata.ColumnSchema(count);
            }
            catch (ArgumentOutOfRangeException error)
                when (error.ParamName == "columnOrdinal" && Equals(error.ActualValue, count))
            {
                rejectedOutOfRange = true;
            }
            catch (ArgumentOutOfRangeException error)
            {
                throw new InvalidDataException("ColumnSchema changed its out-of-range exception contract.", error);
            }

            if (!rejectedOutOfRange)
                throw new InvalidDataException("ColumnSchema accepted an out-of-range ordinal.");
            if (metadata.ColumnSchema(0).PathSegmentCount == 0)
                throw new InvalidDataException("Physical metadata fixture lost its first column path.");
        }

        // Reuse ordinary strict file-schema reading and independent Arrow checks.
        Run(0, parquetBytes, bufferPool);
    }

    static void RunNestedByteStreamSplitDateTimeOffsetProbe(byte[] parquetBytes,
        IParquetBufferPool bufferPool)
    {
        using (var source = new MemoryReadSource(parquetBytes))
        using (var reader = new ParquetReader(new ParquetReaderOptions
        {
            BufferPool = bufferPool,
            Strict = true
        }))
        {
            reader.Reset(source);
            if (reader.Schema.LeafColumns.Length != 1 || reader.RowGroups.Count != 1 ||
                reader.RowGroups[0].RowCount != 2)
                throw new InvalidDataException("The nested BSS timestamp fixture changed its row shape.");

            var column = reader.Schema.LeafColumns[0];
            if (column.PhysicalType != ParquetPhysicalType.Int64 || column.MaxRepetitionLevel != 1 ||
                column.LogicalType is not LogicalType.Timestamp { IsAdjustedToUtc: true, Unit: TimeUnit.Millis })
                throw new InvalidDataException("The nested BSS timestamp fixture changed its physical or logical type.");

            var values = new List<DateTimeOffset>();
            foreach (var page in reader.RowGroups[0].NestedColumn<DateTimeOffset>(0))
                values.AddRange(page.Values.Values.ToArray());
            DateTimeOffset[] expected =
            [
                new(2024, 1, 2, 3, 4, 5, TimeSpan.Zero),
                new(2024, 1, 3, 4, 5, 6, TimeSpan.Zero)
            ];
            if (!values.SequenceEqual(expected))
                throw new InvalidDataException("The nested BSS DateTimeOffset projection changed its values.");
        }

        Run(0, parquetBytes, bufferPool);
    }

    static void RunRowApiNullLeafShapeProbe(byte[] parquetBytes, IParquetBufferPool bufferPool)
    {
        ParquetSchema schema;
        ColumnTrace trace;
        using (var source = new MemoryReadSource(parquetBytes))
        using (var reader = new ParquetReader(new ParquetReaderOptions
        {
            BufferPool = bufferPool,
            Strict = true
        }))
        {
            reader.Reset(source);
            schema = reader.Schema;
            if (schema.LeafColumns.Length != 1 || reader.RowGroups.Count != 1 || reader.RowGroups[0].RowCount != 4)
                throw new InvalidDataException("The Row API null-leaf fixture changed its schema or row-group shape.");

            var leaf = schema.LeafColumns[0];
            if (leaf.PhysicalType != ParquetPhysicalType.Int32 || leaf.MaxRepetitionLevel != 1
                || leaf.MaxDefinitionLevel != 3)
                throw new InvalidDataException("The Row API null-leaf fixture changed its nested INT32 levels.");

            // Strict file-schema control: decode the physical values and both
            // level streams, then compare them with the independent Arrow oracle.
            var group = reader.RowGroups[0];
            var values = new List<int>();
            var definitions = new List<int>();
            var repetitions = new List<int>();
            foreach (var page in group.NestedColumn<int>(0))
            {
                values.AddRange(page.Values.Values.ToArray());
                definitions.AddRange(page.DefinitionLevels.ToArray());
                repetitions.AddRange(page.RepetitionLevels.ToArray());
            }
            if (!values.SequenceEqual([1, 2, 3])
                || !definitions.SequenceEqual([3, 2, 3, 0, 1, 3])
                || !repetitions.SequenceEqual([0, 1, 1, 0, 0, 0]))
                throw new InvalidDataException("The Row API null-leaf fixture changed its strict physical values or levels.");

            trace = ColumnTrace.CapturePlank(group, leaf);
        }

        ReaderAcceptanceOracle.VerifyWithParquetSharp(parquetBytes, [[trace]]);

        var levels = new[] { new RowApiCollectionLevel(1, 1, 2) };
        var nullable = new RowApiNestedColumnDescriptor<int?[], int>("Items", schema.LeafColumns[0], levels);
        var rowOptions = new RowReaderOptions
        {
            BufferPool = bufferPool,
            Execution = new ParquetExecutionOptions { WorkerCount = 1 }
        };
        var actual = new List<string>();
        using (var rows = new RowReaderCore(new MemoryReadSource(parquetBytes), schema, [nullable],
            projection: null, rowOptions, schemaEvolution: null))
        {
            while (rows.MoveNext())
            {
                var row = rows.GetCurrentNested(nullable);
                actual.Add(row is null ? "null" : "[" + string.Join(',', row.Select(static value =>
                    value?.ToString() ?? "null")) + "]");
            }
        }

        if (!actual.SequenceEqual(["[1,null,2]", "null", "[]", "[3]"]))
            throw new InvalidDataException("The nullable Row API descriptor changed its nested null/empty/value shape.");

        var nonNullable = new RowApiNestedColumnDescriptor<int[], int>("Items", schema.LeafColumns[0], levels);
        const string ExpectedMessage =
            "Column 'Items' contains a null leaf that cannot be materialized as System.Int32.";
        var rejected = false;
        using (var rows = new RowReaderCore(new MemoryReadSource(parquetBytes), schema, [nonNullable],
            projection: null, rowOptions, schemaEvolution: null))
        {
            try
            {
                while (rows.MoveNext())
                    _ = rows.GetCurrentNested(nonNullable);
            }
            catch (CorruptParquetException error) when (error.Message == ExpectedMessage)
            {
                rejected = true;
            }
            catch (Exception error)
            {
                throw new InvalidDataException("The non-nullable nested shape changed its rejection classification.", error);
            }
        }

        if (!rejected)
            throw new InvalidDataException("The non-nullable nested shape accepted a valid null leaf.");
    }

    static void RunBufferRetentionProbe(ReadOnlySpan<byte> fileBytes, IParquetBufferPool bufferPool)
    {
        var sourceBytes = fileBytes.ToArray();
        using var source = new MemoryReadSource(sourceBytes);
        using var reader = new ParquetReader(new ParquetReaderOptions
        {
            BufferPool = bufferPool,
            Strict = true
        });
        reader.Reset(source);
        if (reader.RowGroups.Count != 1 || reader.Schema.LeafColumns.Length != 2)
            return;

        var flatColumn = reader.Schema.LeafColumns[0];
        var nestedColumn = reader.Schema.LeafColumns[1];
        if (flatColumn.Column.Name != "flat" || flatColumn.PhysicalType != ParquetPhysicalType.Int32 ||
            flatColumn.MaxDefinitionLevel != 0 || flatColumn.MaxRepetitionLevel != 0 ||
            nestedColumn.Path != "payload.list.element" || nestedColumn.PhysicalType != ParquetPhysicalType.ByteArray ||
            nestedColumn.MaxRepetitionLevel == 0)
            return;
        var rowGroup = reader.RowGroups[0];
        if (rowGroup.RowCount is 0 or > 256)
            return;
        var flatMetadata = rowGroup.GetColumnMetadata(flatColumn);
        if (flatMetadata.Compression != CompressionKind.None ||
            !flatMetadata.Encodings.Contains(EncodingKind.Plain))
            return;

        var flatRetained = new List<(ParquetBuffer Buffer, int[] Expected)>();
        var nestedRetained = new List<(ColumnBuffer<byte> Values, ParquetBuffer Buffer, byte[][] Expected)>();
        var levelRetained = new List<(ParquetBuffer Buffer, int[] Expected)>();
        try
        {
            var flatCount = 0;
            foreach (var buffer in rowGroup.Column<int>(flatColumn))
            {
                if (buffer.Count == 0 || flatCount > 256 - buffer.Count)
                    return;
                var expected = buffer.Values.ToArray();
                using (var retained = buffer.Retain())
                    if (!retained.AsSpan<int>().SequenceEqual(expected))
                        throw new InvalidDataException("A retained borrowed INT32 buffer changed before reader disposal.");
                flatRetained.Add((buffer.Retain(), expected));
                flatCount += buffer.Count;
            }
            if (flatCount != (int)rowGroup.RowCount)
                throw new InvalidDataException("The retention probe's INT32 column did not cover every row.");

            var nestedValueCount = 0;
            var nestedEntryCount = 0;
            foreach (var page in rowGroup.NestedColumn<byte>(nestedColumn))
            {
                if (nestedEntryCount > 512 - page.Count || nestedValueCount > 512 - page.Values.Count)
                    return;
                var expected = new byte[page.Values.Count][];
                for (var i = 0; i < expected.Length; i++)
                {
                    if (page.Values.IsNull(i))
                        throw new InvalidDataException("The retention probe's required binary leaf decoded as null.");
                    expected[i] = page.Values.GetValue(i).ToArray();
                }
                var expectedLevels = page.RepetitionLevels.ToArray();
                expectedLevels = [.. expectedLevels, .. page.DefinitionLevels];
                nestedRetained.Add((page.Values, page.Values.Retain(), expected));
                levelRetained.Add((page.RetainLevels(), expectedLevels));
                nestedValueCount += page.Values.Count;
                nestedEntryCount += page.Count;
            }
            if (nestedEntryCount == 0 || nestedValueCount == 0)
                return;

            reader.Dispose();
            source.Dispose();
            Array.Fill(sourceBytes, (byte)0xDD);
            foreach (var retained in flatRetained)
                if (!retained.Buffer.AsSpan<int>().SequenceEqual(retained.Expected))
                    throw new InvalidDataException("A retained borrowed INT32 buffer changed after reader disposal.");
            foreach (var retained in nestedRetained)
            {
                if (retained.Values.Count != retained.Expected.Length)
                    throw new InvalidDataException("The retained nested binary value count changed after reader disposal.");
                for (var i = 0; i < retained.Expected.Length; i++)
                    if (!retained.Values.GetValue(i).SequenceEqual(retained.Expected[i]))
                        throw new InvalidDataException("A retained nested binary value changed after reader disposal.");
            }
            foreach (var retained in levelRetained)
                if (!retained.Buffer.AsSpan<int>().SequenceEqual(retained.Expected))
                    throw new InvalidDataException("Retained nested levels changed after reader disposal.");
        }
        finally
        {
            foreach (var retained in flatRetained)
                retained.Buffer.Dispose();
            foreach (var retained in nestedRetained)
                retained.Buffer.Dispose();
            foreach (var retained in levelRetained)
                retained.Buffer.Dispose();
        }
    }

    static void RunFileReadSourceProbe(byte selector, byte[] fileBytes, IParquetBufferPool bufferPool)
    {
        var path = Path.Combine(Path.GetTempPath(), $"plank-reader-{Guid.NewGuid():N}.parquet");
        try
        {
            using (var file = new FileStream(path, FileMode.CreateNew, FileAccess.Write, FileShare.None))
                file.Write(fileBytes);

            using var source = new FileReadSource(path);
            Run(selector, fileBytes, bufferPool, source);
        }
        finally
        {
            File.Delete(path);
        }
    }

    static void RunVariableBytesTypeMismatchRoute(byte[] fileBytes, IParquetBufferPool bufferPool)
    {
        using var stream = new MemoryStream(fileBytes, writable: false);
        using var reader = new ParquetReader(new ParquetReaderOptions { BufferPool = bufferPool });
        try
        {
            reader.Reset(stream);
        }
        catch (CorruptParquetException)
        {
            return;
        }

        foreach (var rowGroup in reader.RowGroups)
        foreach (var column in reader.Schema.LeafColumns)
        {
            if (column.Converter is not null || column.PhysicalType != ParquetPhysicalType.ByteArray)
                continue;

            RequireExpectedTypeMismatch(() => rowGroup.Column<string>(column));
            RequireExpectedTypeMismatch(() => rowGroup.Column<Guid>(column));
            RequireExpectedTypeMismatch(() => rowGroup.Column<byte[]>(column));
            RequireExpectedTypeMismatch(() => rowGroup.Column<ReadOnlyMemory<byte>>(column));
        }
    }

    static void RunPageIndexBloomProbe(byte route, ReadOnlySpan<byte> fileBytes)
    {
        using var source = new MemoryReadSource(fileBytes.ToArray());
        using var reader = new Plank.Reading.Physical.ParquetFileReader();
        reader.Reset(source);
        switch (route)
        {
            case 0:
            {
                using var bloom = reader.OpenBloomFilter(0, 0);
                _ = bloom.MightContain(new byte[64]);
                return;
            }
            case 1:
                using (reader.OpenBloomFilter(0, 0)) { }
                return;
            case 2:
                using (reader.OpenBloomFilter(0, 0)) { }
                return;
            default:
                return;
        }
    }

    static void RunPageMetadataEnumeratorProbe(ReadOnlySpan<byte> fileBytes, IParquetBufferPool bufferPool)
    {
        Span<byte> fileHash = stackalloc byte[32];
        SHA256.HashData(fileBytes, fileHash);
        var isKnownFixture = fileHash.SequenceEqual(PageMetadataEnumeratorProbeFileHash);

        using var source = new MemoryReadSource(fileBytes.ToArray());
        using var reader = new ParquetReader(new ParquetReaderOptions { BufferPool = bufferPool });
        reader.Reset(source);
        if (reader.RowGroups.Count == 0 || reader.Schema.LeafColumns.Length == 0)
            return;

        using var pages = reader.RowGroups[0].GetColumnMetadata(0).OpenPages();
        var expectedCount = pages.Count;
        var pageOrdinal = 0;
        ulong previousPageEnd = 0;
        foreach (var page in pages)
        {
            if (page.PageOrdinal != pageOrdinal || page.CompressedSize == 0 || page.Offset < previousPageEnd)
                throw new InvalidDataException("Page metadata enumeration returned inconsistent page locations.");
            if (page.Offset > ulong.MaxValue - page.CompressedSize)
                throw new InvalidDataException("Page metadata enumeration returned an overflowing page location.");

            if (isKnownFixture)
            {
                ReadOnlySpan<ulong> expectedOffsets = [4, 64, 124];
                ReadOnlySpan<uint> expectedSizes = [60, 60, 60];
                if ((uint)pageOrdinal >= (uint)expectedOffsets.Length ||
                    page.Offset != expectedOffsets[pageOrdinal] ||
                    page.CompressedSize != expectedSizes[pageOrdinal])
                    throw new InvalidDataException("The page-metadata probe fixture changed its page layout.");
            }

            previousPageEnd = page.Offset + page.CompressedSize;
            pageOrdinal++;
        }

        if (pageOrdinal != expectedCount)
            throw new InvalidDataException("Page metadata Count disagreed with foreach enumeration.");
        if (isKnownFixture && pageOrdinal != 3)
            throw new InvalidDataException("The page-metadata probe fixture no longer has three data pages.");

        using (var cursorSource = new MemoryReadSource(fileBytes.ToArray()))
        using (var physicalReader = new Plank.Reading.Physical.ParquetFileReader())
        {
            physicalReader.Reset(cursorSource);
            var cursor = physicalReader.OpenPages(0, 0);
            if (isKnownFixture)
            {
                try
                {
                    _ = cursor.Current;
                    throw new InvalidDataException("An unpositioned page cursor exposed a current page.");
                }
                catch (InvalidOperationException error) when (error.GetType() == typeof(InvalidOperationException))
                {
                }

                if (!cursor.MoveNext())
                    throw new InvalidDataException("The page-metadata probe fixture has no first page.");
                _ = cursor.Current;
                cursor.Dispose();

                try
                {
                    _ = cursor.Current;
                    throw new InvalidDataException("A disposed page cursor exposed a current page.");
                }
                catch (ObjectDisposedException)
                {
                }
            }
            cursor.Dispose();
            cursor.Dispose();
        }

        // Keep the marker route's page-metadata and lifecycle probes alongside the
        // normal strict file-schema read and independent Arrow/ParquetSharp checks.
        Run(0, fileBytes.ToArray(), bufferPool);
    }

    static void RequireExpectedTypeMismatch<T>(Func<T> read)
    {
        try
        {
            _ = read();
        }
        catch (NotSupportedException)
        {
            return;
        }
        catch (Exception error)
        {
            // Execute intentionally swallows common reader errors, so preserve a
            // changed classification as a finding instead of masking it.
            throw new InvalidDataException(
                "Variable-length bytes produced an unexpected exception for an incompatible public CLR type.",
                error);
        }

        // This must remain outside Execute's expected-reader-exception filter:
        // a changed public exception classification is a fuzz finding.
        throw new InvalidDataException("Variable-length bytes accepted an incompatible public CLR type.");
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
            // A row group's chunk count comes from its own footer list, which a
            // damaged file can make disagree with the schema's leaf count.
            for (var column = 0; column < metadata.RowGroup(group).ColumnCount; column++)
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
        using var bloom = metadata.OpenBloomFilter();
        _ = bloom.BitsetSizeBytes;
        var bitset = bloom.Bitset;
        Consume(bitset);
        _ = bloom.MightContain(0);
        _ = bloom.MightContain(byte.MaxValue);
        _ = bloom.MightContain(ushort.MaxValue);
        _ = bloom.MightContain(uint.MaxValue);
        _ = bloom.MightContain(long.MaxValue);
        _ = bloom.MightContain(ulong.MaxValue);
        _ = bloom.MightContain(float.NaN);
        _ = bloom.MightContain(double.NegativeInfinity);
        _ = bloom.MightContain(Guid.Empty);
        _ = bloom.MightContainHash(0);
        Span<byte> hashInput = stackalloc byte[40];
        bitset[..Math.Min(bitset.Length, hashInput.Length)].CopyTo(hashInput);
        _ = bloom.MightContain(hashInput[..0]);
        _ = bloom.MightContain(hashInput[..3]);
        _ = bloom.MightContain(hashInput[..4]);
        _ = bloom.MightContain(hashInput[..8]);
        _ = bloom.MightContain(hashInput[..31]);
        _ = bloom.MightContain(hashInput[..32]);
        _ = bloom.MightContain(hashInput);
        bloom.Dispose();
        try
        {
            _ = bloom.BitsetSizeBytes;
            throw new ReaderAcceptanceMismatchException("A disposed Bloom filter still exposed its bitset size.");
        }
        catch (ObjectDisposedException) { }
    }

    static void Consume(ReadOnlySpan<byte> bytes)
    {
        for (var i = 0; i < bytes.Length; i++)
            _ = bytes[i];
    }

    static void RunRowApiStreamResetProbe(byte[] parquetBytes, IParquetBufferPool bufferPool)
    {
        // This seed is intentionally a flat, required INT32 file. Refuse a
        // marker-preserving mutation that changes the shape before creating the
        // descriptor, so the route remains bounded and deterministic.
        using var schemaReader = new ParquetReader(new ParquetReaderOptions
        {
            BufferPool = bufferPool,
            Strict = true
        });
        using var schemaSource = new MemoryReadSource(parquetBytes);
        schemaReader.Reset(schemaSource);
        var schema = schemaReader.Schema;
        if (schema.LeafColumns.Length != 1)
            return;
        var column = schema.LeafColumns[0];
        if (column.PhysicalType != ParquetPhysicalType.Int32 || column.MaxDefinitionLevel != 0
            || column.MaxRepetitionLevel != 0 || column.LogicalType is not null)
            return;

        var descriptor = new RowApiColumnDescriptor<int>("p0", column);
        RowApiColumnDescriptor[] descriptors = [descriptor];
        using var expectedSource = new MemoryReadSource(parquetBytes);
        var expected = CaptureColumnarRows(expectedSource, schema, verifyPageCrc: false, bufferPool);
        if (expected is null || expected.Length != 1 || expected[0] is null)
            throw new ReaderAcceptanceMismatchException(
                "The strict column reader could not read the stream-reset probe fixture.");

        var options = new RowReaderOptions
        {
            BufferPool = bufferPool,
            Execution = new ParquetExecutionOptions { WorkerCount = 1 }
        };
        var stream = new MemoryStream(parquetBytes, writable: false);
        using (var rows = new RowReaderCore(stream, schema, descriptors, projection: null, options,
                   schemaEvolution: null))
        {
            _ = ReadAllRows(rows, descriptors, record: false, expected);
            rows.Reset(stream, projection: null);
            _ = ReadAllRows(rows, descriptors, record: false, expected);
            rows.Reset(new MemoryStream(parquetBytes, writable: false), projection: null);
            _ = ReadAllRows(rows, descriptors, record: false, expected);
        }

        // Also cover the source-to-stream Reset path, which lazily creates its
        // StreamReadSource on the first reset.
        using (var resetSource = new MemoryReadSource(parquetBytes))
        using (var rows = new RowReaderCore(resetSource, schema, descriptors, projection: null, options,
                   schemaEvolution: null))
        {
            rows.Reset(new MemoryStream(parquetBytes, writable: false), projection: null);
            _ = ReadAllRows(rows, descriptors, record: false, expected);
        }

        ReaderAcceptanceOracle.VerifyWithParquetSharp(parquetBytes);
    }

    static void RunRowApiReadAheadProbe(byte[] parquetBytes, IParquetBufferPool bufferPool)
    {
        // This second bounded fixture has only the generated RowFuzzFixed Id
        // column and multiple groups. The other generated columns materialize
        // defaults while the Id column is prefetched from a custom public source.
        using var source = new MemoryReadSource(parquetBytes);
        using var verifier = new ParquetReader(new ParquetReaderOptions
        {
            BufferPool = bufferPool,
            Strict = true
        });
        verifier.Reset(source);
        var schema = verifier.Schema;
        if (schema.LeafColumns.Length != 1 || schema.LeafColumns[0].Column.Name != "Id"
            || schema.LeafColumns[0].PhysicalType != ParquetPhysicalType.Int32
            || schema.LeafColumns[0].MaxDefinitionLevel != 0
            || schema.LeafColumns[0].MaxRepetitionLevel != 0 || schema.LeafColumns[0].LogicalType is not null)
            return;

        var expected = new List<int>();
        var rowGroupCount = 0;
        foreach (var rowGroup in verifier.RowGroups)
        {
            rowGroupCount++;
            foreach (var buffer in rowGroup.Column<int>(schema.LeafColumns[0]))
                expected.AddRange(buffer.Values);
        }
        if (rowGroupCount < 2)
            return;

        var workerCount = 0;
        var options = new RowReaderOptions
        {
            BufferPool = bufferPool,
            Execution = new ParquetExecutionOptions
            {
                WorkerCount = 2,
                OnWorkerStarted = _ => Interlocked.Increment(ref workerCount)
            }
        };
        var evolution = new ParquetSchemaEvolutionOptions
        {
            MissingColumns = MissingColumnEvolutionBehavior.MaterializeDefault
        };
        using var wrappedSource = new RowApiProbeReadSource(parquetBytes);
        using var rows = RowFuzzFixed.CreateRowReader(wrappedSource, options: options,
            schemaEvolution: evolution);
        var row = 0;
        while (rows.MoveNext())
        {
            var current = rows.Current;
            if ((uint)row >= (uint)expected.Count || current.Id != expected[row]
                || current.Flag || current.Sequence != 0 || current.Measure != 0)
                throw new ReaderAcceptanceMismatchException(
                    $"Row API prefetch returned different values or defaults at row {row}.");
            row++;
        }

        if (row != expected.Count || workerCount == 0)
            throw new ReaderAcceptanceMismatchException(
                $"Row API prefetch returned {row} rows and started {workerCount} workers; expected {expected.Count} rows and a worker.");
    }

    sealed class RowApiProbeReadSource(byte[] bytes) : IParquetReadSource
    {
        readonly MemoryReadSource _source = new(bytes);

        public ulong Length => _source.Length;

        public void ReadExactly(ulong offset, Span<byte> destination)
            => _source.ReadExactly(offset, destination);

        public void Dispose()
            => _source.Dispose();
    }

    // RowReaderCore is normally reached through source-generated row types, but
    // it is public and takes the schema and descriptors directly, so the fuzzer
    // can drive it over whatever schema the file declares.
    static void DrainRowApi(IParquetReadSource source, byte[] fileBytes, bool verifyPageCrc, byte selector,
        IParquetBufferPool bufferPool, bool logicalTypeProbe, bool projectionProbe)
    {
        ParquetSchema schema;
        using (var probe = new ParquetReader(new ParquetReaderOptions { BufferPool = bufferPool }))
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
        // Keep workers off during AFL runs: concurrent instrumented code
        // scrambles SharpFuzz's shared previous-location state. A bounded
        // two-worker coverage route is available only when explicitly enabled
        // in a replay process, and only for selector-marked inputs.
        //
        // Bit 3 resets the reader onto the same file and reads it again, as a
        // caller reusing one reader would; the second pass must return exactly
        // what the first did, which catches state carried across Reset.
        var rowOptions = new RowReaderOptions
        {
            BufferPool = bufferPool,
            VerifyPageCrc = verifyPageCrc,
            Execution = new ParquetExecutionOptions
            {
                WorkerCount = (selector & 0x20) != 0
                    && Environment.GetEnvironmentVariable("PLANK_FUZZ_ENABLE_ROW_WORKERS") == "1"
                        ? 2
                        : 1
            }
        };
        // Bit 2 also reads the file through the source-generated row readers,
        // with every schema-evolution allowance switched on. The generated
        // readers (RowReaderBase, RowSchema, schema evolution) only ran in the
        // separate row-API target, never on a corrupt or foreign file.
        if ((selector & 4) != 0)
        {
            DrainGeneratedRows(source, bufferPool);
            var idBitWidth = selector == SignedIntegerStrictProbeSelector ? (byte)32 : (byte)16;
            if (logicalTypeProbe && MatchesSignedIntegerEvolutionSchema(schema, idBitWidth))
                ProbeGeneratedLogicalTypeMismatch(source, bufferPool,
                    strict: selector == SignedIntegerStrictProbeSelector);
        }

        // The row reader has its own buffering on top of the column reader, and
        // nothing checked what it returns: its values were only ever compared
        // with themselves after Reset, and Arrow never saw these inputs. Read the
        // flat columns through the column reader first and require the same
        // values; then hold the row reader to the same acceptance oracle as the
        // column reader. (The two Plank readers may differ on trailing junk the
        // rows never reach, as Arrow does, so their verdicts are not compared.)
        var expected = CaptureColumnarRows(source, schema, verifyPageCrc, bufferPool);
        if (projectionProbe && descriptors.Length != 0)
            DrainProjectedRowApi(source, schema, descriptors, rowOptions, expected);

        var compareAfterReset = (selector & 8) != 0;
        using var rows = new RowReaderCore(source, schema, descriptors, projection: null,
            rowOptions, schemaEvolution: null);
        var first = ReadAllRows(rows, descriptors, compareAfterReset, expected);
        if (ReaderAcceptanceOracle.HasParquetHeader(fileBytes))
            ReaderAcceptanceOracle.VerifyWithParquetSharp(fileBytes);
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

    static void DrainProjectedRowApi(IParquetReadSource source, ParquetSchema schema,
        RowApiColumnDescriptor[] descriptors, RowReaderOptions options, List<byte[]?>?[]? expected)
    {
        var selected = descriptors[0];
        var projection = new[] { selected };
        using var rows = new RowReaderCore(source, schema, descriptors, projection, options, schemaEvolution: null);
        var expectedValues = expected is { Length: > 0 } ? expected[0] : null;
        var row = 0;
        while (rows.MoveNext())
        {
            var actual = ReadCurrent(rows, selected);
            if (expectedValues is not null)
                RequireSameRowValue(selected, expectedValues, row, actual);
            row++;
        }
        if (expectedValues is not null && expectedValues.Count != row)
            throw new ReaderAcceptanceMismatchException(
                $"Decoded value mismatch (projected row reader vs column reader) — returned {row} rows, expected {expectedValues.Count}.");
    }

    // One worker, as for RowReaderCore above: the default follows
    // Environment.ProcessorCount, which differs between the pinned fuzz worker
    // and a coverage run, and threads scramble SharpFuzz's edge map.
    static RowReaderOptions SingleWorker(IParquetBufferPool bufferPool)
        => new() { BufferPool = bufferPool, Execution = new ParquetExecutionOptions { WorkerCount = 1 } };

    static readonly ParquetSchemaEvolutionOptions PermissiveEvolution = new()
    {
        MissingColumns = MissingColumnEvolutionBehavior.MaterializeDefault,
        Repetition = RepetitionEvolutionBehavior.AllowRequiredToOptionalAndOptionalToRequired,
        PhysicalTypes = SchemaTypeEvolutionBehavior.AllowCompatible,
        LogicalTypes = SchemaTypeEvolutionBehavior.AllowCompatible,
        MaterializedTypes = SchemaTypeEvolutionBehavior.AllowCompatible,
    };

    // Each schema is tried on its own: a schema the file cannot bind to is an
    // API refusal for that one only.
    static void DrainGeneratedRows(IParquetReadSource source, IParquetBufferPool bufferPool)
    {
        TryGenerated(() =>
        {
            using var reader = RowFuzzFixed.CreateRowReader(source, options: SingleWorker(bufferPool), schemaEvolution: PermissiveEvolution);
            while (reader.MoveNext())
            {
                var row = reader.Current;
                _ = row.Flag ^ (row.Id == 0) ^ (row.Sequence == 0) ^ double.IsNaN(row.Measure);
            }
        });
        TryGenerated(() =>
        {
            using var reader = RowFuzzNullable.CreateRowReader(source, options: SingleWorker(bufferPool), schemaEvolution: PermissiveEvolution);
            while (reader.MoveNext())
            {
                var row = reader.Current;
                _ = row.Id.HasValue ^ row.Sequence.HasValue ^ row.Measure.HasValue ^ row.Flag.HasValue;
            }
        });
        TryGenerated(() =>
        {
            using var reader = RowFuzzBinary.CreateRowReader(source, options: SingleWorker(bufferPool), schemaEvolution: PermissiveEvolution);
            while (reader.MoveNext())
            {
                var row = reader.Current;
                Consume(row.Payload.Value);
                // A missing Label materializes as null although the property is
                // a non-nullable string (raised as a question on Plank's API).
                _ = row.Id + (row.Label?.Length ?? 0);
            }
        });
    }

    static void TryGenerated(Action read)
    {
        try { read(); }
        catch (Exception error) when (error is InvalidOperationException or NotSupportedException
            or CorruptParquetException) { }
    }

    static void ProbeGeneratedLogicalTypeMismatch(IParquetReadSource source, IParquetBufferPool bufferPool,
        bool strict)
    {
        const string ExpectedMessage = "Column 'Id' has a different logical type than the row API schema.";
        try
        {
            using var reader = RowFuzzFixed.CreateRowReader(source, options: SingleWorker(bufferPool),
                schemaEvolution: strict ? null : PermissiveEvolution);
            while (reader.MoveNext())
                _ = reader.Current.Id;
        }
        catch (InvalidOperationException error) when (error.Message == ExpectedMessage)
        {
            return;
        }
        catch (Exception error)
        {
            throw new RowReaderLogicalTypeProbeException(
                $"Generated row-reader logical-type probe threw an unexpected {error.GetType().Name}: {error.Message}",
                error);
        }

        throw new RowReaderLogicalTypeProbeException(strict
            ? "Strict generated row-reader probe accepted a signed INTEGER annotation without schema evolution."
            : "Generated row-reader probe accepted a signed INTEGER annotation with an incompatible bit width.");
    }

    static bool MatchesSignedIntegerEvolutionSchema(ParquetSchema schema, byte idBitWidth)
    {
        var columns = schema.LeafColumns;
        return columns.Length == 4
            && IsRequiredScalar(columns[0], "Flag", ParquetPhysicalType.Boolean)
            && columns[0].LogicalType is null
            && IsRequiredScalar(columns[1], "Id", ParquetPhysicalType.Int32)
            && columns[1].LogicalType is LogicalType.Int idType
            && idType.IsSigned && idType.BitWidth == idBitWidth
            && IsRequiredScalar(columns[2], "Sequence", ParquetPhysicalType.Int64)
            && columns[2].LogicalType is LogicalType.Int sequenceType
            && sequenceType.IsSigned && sequenceType.BitWidth == 64
            && IsRequiredScalar(columns[3], "Measure", ParquetPhysicalType.Double)
            && columns[3].LogicalType is null;
    }

    static bool IsRequiredScalar(LeafColumn column, string name, ParquetPhysicalType physicalType)
        => column.Path == name && column.PhysicalType == physicalType
            && column.MaxDefinitionLevel == 0 && column.MaxRepetitionLevel == 0;

    // Execute() deliberately ignores ordinary InvalidOperationException values
    // from fuzzed files. This probe expects exactly one binding diagnostic, so
    // turn any different result into a finding that the outer filter cannot
    // mistake for ordinary input rejection.
    sealed class RowReaderLogicalTypeProbeException(string message, Exception? inner = null)
        : Exception(message, inner);

    static List<string>? ReadAllRows(RowReaderCore rows, RowApiColumnDescriptor[] descriptors, bool record,
        List<byte[]?>?[]? expected = null)
    {
        var values = record ? new List<string>() : null;
        var row = 0;
        while (rows.MoveNext())
        {
            for (var i = 0; i < descriptors.Length; i++)
            {
                var value = ReadCurrent(rows, descriptors[i]);
                values?.Add(FormatRowValue(value));
                if (expected?[i] is { } column)
                    RequireSameRowValue(descriptors[i], column, row, value);
            }
            row++;
        }
        if (expected is not null)
            for (var i = 0; i < expected.Length; i++)
                if (expected[i] is { } column && column.Count != row)
                    throw new ReaderAcceptanceMismatchException(
                        $"Decoded value mismatch (row reader vs column reader) — column {i}: row reader returned {row} rows, column reader {column.Count}.");
        return values;
    }

    // Flat leaves only: a nested leaf's row value is a reconstructed shape, not one
    // value per entry. Null when the column reader rejects the file: there is then
    // nothing to compare values with.
    static List<byte[]?>?[]? CaptureColumnarRows(IParquetReadSource source,
        ParquetSchema schema, bool verifyPageCrc, IParquetBufferPool bufferPool)
    {
        var leaves = schema.LeafColumns;
        var values = new List<byte[]?>?[leaves.Length];
        for (var i = 0; i < leaves.Length; i++)
            if (leaves[i].MaxRepetitionLevel == 0)
                values[i] = [];
        try
        {
            using var reader = new ParquetReader(new ParquetReaderOptions
            {
                BufferPool = bufferPool,
                VerifyPageCrc = verifyPageCrc
            });
            reader.Reset(source);
            foreach (var group in reader.RowGroups)
                for (var i = 0; i < leaves.Length; i++)
                {
                    if (values[i] is null)
                        continue;
                    var trace = ColumnTrace.CapturePlank(group, reader.Schema.LeafColumns[i]);
                    if (trace.Overflowed)
                        values[i] = null;
                    else
                        values[i]!.AddRange(trace.FlatValues());
                }
        }
        catch (Exception error) when (error is CorruptParquetException or NotSupportedException
                                          or InvalidOperationException)
        {
            return null;
        }
        return values;
    }

    static void RequireSameRowValue(RowApiColumnDescriptor descriptor, List<byte[]?> column, int row, object? value)
    {
        if (row >= column.Count)
            throw new ReaderAcceptanceMismatchException(
                $"Decoded value mismatch (row reader vs column reader) — row reader returned more than {column.Count} rows.");
        var expected = column[row];
        byte[]? actual = value switch
        {
            null => null,
            byte[] bytes => bytes,
            bool b => [b ? (byte)1 : (byte)0],
            int v => BitConverter.GetBytes(v),
            long v => BitConverter.GetBytes(v),
            float v => BitConverter.GetBytes(v),
            double v => BitConverter.GetBytes(v),
            _ => throw new InvalidOperationException($"unexpected row value {value.GetType()}"),
        };
        // A fixed-width descriptor has no null; for an absent value it returns
        // whatever it returns, so only present values are compared there.
        if (expected is null && descriptor is not RowApiColumnDescriptor<byte[]>)
            return;
        if ((expected is null) != (actual is null)
            || expected is not null && !expected.AsSpan().SequenceEqual(actual))
            throw new ReaderAcceptanceMismatchException(
                $"Decoded value mismatch (row reader vs column reader) — {descriptor.GetType().GenericTypeArguments[0].Name} row {row}: "
                + $"row reader {(actual is null ? "null" : Convert.ToHexString(actual))}, column reader {(expected is null ? "null" : Convert.ToHexString(expected))}.");
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
    // corruption and the same values for the rows both return. A rejection is
    // not a finding on its own (the natural read reports corrupt pages); a path
    // that returns values where the other rejects is.
    static void RequireSameReads(string what,
        string firstName, (object?[]? Values, Exception? Error) first,
        string secondName, (object?[]? Values, Exception? Error) second,
        bool skipNullsOfFirst = false, bool secondMayRejectMore = false)
    {
        // A path that refuses the request (TryReadPath returns neither values nor
        // an error, e.g. NotSupportedException: this encoding cannot be decoded
        // into that CLR shape) has no verdict on the file.
        if (first is (null, null) || second is (null, null))
            return;
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
    static readonly ParquetPagePruner RejectAllPages = static (in ParquetDataPageMetadata _) => false;

    static void CrossCheckPrunedReads(byte[] fileBytes, ParquetReaderOptions options)
    {
        using var plain = new ParquetReader(options);
        plain.Reset(new MemoryReadSource(fileBytes));
        using var pruned = new ParquetReader(options);
        pruned.Reset(new MemoryReadSource(fileBytes), AcceptAllPages);
        using var sparse = new ParquetReader(options);
        sparse.Reset(new MemoryReadSource(fileBytes), AcceptEvenPages);
        using var empty = new ParquetReader(options);
        empty.Reset(new MemoryReadSource(fileBytes), RejectAllPages);

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
                var skipped = TryReadPath(() => ReadPhysical(empty.RowGroups[groupIndex], empty.Schema.LeafColumns[columnIndex]));
                if (skipped.Error is null && skipped.Values is { Length: > 0 })
                    throw new ReaderAcceptanceMismatchException(
                        $"Decoded value mismatch (page pruner) — reject-all scan returned values for column '{column.Path}'.");
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

// Stream.Read is allowed to return fewer bytes than requested. MemoryStream
// normally fills every request, so the stream-backed reader's ReadExactly loop
// never sees that legal case. This wrapper keeps the same seekable byte source
// while forcing short reads; all normal reader comparisons still validate the
// decoded result against the other available oracle.
sealed class FragmentedReadStream(byte[] bytes, int maxRead) : MemoryStream(bytes, writable: false)
{
    public override int Read(Span<byte> buffer)
        => base.Read(buffer[..Math.Min(buffer.Length, maxRead)]);

    public override int Read(byte[] buffer, int offset, int count)
        => base.Read(buffer, offset, Math.Min(count, maxRead));
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
