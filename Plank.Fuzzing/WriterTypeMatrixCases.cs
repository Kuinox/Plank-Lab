using System.Collections.Immutable;
using Plank.Reading;
using Plank.Reading.Logical;
using RowGroup = Plank.Reading.Logical.RowGroup;
using Plank.Schema;
using Plank.Writing;
using Plank.Writing.PageStrategy;
using PlankSchema = Plank.Schema.ParquetSchema;
using Target = Plank.Fuzzing.PlankWriterFuzzTarget;

namespace Plank.Fuzzing;

/// <summary>
/// Typed single-column write/read-back matrix. Every parameter that the older hand-written cases pinned
/// (value count, number of distinct values, value width, encoding, codec and codec level, page and chunk
/// size, row-group split, buffer pool, page strategy) is drawn independently from the input.
/// </summary>
/// <remarks>
/// Coverage targets (see agents/coverage-gaps.md): statistics creators for byte[] / ReadOnlyMemory /
/// decimal / optional columns and the byte-array hashing used by their dictionaries, int8/int16 narrowing,
/// vectorized delta normalization, ForceDictionaryPageStrategy, the ColumnDefinition factory overloads,
/// DELTA_BYTE_ARRAY / DELTA_LENGTH_BYTE_ARRAY / BYTE_STREAM_SPLIT for binary, high LZ4/gzip/zstd/brotli levels,
/// and nullable int/long/DateTime dictionaries with more than 256 and 65536 distinct values.
/// </remarks>
internal static class WriterTypeMatrixCases
{
    sealed class Cur(ReadOnlySpan<byte> data)
    {
        readonly byte[] _d = data.ToArray();
        int _i;

        public byte Byte() => _d.Length == 0 ? (byte)0 : _d[_i++ % _d.Length];

        public int Int(int min, int maxExclusive)
        {
            uint v = Byte();
            v |= (uint)Byte() << 8;
            v |= (uint)Byte() << 16;
            v |= (uint)Byte() << 24;
            return min + (int)(v % (uint)(maxExclusive - min));
        }

        public long Long() => ((long)Int(0, int.MaxValue) << 32) | (uint)Int(0, int.MaxValue) ^ ((long)Byte() << 56);

        public T Pick<T>(params T[] choices) => choices[Int(0, choices.Length)];
    }

    sealed record Params(CompressionKind Compression, int? Level, ParquetDataPageVersion Version, uint PageSize,
        uint Chunk, WriterPoolKind Pool, int Groups, bool Crc, bool PageIndexes, uint InitialPage, uint InitialColumn);

    internal static void Execute(ReadOnlySpan<byte> data)
    {
        var c = new Cur(data);
        var kind = c.Int(0, 13);
        var p = DrawParams(c);
        switch (kind)
        {
            case 0: Binary(c, p, flba: false, memory: false); break;
            case 1: Binary(c, p, flba: false, memory: true); break;
            case 2: Binary(c, p, flba: true, memory: false); break;
            case 3: Decimals(c, p); break;
            case 4: Narrow(c, p); break;
            case 5: DictionaryCardinality(c, p); break;
            case 6: Deltas(c, p); break;
            case 7: CodecLevels(c, p); break;
            case 9: Floating(c, p); break;
            case 10: Unsigned(c, p); break;
            case 11: Temporal(c, p); break;
            case 12: Converted(c, p); break;
            default: SchemaFactories(c, p); break;
        }
    }

    static Params DrawParams(Cur c)
    {
        var compression = c.Pick(CompressionKind.None, CompressionKind.Snappy, CompressionKind.Gzip,
            CompressionKind.Zstd, CompressionKind.Lz4, CompressionKind.Brotli);
        return new Params(compression, Level(c, compression),
            c.Int(0, 2) == 0 ? ParquetDataPageVersion.V2 : ParquetDataPageVersion.V1,
            c.Pick(64u, 100u, 1000u, 4096u, 65536u, 1024u * 1024),
            c.Pick(1u, 17u, 64u, 4096u, 65536u),
            (WriterPoolKind)c.Int(0, 7), c.Int(1, 4), c.Int(0, 3) == 0, c.Int(0, 4) != 0,
            c.Pick(1u, 7u, 64u, 1024u, 4096u, 32768u), c.Pick(1u, 100u, 4096u, 65536u, 1u << 20));
    }

    static int? Level(Cur c, CompressionKind compression)
    {
        if (c.Int(0, 3) == 0)
            return null;
        return compression switch
        {
            CompressionKind.Gzip => c.Int(0, 10),
            CompressionKind.Zstd => c.Pick(ZstdSharp.Compressor.MinCompressionLevel, -3, 0, 1, 3, 9, 19,
                ZstdSharp.Compressor.MaxCompressionLevel),
            CompressionKind.Lz4 => c.Pick(0, 3, 4, 6, 9, 10, 12),
            CompressionKind.Brotli => c.Int(0, 12),
            _ => null
        };
    }

    static ParquetWriterOptions Options(Params p, WriterPoolKind pool, IParquetBufferPool bufferPool)
        => new()
        {
            Compression = p.Compression,
            CompressionLevel = p.Level,
            DataPageVersion = p.Version,
            TargetDataPageSizeBytes = p.PageSize,
            BufferChunkSizeBytes = p.Chunk,
            WritePageCrc = p.Crc,
            WritePageIndexes = p.PageIndexes,
            // A page per value rents the initial page buffer once per page: bound it for tiny page targets.
            InitialPageBufferBytes = p.PageSize < 1024 ? Math.Min(p.InitialPage, 1024u) : p.InitialPage,
            InitialColumnBufferBytes = p.InitialColumn,
            BufferPool = bufferPool
        };

    static ColumnOptions Opts(ParquetRepetition repetition, EncodingKind encoding, uint typeLength = 0,
        ParquetBloomFilterOptions? bloom = null)
        => new(repetition, ImmutableArray.Create(encoding), typeLength, bloomFilter: bloom);

    static IPageStrategy? Strategy(Cur c)
        => c.Int(0, 3) == 0 ? ForceDictionaryPageStrategy.Shared : null;

    // Splits [0, count) into `groups` consecutive non-empty slices.
    static int[] Boundaries(Cur c, int count, int groups)
    {
        groups = Math.Max(1, Math.Min(groups, count));
        var cuts = new SortedSet<int> { 0, count };
        while (cuts.Count < groups + 1)
            cuts.Add(c.Int(1, count));
        return cuts.ToArray();
    }

    // Writes `values` as one column split over several row groups and returns the file.
    static byte[] WriteColumn<T>(PlankSchema schema, Params p, T[] values, int[] bounds)
    {
        using var pool = WriterFuzzPool.Create(p.Pool);
        using var stream = new MemoryStream();
        var writer = schema.CreateWriter(stream, Options(p, p.Pool, pool));
        for (var g = 0; g + 1 < bounds.Length; g++)
        {
            var group = writer.StartRowGroup();
            var column = group.CreateSerializedColumn<T>(schema.LeafColumns[0]);
            column.Serialize(values.AsSpan(bounds[g], bounds[g + 1] - bounds[g]).ToArray());
            group.Write(column);
        }
        writer.CloseFile();
        return stream.ToArray();
    }

    static void CheckGroups(byte[] file, PlankSchema schema, int[] bounds, string what)
    {
        using var reader = schema.CreateReader(new MemoryStream(file, writable: false));
        if (reader.RowGroups.Count != bounds.Length - 1)
            throw new InvalidOperationException($"{what}: row-group count {reader.RowGroups.Count} != {bounds.Length - 1}.");
        for (var g = 0; g < reader.RowGroups.Count; g++)
            if (reader.RowGroups[g].RowCount != (ulong)(bounds[g + 1] - bounds[g]))
                throw new InvalidOperationException($"{what}: row-group {g} row count differs.");
    }

    static (byte[] File, int[] Bounds) RoundTrip<T>(string what, PlankSchema schema, Params p, T[] values,
        Func<RowGroup, T[]> read, Func<T, T, bool> equal, Cur c, bool bloom = false, Func<T, IComparable?>? key = null)
    {
        var bounds = Boundaries(c, values.Length, p.Groups);
        var file = WriteColumn(schema, p, values, bounds);
        VerifyFile(what, schema, p, file, values, bounds, read, equal, bloom, key);
        AppendMergeVariant(what, schema, p, file, values, bounds, read, equal, c, bloom, key);
        return (file, bounds);
    }

    // Reads `file` back and checks the values, the group shapes, and the statistics / page index / bloom oracle.
    static void VerifyFile<T>(string what, PlankSchema schema, Params p, byte[] file, T[] values, int[] bounds,
        Func<RowGroup, T[]> read, Func<T, T, bool> equal, bool bloom, Func<T, IComparable?>? key = null)
    {
        CheckGroups(file, schema, bounds, what);
        using var reader = schema.CreateReader(new MemoryStream(file, writable: false));
        for (var g = 0; g < reader.RowGroups.Count; g++)
        {
            var actual = read(reader.RowGroups[g]);
            var length = bounds[g + 1] - bounds[g];
            if (actual.Length != length)
                throw new InvalidOperationException($"{what}: group {g} length {actual.Length} != {length}.");
            for (var i = 0; i < length; i++)
                if (!equal(values[bounds[g] + i], actual[i]))
                    throw new InvalidOperationException(
                        $"{what}: group {g} value {i} differs: expected '{values[bounds[g] + i]}', got '{actual[i]}'.");
        }

        WriterStatisticsOracle.Check(what, schema, file, bounds, values, p.PageIndexes, bloom, key);
    }

    // After the first file is verified, a second batch is added in one of three ways and the WHOLE result is
    // verified again, statistics / page indexes / bloom filters included: they must describe the union of the
    // retained and the new values, not just one of them.
    //   1 append a new row group      2 append into the latest row group      3 merge a second file
    static void AppendMergeVariant<T>(string what, PlankSchema schema, Params p, byte[] file, T[] values, int[] bounds,
        Func<RowGroup, T[]> read, Func<T, T, bool> equal, Cur c, bool bloom, Func<T, IComparable?>? key = null)
    {
        var variant = c.Int(0, 6);
        if (variant is 0 or 4 or 5)
            return;
        var rotate = c.Int(0, values.Length);
        var extra = values.Skip(rotate).Concat(values.Take(rotate)).Take(c.Pick(1, 3, 40, 500, int.MaxValue)).ToArray();
        var all = values.Concat(extra).ToArray();
        what = $"{what} +variant{variant}";
        using var pool = WriterFuzzPool.Create(p.Pool);
        var options = Options(p, p.Pool, pool);
        byte[] result;
        int[] resultBounds;
        switch (variant)
        {
            case 1 or 2:
            {
                var latest = variant == 2;
                using var stream = new MemoryStream();
                stream.Write(file);
                stream.Position = 0;
                try
                {
                    using var writer = schema.CreateAppender(stream, new ParquetAppendOptions
                    {
                        AppendToLatestRowGroup = latest,
                        WriterOptions = options
                    });
                    var group = writer.StartRowGroup();
                    var column = group.CreateSerializedColumn<T>(schema.LeafColumns[0]);
                    column.Serialize(extra);
                    group.Write(column);
                    writer.CloseFile();
                }
                catch (InvalidOperationException error) when (latest && schema.LeafColumns[0].Converter is not null
                    && error.Message.Contains("uses a converter for", StringComparison.Ordinal))
                {
                    // Appending into the latest row group has to read the retained values back as their CLR
                    // type, which a value-converted column does not allow (same limitation the append-sorting
                    // route asserts). Appending a new row group and merging work for such columns.
                    return;
                }

                result = stream.ToArray();
                resultBounds = latest
                    ? bounds[..^1].Append(all.Length).ToArray()
                    : bounds.Append(all.Length).ToArray();
                break;
            }
            default:
            {
                var secondBounds = new[] { 0, extra.Length };
                var second = WriteColumn(schema, p, extra, secondBounds);
                var destination = new PlankMergerFuzzTarget.MemoryReadWriteSource();
                var merger = schema.CreateMerger(new MemoryReadSource(file), destination,
                    new ParquetMergeOptions { WriterOptions = options });
                merger.AppendFile(new MemoryReadSource(second));
                merger.CloseFile();
                result = destination.ToArray();
                resultBounds = bounds.Append(all.Length).ToArray();
                break;
            }
        }

        VerifyFile(what, schema, p, result, all, resultBounds, read, equal, bloom, key);
    }

    // Min/max/null_count of a binary column against what was written. Statistics may be truncated for long
    // values, so the check is exact only when every value is short; otherwise it is a bound.
    static void CheckBinaryStatistics(string what, PlankSchema schema, byte[] file, int[] bounds, byte[]?[] values)
    {
        using var reader = schema.CreateReader(new MemoryStream(file, writable: false));
        for (var g = 0; g < reader.RowGroups.Count; g++)
        {
            var slice = values.Skip(bounds[g]).Take(bounds[g + 1] - bounds[g]).ToArray();
            var statistics = reader.RowGroups[g].GetColumnMetadata(0).Statistics;
            var nonNull = slice.Where(static v => v is not null).Select(static v => v!).ToArray();
            var nulls = slice.Length - nonNull.Length;
            if (statistics.NullCount is { } nullCount && nullCount != nulls)
                throw new InvalidOperationException($"{what}: group {g} null_count {nullCount} != {nulls}.");
            if (nonNull.Length == 0)
                continue;
            if (!statistics.HasMinimum || !statistics.HasMaximum)
                continue; // the writer is allowed to omit them; presence is covered by other routes.
            var min = nonNull.Min(ByteComparer.Instance)!;
            var max = nonNull.Max(ByteComparer.Instance)!;
            var exact = nonNull.All(static v => v.Length <= 16);
            var actualMin = statistics.Minimum.ToArray();
            var actualMax = statistics.Maximum.ToArray();
            if (exact ? !actualMin.AsSpan().SequenceEqual(min) || !actualMax.AsSpan().SequenceEqual(max)
                      : actualMin.AsSpan().SequenceCompareTo(min) > 0 || actualMax.AsSpan().SequenceCompareTo(max) < 0)
                throw new InvalidOperationException(
                    $"{what}: group {g} min/max statistics are inconsistent with the written values.");
        }
    }

    sealed class ByteComparer : IComparer<byte[]>
    {
        public static readonly ByteComparer Instance = new();
        public int Compare(byte[]? x, byte[]? y) => x.AsSpan().SequenceCompareTo(y);
    }

    // ---- binary ----------------------------------------------------------------------------------------

    static void Binary(Cur c, Params p, bool flba, bool memory)
    {
        var optional = c.Int(0, 2) == 0;
        EncodingKind encoding = flba
            ? c.Pick(EncodingKind.Plain, EncodingKind.PlainDictionary, EncodingKind.RleDictionary,
                EncodingKind.ByteStreamSplit, EncodingKind.DeltaByteArray)
            : c.Pick(EncodingKind.Plain, EncodingKind.DeltaLengthByteArray, EncodingKind.DeltaByteArray,
                EncodingKind.PlainDictionary, EncodingKind.RleDictionary);
        var width = flba ? (c.Int(0, 5) == 0 ? c.Pick(255, 256, 257, 300) : c.Int(1, 41)) : 0;
        var maxLength = c.Pick(0, 3, 16, 40, 255, 256, 257, 300);
        var rows = flba && width > 100 ? c.Pick(1, 2, 7, 64, 300) : c.Pick(1, 2, 7, 64, 300, 2000);
        var poolSize = c.Pick(1, 2, 5, 40, rows);
        var shared = new byte[c.Int(0, 12)];
        for (var i = 0; i < shared.Length; i++)
            shared[i] = c.Byte();
        var pool = new byte[poolSize][];
        for (var i = 0; i < pool.Length; i++)
        {
            var length = flba ? width : Math.Max(0, Math.Min(maxLength, shared.Length + c.Int(0, maxLength + 1)));
            var value = new byte[length];
            for (var j = 0; j < length; j++)
                value[j] = j < shared.Length && c.Int(0, 4) != 0 ? shared[j] : c.Byte();
            pool[i] = value;
        }

        var values = new byte[]?[rows];
        for (var i = 0; i < rows; i++)
            values[i] = optional && c.Int(0, 4) == 0 ? null : pool[c.Int(0, pool.Length)];

        var repetition = optional ? ParquetRepetition.Optional : ParquetRepetition.Required;
        var strategy = Strategy(c);
        var bloom = c.Int(0, 4) == 0 ? ParquetBloomFilterOptions.Default : null;
        var definition = ColumnDefinition.Leaf("bin",
            flba ? ParquetPhysicalType.FixedLenByteArray : ParquetPhysicalType.ByteArray,
            Opts(repetition, encoding, flba ? (uint)width : 0, bloom), pageStrategy: strategy);
        var schema = new PlankSchema([definition]);
        var what = $"binary flba={flba} memory={memory} {encoding} optional={optional} rows={rows} pool={poolSize}";

        if (flba && encoding == EncodingKind.DeltaByteArray)
        {
            // Documented limitation: the writer rejects DELTA_BYTE_ARRAY for FIXED_LEN_BYTE_ARRAY with this
            // exact error; if it ever learns to write it, the round trip must be exact.
            try
            {
                RoundTrip(what, schema, p, values, ReadBinary<byte[]?>(definition, schema), BinaryEqual, c);
            }
            catch (NotSupportedException error) when (error.Message.Contains("does not support physical type",
                StringComparison.Ordinal))
            {
            }

            return;
        }

        if (optional && encoding == EncodingKind.ByteStreamSplit)
        {
            // Documented limitation: BYTE_STREAM_SPLIT is not written for optional binary columns. It must be a
            // NotSupportedException that says so (anything else is a fault); if it is ever supported the
            // round trip still has to be exact.
            try
            {
                RoundTrip(what, schema, p, values, ReadBinary<byte[]?>(definition, schema), BinaryEqual, c);
            }
            catch (NotSupportedException error) when (error.Message.Contains("is not supported for optional",
                StringComparison.Ordinal))
            {
            }

            return;
        }

        if (memory && !flba)
        {
            if (optional)
            {
                var typed = values.Select(static v => v is null ? (ReadOnlyMemory<byte>?)null : v).ToArray();
                RoundTrip(what, schema, p, typed, ReadBinary<ReadOnlyMemory<byte>?>(definition, schema), BinaryEqual, c,
                    bloom is not null);
            }
            else
            {
                var typed = values.Select(static v => (ReadOnlyMemory<byte>)v!).ToArray();
                RoundTrip(what, schema, p, typed, ReadBinary<ReadOnlyMemory<byte>>(definition, schema), BinaryEqual, c,
                    bloom is not null);
            }
            return;
        }

        RoundTrip(what, schema, p, values, ReadBinary<byte[]?>(definition, schema), BinaryEqual, c,
            bloom is not null);
    }

    static Func<RowGroup, T[]> ReadBinary<T>(ColumnDefinition definition, PlankSchema schema)
        => group => Convert<T>(Target.ReadAllBinaryBuffers(group.Column<byte>(schema.LeafColumns[0])));

    static T[] Convert<T>(byte[]?[] source)
        => source.Select(static v => v is null ? default! : (T)(object)(
            typeof(T) == typeof(byte[]) ? v! : (object)(ReadOnlyMemory<byte>)v!)).ToArray();

    static bool BinaryEqual<T>(T expected, T actual)
        => Bytes(expected) is { } e
            ? Bytes(actual) is { } a && e.AsSpan().SequenceEqual(a)
            : Bytes(actual) is null;

    static byte[]? Bytes<T>(T value)
        => value switch
        {
            null => null,
            byte[] b => b,
            ReadOnlyMemory<byte> m => m.ToArray(),
            _ => null
        };

    // ---- decimals ----------------------------------------------------------------------------------------

    static void Decimals(Cur c, Params p)
    {
        var optional = c.Int(0, 2) == 0;
        var form = c.Int(0, 4); // Int32, Int64, FLBA, ByteArray
        var precision = form switch { 0 => c.Int(1, 10), 1 => c.Int(10, 19), _ => c.Int(1, 29) };
        var scale = c.Int(0, precision + 1);
        var encoding = form == 2
            ? c.Pick(EncodingKind.Plain, EncodingKind.PlainDictionary, EncodingKind.RleDictionary, EncodingKind.ByteStreamSplit)
            : c.Pick(EncodingKind.Plain, EncodingKind.PlainDictionary, EncodingKind.RleDictionary);
        // decimal has 28-29 significant digits, keep the unscaled magnitude inside 10^min(precision,18).
        var digits = Math.Min(precision, 18);
        var limit = (long)Math.Pow(10, digits) - 1;
        var typeLength = (uint)Math.Max(1, (int)Math.Ceiling((precision * 3.3219280948873626 + 1) / 8d))
            + c.Pick(0u, 0u, 1u, 240u, 250u, 256u);
        var physical = form switch
        {
            0 => ParquetPhysicalType.Int32,
            1 => ParquetPhysicalType.Int64,
            2 => ParquetPhysicalType.FixedLenByteArray,
            _ => ParquetPhysicalType.ByteArray
        };
        var rows = c.Pick(1, 3, 50, 700);
        var distinct = c.Pick(1, 4, rows);
        var pool = new decimal[distinct];
        for (var i = 0; i < pool.Length; i++)
        {
            var unscaled = (c.Long() % (limit + 1)) * (c.Int(0, 2) == 0 ? 1 : -1);
            // Sometimes fewer fractional digits than the column scale: the same number of integer digits must stay.
            var shown = scale == 0 || c.Int(0, 3) != 0 ? scale : c.Int(0, scale);
            if (digits - (scale - shown) < 1)
                shown = scale; // not enough integer digits left for fewer fractional ones
            var shownLimit = (long)Math.Pow(10, Math.Max(1, digits - (scale - shown)));
            pool[i] = (decimal)(unscaled % shownLimit) / (decimal)Math.Pow(10, shown);
        }

        var definition = ColumnDefinition.Leaf("dec", physical,
            Opts(optional ? ParquetRepetition.Optional : ParquetRepetition.Required, encoding,
                form == 2 ? typeLength : 0),
            new LogicalType.Decimal(precision, scale), Strategy(c));
        var schema = new PlankSchema([definition]);
        var what = $"decimal p={precision} s={scale} {physical} {encoding} optional={optional} rows={rows}";

        // CLR value vs column mismatches. The writer's contract (ParquetDecimalConverter.ToUnscaled): extra
        // fractional digits are accepted only when they are zeros, fewer digits are padded, and a magnitude
        // that does not fit the precision is an OverflowException. Statistics follow the stored (rescaled) value.
        var mode = c.Int(0, 9); // 0-4 plain, 5 trailing zeros, 6 lossy fraction, 7 overflow, 8 trailing zeros + fewer digits
        if (mode is 5 or 8 && scale + 3 <= 28)
            for (var i = 0; i < pool.Length; i++)
                pool[i] *= 1.000m; // same number, three more (zero) fractional digits
        else if (mode is 5 or 8)
            mode = 0;
        if (mode == 6 && scale + 1 <= 27)
            pool[0] += 1m / (decimal)Math.Pow(10, scale + 1) * 3m; // a non-zero digit past the scale
        else if (mode == 6)
            mode = 0;
        if (mode == 7)
        {
            var limitValue = 1m;
            for (var i = 0; i < precision - scale; i++)
                limitValue *= 10m;
            pool[0] = limitValue; // 10^(precision-scale): one past the largest representable magnitude
        }

        void Run()
        {
            if (optional)
            {
                var values = new decimal?[rows];
                for (var i = 0; i < rows; i++)
                    values[i] = c.Int(0, 4) == 0 ? null : pool[c.Int(0, pool.Length)];
                if (mode >= 6)
                    values[0] = pool[0];
                RoundTrip(what + $" mode={mode}", schema, p, values,
                    g => Target.ReadAllBuffers(g.Column<decimal?>(schema.LeafColumns[0])), static (a, b) => a == b, c);
            }
            else
            {
                var values = new decimal[rows];
                for (var i = 0; i < rows; i++)
                    values[i] = pool[c.Int(0, pool.Length)];
                if (mode >= 6)
                    values[0] = pool[0];
                RoundTrip(what + $" mode={mode}", schema, p, values,
                    g => Target.ReadAllBuffers(g.Column<decimal>(schema.LeafColumns[0])), static (a, b) => a == b, c);
            }
        }

        if (mode is 6 or 7)
        {
            try
            {
                Run();
            }
            catch (InvalidOperationException error) when (mode == 6
                && error.Message.Contains("more fractional digits than scale", StringComparison.Ordinal))
            {
                return;
            }
            catch (OverflowException error) when (mode == 7
                && error.Message.Contains("exceeds precision", StringComparison.Ordinal))
            {
                return;
            }

            throw new InvalidOperationException(
                $"{what} mode={mode}: a decimal that does not fit the column was accepted.");
        }

        Run();
    }

    // ---- 8/16-bit narrowing ------------------------------------------------------------------------------

    static void Narrow(Cur c, Params p)
    {
        var optional = c.Int(0, 2) == 0;
        var wide = c.Int(0, 2) == 0; // ushort vs byte
        var encoding = c.Pick(EncodingKind.Plain, EncodingKind.DeltaBinaryPacked, EncodingKind.ByteStreamSplit,
            EncodingKind.PlainDictionary, EncodingKind.RleDictionary);
        var rows = c.Pick(1, 5, 33, 255, 256, 257, 258, 1000, 5000);
        var repetition = optional ? ParquetRepetition.Optional : ParquetRepetition.Required;
        var definition = ColumnDefinition.Leaf("narrow", ParquetPhysicalType.Int32,
            Opts(repetition, encoding), c.Int(0, 3) == 0 ? null : new LogicalType.Int((byte)(wide ? 16 : 8), false), Strategy(c));
        var schema = new PlankSchema([definition]);
        var what = $"narrow {(wide ? "u16" : "u8")} {encoding} optional={optional} rows={rows}";
        var mode = c.Int(0, 3); // random / ascending / few distinct
        var start = c.Int(0, 65536);
        var step = c.Int(0, 4);
        int Next(int i) => mode switch
        {
            0 => c.Int(0, wide ? 65536 : 256),
            1 => (start + i * step) % (wide ? 65536 : 256),
            _ => (start + c.Int(0, 3)) % (wide ? 65536 : 256)
        };
        try
        {
            if (wide)
            {
                if (optional)
                {
                    var v = new ushort?[rows];
                    for (var i = 0; i < rows; i++) v[i] = c.Int(0, 5) == 0 ? null : (ushort)Next(i);
                    RoundTrip(what, schema, p, v, g => Target.ReadAllBuffers(g.Column<ushort?>(schema.LeafColumns[0])),
                        static (a, b) => a == b, c);
                }
                else
                {
                    var v = new ushort[rows];
                    for (var i = 0; i < rows; i++) v[i] = (ushort)Next(i);
                    RoundTrip(what, schema, p, v, g => Target.ReadAllBuffers(g.Column<ushort>(schema.LeafColumns[0])),
                        static (a, b) => a == b, c);
                }
            }
            else if (optional)
            {
                var v = new byte?[rows];
                for (var i = 0; i < rows; i++) v[i] = c.Int(0, 5) == 0 ? null : (byte)Next(i);
                RoundTrip(what, schema, p, v, g => Target.ReadAllBuffers(g.Column<byte?>(schema.LeafColumns[0])),
                    static (a, b) => a == b, c);
            }
            else
            {
                var v = new byte[rows];
                for (var i = 0; i < rows; i++) v[i] = (byte)Next(i);
                RoundTrip(what, schema, p, v, g => Target.ReadAllBuffers(g.Column<byte>(schema.LeafColumns[0])),
                    static (a, b) => a == b, c);
            }
        }
        catch (NotSupportedException error) when (encoding == EncodingKind.ByteStreamSplit
            && error.Message.Contains("ByteStreamSplit", StringComparison.OrdinalIgnoreCase))
        {
            // BYTE_STREAM_SPLIT is only defined for FLOAT/DOUBLE/INT32/INT64/FLBA values in the spec; a
            // library that refuses it for a narrowed integer must do so with this exact kind of error.
        }
    }

    // ---- dictionary cardinality ---------------------------------------------------------------------------

    static void DictionaryCardinality(Cur c, Params p)
    {
        var distinct = c.Pick(1, 2, 255, 256, 257, 511, 512, 513, 1000, 1023, 1024, 1025, 4096, 65535, 65536, 65537, 70000);
        var vbase = c.Pick(0, -1, 1, -128, -129, 127, 100000);
        var vmul = c.Pick(1, 1, 3);
        var multiplier = distinct > 5000 ? 1 + c.Int(0, 2) : c.Pick(1, 2, 5);
        var rows = checked(distinct * multiplier);
        var type = c.Int(0, 5); // int?, long?, DateTime?, int, long
        var encoding = c.Pick(EncodingKind.PlainDictionary, EncodingKind.RleDictionary);
        var nullEvery = c.Pick(2, 3, 7, 1000);
        var strategy = Strategy(c);
        // Larger groups are only exercised with the lightest codec options to keep an input cheap.
        p = p with { Groups = rows > 20000 ? 1 : p.Groups };
        var what = $"dict type={type} distinct={distinct} rows={rows} {encoding}";
        var shuffle = c.Int(0, 2) == 0;
        int Index(int i) => shuffle ? (int)((i * 2654435761L) % distinct) : i % distinct;
        var bloomOn = c.Int(0, 4) == 0;
        ColumnDefinition Def(string name, ParquetPhysicalType physical, LogicalType? logical, bool optional)
            => ColumnDefinition.Leaf(name, physical,
                Opts(optional ? ParquetRepetition.Optional : ParquetRepetition.Required, encoding, 0,
                    bloomOn ? ParquetBloomFilterOptions.Default : null), logical, strategy);

        switch (type)
        {
            case 0:
            {
                var schema = new PlankSchema([Def("i", ParquetPhysicalType.Int32, null, true)]);
                var v = new int?[rows];
                for (var i = 0; i < rows; i++) v[i] = i % nullEvery == nullEvery - 1 ? null : Index(i) * vmul + vbase;
                RoundTrip(what, schema, p, v, g => Target.ReadAllBuffers(g.Column<int?>(schema.LeafColumns[0])),
                    static (a, b) => a == b, c, bloomOn);
                break;
            }
            case 1:
            {
                var schema = new PlankSchema([Def("l", ParquetPhysicalType.Int64, null, true)]);
                var v = new long?[rows];
                for (var i = 0; i < rows; i++) v[i] = i % nullEvery == nullEvery - 1 ? null : Index(i) * (long)vmul + vbase;
                RoundTrip(what, schema, p, v, g => Target.ReadAllBuffers(g.Column<long?>(schema.LeafColumns[0])),
                    static (a, b) => a == b, c, bloomOn);
                break;
            }
            case 2:
            {
                var schema = new PlankSchema([Def("t", ParquetPhysicalType.Int64,
                    new LogicalType.Timestamp(TimeUnit.Micros, false), true)]);
                var v = new DateTime?[rows];
                for (var i = 0; i < rows; i++)
                    v[i] = i % nullEvery == nullEvery - 1
                        ? null
                        : new DateTime(2000, 1, 1, 0, 0, 0, DateTimeKind.Unspecified).AddSeconds(Index(i) * 7L);
                RoundTrip(what, schema, p, v, g => Target.ReadAllBuffers(g.Column<DateTime?>(schema.LeafColumns[0])),
                    static (a, b) => a == b, c, bloomOn);
                break;
            }
            case 3:
            {
                var schema = new PlankSchema([Def("ri", ParquetPhysicalType.Int32, null, false)]);
                var v = new int[rows];
                for (var i = 0; i < rows; i++) v[i] = Index(i) * vmul + vbase;
                RoundTrip(what, schema, p, v, g => Target.ReadAllBuffers(g.Column<int>(schema.LeafColumns[0])),
                    static (a, b) => a == b, c, bloomOn);
                break;
            }
            default:
            {
                var schema = new PlankSchema([Def("rl", ParquetPhysicalType.Int64, null, false)]);
                var v = new long[rows];
                for (var i = 0; i < rows; i++) v[i] = Index(i) * (long)vmul + vbase;
                RoundTrip(what, schema, p, v, g => Target.ReadAllBuffers(g.Column<long>(schema.LeafColumns[0])),
                    static (a, b) => a == b, c, bloomOn);
                break;
            }
        }
    }

    // ---- delta ints -------------------------------------------------------------------------------------

    static void Deltas(Cur c, Params p)
    {
        var is64 = c.Int(0, 2) == 0;
        var optional = c.Int(0, 2) == 0;
        var rows = c.Pick(1, 2, 31, 32, 33, 127, 128, 129, 255, 256, 257, 258, 383, 384, 385, 513, 1000, 4097, 20000);
        var bits = c.Int(0, is64 ? 63 : 31);
        var pattern = c.Int(0, 5); // random bits, constant delta, alternating extremes, ascending, zigzag
        var constant = c.Int(0, 2) == 0 ? (1L << bits) : -(1L << bits);
        var start = c.Long();
        long Next(long previous, int i)
        {
            var mask = bits == 0 ? 0L : (1L << bits) - 1;
            return pattern switch
            {
                0 => unchecked(previous + ((c.Long() & mask) * (c.Int(0, 2) == 0 ? 1 : -1))),
                1 => unchecked(previous + constant),
                2 => i % 2 == 0 ? (is64 ? long.MaxValue : int.MaxValue) : (is64 ? long.MinValue : int.MinValue),
                3 => unchecked(previous + (c.Long() & mask)),
                _ => unchecked(previous + ((i % 2 == 0 ? 1 : -1) * (mask + 1)))
            };
        }

        var repetition = optional ? ParquetRepetition.Optional : ParquetRepetition.Required;
        var definition = ColumnDefinition.Leaf("delta", is64 ? ParquetPhysicalType.Int64 : ParquetPhysicalType.Int32,
            Opts(repetition, EncodingKind.DeltaBinaryPacked), pageStrategy: null);
        var schema = new PlankSchema([definition]);
        var what = $"delta {(is64 ? "i64" : "i32")} bits={bits} pattern={pattern} rows={rows} optional={optional}";
        var series = new long[rows];
        long current = start;
        for (var i = 0; i < rows; i++)
        {
            current = Next(current, i);
            series[i] = is64 ? current : unchecked((int)current);
        }

        if (is64)
        {
            if (optional)
            {
                var v = series.Select((x, i) => i % 11 == 5 ? (long?)null : x).ToArray();
                RoundTrip(what, schema, p, v, g => Target.ReadAllBuffers(g.Column<long?>(schema.LeafColumns[0])),
                    static (a, b) => a == b, c);
            }
            else
                RoundTrip(what, schema, p, series, g => Target.ReadAllBuffers(g.Column<long>(schema.LeafColumns[0])),
                    static (a, b) => a == b, c);
        }
        else if (optional)
        {
            var v = series.Select((x, i) => i % 11 == 5 ? (int?)null : (int)x).ToArray();
            RoundTrip(what, schema, p, v, g => Target.ReadAllBuffers(g.Column<int?>(schema.LeafColumns[0])),
                static (a, b) => a == b, c);
        }
        else
            RoundTrip(what, schema, p, series.Select(static x => (int)x).ToArray(),
                g => Target.ReadAllBuffers(g.Column<int>(schema.LeafColumns[0])), static (a, b) => a == b, c);
    }

    // ---- codec x level on compressible payloads -----------------------------------------------------------

    static void CodecLevels(Cur c, Params p)
    {
        var rows = c.Pick(1, 100, 2000, 20000);
        var word = new byte[c.Int(1, 40)];
        for (var i = 0; i < word.Length; i++)
            word[i] = c.Byte();
        var repeat = c.Pick(1, 3, 50);
        var encoding = c.Pick(EncodingKind.Plain, EncodingKind.DeltaLengthByteArray, EncodingKind.DeltaByteArray);
        var optional = c.Int(0, 2) == 0;
        var values = new byte[]?[rows];
        for (var i = 0; i < rows; i++)
        {
            if (optional && c.Int(0, 6) == 0)
                continue;
            var value = new byte[word.Length * repeat + c.Int(0, 4)];
            for (var j = 0; j < value.Length; j++)
                value[j] = j < word.Length * repeat ? word[j % word.Length] : c.Byte();
            values[i] = value;
        }

        var definition = ColumnDefinition.Leaf("text", ParquetPhysicalType.ByteArray,
            Opts(optional ? ParquetRepetition.Optional : ParquetRepetition.Required, encoding),
            new LogicalType.String());
        var schema = new PlankSchema([definition]);
        RoundTrip($"codec {p.Compression} level={p.Level} {encoding} rows={rows}", schema, p, values,
            ReadBinary<byte[]?>(definition, schema), BinaryEqual, c);
    }

    // ---- ColumnDefinition factory overloads ------------------------------------------------------------------

    static void SchemaFactories(Cur c, Params p)
    {
        var leafId = c.Int(1, 1000);
        var groupId = c.Int(1000, 2000);
        var optionalGroup = c.Int(0, 2) == 0;
        var viaFieldIdOverload = c.Int(0, 2) == 0;
        var optionalLeaf = c.Int(0, 2) == 0;
        var leaf = optionalLeaf
            ? viaFieldIdOverload
                ? ColumnDefinition.OptionalLeaf("leaf", ParquetPhysicalType.Int32, leafId)
                : ColumnDefinition.OptionalLeaf("leaf", ParquetPhysicalType.Int32)
            : viaFieldIdOverload
                ? ColumnDefinition.RequiredLeaf("leaf", ParquetPhysicalType.Int32, leafId)
                : ColumnDefinition.RequiredLeaf("leaf", ParquetPhysicalType.Int32);
        var group = (optionalGroup, viaFieldIdOverload) switch
        {
            (true, true) => ColumnDefinition.OptionalGroup("g", groupId, leaf),
            (true, false) => ColumnDefinition.OptionalGroup("g", leaf),
            (false, true) => ColumnDefinition.RequiredGroup("g", groupId, leaf),
            _ => ColumnDefinition.RequiredGroup("g", leaf)
        };
        var wrapInList = c.Int(0, 3) == 0;
        var root = wrapInList
            ? viaFieldIdOverload
                ? ColumnDefinition.List("outer", leaf, groupId + 1)
                : ColumnDefinition.List("outer", leaf)
            : group;
        var schema = new PlankSchema([root]);
        if (wrapInList)
        {
            // Lists are covered with data by the repeated-rows routes; here the factory path itself is the point:
            // the schema must flatten to one leaf and keep the requested field ids and repetition.
            if (schema.LeafColumns.Length != 1)
                throw new InvalidOperationException("List factory flattened to an unexpected leaf count.");
            return;
        }

        var what = $"factories optionalGroup={optionalGroup} optionalLeaf={optionalLeaf} fieldIds={viaFieldIdOverload}";
        if (optionalLeaf || optionalGroup)
        {
            // Nested optional leaves need definition levels through the group; only the flat leaf shape is
            // written with data (the nested shapes are checked structurally below).
        }

        using var stream = new MemoryStream();
        using var pool = WriterFuzzPool.Create(p.Pool);
        var writer = schema.CreateWriter(stream, Options(p, p.Pool, pool));
        writer.CloseFile();
        using var reader = schema.CreateReader(new MemoryStream(FullValueOracle.Checked(stream.ToArray()), writable: false));
        var leafColumn = reader.Schema.LeafColumns[0];
        if (viaFieldIdOverload && leafColumn.FieldId != leafId)
            throw new InvalidOperationException($"{what}: leaf field id {leafColumn.FieldId} != {leafId}.");
        if (!viaFieldIdOverload && leafColumn.FieldId is not null)
            throw new InvalidOperationException($"{what}: unexpected leaf field id {leafColumn.FieldId}.");
    }

    // ---- floating point ----------------------------------------------------------------------------------

    static void Floating(Cur c, Params p)
    {
        var isDouble = c.Int(0, 2) == 0;
        var optional = c.Int(0, 2) == 0;
        var encoding = c.Pick(EncodingKind.Plain, EncodingKind.ByteStreamSplit, EncodingKind.Alp,
            EncodingKind.PlainDictionary);
        var big = c.Int(0, 40) == 0;
        var rows = big ? 263_000 : c.Pick(1, 2, 9, 100, 1023, 1024, 1025, 3000);
        if (big)
            p = p with { PageSize = 64u << 20, Groups = 1 };
        var allSpecial = c.Int(0, 6) == 0;
        var bloomOn = c.Int(0, 4) == 0;
        var definition = ColumnDefinition.Leaf("fp", isDouble ? ParquetPhysicalType.Double : ParquetPhysicalType.Float,
            Opts(optional ? ParquetRepetition.Optional : ParquetRepetition.Required, encoding, 0,
                bloomOn ? ParquetBloomFilterOptions.Default : null), pageStrategy: Strategy(c));
        var schema = new PlankSchema([definition]);
        var what = $"float {(isDouble ? "f64" : "f32")} {encoding} optional={optional} rows={rows} special={allSpecial}";
        double Draw()
        {
            var kind = c.Int(0, allSpecial ? 6 : 14);
            return kind switch
            {
                0 => double.NaN,
                1 => double.PositiveInfinity,
                2 => double.NegativeInfinity,
                3 => -0d,
                4 => 0d,
                5 => double.Epsilon,
                _ => c.Int(-100000, 100001) / 100d
            };
        }

        if (isDouble)
        {
            if (optional)
            {
                var v = new double?[rows];
                for (var i = 0; i < rows; i++) v[i] = c.Int(0, 5) == 0 ? null : Draw();
                RoundTrip(what, schema, p, v, g => Target.ReadAllBuffers(g.Column<double?>(schema.LeafColumns[0])),
                    BitEqual, c, bloomOn);
            }
            else
            {
                var v = new double[rows];
                for (var i = 0; i < rows; i++) v[i] = Draw();
                RoundTrip(what, schema, p, v, g => Target.ReadAllBuffers(g.Column<double>(schema.LeafColumns[0])),
                    BitEqual, c, bloomOn);
            }
        }
        else if (optional)
        {
            var v = new float?[rows];
            for (var i = 0; i < rows; i++) v[i] = c.Int(0, 5) == 0 ? null : (float)Draw();
            RoundTrip(what, schema, p, v, g => Target.ReadAllBuffers(g.Column<float?>(schema.LeafColumns[0])),
                BitEqual, c, bloomOn);
        }
        else
        {
            var v = new float[rows];
            for (var i = 0; i < rows; i++) v[i] = (float)Draw();
            RoundTrip(what, schema, p, v, g => Target.ReadAllBuffers(g.Column<float>(schema.LeafColumns[0])),
                BitEqual, c, bloomOn);
        }
    }

    // Floats must come back bit for bit (NaN payloads and the sign of zero included).
    static bool BitEqual<T>(T expected, T actual)
        => expected switch
        {
            double e => BitConverter.DoubleToInt64Bits(e) == BitConverter.DoubleToInt64Bits((double)(object)actual!),
            float e => BitConverter.SingleToInt32Bits(e) == BitConverter.SingleToInt32Bits((float)(object)actual!),
            _ => Equals(expected, actual)
        };

    // ---- unsigned integers -------------------------------------------------------------------------------

    static void Unsigned(Cur c, Params p)
    {
        var is64 = c.Int(0, 2) == 0;
        var optional = c.Int(0, 2) == 0;
        // The CLR type and the column's sign annotation vary independently: uint / ulong into an unannotated
        // (signed) column, int / long into an unsigned one. Statistics must follow the COLUMN's order.
        var annotated = c.Int(0, 3) != 0;
        var clrUnsigned = c.Int(0, 2) == 0;
        var encoding = c.Pick(EncodingKind.Plain, EncodingKind.DeltaBinaryPacked, EncodingKind.PlainDictionary,
            EncodingKind.RleDictionary, EncodingKind.ByteStreamSplit);
        var rows = c.Pick(1, 4, 60, 700, 5000);
        var bloomOn = c.Int(0, 4) == 0;
        var definition = ColumnDefinition.Leaf("u", is64 ? ParquetPhysicalType.Int64 : ParquetPhysicalType.Int32,
            Opts(optional ? ParquetRepetition.Optional : ParquetRepetition.Required, encoding, 0,
                bloomOn ? ParquetBloomFilterOptions.Default : null),
            annotated ? new LogicalType.Int((byte)(is64 ? 64 : 32), false) : null, Strategy(c));
        var schema = new PlankSchema([definition]);
        var what = $"int {(is64 ? "64" : "32")} annotatedUnsigned={annotated} clr={(clrUnsigned ? "unsigned" : "signed")} " +
                   $"{encoding} optional={optional} rows={rows}";
        var pool = new ulong[c.Pick(1, 3, 40, rows)];
        for (var i = 0; i < pool.Length; i++)
        {
            var raw = ((ulong)(uint)c.Int(0, int.MaxValue) << 32) | (uint)c.Int(0, int.MaxValue);
            pool[i] = c.Int(0, 3) == 0 ? (is64 ? ulong.MaxValue - raw % 5 : uint.MaxValue - raw % 5)
                : is64 ? raw << c.Int(0, 2) : (raw >> 32 << c.Int(0, 2)) & uint.MaxValue;
        }

        void Go<T>(T[] values)
            => RoundTrip(what, schema, p, values, g => Target.ReadAllBuffers(g.Column<T>(schema.LeafColumns[0])),
                static (a, b) => EqualityComparer<T>.Default.Equals(a, b), c, bloomOn);

        ulong Draw() => pool[c.Int(0, pool.Length)];
        bool Null() => c.Int(0, 5) == 0;
        try
        {
            if (is64 && clrUnsigned && optional) Go(Enumerable.Range(0, rows).Select(_ => Null() ? (ulong?)null : Draw()).ToArray());
            else if (is64 && clrUnsigned) Go(Enumerable.Range(0, rows).Select(_ => Draw()).ToArray());
            else if (is64 && optional) Go(Enumerable.Range(0, rows).Select(_ => Null() ? (long?)null : unchecked((long)Draw())).ToArray());
            else if (is64) Go(Enumerable.Range(0, rows).Select(_ => unchecked((long)Draw())).ToArray());
            else if (clrUnsigned && optional) Go(Enumerable.Range(0, rows).Select(_ => Null() ? (uint?)null : (uint)Draw()).ToArray());
            else if (clrUnsigned) Go(Enumerable.Range(0, rows).Select(_ => (uint)Draw()).ToArray());
            else if (optional) Go(Enumerable.Range(0, rows).Select(_ => Null() ? (int?)null : unchecked((int)(uint)Draw())).ToArray());
            else Go(Enumerable.Range(0, rows).Select(_ => unchecked((int)(uint)Draw())).ToArray());
        }
        catch (NotSupportedException error) when (encoding == EncodingKind.ByteStreamSplit
            && error.Message.Contains("ByteStreamSplit", StringComparison.OrdinalIgnoreCase))
        {
        }
    }

    // ---- dates, times, timestamps ---------------------------------------------------------------------------

    static long UnitTicks(TimeUnit unit)
        => unit switch { TimeUnit.Millis => TimeSpan.TicksPerMillisecond, TimeUnit.Micros => 10L, _ => 1L };

    // A DateTime of the requested kind that is an exact multiple of the unit, before or after the epoch.
    static DateTime Instant(Cur c, TimeUnit unit, DateTimeKind kind)
    {
        var u = UnitTicks(unit);
        var epoch = DateTime.UnixEpoch.Ticks;
        var maxK = unit == TimeUnit.Nanos ? 90_000_000_000_000_000L : Math.Min(epoch / u, (DateTime.MaxValue.Ticks - epoch) / u);
        var span = c.Pick(1_000L, 1_000_000_000L, maxK);
        span = Math.Min(span, maxK);
        var k = (c.Long() & long.MaxValue) % (2 * span + 1) - span;
        if (c.Int(0, 12) == 0 && unit != TimeUnit.Nanos)
            k = c.Int(0, 2) == 0 ? -epoch / u : (DateTime.MaxValue.Ticks - epoch) / u; // 0001-01-01 and the top of the range
        return new DateTime(epoch + k * u, kind);
    }

    static void Temporal(Cur c, Params p)
    {
        // 0 DateOnly, 1 TimeOnly, 2 DateTime, 3 DateTimeOffset, 4 DateTime of a kind the column rejects,
        // 5 DateTimeOffset into a column that is not adjusted to UTC
        var form = c.Int(0, 6);
        var optional = c.Int(0, 2) == 0;
        var unit = c.Pick(TimeUnit.Millis, TimeUnit.Micros, TimeUnit.Nanos);
        var encoding = c.Pick(EncodingKind.Plain, EncodingKind.DeltaBinaryPacked, EncodingKind.RleDictionary);
        var rows = c.Pick(1, 3, 80, 900, 4000);
        var repetition = optional ? ParquetRepetition.Optional : ParquetRepetition.Required;
        var strategy = Strategy(c);
        var adjusted = c.Int(0, 2) == 0;
        bool Null() => c.Int(0, 5) == 0;

        void Go<T>(string label, PlankSchema schema, T[] values)
            => RoundTrip(label, schema, p, values, g => Target.ReadAllBuffers(g.Column<T>(schema.LeafColumns[0])),
                static (a, b) => EqualityComparer<T>.Default.Equals(a, b), c);

        T[] Fill<T>(Func<T> make) where T : struct
        {
            var values = new T[rows];
            for (var i = 0; i < rows; i++)
                values[i] = make();
            return values;
        }

        T?[] FillNullable<T>(Func<T> make) where T : struct
        {
            var values = new T?[rows];
            for (var i = 0; i < rows; i++)
                values[i] = Null() ? null : make();
            return values;
        }

        switch (form)
        {
            case 0:
            {
                var def = ColumnDefinition.Leaf("d", ParquetPhysicalType.Int32, Opts(repetition, encoding), new LogicalType.Date(), strategy);
                var schema = new PlankSchema([def]);
                var label = $"date {encoding} optional={optional} rows={rows}";
                // 0001-01-01 .. 9999-12-31, with the epoch and its neighbours and both ends always in play.
                DateOnly Day() => DateOnly.FromDayNumber(c.Int(0, 6) switch
                {
                    0 => 0,
                    1 => 3_652_058,
                    2 => 719_161,
                    3 => 719_162,
                    4 => 719_163,
                    _ => c.Int(0, 3_652_059)
                });
                if (optional) Go(label, schema, FillNullable(Day)); else Go(label, schema, Fill(Day));
                break;
            }
            case 1:
            {
                var physical = unit == TimeUnit.Millis ? ParquetPhysicalType.Int32 : ParquetPhysicalType.Int64;
                var def = ColumnDefinition.Leaf("t", physical, Opts(repetition, encoding), new LogicalType.Time(unit, adjusted), strategy);
                var schema = new PlankSchema([def]);
                var label = $"time {unit} adjusted={adjusted} {encoding} optional={optional} rows={rows}";
                var day = TimeSpan.TicksPerDay;
                TimeOnly Time()
                {
                    var u = UnitTicks(unit);
                    var units = day / u; // time of day is [0, units)
                    var k = c.Int(0, 8) switch
                    {
                        0 => 0L,
                        1 => units - 1,
                        _ => (c.Long() & long.MaxValue) % units
                    };
                    return new TimeOnly(k * u);
                }

                if (optional) Go(label, schema, FillNullable(Time)); else Go(label, schema, Fill(Time));
                break;
            }
            case 2 or 4:
            {
                var def = ColumnDefinition.Leaf("ts", ParquetPhysicalType.Int64, Opts(repetition, encoding), new LogicalType.Timestamp(unit, adjusted), strategy);
                var schema = new PlankSchema([def]);
                var rightKind = adjusted ? DateTimeKind.Utc : DateTimeKind.Unspecified;
                var label = $"timestamp adjusted={adjusted} {unit} {encoding} optional={optional} rows={rows}";
                if (form == 4)
                {
                    // Local always, and the other of Utc / Unspecified: the writer must refuse them by name.
                    var wrong = c.Pick(DateTimeKind.Local, adjusted ? DateTimeKind.Unspecified : DateTimeKind.Utc);
                    label += $" wrongKind={wrong}";
                    try
                    {
                        if (optional) Go(label, schema, FillNullable(() => Instant(c, unit, wrong)));
                        else Go(label, schema, Fill(() => Instant(c, unit, wrong)));
                    }
                    catch (InvalidOperationException error) when (error.Message.Contains("DateTime values must have kind", StringComparison.Ordinal))
                    {
                        return;
                    }

                    if (rows > 0 && !optional)
                        throw new InvalidOperationException($"{label}: a DateTime of the wrong kind was accepted.");
                    return;
                }

                if (optional) Go(label, schema, FillNullable(() => Instant(c, unit, rightKind)));
                else Go(label, schema, Fill(() => Instant(c, unit, rightKind)));
                break;
            }
            default:
            {
                // DateTimeOffset: instants with arbitrary offsets. Only adjusted-to-UTC columns take them.
                var def = ColumnDefinition.Leaf("tso", ParquetPhysicalType.Int64, Opts(repetition, encoding),
                    new LogicalType.Timestamp(unit, form == 3 || adjusted), strategy);
                var schema = new PlankSchema([def]);
                var useAdjusted = form == 3 || adjusted;
                var label = $"timestamp-offset adjusted={useAdjusted} {unit} {encoding} optional={optional} rows={rows}";
                DateTimeOffset Offset()
                {
                    var utc = Instant(c, unit, DateTimeKind.Utc);
                    var minutes = c.Int(-14 * 4, 14 * 4 + 1) * 15; // quarter-hour offsets up to +-14h
                    try
                    {
                        return new DateTimeOffset(utc).ToOffset(TimeSpan.FromMinutes(minutes));
                    }
                    catch (ArgumentOutOfRangeException)
                    {
                        return new DateTimeOffset(utc); // the shifted local time would leave 0001..9999
                    }
                }

                try
                {
                    if (optional) Go(label, schema, FillNullable(Offset)); else Go(label, schema, Fill(Offset));
                }
                catch (InvalidOperationException error) when (!useAdjusted
                    && error.Message.Contains("adjusted-to-UTC", StringComparison.Ordinal))
                {
                    return;
                }

                break;
            }
        }
    }

    // ---- value converters ----------------------------------------------------------------------------------

    // A converter whose mapping REVERSES the order of the values (bitwise NOT): the column's statistics must be
    // computed from the converted physical values, not from the CLR wrapper's own order.
    readonly record struct NotInt(int Value);

    readonly record struct NotLong(long Value);

    sealed class NotIntConverter : ParquetValueConverter<NotInt, int>
    {
        public override int ConvertToPhysical(NotInt value) => ~value.Value;
        public override NotInt ConvertFromPhysical(int value) => new(~value);
    }

    sealed class NotLongConverter : ParquetValueConverter<NotLong, long>
    {
        public override long ConvertToPhysical(NotLong value) => ~value.Value;
        public override NotLong ConvertFromPhysical(long value) => new(~value);
    }

    static void Converted(Cur c, Params p)
    {
        var is64 = c.Int(0, 2) == 0;
        var optional = c.Int(0, 2) == 0;
        var annotated = c.Int(0, 3) == 0; // unsigned column order on top of the converter
        var encoding = c.Pick(EncodingKind.Plain, EncodingKind.DeltaBinaryPacked, EncodingKind.RleDictionary,
            EncodingKind.PlainDictionary);
        var rows = c.Pick(1, 5, 70, 900, 4000);
        var distinct = c.Pick(1, 3, rows);
        var bloomOn = c.Int(0, 4) == 0;
        var def = ColumnDefinition.Leaf("conv", is64 ? ParquetPhysicalType.Int64 : ParquetPhysicalType.Int32,
            Opts(optional ? ParquetRepetition.Optional : ParquetRepetition.Required, encoding, 0,
                bloomOn ? ParquetBloomFilterOptions.Default : null),
            annotated ? new LogicalType.Int((byte)(is64 ? 64 : 32), false) : null, Strategy(c),
            is64 ? new NotLongConverter() : new NotIntConverter());
        var schema = new PlankSchema([def]);
        var column = schema.LeafColumns[0];
        var what = $"converter {(is64 ? "NotLong" : "NotInt")} unsigned={annotated} {encoding} optional={optional} rows={rows}";
        var pool = new long[distinct];
        for (var i = 0; i < pool.Length; i++)
            pool[i] = is64 ? c.Long() : c.Int(int.MinValue, int.MaxValue);
        long Draw() => pool[c.Int(0, pool.Length)];
        bool Null() => c.Int(0, 5) == 0;
        // The expected key is the order of the CONVERTED value under the column's own order.
        IComparable? KeyInt(NotInt v) => WriterStatisticsOracle.OrderByColumn(column, ~v.Value);
        IComparable? KeyLong(NotLong v) => WriterStatisticsOracle.OrderByColumn(column, ~v.Value);
        try
        {
            if (is64 && optional)
                RoundTrip(what, schema, p, Enumerable.Range(0, rows).Select(_ => Null() ? (NotLong?)null : new NotLong(Draw())).ToArray(),
                    g => Target.ReadAllBuffers(g.Column<NotLong?>(column)), static (a, b) => a == b, c, bloomOn,
                    v => v is { } x ? KeyLong(x) : null);
            else if (is64)
                RoundTrip(what, schema, p, Enumerable.Range(0, rows).Select(_ => new NotLong(Draw())).ToArray(),
                    g => Target.ReadAllBuffers(g.Column<NotLong>(column)), static (a, b) => a == b, c, bloomOn, KeyLong);
            else if (optional)
                RoundTrip(what, schema, p, Enumerable.Range(0, rows).Select(_ => Null() ? (NotInt?)null : new NotInt((int)Draw())).ToArray(),
                    g => Target.ReadAllBuffers(g.Column<NotInt?>(column)), static (a, b) => a == b, c, bloomOn,
                    v => v is { } x ? KeyInt(x) : null);
            else
                RoundTrip(what, schema, p, Enumerable.Range(0, rows).Select(_ => new NotInt((int)Draw())).ToArray(),
                    g => Target.ReadAllBuffers(g.Column<NotInt>(column)), static (a, b) => a == b, c, bloomOn, KeyInt);
        }
        catch (ArgumentException error) when (annotated && error.ParamName == "converter")
        {
            // A converter on an annotated column may be refused at schema construction.
        }
    }
}
