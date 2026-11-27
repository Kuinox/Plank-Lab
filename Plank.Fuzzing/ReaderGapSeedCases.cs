using System.Collections.Immutable;
using Plank.Schema;
using Plank.Writing;

namespace Plank.Fuzzing;

/// <summary>
/// Reader seeds for decoders the base corpus reached only at five values per
/// file or not at all: DELTA_LENGTH_BYTE_ARRAY / DELTA_BYTE_ARRAY / BYTE_STREAM_SPLIT
/// binary, DELTA_BINARY_PACKED at every size around the block and mini-block
/// boundaries (partial mini-blocks included), nullable dictionaries around each
/// index-width threshold, and logical types over every encoding (the converted
/// "into native" path). Every case is also emitted under the cross-path, row-API and
/// fragmented-stream selectors, because the same file takes a different decoder
/// under each.
/// </summary>
public static partial class CorpusGenerator
{
    // Sizes straddling the DELTA_BINARY_PACKED block (128) and mini-block (32)
    // boundaries, plus the degenerate ones.
    static readonly int[] BoundarySizes = [1, 2, 3, 31, 32, 33, 64, 65, 127, 128, 129, 160, 257, 1025];

    static IEnumerable<(string Name, byte Selector, byte[] Bytes)> ReaderGapCases()
    {
        foreach (var c in BinaryGapCases()) yield return c;
        foreach (var c in DeltaIntegerGapCases()) yield return c;
        foreach (var c in NullableDictionaryGapCases()) yield return c;
        foreach (var c in LogicalEncodingGapCases()) yield return c;
        foreach (var c in MultiPageGapCases()) yield return c;
        foreach (var c in NestedGapCases()) yield return c;
    }

    // ---- helpers ---------------------------------------------------------

    static ColumnDefinition GapColumn(ParquetPhysicalType type, EncodingKind encoding, bool optional,
        LogicalType? logical = null, uint typeLength = 0)
    {
        var options = typeLength == 0
            ? new ColumnOptions(optional ? ParquetRepetition.Optional : ParquetRepetition.Required,
                encodings: ImmutableArray.Create(encoding))
            : new ColumnOptions(optional ? ParquetRepetition.Optional : ParquetRepetition.Required,
                encodings: ImmutableArray.Create(encoding), typeLength: typeLength);
        return optional
            ? ColumnDefinition.OptionalLeaf("c", type, options, logical)
            : ColumnDefinition.RequiredLeaf("c", type, options, logical);
    }

    // One built file, emitted under four selectors: file schema, cross-path
    // (bit 2: both nullabilities must agree), row API (low bits 2) and a
    // fragmented stream source with non-strict binding.
    static IEnumerable<(string Name, byte Selector, byte[] Bytes)> GapVariants(string name, ColumnDefinition column,
        Action<ParquetWriter, RowGroupWriter, LeafColumn> write, ParquetWriterOptions? options = null,
        int rowGroups = 1, bool allVariants = true)
    {
        byte[] bytes;
        try
        {
            var schema = new ParquetSchema([column]);
            using var stream = new MemoryStream();
            var writer = schema.CreateWriter(stream, options ?? new ParquetWriterOptions());
            for (var i = 0; i < rowGroups; i++)
            {
                var group = writer.StartRowGroup();
                write(writer, group, schema.LeafColumns[0]);
            }
            writer.CloseFile();
            bytes = stream.ToArray();
        }
        catch (Exception ex) when (ex is NotSupportedException or InvalidOperationException or ArgumentException)
        {
            Console.Error.WriteLine($"  skipped {name}: {ex.GetType().Name}: {ex.Message}");
            yield break;
        }

        yield return ($"gap-{name}", FileSchemaSelector, bytes);
        yield return ($"gap-{name}-row", RowApiSelector, bytes);
        if (!allVariants)
            yield break;
        yield return ($"gap-{name}-x", CrossPathSelector, bytes);
        yield return ($"gap-{name}-strm", (byte)(StreamSelector | NonStrictSelector | 0x04), bytes);
    }

    static byte[] Text(string s) => System.Text.Encoding.UTF8.GetBytes(s);

    // Sorted, heavily prefix-sharing strings (what DELTA_BYTE_ARRAY is for), with
    // empties and one long value so lengths span one and two varint bytes.
    static byte[][] PrefixedValues(int count)
    {
        var values = new byte[count][];
        for (var i = 0; i < count; i++)
        {
            values[i] = (i % 17) switch
            {
                5 => [],
                11 => Text(new string('z', 70 + i % 5)),
                _ => Text($"prefix/{i / 8:D4}/{(i % 8 == 0 ? "" : new string((char)('a' + i % 8), i % 8))}")
            };
        }
        return values;
    }

    static T?[] NullEveryOther<T>(T[] values, int phase) where T : struct
    {
        var result = new T?[values.Length];
        for (var i = 0; i < values.Length; i++)
            result[i] = (i + phase) % 3 == 0 ? null : values[i];
        return result;
    }

    static byte[]?[] NullEveryOtherRef(byte[][] values, int phase)
    {
        var result = new byte[]?[values.Length];
        for (var i = 0; i < values.Length; i++)
            result[i] = (i + phase) % 3 == 0 ? null : values[i];
        return result;
    }

    // ---- (a) binary encodings --------------------------------------------

    static IEnumerable<(string, byte, byte[])> BinaryGapCases()
    {
        foreach (var encoding in (EncodingKind[])[EncodingKind.Plain, EncodingKind.DeltaLengthByteArray,
                     EncodingKind.DeltaByteArray, EncodingKind.RleDictionary])
            foreach (var size in (int[])[1, 9, 129, 3000])
            {
                var values = PrefixedValues(size);
                var tag = $"bin-{encoding}-{size}".ToLowerInvariant();
                foreach (var c in GapVariants(tag, GapColumn(ParquetPhysicalType.ByteArray, encoding, false),
                             (w, g, col) => Write<byte[]>(w, g, col, values)))
                    yield return c;
                foreach (var c in GapVariants(tag + "-opt", GapColumn(ParquetPhysicalType.ByteArray, encoding, true),
                             (w, g, col) => Write<byte[]?>(w, g, col, NullEveryOtherRef(values, 1))))
                    yield return c;
            }

        // 16-byte fixed binary: delta byte array is refused by the writer for
        // FIXED_LEN_BYTE_ARRAY (GapVariants logs and skips it); the others run.
        foreach (var encoding in (EncodingKind[])[EncodingKind.Plain, EncodingKind.ByteStreamSplit,
                     EncodingKind.RleDictionary, EncodingKind.DeltaByteArray])
            foreach (var size in (int[])[1, 9, 129, 3000])
            {
                var values = new byte[size][];
                for (var i = 0; i < size; i++)
                {
                    values[i] = new byte[16];
                    BitConverter.GetBytes(i / 3).CopyTo(values[i], 0);
                    values[i][15] = (byte)(i % 5);
                }
                var tag = $"flba16-{encoding}-{size}".ToLowerInvariant();
                foreach (var c in GapVariants(tag, GapColumn(ParquetPhysicalType.FixedLenByteArray, encoding, false,
                             typeLength: 16), (w, g, col) => Write<byte[]>(w, g, col, values)))
                    yield return c;
                foreach (var c in GapVariants(tag + "-opt", GapColumn(ParquetPhysicalType.FixedLenByteArray, encoding,
                             true, typeLength: 16),
                             (w, g, col) => Write<byte[]?>(w, g, col, NullEveryOtherRef(values, 2))))
                    yield return c;
            }

        // Odd widths: 1, 3 and 12 (INT96-sized) byte fixed values.
        foreach (var length in (uint[])[1, 3, 12, 33])
        {
            var values = new byte[200][];
            for (var i = 0; i < values.Length; i++)
            {
                values[i] = new byte[length];
                values[i][0] = (byte)(i % 11);
                values[i][^1] = (byte)(i % 3);
            }
            foreach (var encoding in (EncodingKind[])[EncodingKind.Plain, EncodingKind.ByteStreamSplit])
                foreach (var c in GapVariants($"flba{length}-{encoding}".ToLowerInvariant(),
                             GapColumn(ParquetPhysicalType.FixedLenByteArray, encoding, false, typeLength: length),
                             (w, g, col) => Write<byte[]>(w, g, col, values)))
                    yield return c;
        }
    }

    // ---- (b) DELTA_BINARY_PACKED ------------------------------------------

    static long[] DeltaPattern(string pattern, int count, int width)
    {
        var values = new long[count];
        var random = new Random(count * 31 + width);
        long current = 0;
        for (var i = 0; i < count; i++)
        {
            switch (pattern)
            {
                case "const": current = 7; break;
                case "arith": current += 3; break;
                case "alt": current = i % 2 == 0 ? int.MaxValue : int.MinValue; break;
                case "wide":
                    var max = width >= 63 ? long.MaxValue : (1L << width) - 1;
                    current = unchecked(current + random.NextInt64(0, max) - (max >> 1));
                    break;
                default: current = i; break;
            }
            values[i] = current;
        }
        return values;
    }

    static IEnumerable<(string, byte, byte[])> DeltaIntegerGapCases()
    {
        foreach (var size in BoundarySizes)
            foreach (var pattern in (string[])["const", "arith", "alt", "wide"])
            {
                var widths = pattern == "wide" ? (int[])[1, 7, 17, 31] : (int[])[0];
                foreach (var width in widths)
                {
                    var longs = DeltaPattern(pattern, size, width);
                    var ints = Array.ConvertAll(longs, static v => unchecked((int)v));
                    var tag = $"delta-{pattern}{(width == 0 ? "" : width)}-{size}";
                    foreach (var c in GapVariants($"i32-{tag}", GapColumn(ParquetPhysicalType.Int32,
                                 EncodingKind.DeltaBinaryPacked, false), (w, g, col) => Write<int>(w, g, col, ints)))
                        yield return c;
                    foreach (var c in GapVariants($"i64-{tag}", GapColumn(ParquetPhysicalType.Int64,
                                 EncodingKind.DeltaBinaryPacked, false), (w, g, col) => Write<long>(w, g, col, longs)))
                        yield return c;
                    foreach (var c in GapVariants($"i32-{tag}-opt", GapColumn(ParquetPhysicalType.Int32,
                                 EncodingKind.DeltaBinaryPacked, true),
                                 (w, g, col) => Write<int?>(w, g, col, NullEveryOther(ints, size))))
                        yield return c;
                    foreach (var c in GapVariants($"i64-{tag}-opt", GapColumn(ParquetPhysicalType.Int64,
                                 EncodingKind.DeltaBinaryPacked, true),
                                 (w, g, col) => Write<long?>(w, g, col, NullEveryOther(longs, size))))
                        yield return c;
                }
            }

        // 33..64 bit deltas: only 64-bit columns can need them.
        foreach (var width in (int[])[33, 40, 48, 56, 63, 64])
        {
            var longs = DeltaPattern("wide", 300, width);
            foreach (var c in GapVariants($"i64-delta-wide{width}", GapColumn(ParquetPhysicalType.Int64,
                         EncodingKind.DeltaBinaryPacked, false), (w, g, col) => Write<long>(w, g, col, longs)))
                yield return c;
            foreach (var c in GapVariants($"i64-delta-wide{width}-opt", GapColumn(ParquetPhysicalType.Int64,
                         EncodingKind.DeltaBinaryPacked, true),
                         (w, g, col) => Write<long?>(w, g, col, NullEveryOther(longs, 0))))
                yield return c;
        }

        // Optional columns with no nulls at all and with only nulls.
        var plain = DeltaPattern("arith", 200, 0);
        var plainInts = Array.ConvertAll(plain, static v => (int)v);
        foreach (var c in GapVariants("i32-delta-opt-nonulls", GapColumn(ParquetPhysicalType.Int32,
                     EncodingKind.DeltaBinaryPacked, true),
                     (w, g, col) => Write<int?>(w, g, col, Array.ConvertAll(plainInts, static v => (int?)v))))
            yield return c;
        foreach (var c in GapVariants("i64-delta-opt-allnulls", GapColumn(ParquetPhysicalType.Int64,
                     EncodingKind.DeltaBinaryPacked, true),
                     (w, g, col) => Write<long?>(w, g, col, new long?[200])))
            yield return c;
    }

    // ---- (c) nullable dictionaries ----------------------------------------

    static IEnumerable<(string, byte, byte[])> NullableDictionaryGapCases()
    {
        // Distinct counts either side of each index-width threshold (8, 9, 10,
        // 11, 12, 13 bits and 17 bits for the wide path).
        foreach (var distinct in (int[])[2, 255, 256, 257, 511, 512, 513, 1023, 1024, 1025, 2047, 2048, 2049, 4097, 8193])
        {
            var longs = new long[distinct * 2];
            for (var i = 0; i < longs.Length; i++)
                longs[i] = i % distinct;
            var ints = Array.ConvertAll(longs, static v => (int)v);
            foreach (var c in GapVariants($"i32-dictopt-{distinct}", GapColumn(ParquetPhysicalType.Int32,
                         EncodingKind.RleDictionary, true),
                         (w, g, col) => Write<int?>(w, g, col, NullEveryOther(ints, 0))))
                yield return c;
            foreach (var c in GapVariants($"i64-dictopt-{distinct}", GapColumn(ParquetPhysicalType.Int64,
                         EncodingKind.RleDictionary, true),
                         (w, g, col) => Write<long?>(w, g, col, NullEveryOther(longs, 1))))
                yield return c;
            var ts = new LogicalType.Timestamp(TimeUnit.Micros, IsAdjustedToUtc: true);
            var times = Array.ConvertAll(longs, static v => DateTime.UnixEpoch.AddSeconds(v));
            foreach (var c in GapVariants($"ts-dictopt-{distinct}", GapColumn(ParquetPhysicalType.Int64,
                         EncodingKind.RleDictionary, true, ts),
                         (w, g, col) => Write<DateTime?>(w, g, col, NullEveryOther(times, 2))))
                yield return c;
            var dates = Array.ConvertAll(longs, static v => DateOnly.FromDayNumber((int)v + 1000));
            foreach (var c in GapVariants($"date-dictopt-{distinct}", GapColumn(ParquetPhysicalType.Int32,
                         EncodingKind.RleDictionary, true, new LogicalType.Date()),
                         (w, g, col) => Write<DateOnly?>(w, g, col, NullEveryOther(dates, 0))))
                yield return c;
            // Required twins of the same widths (the batched required decoders).
            foreach (var c in GapVariants($"ts-dict-{distinct}", GapColumn(ParquetPhysicalType.Int64,
                         EncodingKind.RleDictionary, false, ts), (w, g, col) => Write<DateTime>(w, g, col, times)))
                yield return c;
        }

        // 17-bit indexes (> 65536 distinct values) take the "wide" dictionary
        // path. One required and one optional INT64 file; the dictionary page is
        // ~0.5 MB, so this is only built once.
        var wide = new long[70_000 + 100];
        for (var i = 0; i < wide.Length; i++)
            wide[i] = i % 70_000;
        foreach (var c in GapVariants("i64-dict-17bit-opt", GapColumn(ParquetPhysicalType.Int64,
                     EncodingKind.RleDictionary, true), (w, g, col) => Write<long?>(w, g, col, NullEveryOther(wide, 0)),
                     new ParquetWriterOptions { TargetDataPageSizeBytes = 8 * 1024 * 1024 }))
            yield return c;
    }

    // ---- (d) logical types x encodings ------------------------------------

    static IEnumerable<(string, byte, byte[])> LogicalEncodingGapCases()
    {
        var encodings = (EncodingKind[])[EncodingKind.Plain, EncodingKind.DeltaBinaryPacked,
            EncodingKind.ByteStreamSplit, EncodingKind.RleDictionary];
        var longs = DeltaPattern("wide", 300, 20);
        var smallLongs = DeltaPattern("arith", 300, 0);
        foreach (var encoding in encodings)
            foreach (var optional in (bool[])[false, true])
            {
                var e = encoding.ToString().ToLowerInvariant() + (optional ? "-opt" : "");
                foreach (var unit in (TimeUnit[])[TimeUnit.Millis, TimeUnit.Micros, TimeUnit.Nanos])
                {
                    // The CLR value is DateTime; keep it inside the unit's range.
                    var times = Array.ConvertAll(smallLongs, v => DateTime.UnixEpoch.AddSeconds(v * 1000));
                    var type = new LogicalType.Timestamp(unit, IsAdjustedToUtc: true);
                    foreach (var c in GapVariants($"ts-{unit}-{e}".ToLowerInvariant(),
                                 GapColumn(ParquetPhysicalType.Int64, encoding, optional, type),
                                 optional
                                     ? (w, g, col) => Write<DateTime?>(w, g, col, NullEveryOther(times, 0))
                                     : (w, g, col) => Write<DateTime>(w, g, col, times)))
                        yield return c;
                }

                var dates = Array.ConvertAll(smallLongs, static v => DateOnly.FromDayNumber((int)v + 500));
                foreach (var c in GapVariants($"date-{e}", GapColumn(ParquetPhysicalType.Int32, encoding, optional,
                             new LogicalType.Date()),
                             optional
                                 ? (w, g, col) => Write<DateOnly?>(w, g, col, NullEveryOther(dates, 0))
                                 : (w, g, col) => Write<DateOnly>(w, g, col, dates)))
                    yield return c;

                var times64 = Array.ConvertAll(smallLongs, static v => new TimeOnly(0).Add(TimeSpan.FromSeconds(v % 80000)));
                foreach (var c in GapVariants($"time-{e}", GapColumn(ParquetPhysicalType.Int64, encoding, optional,
                             new LogicalType.Time(TimeUnit.Micros, IsAdjustedToUtc: false)),
                             optional
                                 ? (w, g, col) => Write<TimeOnly?>(w, g, col, NullEveryOther(times64, 0))
                                 : (w, g, col) => Write<TimeOnly>(w, g, col, times64)))
                    yield return c;

                var dec = Array.ConvertAll(longs, static v => (decimal)(v % 1_000_000) / 100m);
                foreach (var c in GapVariants($"dec64-{e}", GapColumn(ParquetPhysicalType.Int64, encoding, optional,
                             new LogicalType.Decimal(18, 2)),
                             optional
                                 ? (w, g, col) => Write<decimal?>(w, g, col, NullEveryOther(dec, 0))
                                 : (w, g, col) => Write<decimal>(w, g, col, dec)))
                    yield return c;
                foreach (var c in GapVariants($"dec32-{e}", GapColumn(ParquetPhysicalType.Int32, encoding, optional,
                             new LogicalType.Decimal(9, 2)),
                             optional
                                 ? (w, g, col) => Write<decimal?>(w, g, col, NullEveryOther(dec, 1))
                                 : (w, g, col) => Write<decimal>(w, g, col, dec)))
                    yield return c;

                var u32 = Array.ConvertAll(longs, static v => unchecked((uint)v));
                foreach (var c in GapVariants($"u32-{e}", GapColumn(ParquetPhysicalType.Int32, encoding, optional,
                             new LogicalType.Int(32, false)),
                             optional
                                 ? (w, g, col) => Write<uint?>(w, g, col, NullEveryOther(u32, 0))
                                 : (w, g, col) => Write<uint>(w, g, col, u32)))
                    yield return c;
                var u64 = Array.ConvertAll(longs, static v => unchecked((ulong)v));
                foreach (var c in GapVariants($"u64-{e}", GapColumn(ParquetPhysicalType.Int64, encoding, optional,
                             new LogicalType.Int(64, false)),
                             optional
                                 ? (w, g, col) => Write<ulong?>(w, g, col, NullEveryOther(u64, 0))
                                 : (w, g, col) => Write<ulong>(w, g, col, u64)))
                    yield return c;
                var u16 = Array.ConvertAll(longs, static v => unchecked((ushort)v));
                foreach (var c in GapVariants($"u16-{e}", GapColumn(ParquetPhysicalType.Int32, encoding, optional,
                             new LogicalType.Int(16, false)),
                             optional
                                 ? (w, g, col) => Write<ushort?>(w, g, col, NullEveryOther(u16, 0))
                                 : (w, g, col) => Write<ushort>(w, g, col, u16)))
                    yield return c;
                var u8 = Array.ConvertAll(longs, static v => unchecked((byte)v));
                foreach (var c in GapVariants($"u8-{e}", GapColumn(ParquetPhysicalType.Int32, encoding, optional,
                             new LogicalType.Int(8, false)),
                             optional
                                 ? (w, g, col) => Write<byte?>(w, g, col, NullEveryOther(u8, 0))
                                 : (w, g, col) => Write<byte>(w, g, col, u8)))
                    yield return c;
            }
    }

    // ---- page / row-group size variation ----------------------------------

    static IEnumerable<(string, byte, byte[])> MultiPageGapCases()
    {
        var ints = Array.ConvertAll(DeltaPattern("wide", 700, 12), static v => unchecked((int)v));
        var values = PrefixedValues(700);
        foreach (var pageSize in (uint[])[1, 64, 500, 4096])
            foreach (var groups in (int[])[1, 3])
                foreach (var version in (ParquetDataPageVersion[])[ParquetDataPageVersion.V1, ParquetDataPageVersion.V2])
                {
                    var options = new ParquetWriterOptions { TargetDataPageSizeBytes = pageSize, DataPageVersion = version };
                    var tag = $"p{pageSize}-g{groups}-{version}".ToLowerInvariant();
                    foreach (var encoding in (EncodingKind[])[EncodingKind.Plain, EncodingKind.DeltaBinaryPacked,
                                 EncodingKind.RleDictionary, EncodingKind.ByteStreamSplit])
                    {
                        foreach (var c in GapVariants($"multipage-i32-{encoding}-{tag}".ToLowerInvariant(),
                                     GapColumn(ParquetPhysicalType.Int32, encoding, false),
                                     (w, g, col) => Write<int>(w, g, col, ints), options, groups, allVariants: false))
                            yield return c;
                        foreach (var c in GapVariants($"multipage-i32-{encoding}-opt-{tag}".ToLowerInvariant(),
                                     GapColumn(ParquetPhysicalType.Int32, encoding, true),
                                     (w, g, col) => Write<int?>(w, g, col, NullEveryOther(ints, 0)), options, groups, allVariants: false))
                            yield return c;
                    }
                    foreach (var encoding in (EncodingKind[])[EncodingKind.Plain, EncodingKind.DeltaLengthByteArray,
                                 EncodingKind.DeltaByteArray, EncodingKind.RleDictionary])
                    {
                        foreach (var c in GapVariants($"multipage-bin-{encoding}-{tag}".ToLowerInvariant(),
                                     GapColumn(ParquetPhysicalType.ByteArray, encoding, false),
                                     (w, g, col) => Write<byte[]>(w, g, col, values), options, groups, allVariants: false))
                            yield return c;
                        foreach (var c in GapVariants($"multipage-bin-{encoding}-opt-{tag}".ToLowerInvariant(),
                                     GapColumn(ParquetPhysicalType.ByteArray, encoding, true),
                                     (w, g, col) => Write<byte[]?>(w, g, col, NullEveryOtherRef(values, 0)), options,
                                     groups, allVariants: false))
                            yield return c;
                    }
                }
    }

    // ---- nested leaves ----------------------------------------------------
    //
    // Repeated leaves never take the batched flat decoders: TryDecodeNestedPageIntoNative
    // decodes the whole page through TryDecodeBinaryValues / TryDecodeValuesIntoNative, which
    // is the only caller of DecodeDeltaBinaryValues, DecodeDeltaLengthBinaryValues,
    // DecodeByteStreamSplitBinaryValues, TryDecodeDeltaBinaryPackedIntoNative,
    // TryDecodeDeltaByteArrayIntoNative and the ALP/BSS "into native" kernels.

    static ColumnDefinition NestedList(ParquetPhysicalType type, EncodingKind encoding, bool optionalElement,
        LogicalType? logical = null, uint typeLength = 0)
    {
        var rep = optionalElement ? ParquetRepetition.Optional : ParquetRepetition.Required;
        var options = typeLength == 0
            ? new ColumnOptions(rep, encodings: ImmutableArray.Create(encoding))
            : new ColumnOptions(rep, encodings: ImmutableArray.Create(encoding), typeLength: typeLength);
        return ColumnDefinition.List("c", ColumnDefinition.Leaf("element", type, options, logical));
    }

    static ColumnDefinition NestedRepeated(ParquetPhysicalType type, EncodingKind encoding, uint typeLength = 0)
    {
        var options = typeLength == 0
            ? new ColumnOptions(ParquetRepetition.Repeated, encodings: ImmutableArray.Create(encoding))
            : new ColumnOptions(ParquetRepetition.Repeated, encodings: ImmutableArray.Create(encoding),
                typeLength: typeLength);
        return ColumnDefinition.Leaf("c", type, options);
    }

    // Rows of 0..4 elements; row r has (r % 5) elements, so lists are empty, short and
    // long in one page. `empty` allows zero-length rows (only a LIST can express them).
    static TElement[][] Rows<TElement>(int rows, Func<int, TElement> element, bool empty = true)
    {
        var result = new TElement[rows][];
        var next = 0;
        for (var r = 0; r < rows; r++)
        {
            var length = r % 5;
            if (!empty && length == 0)
                length = 1;
            result[r] = new TElement[length];
            for (var i = 0; i < length; i++)
                result[r][i] = element(next++);
        }
        return result;
    }

    static IEnumerable<(string, byte, byte[])> NestedGapCases()
    {
        foreach (var rows in (int[])[3, 200])
        {
            var tag = $"-r{rows}";

            // Integers: Plain, Delta, BSS, Dictionary — required and optional elements.
            foreach (var encoding in (EncodingKind[])[EncodingKind.Plain, EncodingKind.DeltaBinaryPacked,
                         EncodingKind.ByteStreamSplit, EncodingKind.RleDictionary])
            {
                var e = encoding.ToString().ToLowerInvariant();
                var i32 = Rows(rows, static n => (n * 7) % 100 - 20);
                var i64 = Rows(rows, static n => (long)n * 1_000_003 % 99991);
                foreach (var c in GapVariants($"nest-i32-{e}{tag}", NestedList(ParquetPhysicalType.Int32, encoding, false),
                             (w, g, col) => WriteRows<int[]>(g, col, i32), allVariants: false))
                    yield return c;
                foreach (var c in GapVariants($"nest-i64-{e}{tag}", NestedList(ParquetPhysicalType.Int64, encoding, false),
                             (w, g, col) => WriteRows<long[]>(g, col, i64), allVariants: false))
                    yield return c;
                var oi32 = Rows(rows, static n => n % 4 == 1 ? (int?)null : n % 31);
                foreach (var c in GapVariants($"nest-i32-{e}-opt{tag}", NestedList(ParquetPhysicalType.Int32, encoding, true),
                             (w, g, col) => WriteRows<int?[]>(g, col, oi32), allVariants: false))
                    yield return c;
                var ri32 = Rows(rows, static n => n % 13, empty: false);
                foreach (var c in GapVariants($"nest-i32-{e}-rep{tag}", NestedRepeated(ParquetPhysicalType.Int32, encoding),
                             (w, g, col) => WriteRows<int[]>(g, col, ri32), allVariants: false))
                    yield return c;
            }

            // Floating point: Plain, BSS, ALP, Dictionary.
            foreach (var encoding in (EncodingKind[])[EncodingKind.Plain, EncodingKind.ByteStreamSplit,
                         EncodingKind.Alp, EncodingKind.RleDictionary])
            {
                var e = encoding.ToString().ToLowerInvariant();
                var f64 = Rows(rows, static n => (n % 50) / 4d);
                var f32 = Rows(rows, static n => (n % 50) / 4f);
                foreach (var c in GapVariants($"nest-f64-{e}{tag}", NestedList(ParquetPhysicalType.Double, encoding, false),
                             (w, g, col) => WriteRows<double[]>(g, col, f64), allVariants: false))
                    yield return c;
                foreach (var c in GapVariants($"nest-f32-{e}{tag}", NestedList(ParquetPhysicalType.Float, encoding, false),
                             (w, g, col) => WriteRows<float[]>(g, col, f32), allVariants: false))
                    yield return c;
                var of64 = Rows(rows, static n => n % 5 == 2 ? (double?)null : (n % 50) / 4d);
                foreach (var c in GapVariants($"nest-f64-{e}-opt{tag}", NestedList(ParquetPhysicalType.Double, encoding, true),
                             (w, g, col) => WriteRows<double?[]>(g, col, of64), allVariants: false))
                    yield return c;
            }

            // Booleans: Plain, RLE.
            foreach (var encoding in (EncodingKind[])[EncodingKind.Plain, EncodingKind.Rle])
            {
                var bools = Rows(rows, static n => n % 3 != 0);
                foreach (var c in GapVariants($"nest-bool-{encoding}{tag}".ToLowerInvariant(),
                             NestedList(ParquetPhysicalType.Boolean, encoding, false),
                             (w, g, col) => WriteRows<bool[]>(g, col, bools), allVariants: false))
                    yield return c;
            }

            // Binary: every encoding the writer offers for byte arrays.
            foreach (var encoding in (EncodingKind[])[EncodingKind.Plain, EncodingKind.DeltaLengthByteArray,
                         EncodingKind.DeltaByteArray, EncodingKind.RleDictionary])
            {
                var e = encoding.ToString().ToLowerInvariant();
                var pool = PrefixedValues(64);
                var bin = Rows(rows, n => pool[n % pool.Length]);
                foreach (var c in GapVariants($"nest-bin-{e}{tag}", NestedList(ParquetPhysicalType.ByteArray, encoding, false),
                             (w, g, col) => WriteRows<byte[][]>(g, col, bin), allVariants: false))
                    yield return c;
                var obin = Rows(rows, n => n % 4 == 3 ? null : pool[n % pool.Length]);
                foreach (var c in GapVariants($"nest-bin-{e}-opt{tag}", NestedList(ParquetPhysicalType.ByteArray, encoding, true),
                             (w, g, col) => WriteRows<byte[]?[]>(g, col, obin), allVariants: false))
                    yield return c;
            }

            // 16-byte fixed binary: Plain, BSS, Dictionary.
            foreach (var encoding in (EncodingKind[])[EncodingKind.Plain, EncodingKind.ByteStreamSplit,
                         EncodingKind.RleDictionary, EncodingKind.DeltaByteArray])
            {
                var fixedValues = Rows(rows, static n =>
                {
                    var v = new byte[16];
                    BitConverter.GetBytes(n / 2).CopyTo(v, 0);
                    return v;
                });
                foreach (var c in GapVariants($"nest-flba16-{encoding}{tag}".ToLowerInvariant(),
                             NestedList(ParquetPhysicalType.FixedLenByteArray, encoding, false, typeLength: 16),
                             (w, g, col) => WriteRows<byte[][]>(g, col, fixedValues), allVariants: false))
                    yield return c;
            }

            // Logical element types across the integer encodings (converted nested path).
            foreach (var encoding in (EncodingKind[])[EncodingKind.Plain, EncodingKind.DeltaBinaryPacked,
                         EncodingKind.ByteStreamSplit, EncodingKind.RleDictionary])
            {
                var e = encoding.ToString().ToLowerInvariant();
                var times = Rows(rows, static n => (long)(n % 40) * 3_600_000_000L);
                foreach (var c in GapVariants($"nest-ts-{e}{tag}", NestedList(ParquetPhysicalType.Int64, encoding, false,
                             new LogicalType.Timestamp(TimeUnit.Micros, IsAdjustedToUtc: true)),
                             (w, g, col) => WriteRows<long[]>(g, col, times), allVariants: false))
                    yield return c;
                var dates = Rows(rows, static n => 18_000 + n % 40);
                foreach (var c in GapVariants($"nest-date-{e}{tag}", NestedList(ParquetPhysicalType.Int32, encoding, false,
                             new LogicalType.Date()),
                             (w, g, col) => WriteRows<int[]>(g, col, dates), allVariants: false))
                    yield return c;
                var decimals = Rows(rows, static n => (long)(n % 1000));
                foreach (var c in GapVariants($"nest-dec-{e}{tag}", NestedList(ParquetPhysicalType.Int64, encoding, false,
                             new LogicalType.Decimal(18, 2)),
                             (w, g, col) => WriteRows<long[]>(g, col, decimals), allVariants: false))
                    yield return c;
            }
        }
    }
}
