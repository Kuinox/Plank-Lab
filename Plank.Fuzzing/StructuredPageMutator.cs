using System.Buffers.Binary;
using System.Numerics;
using System.IO.Hashing;
using Plank.Reading;
using Plank.Reading.Logical;
using Plank.Schema;
using static Plank.Fuzzing.ThriftCompact;
using Ps = ParquetSharp;

namespace Plank.Fuzzing;

/// <summary>
/// Structure-aware mutation of Parquet files at the level of encoded page payloads.
/// </summary>
/// <remarks>
/// Byte mutation of a whole file mostly breaks Thrift, compression or CRCs, so the decoders
/// rarely see "valid-looking but semantically corrupt" data — dictionary indices past the
/// dictionary, runs past the page, levels above the maximum, value counts that disagree with the
/// levels, DELTA headers with impossible block shapes, byte-array lengths past the data. This
/// parses the file (footer and every page header), decompresses every page, rewrites the file
/// uncompressed with every size, offset and count fixed up (statistics, page indexes, Bloom
/// filters and CRCs dropped), and then mutates one encoded stream semantically so the envelope
/// stays valid and the corruption reaches the decoder.
///
/// The oracle, per mutant: Plank must throw <see cref="CorruptParquetException"/> or return
/// exactly what Arrow returns when Arrow accepts the file (and then every read API must agree,
/// see <see cref="ReadApiMatrix"/>). A mutant marked impossible (no correct reader can return
/// values: an index outside the dictionary, a level above the maximum, fewer bytes than the
/// values need) must be rejected; Plank returning values for it is a finding, as is any other
/// exception type.
/// </remarks>
public static class StructuredPageMutator
{
    // ---- Parsed file model ----------------------------------------------------------

    sealed class Page
    {
        public TStruct Header = null!;
        public byte[] Body = null!; // uncompressed (v2: levels + uncompressed values)
        public int Type => (int)(Header.Long(1) ?? -1);
        public bool IsDictionary => Type == 2;
        public bool IsData => Type is 0 or 3;
        public bool IsV2 => Type == 3;
        public TStruct? V1 => Header.Child(5);
        public TStruct? V2 => Header.Child(8);
        public TStruct? Dict => Header.Child(7);
        public int Encoding => (int)((IsV2 ? V2?.Long(4) : IsDictionary ? Dict?.Long(2) : V1?.Long(2)) ?? -1);
        public int NumValues => (int)((IsV2 ? V2?.Long(1) : IsDictionary ? Dict?.Long(1) : V1?.Long(1)) ?? 0);
        public Page Clone() => new() { Header = Header.Clone(), Body = Body.ToArray() };
    }

    sealed class Leaf
    {
        public int MaxDef, MaxRep, TypeLength;
        public ParquetPhysicalType Physical;
    }

    sealed class Parsed
    {
        public TStruct Footer = null!;
        public List<Page>[][] Pages = null!; // [group][column]
        public Leaf[] Leaves = null!;
    }

    static CompressionKind? Codec(long thrift) => thrift switch
    {
        0 => CompressionKind.None, 1 => CompressionKind.Snappy, 2 => CompressionKind.Gzip, 4 => CompressionKind.Brotli,
        5 => CompressionKind.Lz4Legacy, 6 => CompressionKind.Zstd, 7 => CompressionKind.Lz4, _ => null,
    };

    static Parsed? Parse(byte[] file)
    {
        if (file.Length < 12 || !file.AsSpan(0, 4).SequenceEqual("PAR1"u8) || !file.AsSpan(file.Length - 4).SequenceEqual("PAR1"u8))
            return null;
        var footerLength = BinaryPrimitives.ReadInt32LittleEndian(file.AsSpan(file.Length - 8));
        if (footerLength <= 0 || footerLength > file.Length - 12)
            return null;
        var footer = new Reader(file, file.Length - 8 - footerLength).ReadStruct();
        if (footer.Get(8) is not null) // encryption_algorithm
            return null;

        Leaf[] leaves;
        try
        {
            using var plank = new ParquetReader();
            plank.Reset(new MemoryReadSource(file));
            leaves = plank.Schema.LeafColumns.Select(l => new Leaf
            {
                MaxDef = l.MaxDefinitionLevel, MaxRep = l.MaxRepetitionLevel, Physical = l.PhysicalType,
                TypeLength = (int)l.Options.TypeLength,
            }).ToArray();
        }
        catch (Exception error) when (error is CorruptParquetException or NotSupportedException or InvalidOperationException)
        {
            return null;
        }

        var groups = footer.ListOf(4)?.Items ?? [];
        var pages = new List<Page>[groups.Count][];
        for (var g = 0; g < groups.Count; g++)
        {
            var columns = (groups[g] as TStruct)?.ListOf(1)?.Items ?? [];
            if (columns.Count != leaves.Length)
                return null;
            pages[g] = new List<Page>[columns.Count];
            for (var c = 0; c < columns.Count; c++)
            {
                var meta = (columns[c] as TStruct)?.Child(3);
                if (meta is null || Codec(meta.Long(4) ?? -1) is not { } codec)
                    return null;
                var dictionaryOffset = meta.Long(11) ?? 0;
                var dataOffset = meta.Long(9) ?? 0;
                var start = dictionaryOffset > 0 && dictionaryOffset < dataOffset ? dictionaryOffset : dataOffset;
                var end = start + (meta.Long(7) ?? 0);
                if (start < 4 || end > file.Length - 8 - footerLength)
                    return null;
                var list = new List<Page>();
                var position = (int)start;
                while (position < end)
                {
                    var reader = new Reader(file, position);
                    var header = reader.ReadStruct();
                    var compressed = (int)(header.Long(3) ?? -1);
                    var uncompressed = (int)(header.Long(2) ?? -1);
                    if (compressed < 0 || uncompressed < 0 || uncompressed > 64 << 20 || reader.Position + compressed > end)
                        return null;
                    var payload = file.AsSpan(reader.Position, compressed);
                    var page = new Page { Header = header };
                    if (page.IsV2)
                    {
                        var levels = (int)((page.V2!.Long(5) ?? 0) + (page.V2.Long(6) ?? 0));
                        if (levels > compressed || levels > uncompressed)
                            return null;
                        var valuesCompressed = page.V2.Get(7) is not false && codec != CompressionKind.None;
                        var values = valuesCompressed
                            ? ParquetDecompressor.Decompress(payload[levels..], (uint)(uncompressed - levels), codec)
                            : payload[levels..].ToArray();
                        page.Body = Join(payload[..levels].ToArray(), values);
                    }
                    else
                        page.Body = codec == CompressionKind.None ? payload.ToArray() : ParquetDecompressor.Decompress(payload, (uint)uncompressed, codec);
                    list.Add(page);
                    position = reader.Position + compressed;
                }
                pages[g][c] = list;
            }
        }
        return new Parsed { Footer = footer, Pages = pages, Leaves = leaves };
    }

    /// <summary>Re-serializes the model as an uncompressed file with every size and offset recomputed.</summary>
    static byte[] Build(TStruct footerTemplate, List<Page>[][] pages)
    {
        var output = new List<byte>(4096);
        output.AddRange("PAR1"u8.ToArray());
        var footer = footerTemplate.Clone();
        var groups = footer.ListOf(4)!.Items;
        for (var g = 0; g < groups.Count; g++)
        {
            var group = (TStruct)groups[g]!;
            var groupStart = output.Count;
            long uncompressedTotal = 0;
            var columns = group.ListOf(1)!.Items;
            for (var c = 0; c < columns.Count; c++)
            {
                var chunk = (TStruct)columns[c]!;
                var meta = chunk.Child(3)!;
                var chunkStart = output.Count;
                long? dictionaryOffset = null, dataOffset = null;
                foreach (var page in pages[g][c])
                {
                    if (page.IsDictionary)
                        dictionaryOffset ??= output.Count;
                    else if (page.IsData)
                        dataOffset ??= output.Count;
                    var header = page.Header.Clone();
                    header.SetLong(2, I32, page.Body.Length);
                    header.SetLong(3, I32, page.Body.Length);
                    header.Remove(4); // crc
                    header.Child(5)?.Remove(5);
                    if (header.Child(8) is { } v2)
                    {
                        v2.Set(7, Bool, false);
                        v2.Remove(8);
                    }
                    var start = output.Count;
                    Write(output, header);
                    output.AddRange(page.Body);
                    _ = start;
                }
                var chunkSize = output.Count - chunkStart;
                uncompressedTotal += chunkSize;
                meta.SetLong(4, I32, 0);
                meta.SetLong(6, I64, chunkSize);
                meta.SetLong(7, I64, chunkSize);
                meta.SetLong(9, I64, dataOffset ?? chunkStart);
                if (dictionaryOffset is { } d) meta.SetLong(11, I64, d); else meta.Remove(11);
                foreach (var id in new short[] { 10, 12, 13, 14, 15, 16, 17 })
                    meta.Remove(id);
                chunk.SetLong(2, I64, chunkStart);
                foreach (var id in new short[] { 4, 5, 6, 7, 8, 9 })
                    chunk.Remove(id);
            }
            group.SetLong(2, I64, uncompressedTotal);
            group.SetLong(5, I64, groupStart);
            group.SetLong(6, I64, output.Count - groupStart);
        }
        var footerStart = output.Count;
        Write(output, footer);
        var length = output.Count - footerStart;
        output.AddRange(BitConverter.GetBytes(length));
        output.AddRange("PAR1"u8.ToArray());
        return output.ToArray();
    }

    // ---- Encoded-stream helpers -------------------------------------------------------

    static int BitWidth(long max) => max <= 0 ? 0 : 64 - BitOperations.LeadingZeroCount((ulong)max);

    static (List<long> Values, int End)? DecodeHybrid(byte[] b, int start, int end, int width, int count)
    {
        var values = new List<long>(count);
        var p = start;
        var bytesPerValue = (width + 7) / 8;
        while (values.Count < count)
        {
            if (p >= end) return null;
            ulong header = 0;
            for (var shift = 0; ; shift += 7)
            {
                if (p >= end || shift > 63) return null;
                var x = b[p++];
                header |= (ulong)(x & 0x7F) << shift;
                if (x < 0x80) break;
            }
            if ((header & 1) == 0)
            {
                var run = (long)(header >> 1);
                if (p + bytesPerValue > end) return null;
                long v = 0;
                for (var i = 0; i < bytesPerValue; i++) v |= (long)b[p + i] << (8 * i);
                p += bytesPerValue;
                for (long i = 0; i < run && values.Count < count; i++) values.Add(v);
            }
            else
            {
                var groups = (long)(header >> 1);
                var bytes = groups * width;
                if (bytes > end - p) return null;
                for (long i = 0; i < groups * 8 && values.Count < count; i++)
                {
                    long v = 0;
                    for (var bit = 0; bit < width; bit++)
                    {
                        var at = i * width + bit;
                        if ((b[p + (int)(at >> 3)] >> (int)(at & 7) & 1) != 0) v |= 1L << bit;
                    }
                    values.Add(v);
                }
                p += (int)bytes;
            }
        }
        return (values, p);
    }

    static byte[] EncodeBitPacked(IReadOnlyList<long> values, int width)
    {
        var output = new List<byte>();
        if (width == 0)
        {
            WriteVarint(output, (ulong)values.Count << 1);
            return output.ToArray();
        }
        var groups = (values.Count + 7) / 8;
        WriteVarint(output, ((ulong)groups << 1) | 1);
        var packed = new byte[groups * width];
        for (var i = 0; i < values.Count; i++)
            for (var bit = 0; bit < width; bit++)
                if ((values[i] >> bit & 1) != 0)
                {
                    var at = (long)i * width + bit;
                    packed[at >> 3] |= (byte)(1 << (int)(at & 7));
                }
        output.AddRange(packed);
        return output.ToArray();
    }

    /// <summary>Where the level and value streams of a data page are, and its decoded levels.</summary>
    sealed class Layout
    {
        public int RepStart, RepEnd, DefStart, DefEnd, ValuesStart;
        public bool RepPrefixed, DefPrefixed; // v1: 4-byte length prefix before the RLE stream
        public List<long>? Rep, Def;
        public int Present;
    }

    static Layout? Lay(Page page, Leaf leaf)
    {
        var body = page.Body;
        var n = page.NumValues;
        var layout = new Layout();
        var repWidth = BitWidth(leaf.MaxRep);
        var defWidth = BitWidth(leaf.MaxDef);
        if (page.IsV2)
        {
            var repLength = (int)(page.V2!.Long(6) ?? 0);
            var defLength = (int)(page.V2.Long(5) ?? 0);
            layout.RepStart = 0; layout.RepEnd = repLength;
            layout.DefStart = repLength; layout.DefEnd = repLength + defLength;
            layout.ValuesStart = repLength + defLength;
            if (layout.ValuesStart > body.Length) return null;
        }
        else
        {
            var p = 0;
            if (leaf.MaxRep > 0)
            {
                if ((page.V1!.Long(4) ?? 3) != 3 || p + 4 > body.Length) return null;
                var length = BinaryPrimitives.ReadInt32LittleEndian(body.AsSpan(p));
                if (length < 0 || p + 4 + length > body.Length) return null;
                layout.RepPrefixed = true; layout.RepStart = p + 4; layout.RepEnd = p + 4 + length; p = layout.RepEnd;
            }
            else { layout.RepStart = layout.RepEnd = p; }
            if (leaf.MaxDef > 0)
            {
                if ((page.V1!.Long(3) ?? 3) != 3 || p + 4 > body.Length) return null;
                var length = BinaryPrimitives.ReadInt32LittleEndian(body.AsSpan(p));
                if (length < 0 || p + 4 + length > body.Length) return null;
                layout.DefPrefixed = true; layout.DefStart = p + 4; layout.DefEnd = p + 4 + length; p = layout.DefEnd;
            }
            else { layout.DefStart = layout.DefEnd = p; }
            layout.ValuesStart = p;
        }
        if (leaf.MaxRep > 0)
            layout.Rep = DecodeHybrid(body, layout.RepStart, layout.RepEnd, repWidth, n)?.Values;
        if (leaf.MaxDef > 0)
        {
            layout.Def = DecodeHybrid(body, layout.DefStart, layout.DefEnd, defWidth, n)?.Values;
            if (layout.Def is null) return null;
            layout.Present = layout.Def.Count(d => d == leaf.MaxDef);
        }
        else
            layout.Present = n;
        return layout;
    }

    /// <summary>Replaces body[start..end) with <paramref name="replacement"/> and fixes the length fields that cover it.</summary>
    static void Splice(Page page, Layout layout, int start, int end, byte[] replacement, char stream)
    {
        var body = page.Body;
        var delta = replacement.Length - (end - start);
        page.Body = Join(body[..start], replacement, body[end..]);
        if (page.IsV2)
        {
            if (stream == 'r') page.V2!.SetLong(6, I32, (page.V2.Long(6) ?? 0) + delta);
            if (stream == 'd') page.V2!.SetLong(5, I32, (page.V2.Long(5) ?? 0) + delta);
        }
        else
        {
            if (stream == 'r' && layout.RepPrefixed)
                BinaryPrimitives.WriteInt32LittleEndian(page.Body.AsSpan(layout.RepStart - 4), layout.RepEnd - layout.RepStart + delta);
            if (stream == 'd' && layout.DefPrefixed)
                BinaryPrimitives.WriteInt32LittleEndian(page.Body.AsSpan(layout.DefStart - 4), layout.DefEnd - layout.DefStart + delta);
        }
    }

    static int FixedWidth(Leaf leaf) => leaf.Physical switch
    {
        ParquetPhysicalType.Int32 or ParquetPhysicalType.Float => 4,
        ParquetPhysicalType.Int64 or ParquetPhysicalType.Double => 8,
        ParquetPhysicalType.Int96 => 12,
        ParquetPhysicalType.FixedLenByteArray => leaf.TypeLength,
        _ => 0,
    };

    static (long Value, int Next)? ReadUleb(byte[] b, int p)
    {
        long value = 0;
        for (var shift = 0; shift < 64; shift += 7)
        {
            if (p >= b.Length) return null;
            var x = b[p++];
            value |= (long)(x & 0x7F) << shift;
            if (x < 0x80) return (value, p);
        }
        return null;
    }

    static byte[] Uleb(ulong value) { var o = new List<byte>(); WriteVarint(o, value); return o.ToArray(); }

    static byte[] Join(params byte[][] parts)
    {
        var result = new byte[parts.Sum(static p => p.Length)];
        var at = 0;
        foreach (var part in parts)
        {
            part.CopyTo(result, at);
            at += part.Length;
        }
        return result;
    }

    // ---- Mutations ----------------------------------------------------------------------

    public readonly record struct Mutation(string Kind, string Detail, bool Impossible);

    delegate Mutation? Mutator(Random rng, List<Page> pages, int index, Leaf leaf, Layout layout);

    static readonly (string Name, Mutator Apply)[] Mutators =
    [
        ("dict-index-oob", DictIndexOutOfRange),
        ("dict-bit-width", DictBitWidth),
        ("dict-page-count", DictPageCount),
        ("run-past-end", RunPastEnd),
        ("rle-run-huge", RleRunHuge),
        ("level-above-max", LevelAboveMax),
        ("rep-not-zero", RepNotStartingAtZero),
        ("more-present", MorePresentValues),
        ("fewer-present", FewerPresentValues),
        ("delta-header", DeltaHeader),
        ("delta-width", DeltaMiniblockWidth),
        ("delta-length", DeltaLengthLengths),
        ("delta-prefix", DeltaByteArrayPrefix),
        ("bss-size", ByteStreamSplitSize),
        ("plain-binary-length", PlainBinaryLength),
        ("fixed-truncate", FixedTruncate),
        ("v2-level-lengths", V2LevelLengths),
        ("v2-num-nulls", V2NumNulls),
        ("num-values", NumValues),
        ("values-havoc", ValuesHavoc),
    ];

    static bool IsDictionaryEncoded(Page page) => page.Encoding is 2 or 8;

    static int DictionarySize(List<Page> pages) => pages.FirstOrDefault(static p => p.IsDictionary)?.NumValues ?? -1;

    static Mutation? DictIndexOutOfRange(Random rng, List<Page> pages, int index, Leaf leaf, Layout layout)
    {
        var page = pages[index];
        var size = DictionarySize(pages);
        if (!IsDictionaryEncoded(page) || size < 0 || layout.Present == 0 || layout.ValuesStart >= page.Body.Length)
            return null;
        var width = page.Body[layout.ValuesStart];
        if (width > 32) return null;
        var decoded = DecodeHybrid(page.Body, layout.ValuesStart + 1, page.Body.Length, width, layout.Present);
        if (decoded is null) return null;
        var indices = decoded.Value.Values;
        var target = rng.Next(4) switch
        {
            0 => size,
            1 => size + 1L,
            2 => Math.Max(size, (1L << Math.Max(width, BitWidth(size))) - 1),
            _ => size + rng.Next(1, 100000),
        };
        var newWidth = Math.Max(width, BitWidth(target));
        if (newWidth > 32) return null;
        var position = rng.Next(indices.Count);
        indices[position] = target;
        Splice(page, layout, layout.ValuesStart, page.Body.Length, Join(new[] { (byte)newWidth }, EncodeBitPacked(indices, newWidth)), 'v');
        return new("dict-index-oob", $"index {position} = {target} (dictionary size {size}, width {width}->{newWidth})", true);
    }

    static Mutation? DictBitWidth(Random rng, List<Page> pages, int index, Leaf leaf, Layout layout)
    {
        var page = pages[index];
        if (!IsDictionaryEncoded(page) || layout.Present == 0 || layout.ValuesStart >= page.Body.Length)
            return null;
        var width = new byte[] { 0, 32, 33, 40, 64, 255 }[rng.Next(6)];
        page.Body[layout.ValuesStart] = width;
        return new("dict-bit-width", $"index bit width {width}", width > 32);
    }

    static Mutation? DictPageCount(Random rng, List<Page> pages, int index, Leaf leaf, Layout layout)
    {
        var dictionary = pages.FirstOrDefault(static p => p.IsDictionary);
        if (dictionary is null || !IsDictionaryEncoded(pages[index]))
            return null;
        var n = dictionary.NumValues;
        var count = rng.Next(5) switch { 0 => 0, 1 => n - 1, 2 => n + 1, 3 => n * 2 + 5, _ => int.MaxValue };
        if (count < 0) return null;
        dictionary.Dict!.SetLong(1, I32, count);
        var width = FixedWidth(leaf);
        // Declaring more fixed-width entries than the page holds cannot be decoded.
        var impossible = width > 0 && (long)count * width > dictionary.Body.Length;
        return new("dict-page-count", $"dictionary num_values {n} -> {count}", impossible);
    }

    static Mutation? RunPastEnd(Random rng, List<Page> pages, int index, Leaf leaf, Layout layout)
    {
        var page = pages[index];
        var n = page.NumValues;
        // Target: definition levels, repetition levels, or dictionary indices.
        var choice = rng.Next(3);
        if (choice == 0 && layout.Def is { Count: > 0 } def)
        {
            var width = BitWidth(leaf.MaxDef);
            var packed = EncodeBitPacked(def, width);
            var cut = Truncated(rng, packed, width, n);
            if (cut is null) return null;
            Splice(page, layout, layout.DefStart, layout.DefEnd, cut, 'd');
            return new("run-past-end", $"definition bit-packed run cut to {cut.Length} of {packed.Length} bytes", true);
        }
        if (choice == 1 && layout.Rep is { Count: > 0 } rep)
        {
            var width = BitWidth(leaf.MaxRep);
            var packed = EncodeBitPacked(rep, width);
            var cut = Truncated(rng, packed, width, n);
            if (cut is null) return null;
            Splice(page, layout, layout.RepStart, layout.RepEnd, cut, 'r');
            return new("run-past-end", $"repetition bit-packed run cut to {cut.Length} of {packed.Length} bytes", true);
        }
        if (IsDictionaryEncoded(page) && layout.Present > 0 && layout.ValuesStart < page.Body.Length)
        {
            var width = page.Body[layout.ValuesStart];
            if (width is 0 or > 32) return null;
            var decoded = DecodeHybrid(page.Body, layout.ValuesStart + 1, page.Body.Length, width, layout.Present);
            if (decoded is null) return null;
            var packed = EncodeBitPacked(decoded.Value.Values, width);
            var cut = Truncated(rng, packed, width, layout.Present);
            if (cut is null) return null;
            Splice(page, layout, layout.ValuesStart, page.Body.Length, Join(new[] { width }, cut), 'v');
            return new("run-past-end", $"dictionary-index bit-packed run cut to {cut.Length} of {packed.Length} bytes", true);
        }
        return null;
    }

    // A bit-packed run whose header covers every value but whose bytes stop before the last
    // needed value: nothing after the stream belongs to it.
    static byte[]? Truncated(Random rng, byte[] packed, int width, int count)
    {
        var headerLength = Uleb(((ulong)((count + 7) / 8) << 1) | 1).Length;
        var needed = ((long)count * width + 7) / 8;
        if (width == 0 || needed == 0) return null;
        var keep = rng.NextInt64(0, needed);
        return packed.AsSpan(0, (int)(headerLength + keep)).ToArray();
    }

    static Mutation? RleRunHuge(Random rng, List<Page> pages, int index, Leaf leaf, Layout layout)
    {
        var page = pages[index];
        if (layout.Def is not { Count: > 0 } def)
            return null;
        // One RLE run of the first level, with a count far past num_values: decodable (only the
        // first num_values matter), so it must match Arrow when Arrow accepts it.
        var width = BitWidth(leaf.MaxDef);
        var count = rng.Next(2) == 0 ? (ulong)int.MaxValue : (ulong)page.NumValues + (ulong)rng.Next(1, 1000);
        var run = new List<byte>();
        WriteVarint(run, count << 1);
        for (var i = 0; i < (width + 7) / 8; i++) run.Add((byte)(def[0] >> (8 * i)));
        Splice(page, layout, layout.DefStart, layout.DefEnd, run.ToArray(), 'd');
        // The values now follow the run's level for every entry.
        return new("rle-run-huge", $"definition RLE run of {count} x {def[0]}", false);
    }

    static Mutation? LevelAboveMax(Random rng, List<Page> pages, int index, Leaf leaf, Layout layout)
    {
        var page = pages[index];
        var repetition = rng.Next(2) == 0 && layout.Rep is { Count: > 0 };
        var levels = repetition ? layout.Rep : layout.Def;
        var max = repetition ? leaf.MaxRep : leaf.MaxDef;
        if (levels is not { Count: > 0 }) return null;
        var width = BitWidth(max);
        if (max + 1 > (1L << width) - 1) return null; // not encodable in the stream's width
        var position = rng.Next(levels.Count);
        var mutated = levels.ToList();
        mutated[position] = rng.Next(2) == 0 ? max + 1 : (1L << width) - 1;
        Splice(page, layout, repetition ? layout.RepStart : layout.DefStart, repetition ? layout.RepEnd : layout.DefEnd,
            EncodeBitPacked(mutated, width), repetition ? 'r' : 'd');
        return new("level-above-max", $"{(repetition ? "repetition" : "definition")} level {position} = {mutated[position]} (max {max})", true);
    }

    static Mutation? RepNotStartingAtZero(Random rng, List<Page> pages, int index, Leaf leaf, Layout layout)
    {
        var page = pages[index];
        // Only the chunk's first data page must start a record (v1 pages may split records).
        if (layout.Rep is not { Count: > 0 } rep || pages.FindIndex(static p => p.IsData) != index)
            return null;
        var mutated = rep.ToList();
        mutated[0] = rng.Next(1, leaf.MaxRep + 1);
        Splice(page, layout, layout.RepStart, layout.RepEnd, EncodeBitPacked(mutated, BitWidth(leaf.MaxRep)), 'r');
        return new("rep-not-zero", $"first repetition level {mutated[0]}", true);
    }

    static Mutation? MorePresentValues(Random rng, List<Page> pages, int index, Leaf leaf, Layout layout)
    {
        var page = pages[index];
        var width = FixedWidth(leaf);
        if (layout.Def is not { } def || leaf.MaxRep > 0 || page.Encoding != 0 || width == 0
            || leaf.Physical == ParquetPhysicalType.Boolean)
            return null;
        var nulls = Enumerable.Range(0, def.Count).Where(i => def[i] < leaf.MaxDef).ToList();
        if (nulls.Count == 0 || page.Body.Length - layout.ValuesStart != layout.Present * width) return null;
        var mutated = def.ToList();
        var flips = rng.Next(1, Math.Min(4, nulls.Count) + 1);
        foreach (var i in nulls.OrderBy(_ => rng.Next()).Take(flips))
            mutated[i] = leaf.MaxDef;
        Splice(page, layout, layout.DefStart, layout.DefEnd, EncodeBitPacked(mutated, BitWidth(leaf.MaxDef)), 'd');
        return new("more-present", $"{flips} null(s) made present with no value bytes for them", true);
    }

    static Mutation? FewerPresentValues(Random rng, List<Page> pages, int index, Leaf leaf, Layout layout)
    {
        var page = pages[index];
        if (layout.Def is not { } def || leaf.MaxRep > 0)
            return null;
        var present = Enumerable.Range(0, def.Count).Where(i => def[i] == leaf.MaxDef).ToList();
        if (present.Count == 0) return null;
        var mutated = def.ToList();
        mutated[present[rng.Next(present.Count)]] = leaf.MaxDef - 1;
        Splice(page, layout, layout.DefStart, layout.DefEnd, EncodeBitPacked(mutated, BitWidth(leaf.MaxDef)), 'd');
        return new("fewer-present", "a present value made null (one value byte run left over)", false);
    }

    static Mutation? DeltaHeader(Random rng, List<Page> pages, int index, Leaf leaf, Layout layout)
    {
        var page = pages[index];
        if (page.Encoding != 5) return null;
        var b = page.Body;
        var p0 = layout.ValuesStart;
        if (ReadUleb(b, p0) is not { } blockSize || ReadUleb(b, blockSize.Next) is not { } miniblocks
            || ReadUleb(b, miniblocks.Next) is not { } total || ReadUleb(b, total.Next) is not { } first)
            return null;
        long bs = blockSize.Value, mb = miniblocks.Value, tc = total.Value;
        var fv = (ulong)first.Value;
        string what;
        bool impossible;
        switch (rng.Next(5))
        {
            case 0: bs = new long[] { 0, 1, 127, 129, int.MaxValue, long.MaxValue >> 1 }[rng.Next(6)]; what = $"block size {bs}"; impossible = bs <= 0 || bs % 128 != 0; break;
            case 1: mb = new long[] { 0, bs + 1, 3, int.MaxValue }[rng.Next(4)]; what = $"miniblocks {mb}"; impossible = mb <= 0 || bs % mb != 0 || bs / mb % 32 != 0; break;
            case 2: tc = new long[] { 0, layout.Present - 1L, layout.Present + 1000000L, long.MaxValue >> 1 }[rng.Next(4)]; what = $"total count {tc}"; impossible = tc >= 0 && tc < layout.Present; break;
            case 3: fv = ZigZagEncode(rng.Next(2) == 0 ? long.MaxValue : long.MinValue); what = $"first value {(rng.Next(2) == 0 ? "max" : "min")}"; impossible = false; break;
            default: fv = ZigZagEncode(rng.NextInt64()); what = "first value random"; impossible = false; break;
        }
        if (tc < 0) return null;
        var replacement = Uleb((ulong)bs).Concat(Uleb((ulong)mb)).Concat(Uleb((ulong)tc)).Concat(Uleb(fv)).ToArray();
        Splice(page, layout, p0, first.Next, replacement, 'v');
        return new("delta-header", what, impossible && layout.Present > 1);
    }

    static Mutation? DeltaMiniblockWidth(Random rng, List<Page> pages, int index, Leaf leaf, Layout layout)
    {
        var page = pages[index];
        if (page.Encoding != 5 || layout.Present < 2) return null;
        var b = page.Body;
        if (ReadUleb(b, layout.ValuesStart) is not { } blockSize || ReadUleb(b, blockSize.Next) is not { } miniblocks
            || ReadUleb(b, miniblocks.Next) is not { } total || ReadUleb(b, total.Next) is not { } first
            || ReadUleb(b, first.Next) is not { } minDelta || miniblocks.Value is <= 0 or > 256)
            return null;
        var widthsAt = minDelta.Next;
        if (widthsAt + miniblocks.Value > b.Length) return null;
        var width = new byte[] { 33, 64, 65, 100, 255 }[rng.Next(5)];
        // The first miniblock is always used when more than one value is present.
        b[widthsAt] = width;
        return new("delta-width", $"first miniblock bit width {width} ({leaf.Physical})", width > 64);
    }

    static Mutation? DeltaLengthLengths(Random rng, List<Page> pages, int index, Leaf leaf, Layout layout)
    {
        var page = pages[index];
        if (page.Encoding != 6 || layout.Present == 0) return null;
        var b = page.Body;
        if (ReadUleb(b, layout.ValuesStart) is not { } blockSize || ReadUleb(b, blockSize.Next) is not { } miniblocks
            || ReadUleb(b, miniblocks.Next) is not { } total || ReadUleb(b, total.Next) is not { } first)
            return null;
        var value = rng.Next(3) switch { 0 => -5L, 1 => 1L << 40, _ => (long)(b.Length - layout.ValuesStart) + 1 };
        var replacement = Uleb((ulong)blockSize.Value).Concat(Uleb((ulong)miniblocks.Value)).Concat(Uleb((ulong)total.Value))
            .Concat(Uleb(ZigZagEncode(value))).ToArray();
        Splice(page, layout, layout.ValuesStart, first.Next, replacement, 'v');
        return new("delta-length", $"first length {value}", true);
    }

    static Mutation? DeltaByteArrayPrefix(Random rng, List<Page> pages, int index, Leaf leaf, Layout layout)
    {
        var page = pages[index];
        if (page.Encoding != 7 || layout.Present == 0) return null;
        var b = page.Body;
        if (ReadUleb(b, layout.ValuesStart) is not { } blockSize || ReadUleb(b, blockSize.Next) is not { } miniblocks
            || ReadUleb(b, miniblocks.Next) is not { } total || ReadUleb(b, total.Next) is not { } first)
            return null;
        // The first value has no predecessor: any prefix length but 0 is impossible.
        var value = rng.Next(2) == 0 ? rng.Next(1, 64) : -1L;
        var replacement = Uleb((ulong)blockSize.Value).Concat(Uleb((ulong)miniblocks.Value)).Concat(Uleb((ulong)total.Value))
            .Concat(Uleb(ZigZagEncode(value))).ToArray();
        Splice(page, layout, layout.ValuesStart, first.Next, replacement, 'v');
        return new("delta-prefix", $"first prefix length {value}", true);
    }

    static Mutation? ByteStreamSplitSize(Random rng, List<Page> pages, int index, Leaf leaf, Layout layout)
    {
        var page = pages[index];
        var width = FixedWidth(leaf);
        if (page.Encoding != 9 || width < 2 || layout.Present == 0) return null;
        var shift = rng.Next(1, width);
        var b = page.Body;
        if (rng.Next(2) == 0 && b.Length - layout.ValuesStart > shift)
            page.Body = b[..^shift];
        else
            page.Body = Join(b, new byte[shift]);
        return new("bss-size", $"values region {(page.Body.Length < b.Length ? "-" : "+")}{shift} bytes (width {width})", true);
    }

    static Mutation? PlainBinaryLength(Random rng, List<Page> pages, int index, Leaf leaf, Layout layout)
    {
        // A data page's or the dictionary page's PLAIN BYTE_ARRAY values.
        var useDictionary = rng.Next(3) == 0 && pages.FirstOrDefault(static p => p.IsDictionary) is not null;
        var page = useDictionary ? pages.First(static p => p.IsDictionary) : pages[index];
        if (leaf.Physical != ParquetPhysicalType.ByteArray || page.Encoding is not (0 or 2) || (!useDictionary && page.Encoding != 0))
            return null;
        var start = useDictionary ? 0 : layout.ValuesStart;
        var count = useDictionary ? page.NumValues : layout.Present;
        if (count == 0) return null;
        var b = page.Body;
        var offsets = new List<int>();
        var p = start;
        for (var i = 0; i < count; i++)
        {
            if (p + 4 > b.Length) return null;
            offsets.Add(p);
            var length = BinaryPrimitives.ReadInt32LittleEndian(b.AsSpan(p));
            if (length < 0 || p + 4 + length > b.Length) return null;
            p += 4 + length;
        }
        var at = offsets[rng.Next(offsets.Count)];
        var remaining = b.Length - at - 4;
        var value = rng.Next(3) switch { 0 => remaining + 1, 1 => int.MaxValue, _ => int.MinValue };
        BinaryPrimitives.WriteInt32LittleEndian(b.AsSpan(at), value);
        return new("plain-binary-length", $"{(useDictionary ? "dictionary" : "data")} length prefix {value} ({remaining} bytes left)", true);
    }

    static Mutation? FixedTruncate(Random rng, List<Page> pages, int index, Leaf leaf, Layout layout)
    {
        var page = pages[index];
        var width = FixedWidth(leaf);
        if (page.Encoding != 0 || width == 0 || layout.Present == 0) return null;
        var b = page.Body;
        if (b.Length - layout.ValuesStart != layout.Present * width) return null;
        var cut = rng.Next(1, Math.Min(width * 2, b.Length - layout.ValuesStart) + 1);
        page.Body = b[..^cut];
        return new("fixed-truncate", $"PLAIN {leaf.Physical} values short by {cut} bytes (width {width})", true);
    }

    static Mutation? V2LevelLengths(Random rng, List<Page> pages, int index, Leaf leaf, Layout layout)
    {
        var page = pages[index];
        if (!page.IsV2) return null;
        var field = (short)(rng.Next(2) == 0 ? 5 : 6);
        var current = page.V2!.Long(field) ?? 0;
        var delta = rng.Next(2) == 0 ? rng.Next(1, 4) : -rng.Next(1, 4);
        var value = current + delta;
        if (value < 0) value = page.Body.Length + 1;
        page.V2.SetLong(field, I32, value);
        var total = (page.V2.Long(5) ?? 0) + (page.V2.Long(6) ?? 0);
        return new("v2-level-lengths", $"{(field == 5 ? "definition" : "repetition")} levels byte length {current} -> {value}",
            total > page.Body.Length);
    }

    static Mutation? V2NumNulls(Random rng, List<Page> pages, int index, Leaf leaf, Layout layout)
    {
        var page = pages[index];
        if (!page.IsV2) return null;
        var current = page.V2!.Long(2) ?? 0;
        var value = rng.Next(3) switch { 0 => current + 1, 1 => Math.Max(0, current - 1), _ => page.NumValues + 5L };
        page.V2.SetLong(2, I32, value);
        return new("v2-num-nulls", $"num_nulls {current} -> {value}", false);
    }

    static Mutation? NumValues(Random rng, List<Page> pages, int index, Leaf leaf, Layout layout)
    {
        var page = pages[index];
        var header = page.IsV2 ? page.V2 : page.V1;
        if (header is null) return null;
        var n = page.NumValues;
        var value = rng.Next(4) switch { 0 => n + 1, 1 => Math.Max(0, n - 1), 2 => n * 2 + 7, _ => int.MaxValue };
        header.SetLong(1, I32, value);
        return new("num-values", $"page num_values {n} -> {value}", false);
    }

    static Mutation? ValuesHavoc(Random rng, List<Page> pages, int index, Leaf leaf, Layout layout)
    {
        var page = pages[index];
        var length = page.Body.Length - layout.ValuesStart;
        if (length <= 0) return null;
        var flips = rng.Next(1, 5);
        for (var i = 0; i < flips; i++)
            page.Body[layout.ValuesStart + rng.Next(length)] ^= (byte)(1 << rng.Next(8));
        return new("values-havoc", $"{flips} bit flip(s) in the values (encoding {page.Encoding})", false);
    }

    /// <summary>One mutant of <paramref name="file"/>, or null when no mutation applies.</summary>
    public static (byte[] File, Mutation Mutation)? Mutate(byte[] file, Random rng, string? onlyKind = null)
    {
        var parsed = Parse(file);
        if (parsed is null)
            return null;
        return MutateParsed(parsed, rng, onlyKind);
    }

    static (byte[] File, Mutation Mutation)? MutateParsed(Parsed parsed, Random rng, string? onlyKind)
    {
        var chunks = new List<(int G, int C)>();
        for (var g = 0; g < parsed.Pages.Length; g++)
            for (var c = 0; c < parsed.Pages[g].Length; c++)
                if (parsed.Pages[g][c].Any(static p => p.IsData))
                    chunks.Add((g, c));
        if (chunks.Count == 0)
            return null;
        for (var attempt = 0; attempt < 24; attempt++)
        {
            var (g, c) = chunks[rng.Next(chunks.Count)];
            var pages = parsed.Pages[g][c].Select(static p => p.Clone()).ToList();
            var dataPages = Enumerable.Range(0, pages.Count).Where(i => pages[i].IsData).ToList();
            var index = dataPages[rng.Next(dataPages.Count)];
            var leaf = parsed.Leaves[c];
            if (Lay(pages[index], leaf) is not { } layout)
                continue;
            var candidates = onlyKind is null ? Mutators : Mutators.Where(m => m.Name == onlyKind).ToArray();
            if (candidates.Length == 0)
                return null;
            var (name, apply) = candidates[rng.Next(candidates.Length)];
            Mutation? mutation;
            try
            {
                mutation = apply(rng, pages, index, leaf, layout);
            }
            catch (Exception error) when (error is ArgumentException or IndexOutOfRangeException or OverflowException)
            {
                continue; // the mutator could not apply to this page shape
            }
            if (mutation is not { } m)
                continue;
            var all = parsed.Pages.Select(static row => row.ToArray()).ToArray();
            all[g][c] = pages;
            return (Build(parsed.Footer, all), m with { Detail = $"row group {g}, column {c}, page {index}: {m.Detail}" });
        }
        return null;
    }

    /// <summary>The seed rewritten uncompressed with no mutation (the envelope round trip).</summary>
    public static byte[]? Baseline(byte[] file)
        => Parse(file) is { } parsed ? Build(parsed.Footer, parsed.Pages) : null;

    // ---- Driver ------------------------------------------------------------------------

    static string? LastPlankError;
    static readonly int Stack = int.TryParse(Environment.GetEnvironmentVariable("PLANK_FUZZ_STACK"), out var stack) ? stack : 0;

    public static long Mutants, BothReject, PlankOnlyReject, ArrowOnlyReject, BothAccept, Findings, BaselineFailures, Seeds;

    static readonly Dictionary<string, long[]> PerKind = []; // [plank reject, arrow reject, both accept, findings]

    /// <summary>
    /// Runs <paramref name="perSeed"/> mutants of each seed through the oracle. Writes "SFINDING" lines
    /// and saves findings under <paramref name="dumpDirectory"/>.
    /// </summary>
    public static void Run(IEnumerable<string> seedFiles, int perSeed, int seed, string dumpDirectory, TextWriter log)
    {
        var rng = new Random(seed);
        foreach (var path in seedFiles)
        {
            byte[] bytes;
            try { bytes = File.ReadAllBytes(path); } catch (IOException) { continue; }
            // Reader seeds carry a selector byte before the file.
            if (bytes.Length > 5 && !bytes.AsSpan(0, 4).SequenceEqual("PAR1"u8) && bytes.AsSpan(1, 4).SequenceEqual("PAR1"u8))
                bytes = bytes[1..];
            Parsed? parsed;
            try { parsed = Parse(bytes); }
            catch (Exception error) when (error is InvalidDataException or CorruptParquetException or OverflowException
                                              or ArgumentException or InvalidOperationException or NotSupportedException)
            {
                continue;
            }
            if (parsed is null)
                continue;
            // The rewritten seed must read exactly like the original, or the rewriter is wrong.
            var baseline = Build(parsed.Footer, parsed.Pages);
            var baselineVerdict = Judge(baseline, new Mutation("baseline", path, false), dumpDirectory, log, quiet: true);
            if (baselineVerdict != "both-accept")
            {
                BaselineFailures++;
                Directory.CreateDirectory(dumpDirectory);
                var baselineFile = Path.Combine(dumpDirectory, "baseline-" + Path.GetFileName(path) + ".parquet");
                File.WriteAllBytes(baselineFile, baseline);
                log.WriteLine($"SBASELINE\t{baselineVerdict}\t{path}\t{baselineFile}\t{LastPlankError}");
                continue;
            }
            Seeds++;
            for (var i = 0; i < perSeed; i++)
            {
                (byte[] File, Mutation Mutation)? mutant;
                try { mutant = MutateParsed(parsed, rng, null); }
                catch (Exception error) when (error is InvalidDataException or ArgumentException or OverflowException or InvalidOperationException)
                {
                    continue;
                }
                if (mutant is not { } m)
                    break;
                // Stacked corruption: mutate the mutant again (each re-parse keeps the envelope valid).
                for (var extra = rng.Next(Stack + 1); extra > 0; extra--)
                {
                    (byte[] File, Mutation Mutation)? next;
                    try { next = Mutate(m.File, rng); }
                    catch (Exception error) when (error is InvalidDataException or ArgumentException or OverflowException
                                                      or InvalidOperationException or CorruptParquetException or NotSupportedException)
                    {
                        break;
                    }
                    if (next is not { } n)
                        break;
                    m = (n.File, new Mutation(m.Mutation.Kind + "+" + n.Mutation.Kind, m.Mutation.Detail + " | " + n.Mutation.Detail,
                        m.Mutation.Impossible || n.Mutation.Impossible));
                }
                Mutants++;
                Judge(m.File, m.Mutation with { Detail = $"{Path.GetFileName(path)}: {m.Mutation.Detail}" }, dumpDirectory, log, quiet: false);
            }
        }
        log.WriteLine($"structured: {Seeds} seeds ({BaselineFailures} baseline failures), {Mutants} mutants: both reject {BothReject}, "
            + $"Plank-only reject {PlankOnlyReject}, Arrow-only reject {ArrowOnlyReject}, both accept {BothAccept}, findings {Findings}");
        foreach (var (kind, c) in PerKind.OrderBy(static k => k.Key))
            log.WriteLine($"structured-kind\t{kind}\tplank-reject={c[0]}\tarrow-reject={c[1]}\tboth-accept={c[2]}\tfindings={c[3]}");
    }

    // PLANK_FUZZ_POOL=1 (exact-fit, guard bytes checked on return) / 2 (also poisoned 0xA5 payload), as the reader target.
    static readonly IParquetBufferPool? Pool = Environment.GetEnvironmentVariable("PLANK_FUZZ_POOL") switch
    {
        "1" => new ExactFitBufferPool(poison: false),
        "2" => new ExactFitBufferPool(poison: true),
        _ => null,
    };

    static string Judge(byte[] file, Mutation mutation, string dumpDirectory, TextWriter log, bool quiet)
    {
        var counts = quiet ? new long[4] : PerKind.TryGetValue(mutation.Kind, out var existing) ? existing : PerKind[mutation.Kind] = new long[4];

        // Plank: every column through the physical read (levels + values).
        LastPlankError = null;
        List<ColumnTrace?[]>? plankTraces = new();
        Exception? plankError = null;
        ParquetReader? plank = null;
        try
        {
            plank = new ParquetReader(Pool is null ? null : new ParquetReaderOptions { BufferPool = Pool });
            plank.Reset(new MemoryReadSource(file));
            foreach (var group in plank.RowGroups)
            {
                var traces = new ColumnTrace?[plank.Schema.LeafColumns.Length];
                plankTraces.Add(traces);
                for (var c = 0; c < traces.Length; c++)
                    traces[c] = ColumnTrace.CapturePlank(group, plank.Schema.LeafColumns[c]);
            }
        }
        catch (CorruptParquetException error) { plankError = error; LastPlankError = error.Message; }
        catch (NotSupportedException error) { plankError = error; LastPlankError = "NotSupported: " + error.Message; }
        catch (Exception error) when (error is not OutOfMemoryException)
        {
            plank?.Dispose();
            return Finding("Plank threw an exception other than CorruptParquetException", $"{error.GetType().Name}: {error.Message}", error);
        }

        // Arrow: every column, levels and values.
        List<ColumnTrace?[]>? arrowTraces = new();
        try
        {
            using var arrow = new Ps.ParquetFileReader(new MemoryStream(file, writable: false), leaveOpen: false);
            for (var g = 0; g < arrow.FileMetaData.NumRowGroups; g++)
            {
                using var group = arrow.RowGroup(g);
                var traces = new ColumnTrace?[arrow.FileMetaData.NumColumns];
                arrowTraces.Add(traces);
                for (var c = 0; c < traces.Length; c++)
                {
                    using var column = group.Column(c);
                    var descriptor = column.ColumnDescriptor;
                    traces[c] = ColumnTrace.CaptureArrow(column, descriptor.MaxRepetitionLevel > 0, descriptor.MaxDefinitionLevel, descriptor.TypeLength);
                }
            }
        }
        catch (Exception error) when (error is not OutOfMemoryException)
        {
            arrowTraces = null;
        }

        try
        {
            if (plankError is not null)
            {
                if (arrowTraces is null) { if (!quiet) { BothReject++; counts[0]++; counts[1]++; } return "both-reject"; }
                if (!quiet) { PlankOnlyReject++; counts[0]++; }
                return "plank-reject";
            }
            if (mutation.Impossible)
                return Finding("Plank returned values for impossible data", $"Arrow {(arrowTraces is null ? "rejects" : "accepts")}", null);
            if (arrowTraces is null)
            {
                if (!quiet) { ArrowOnlyReject++; counts[1]++; }
                return "arrow-reject";
            }
            if (arrowTraces.Count != plankTraces.Count)
                return Finding("row group count differs from Arrow", $"Plank={plankTraces.Count}, Arrow={arrowTraces.Count}", null);
            for (var g = 0; g < plankTraces.Count; g++)
                for (var c = 0; c < plankTraces[g].Length; c++)
                    if (plankTraces[g][c] is { } a && c < arrowTraces[g].Length && arrowTraces[g][c] is { } b
                        && ColumnTrace.Difference(a, b) is { } difference)
                        return Finding($"decoded values differ from Arrow ({difference[..difference.IndexOf('\n')]})",
                            $"row group {g}, column {c}: {difference[(difference.IndexOf('\n') + 1)..]}", null);
            // Both accept and agree: every other read API must agree too.
            try
            {
                FullValueOracle.VerifyAccepted(file, plank!);
            }
            catch (ReaderAcceptanceMismatchException mismatch)
            {
                return Finding("read API disagrees with Arrow", mismatch.InnerException?.Message ?? mismatch.Message, null);
            }
            catch (CorruptParquetException)
            {
                // A second API rejecting what the first accepted: allowed (each validates what it reads).
            }
            catch (Exception error) when (error is not OutOfMemoryException and not ReaderAcceptanceMismatchException)
            {
                return Finding("read API threw an exception other than CorruptParquetException", $"{error.GetType().Name}: {error.Message}", error);
            }
            if (!quiet) { BothAccept++; counts[2]++; }
            return "both-accept";
        }
        finally
        {
            plank?.Dispose();
        }

        string Finding(string bucket, string detail, Exception? error)
        {
            if (quiet)
                return "finding: " + bucket + " — " + detail;
            Findings++;
            counts[3]++;
            Directory.CreateDirectory(dumpDirectory);
            var name = Path.Combine(dumpDirectory, $"{mutation.Kind}-{XxHash64.HashToUInt64(file):x16}.parquet");
            File.WriteAllBytes(name, file);
            var where = error?.StackTrace?.Split('\n').FirstOrDefault(static l => l.Contains("Plank.", StringComparison.Ordinal) && !l.Contains("Plank.Fuzzing", StringComparison.Ordinal))?.Trim();
            log.WriteLine($"SFINDING\t{mutation.Kind}\t{bucket}\t{detail.Replace('\n', ' ')}\t{mutation.Detail}\t{where}\t{name}");
            return "finding";
        }
    }
}
