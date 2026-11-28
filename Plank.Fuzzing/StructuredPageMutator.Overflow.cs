using System.Buffers.Binary;
using System.IO.Compression;
using System.Numerics;
using Plank.Schema;
using static Plank.Fuzzing.ThriftCompact;

namespace Plank.Fuzzing;

/// <summary>
/// Arithmetic-overflow boundary mutations: every count/length field the mutator rewrites also gets
/// values whose products with the multipliers the format implies wrap 32 or 64 bits — to 0, to a
/// small value, or to just under the remaining payload — plus the classic 2^k, 2^k±1 and
/// uint.MaxValue/unit±1. A decoder that multiplies such a field in a narrow unchecked type sizes
/// its slice from the wrapped value and reads past it; whether a mutant is impossible is computed
/// here exactly (BigInteger), never with the reader's arithmetic.
/// </summary>
public static partial class StructuredPageMutator
{
    static readonly BigInteger Two32 = BigInteger.One << 32, Two64 = BigInteger.One << 64;

    /// <summary>
    /// Boundary values v (1 ≤ v ≤ max) for a field whose value is multiplied by each of
    /// <paramref name="units"/> somewhere in a decoder. <paramref name="remaining"/> is the payload
    /// size (in the unit's result) a wrapped product should land just under.
    /// </summary>
    internal static List<BigInteger> OverflowValues(BigInteger max, long remaining, params long[] units)
    {
        var values = new HashSet<BigInteger>();
        void Add(BigInteger v) { if (v >= 1 && v <= max) values.Add(v); }
        foreach (var unit in units.Where(static u => u >= 1).Distinct())
        {
            foreach (var modulus in new[] { Two32, Two64 })
            {
                for (var m = 1; m <= Math.Min(unit, 4); m++)
                {
                    var target = modulus * m;
                    // v·unit ≡ r (mod 2^W): wraps to 0, to small values, to just under the payload.
                    foreach (var r in new long[] { 0, 1, 2, 7, 8, 63, 64, Math.Max(0, remaining - 1), remaining })
                    {
                        var v = BigInteger.Divide(target + r + unit - 1, unit); // ceil((target + r) / unit)
                        Add(v); Add(v + 1); Add(v - 1);
                    }
                    Add(target / unit); Add(target / unit - 1);
                }
                Add((modulus - 1) / unit); Add((modulus - 1) / unit + 1); Add((modulus - 1) / unit - 1);
            }
        }
        for (var k = 0; k < 64; k++)
        {
            var p = BigInteger.One << k;
            Add(p); Add(p - 1); Add(p + 1);
        }
        return [.. values];
    }

    static BigInteger PickOverflow(Random rng, BigInteger max, long remaining, params long[] units)
    {
        var values = OverflowValues(max, remaining, units);
        // Favour the wrap values (the ones derived from the units) over the plain powers of two.
        return values[rng.Next(values.Count)];
    }

    static byte[] UlebBig(BigInteger value)
    {
        var output = new List<byte>();
        do
        {
            var b = (byte)(value & 0x7F);
            value >>= 7;
            output.Add(value.IsZero ? b : (byte)(b | 0x80));
        } while (!value.IsZero);
        return [.. output];
    }

    static long ElementSize(Leaf leaf) => FixedWidth(leaf) is > 0 and var w ? w : 1;

    // ---- Run-header overflow (levels and dictionary indices) ------------------------------------

    /// <summary>
    /// Replaces a hybrid RLE/bit-packed stream (definition levels, repetition levels or dictionary
    /// indices, re-encoded at any width 1..32 for indices) with a valid bit-packed prefix followed by
    /// one bit-packed header whose group count is an overflow boundary for ×8, ×width and ×width/8,
    /// and then the real packed bytes of the remaining values. The run claims groups·8 values whose
    /// bytes (groups·width) are not in the stream: impossible, whatever a reader's arithmetic says.
    /// </summary>
    static Mutation? HybridRunOverflow(Random rng, List<Page> pages, int index, Leaf leaf, Layout layout)
    {
        var page = pages[index];
        var target = rng.Next(3);
        List<long> values;
        int width, start, end;
        char stream;
        var widthByte = false;
        if (target == 0 && IsDictionaryEncoded(page) && layout.Present > 0 && layout.ValuesStart < page.Body.Length)
        {
            var current = page.Body[layout.ValuesStart];
            if (current > 32) return null;
            var decoded = DecodeHybrid(page.Body, layout.ValuesStart + 1, page.Body.Length, current, layout.Present);
            if (decoded is null) return null;
            values = decoded.Value.Values;
            var needed = Math.Max(1, BitWidth(values.Count == 0 ? 0 : values.Max()));
            width = rng.Next(2) == 0 ? current : rng.Next(Math.Max(needed, current == 0 ? 1 : needed), 33);
            if (width == 0) width = 1;
            start = layout.ValuesStart; end = page.Body.Length; stream = 'v'; widthByte = true;
        }
        else if (target == 1 && layout.Def is { Count: > 0 } def)
        {
            values = def; width = BitWidth(leaf.MaxDef); start = layout.DefStart; end = layout.DefEnd; stream = 'd';
        }
        else if (layout.Rep is { Count: > 0 } rep)
        {
            values = rep; width = BitWidth(leaf.MaxRep); start = layout.RepStart; end = layout.RepEnd; stream = 'r';
        }
        else
            return null;
        if (width == 0 || values.Count == 0) return null;

        // Prefix: a whole number of valid bit-packed groups (possibly none).
        var prefixValues = rng.Next(2) == 0 ? 0 : rng.Next(values.Count / 8 + 1) * 8;
        var prefix = prefixValues == 0 ? [] : EncodeBitPacked(values.Take(prefixValues).ToList(), width);
        var rest = values.Skip(prefixValues).ToList();
        if (rest.Count == 0) return null;
        // The bytes of the remaining values, as a correctly packed run would hold them (without header).
        var packedRest = EncodeBitPacked(rest, width);
        var restBytes = packedRest.AsSpan(Uleb(((ulong)((rest.Count + 7) / 8) << 1) | 1).Length).ToArray();
        // Header value is a uint32 varint (groups << 1 | 1): groups ≤ 2^31 - 1.
        var groups = PickOverflow(rng, (BigInteger.One << 31) - 1, restBytes.Length, 8, 8L * width, width, Math.Max(1, width / 8));
        var header = UlebBig((groups << 1) | 1);
        var replacement = widthByte
            ? Join([(byte)width], prefix, header, restBytes)
            : Join(prefix, header, restBytes);
        Splice(page, layout, start, end, replacement, stream);
        var claimedBytes = (groups * 8 * width + 7) / 8;
        var impossible = claimedBytes > restBytes.Length;
        return new("hybrid-overflow",
            $"{(stream == 'v' ? "dictionary-index" : stream == 'd' ? "definition" : "repetition")} stream, width {width}, "
            + $"{prefixValues} valid values then a bit-packed header of {groups} groups ({claimedBytes} bytes claimed, {restBytes.Length} present)",
            impossible);
    }

    /// <summary>An RLE run whose length is an overflow boundary (decodable: only num_values matter).</summary>
    static Mutation? RleRunOverflow(Random rng, List<Page> pages, int index, Leaf leaf, Layout layout)
    {
        var page = pages[index];
        if (layout.Def is not { Count: > 0 } def) return null;
        var width = BitWidth(leaf.MaxDef);
        var length = PickOverflow(rng, (BigInteger.One << 31) - 1, page.NumValues, 1, ElementSize(leaf), 8);
        var run = new List<byte>(UlebBig(length << 1));
        for (var i = 0; i < (width + 7) / 8; i++) run.Add((byte)(def[0] >> (8 * i)));
        Splice(page, layout, layout.DefStart, layout.DefEnd, run.ToArray(), 'd');
        return new("rle-run-overflow", $"definition RLE run of {length} x {def[0]}", false);
    }

    /// <summary>A run header varint wider than 32 bits (5-10 bytes): a uint32 header cannot hold it.</summary>
    static Mutation? VarintHeaderWide(Random rng, List<Page> pages, int index, Leaf leaf, Layout layout)
    {
        var page = pages[index];
        if (!IsDictionaryEncoded(page) || layout.Present == 0 || layout.ValuesStart >= page.Body.Length) return null;
        var width = page.Body[layout.ValuesStart];
        if (width is 0 or > 32) return null;
        var decoded = DecodeHybrid(page.Body, layout.ValuesStart + 1, page.Body.Length, width, layout.Present);
        if (decoded is null) return null;
        var packed = EncodeBitPacked(decoded.Value.Values, width);
        var headerLength = Uleb(((ulong)((decoded.Value.Values.Count + 7) / 8) << 1) | 1).Length;
        // Groups whose low 32 bits look like the real count: a reader truncating the varint decodes "correctly".
        var real = (BigInteger)((decoded.Value.Values.Count + 7) / 8);
        var groups = real + (BigInteger.One << (31 + rng.Next(1, 30)));
        Splice(page, layout, layout.ValuesStart, page.Body.Length,
            Join([width], UlebBig((groups << 1) | 1), packed[headerLength..]), 'v');
        return new("varint-header-wide", $"dictionary-index bit-packed header {groups} groups (> 32 bits)", true);
    }

    /// <summary>Re-encodes the dictionary indices at another valid width (1..32): must decode the same.</summary>
    static Mutation? DictReencodeWidth(Random rng, List<Page> pages, int index, Leaf leaf, Layout layout)
    {
        var page = pages[index];
        if (!IsDictionaryEncoded(page) || layout.Present == 0 || layout.ValuesStart >= page.Body.Length) return null;
        var width = page.Body[layout.ValuesStart];
        if (width > 32) return null;
        var decoded = DecodeHybrid(page.Body, layout.ValuesStart + 1, page.Body.Length, width, layout.Present);
        if (decoded is null) return null;
        var values = decoded.Value.Values;
        var needed = Math.Max(1, BitWidth(values.Max()));
        var newWidth = rng.Next(needed, 33);
        Splice(page, layout, layout.ValuesStart, page.Body.Length, Join([(byte)newWidth], EncodeBitPacked(values, newWidth)), 'v');
        return new("dict-reencode-width", $"indices re-encoded at width {newWidth} (was {width})", false);
    }

    // ---- Count / length fields --------------------------------------------------------------------

    static Mutation? CountOverflow(Random rng, List<Page> pages, int index, Leaf leaf, Layout layout)
    {
        var page = pages[index];
        var element = ElementSize(leaf);
        var int32Max = (BigInteger)int.MaxValue;
        switch (rng.Next(5))
        {
            case 0:
            {
                // Page num_values (levels/values count) × element size, × bit widths, × 8.
                var header = page.IsV2 ? page.V2 : page.V1;
                if (header is null) return null;
                var value = PickOverflow(rng, int32Max, page.Body.Length - layout.ValuesStart, element, 8, BitWidth(leaf.MaxDef), 4);
                header.SetLong(1, I32, (long)value);
                // Fixed-width PLAIN without levels: more values than bytes is impossible.
                var impossible = page.Encoding == 0 && FixedWidth(leaf) > 0 && leaf.MaxDef == 0 && leaf.MaxRep == 0
                    && value * FixedWidth(leaf) > page.Body.Length - layout.ValuesStart;
                return new("count-overflow", $"page num_values {page.NumValues} -> {value}", impossible);
            }
            case 1:
            {
                var dictionary = pages.FirstOrDefault(static p => p.IsDictionary);
                if (dictionary is null) return null;
                var value = PickOverflow(rng, int32Max, dictionary.Body.Length, element, 8, 4, 16);
                var old = dictionary.NumValues;
                dictionary.Dict!.SetLong(1, I32, (long)value);
                var impossible = FixedWidth(leaf) > 0 && value * FixedWidth(leaf) > dictionary.Body.Length;
                return new("count-overflow", $"dictionary num_values {old} -> {value} (element {element})", impossible);
            }
            case 2:
            {
                if (!page.IsV2) return null;
                var field = (short)(rng.Next(2) == 0 ? 5 : 6);
                var value = PickOverflow(rng, int32Max, page.Body.Length, 1, 8);
                var old = page.V2!.Long(field) ?? 0;
                page.V2.SetLong(field, I32, (long)value);
                var total = (BigInteger)(page.V2.Long(5) ?? 0) + (page.V2.Long(6) ?? 0);
                return new("count-overflow", $"v2 {(field == 5 ? "definition" : "repetition")} byte length {old} -> {value}", total > page.Body.Length);
            }
            case 3:
            {
                if (!page.IsV2) return null;
                var field = (short)(rng.Next(2) == 0 ? 2 : 3);
                var value = PickOverflow(rng, int32Max, page.NumValues, 1, element, 8);
                page.V2!.SetLong(field, I32, (long)value);
                return new("count-overflow", $"v2 {(field == 2 ? "num_nulls" : "num_rows")} -> {value}", false);
            }
            default:
            {
                // A PLAIN BYTE_ARRAY length prefix (int32 on the wire; also as wrapped negative values).
                if (leaf.Physical != ParquetPhysicalType.ByteArray || page.Encoding != 0 || layout.Present == 0) return null;
                var b = page.Body;
                var p = layout.ValuesStart;
                if (p + 4 > b.Length) return null;
                var value = PickOverflow(rng, uint.MaxValue, b.Length - p - 4, 1, 4, 8);
                BinaryPrimitives.WriteUInt32LittleEndian(b.AsSpan(p), (uint)value);
                return new("count-overflow", $"first PLAIN length prefix {(uint)value} ({b.Length - p - 4} bytes left)",
                    (long)(uint)value > b.Length - p - 4 || (int)(uint)value < 0);
            }
        }
    }

    static Mutation? DeltaOverflow(Random rng, List<Page> pages, int index, Leaf leaf, Layout layout)
    {
        var page = pages[index];
        if (page.Encoding is not (5 or 6 or 7) || layout.Present == 0) return null;
        var b = page.Body;
        if (ReadUleb(b, layout.ValuesStart) is not { } blockSize || ReadUleb(b, blockSize.Next) is not { } miniblocks
            || ReadUleb(b, miniblocks.Next) is not { } total || ReadUleb(b, total.Next) is not { } first)
            return null;
        BigInteger bs = blockSize.Value, mb = miniblocks.Value, tc = total.Value;
        var max = (BigInteger)ulong.MaxValue >> 1;
        string what;
        switch (rng.Next(3))
        {
            case 0: bs = PickOverflow(rng, max, b.Length, 1, 8, ElementSize(leaf), 128); what = $"block size {bs}"; break;
            case 1: mb = PickOverflow(rng, max, b.Length, 1, 32, 8); what = $"miniblocks {mb}"; break;
            default: tc = PickOverflow(rng, max, b.Length, 1, ElementSize(leaf), 8); what = $"total count {tc}"; break;
        }
        var replacement = Join(UlebBig(bs), UlebBig(mb), UlebBig(tc), b[total.Next..first.Next]);
        Splice(page, layout, layout.ValuesStart, first.Next, replacement, 'v');
        // Spec shape: block size a positive multiple of 128, miniblocks dividing it into multiples of 32.
        var impossible = (bs <= 0 || bs % 128 != 0 || mb <= 0 || bs % mb != 0 || bs / mb % 32 != 0 || tc < layout.Present)
            && layout.Present > 1;
        return new("delta-overflow", $"{(page.Encoding == 5 ? "DELTA_BINARY_PACKED" : page.Encoding == 6 ? "DELTA_LENGTH lengths" : "DELTA_BYTE_ARRAY prefixes")} {what}", impossible);
    }

    // ---- Re-compression --------------------------------------------------------------------------

    static readonly double RecompressProbability =
        double.TryParse(Environment.GetEnvironmentVariable("PLANK_FUZZ_RECOMPRESS"), System.Globalization.CultureInfo.InvariantCulture, out var p) ? p : 0.3;

    static long PickCodec(Random rng) => rng.NextDouble() < RecompressProbability ? new long[] { 1, 2, 4 }[rng.Next(3)] : 0;

    static byte[] Compress(long codec, byte[] data)
    {
        switch (codec)
        {
            case 1: return Snappier.Snappy.CompressToArray(data);
            case 2:
            {
                using var output = new MemoryStream();
                using (var gzip = new GZipStream(output, CompressionLevel.Fastest, leaveOpen: true))
                    gzip.Write(data);
                return output.ToArray();
            }
            case 4:
            {
                using var output = new MemoryStream();
                using (var brotli = new BrotliStream(output, CompressionLevel.Fastest, leaveOpen: true))
                    brotli.Write(data);
                return output.ToArray();
            }
            default: return data;
        }
    }
}
