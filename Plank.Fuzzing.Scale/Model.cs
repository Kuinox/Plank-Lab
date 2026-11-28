using System.Buffers.Binary;
using System.Collections.Immutable;
using System.Runtime.CompilerServices;
using System.Text;
using Plank.Schema;

namespace Plank.Fuzzing.Scale;

/// <summary>Deterministic random source (splitmix64).</summary>
public sealed class Rng(ulong seed)
{
    ulong _state = seed;

    public ulong Next()
    {
        var z = _state += 0x9E3779B97F4A7C15UL;
        z = (z ^ (z >> 30)) * 0xBF58476D1CE4E5B9UL;
        z = (z ^ (z >> 27)) * 0x94D049BB133111EBUL;
        return z ^ (z >> 31);
    }

    public int Int(int maxExclusive) => maxExclusive <= 1 ? 0 : (int)(Next() % (ulong)maxExclusive);
    public long Long(long maxExclusive) => maxExclusive <= 1 ? 0 : (long)(Next() % (ulong)maxExclusive);
    public bool Chance(int percent) => Int(100) < percent;
    public T Pick<T>(params T[] items) => items[Int(items.Length)];

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public static ulong Mix(ulong z)
    {
        z += 0x9E3779B97F4A7C15UL;
        z = (z ^ (z >> 30)) * 0xBF58476D1CE4E5B9UL;
        z = (z ^ (z >> 27)) * 0x94D049BB133111EBUL;
        return z ^ (z >> 31);
    }
}

public enum Kind { Int32, Int64, Double, Float, Bool, Bytes, String, Fixed }

public static class KindExt
{
    public static bool IsBinary(this Kind k) => k is Kind.Bytes or Kind.String or Kind.Fixed;
}

/// <summary>
/// One column of a drawn shape. Every value is a pure function of (column seed, global row index), so a
/// file of any size can be verified while streaming, without keeping the expected data.
/// </summary>
public sealed class ColSpec
{
    public required string Name;
    public required Kind Kind;
    public bool Optional;
    public ulong Seed;
    // Value pattern.
    public int Pattern;
    public long P1, P2, P3;
    // Null pattern (optional columns only).
    public int NullPattern;
    public long N1, N2;
    // Byte length model.
    public int LenMode;
    public int L1, L2, L3;
    // Floating specials (NaN, -0, inf) every N values (0 = never).
    public int SpecialEvery;
    public ImmutableArray<EncodingKind> Encodings = [];
    public CompressionKind? Compression;
    public bool Bloom;
    public double BloomFpp = 0.01;
    public uint? BloomNdv;
    public uint BloomMaxBytes = 128 << 20;
    public int? CompressionLevel;

    /// <summary>Byte budget for one drawn binary column (set per file by the caller; SCALE_BUDGET_MB caps the file).</summary>
    [ThreadStatic] public static long BudgetBytes;
    public static long FileBudgetBytes => (Environment.GetEnvironmentVariable("SCALE_BUDGET_MB") is { } mb ? long.Parse(mb) : 600) << 20;

    public static readonly long[] Cardinalities =
        [1, 2, 3, 127, 128, 255, 256, 257, 511, 512, 513, 1023, 1024, 1025, 2047, 2048, 2049, 4095, 4096, 4097,
         32767, 32768, 32769, 65535, 65536, 65537, 1 << 20, (1 << 20) + 1];

    public override string ToString()
        => $"{Name}:{Kind}{(Optional ? "?" : "")} pat={Pattern}({P1},{P2},{P3}) null={NullPattern}({N1},{N2}) len={LenMode}({L1},{L2},{L3}) sp={SpecialEvery} enc=[{string.Join(",", Encodings)}] comp={Compression}{(CompressionLevel is { } l ? "/" + l : "")} bloom={Bloom}{(Bloom ? $"(fpp={BloomFpp},ndv={BloomNdv},max={BloomMaxBytes})" : "")}";

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    ulong H(long r, ulong salt = 0) => Rng.Mix(Seed ^ salt ^ (ulong)r * 0xD6E8FEB86659FD93UL);

    public bool IsNull(long r)
    {
        if (!Optional)
            return false;
        return NullPattern switch
        {
            0 => false,
            1 => true,
            2 => r % N1 == 0,                         // every N1-th
            3 => (long)(H(r, 77) % 1000) < N1,        // random, N1 per mille
            4 => (r / N1) % 2 == 1,                   // runs of N1
            5 => r >= N1,                             // tail nulls
            6 => r < N1,                              // head nulls
            _ => (long)(H(r / Math.Max(1, N2), 78) % 1000) < N1, // random runs
        };
    }

    public long Base(long r)
    {
        return Pattern switch
        {
            0 => P1,                                              // constant
            1 => unchecked(P1 + r * P2),                          // ascending (step P2)
            2 => unchecked(P1 - r * P2),                          // descending
            3 => unchecked(P1 + (r / Math.Max(1, P3)) * P2),      // ascending runs
            4 => (long)(H(r) % (ulong)Math.Max(1, P1)),           // random, cardinality P1
            5 => (long)H(r),                                      // random, full width
            6 => r % Math.Max(1, P1),                             // sawtooth
            7 => (r / Math.Max(1, P3)) % 2 == 0                   // sorted segments then random segments
                ? unchecked(P1 + r)
                : (long)(H(r) % (ulong)Math.Max(1, P2)),
            8 => (H(r) % 5) switch                                // extremes
            {
                0 => long.MinValue, 1 => long.MaxValue, 2 => 0, 3 => -1, _ => 1
            },
            9 => (long)((ulong)r * (ulong)Math.Max(1, P1) / (ulong)Math.Max(1, P2)), // sorted, ~P1 distinct
            10 => r < P3 ? (long)(H(r) % (ulong)Math.Max(1, P1)) : (long)H(r), // low-card prefix then high-card
            _ => (long)(H(r) % (ulong)Math.Max(1, P1)) * P2,     // random multiples
        };
    }

    public int Int32(long r)
    {
        var b = Base(r);
        return Pattern == 8 ? (H(r) % 5) switch { 0 => int.MinValue, 1 => int.MaxValue, 2 => 0, 3 => -1, _ => 1 } : unchecked((int)b);
    }

    public long Int64(long r) => Base(r);

    public double Double(long r)
    {
        var b = Base(r);
        if (SpecialEvery > 0 && r % SpecialEvery == 0)
        {
            return (H(r, 5) % 6) switch
            {
                0 => double.NaN, 1 => -0.0, 2 => 0.0, 3 => double.PositiveInfinity, 4 => double.NegativeInfinity,
                _ => BitConverter.Int64BitsToDouble(0x7FF8_0000_0000_0123L),
            };
        }
        if (Pattern == 8)
            return (H(r) % 5) switch { 0 => double.MinValue, 1 => double.MaxValue, 2 => 0, 3 => -1, _ => double.Epsilon };
        return (b % (1L << 52)) * 0.5;
    }

    public float Float(long r)
    {
        var b = Base(r);
        if (SpecialEvery > 0 && r % SpecialEvery == 0)
        {
            return (H(r, 5) % 6) switch
            {
                0 => float.NaN, 1 => -0.0f, 2 => 0.0f, 3 => float.PositiveInfinity, 4 => float.NegativeInfinity,
                _ => BitConverter.Int32BitsToSingle(0x7FC0_0123),
            };
        }
        if (Pattern == 8)
            return (H(r) % 5) switch { 0 => float.MinValue, 1 => float.MaxValue, 2 => 0, 3 => -1, _ => float.Epsilon };
        return (b % (1L << 23)) * 0.25f;
    }

    public bool Bool(long r) => (Base(r) & 1) != 0;

    public int ByteLength(long b)
    {
        var m = Rng.Mix((ulong)b ^ Seed ^ 0x51);
        return LenMode switch
        {
            0 => L1,                                                      // fixed
            1 => L1 + (int)(m % (ulong)(L2 + 1)),                         // uniform [L1, L1+L2]
            2 => m % (ulong)Math.Max(1, L3) == 0 ? L2 : L1,               // mostly L1, rarely huge L2
            _ => (int)(m % 3) switch { 0 => 0, 1 => L1, _ => L2 },        // 0 / small / large
        };
    }

    public long EstimatedBytes(long rows)
    {
        double avg = LenMode switch
        {
            0 => L1,
            1 => L1 + L2 / 2.0,
            2 => L1 + (double)L2 / Math.Max(1, L3),
            _ => (L1 + L2) / 3.0,
        };
        // Low-cardinality patterns repeat values, but the writer still materializes each row's value.
        return (long)(avg * rows) + rows * 16;
    }

    public byte[] Bytes(long r)
    {
        var b = Base(r);
        var length = ByteLength(b);
        var bytes = new byte[length];
        FillBytes(b, bytes);
        return bytes;
    }

    public void FillBytes(long b, Span<byte> destination)
    {
        // A pure function of the base value, so equal bases give equal (dictionary-able) values. ASCII for strings.
        var x = Rng.Mix((ulong)b ^ Seed);
        var i = 0;
        Span<byte> prefix = stackalloc byte[20];
        // Leading decimal of b keeps values distinct for short lengths and roughly ordered for sorted patterns.
        var ok = ((ulong)b).TryFormat(prefix, out var written, "D20");
        if (ok)
            for (; i < destination.Length && i < written; i++)
                destination[i] = prefix[i];
        for (; i < destination.Length; i++)
        {
            if ((i & 7) == 0)
                x = Rng.Mix(x);
            var v = (byte)(x >> ((i & 7) * 8));
            destination[i] = Kind == Kind.String ? (byte)('a' + v % 26) : v;
        }
    }

    public string Str(long r) => Encoding.ASCII.GetString(Bytes(r));

    public ParquetPhysicalType Physical => Kind switch
    {
        Kind.Int32 => ParquetPhysicalType.Int32,
        Kind.Int64 => ParquetPhysicalType.Int64,
        Kind.Double => ParquetPhysicalType.Double,
        Kind.Float => ParquetPhysicalType.Float,
        Kind.Bool => ParquetPhysicalType.Boolean,
        Kind.Fixed => ParquetPhysicalType.FixedLenByteArray,
        _ => ParquetPhysicalType.ByteArray,
    };

    /// <summary>Plain little-endian/raw bytes of the value, for statistics/bloom comparisons.</summary>
    public byte[] PlainBytes(long r) => Kind switch
    {
        Kind.Int32 => Le32(Int32(r)),
        Kind.Int64 => Le64(Int64(r)),
        Kind.Double => Le64(BitConverter.DoubleToInt64Bits(Double(r))),
        Kind.Float => Le32(BitConverter.SingleToInt32Bits(Float(r))),
        Kind.Bool => [(byte)(Bool(r) ? 1 : 0)],
        _ => Bytes(r),
    };

    static byte[] Le32(int v) { var b = new byte[4]; BinaryPrimitives.WriteInt32LittleEndian(b, v); return b; }
    static byte[] Le64(long v) { var b = new byte[8]; BinaryPrimitives.WriteInt64LittleEndian(b, v); return b; }

    /// <summary>Draw a column. <paramref name="kinds"/> restricts the kind; <paramref name="rows"/> sizes patterns.</summary>
    public static ColSpec Draw(Rng rng, string name, Kind kind, bool optional, long rows, bool allowHuge)
    {
        var c = new ColSpec { Name = name, Kind = kind, Optional = optional, Seed = rng.Next() };
        c.Pattern = rng.Int(12);
        c.P1 = c.Pattern switch
        {
            4 or 6 or 9 or 10 or 11 => rng.Pick(Cardinalities),
            _ => rng.Pick(0L, 1L, -5L, long.MaxValue - rows, int.MaxValue - 100L, (long)rng.Next()),
        };
        c.P2 = c.Pattern switch
        {
            7 => rng.Pick(Cardinalities),
            9 => Math.Max(1, rows),
            11 => rng.Pick(1L, 3L, 1L << 33, -7L),
            _ => rng.Pick(1L, 2L, 1000L, (1L << 31) + 1, 0L),
        };
        c.P3 = c.Pattern switch
        {
            10 => rng.Pick(0L, 2047L, 2048L, 2049L, rows / 2, rows - 1),
            _ => rng.Pick(1L, 2L, 7L, 1024L, 2048L, 2049L, 65536L, Math.Max(1, rows / 3)),
        };
        if (optional)
        {
            c.NullPattern = rng.Int(8);
            c.N1 = c.NullPattern switch
            {
                2 => rng.Pick(1L, 2L, 3L, 1000L, 2048L),
                3 or 7 => rng.Pick(1L, 10L, 500L, 990L, 999L),
                4 => rng.Pick(1L, 100L, 2048L, 65536L, 1L << 20),
                5 or 6 => rng.Long(Math.Max(1, rows + 1)),
                _ => 0,
            };
            c.N2 = rng.Pick(1L, 64L, 4096L, 1L << 18);
        }
        if (kind == Kind.Fixed)
        {
            c.LenMode = 0;
            c.L1 = rng.Pick(1, 2, 3, 4, 8, 12, 16, 16, 17, 100);
        }
        if (kind is Kind.Bytes or Kind.String)
        {
            c.LenMode = rng.Int(4);
            c.L1 = rng.Pick(0, 1, 4, 8, 16, 33, 100, 1000);
            c.L2 = allowHuge && rng.Chance(30)
                ? rng.Pick(1 << 16, (1 << 20) + 3, 1 << 22, 17 << 20)
                : rng.Pick(0, 1, 16, 255, 1000, 4096);
            c.L3 = rng.Pick(1, 10, 1000, 100_000);
            if (c.LenMode == 1 && c.L2 > (1 << 16))
                c.L2 = 1 << 12; // uniform lengths stay small; huge values come from modes 2/3
            if (c.LenMode == 3 && c.L2 > (1 << 20))
                c.L2 = allowHuge ? (1 << 20) : 4096;
        }
        if (kind is Kind.Bytes or Kind.String)
        {
            // Keep the column affordable: the columnar writer holds a row group's values in memory.
            var budget = BudgetBytes;
            while (c.EstimatedBytes(rows) > budget && (c.L2 > 16 || c.L1 > 16))
            {
                c.L2 = Math.Max(16, c.L2 / 4);
                c.L1 = Math.Min(c.L1, 16);
            }
        }
        if (kind is Kind.Double or Kind.Float && rng.Chance(30))
            c.SpecialEvery = rng.Pick(1, 2, 7, 1000, 4099);
        c.Encodings = DrawEncodings(rng, kind, optional);
        if (rng.Chance(30))
            c.Compression = rng.Pick(CompressionKind.None, CompressionKind.Snappy, CompressionKind.Gzip,
                CompressionKind.Zstd, CompressionKind.Lz4, CompressionKind.Brotli);
        c.Bloom = kind != Kind.Bool && rng.Chance(25);
        if (c.Bloom && rng.Chance(60))
        {
            c.BloomFpp = rng.Pick(0.5, 0.1, 0.01, 0.001, 1e-6);
            c.BloomNdv = rng.Chance(50) ? rng.Pick(1u, 2u, 1000u, 1u << 20, 100_000_000u) : null;
            c.BloomMaxBytes = rng.Pick(32u, 1024u, 65536u, 1u << 20, 128u << 20);
        }
        if (c.Compression is { } comp && rng.Chance(40))
            c.CompressionLevel = comp switch
            {
                CompressionKind.Zstd => rng.Pick(-5, 1, 3, 9, 19, 22),
                CompressionKind.Gzip => rng.Pick(0, 1, 6, 9),
                CompressionKind.Brotli => rng.Pick(0, 1, 5, 11),
                _ => null,
            };
        return c;
    }

    static ImmutableArray<EncodingKind> DrawEncodings(Rng rng, Kind kind, bool optional)
    {
        var choice = rng.Int(10);
        return kind switch
        {
            Kind.Int32 or Kind.Int64 => choice switch
            {
                0 or 1 => [],
                2 => [EncodingKind.Plain],
                3 => [EncodingKind.RleDictionary],
                4 => [EncodingKind.DeltaBinaryPacked],
                5 => [EncodingKind.ByteStreamSplit],
                6 => [EncodingKind.RleDictionary, EncodingKind.DeltaBinaryPacked],
                7 => [EncodingKind.PlainDictionary],
                _ => [EncodingKind.RleDictionary, EncodingKind.Plain],
            },
            Kind.Double or Kind.Float => choice switch
            {
                0 or 1 => [],
                2 => [EncodingKind.Plain],
                3 => [EncodingKind.RleDictionary],
                4 => [EncodingKind.ByteStreamSplit],
                5 => [EncodingKind.Alp],
                6 => [EncodingKind.RleDictionary, EncodingKind.ByteStreamSplit],
                7 => [EncodingKind.RleDictionary, EncodingKind.Alp],
                _ => [EncodingKind.RleDictionary, EncodingKind.Plain],
            },
            Kind.Fixed => choice switch
            {
                0 or 1 or 2 => [],
                3 => [EncodingKind.Plain],
                4 or 5 => [EncodingKind.RleDictionary],
                6 when !optional => [EncodingKind.ByteStreamSplit],
                7 => [EncodingKind.RleDictionary, EncodingKind.Plain],
                _ => [EncodingKind.PlainDictionary],
            },
            Kind.Bool => choice switch
            {
                0 or 1 or 2 => [],
                3 or 4 => [EncodingKind.Plain],
                _ => [EncodingKind.Rle],
            },
            _ => choice switch
            {
                0 or 1 => [],
                2 => [EncodingKind.Plain],
                3 => [EncodingKind.RleDictionary],
                4 => [EncodingKind.DeltaLengthByteArray],
                5 => [EncodingKind.DeltaByteArray],
                6 => [EncodingKind.RleDictionary, EncodingKind.DeltaByteArray],
                7 => [EncodingKind.RleDictionary, EncodingKind.DeltaLengthByteArray],
                _ => [EncodingKind.RleDictionary, EncodingKind.Plain],
            },
        };
    }

    public ColumnDefinition Definition()
    {
        var bloom = Bloom ? new ParquetBloomFilterOptions { FalsePositiveProbability = BloomFpp, ExpectedDistinctValueCount = BloomNdv, MaximumBytes = BloomMaxBytes } : null;
        var options = new ColumnOptions(encodings: Encodings, typeLength: Kind == Kind.Fixed ? (uint)L1 : 0, compression: Compression,
            compressionLevel: CompressionLevel, bloomFilter: bloom);
        LogicalType? logical = Kind == Kind.String ? new LogicalType.String() : null;
        return Optional
            ? ColumnDefinition.OptionalLeaf(Name, Physical, options, logical)
            : ColumnDefinition.RequiredLeaf(Name, Physical, options, logical);
    }
}
