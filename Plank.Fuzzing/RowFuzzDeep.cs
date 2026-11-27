using Plank.Schema;

namespace Plank.Fuzzing;

/// <summary>A nested record carrying a required record, a string and a decimal (groups cannot hold collections or a second optional boundary).</summary>
public sealed record RowFuzzOuter
{
    public RowFuzzAddress Home { get; init; } = new();

    public string Note { get; init; } = string.Empty;

    [ParquetColumn(Precision = 12, Scale = 3)]
    public decimal Balance { get; init; }
}

/// <summary>A record of scalar properties only: the shape allowed as a list element.</summary>
public sealed record RowFuzzMixed
{
    public int A { get; init; }

    public long B { get; init; }

    public string C { get; init; } = string.Empty;

    public Guid D { get; init; }

    public double E { get; init; }

    public bool F { get; init; }

    public byte G { get; init; }

    public DateOnly H { get; init; }
}

/// <summary>
/// Collection, map and record shapes beyond RowFuzzNested: required lists, nullable arrays, arrays of
/// lists, maps with string keys and list values, records nested in records and in lists, nested decimals
/// and binary leaves. Driven by the same generated routes as the wide schemas (see RowFuzzDeepOps).
/// </summary>
[ParquetSchema(AllowAllocatingValues = true)]
public sealed partial class RowFuzzDeep
{
    public int Seq { get; set; }

    public List<int> Ints { get; set; } = [];

    public int?[]? Array { get; set; }

    public string?[][]? Grid { get; set; }

    public Dictionary<string, int?>? Lookup { get; set; }

    public Dictionary<long, double>? Series { get; set; }

    public RowFuzzOuter? Outer { get; set; }

    public List<RowFuzzMixed>? Outers { get; set; }

    public Guid[] Ids { get; set; } = [];

    public List<byte[]?>? Blobs { get; set; }

    public List<bool> Flags { get; set; } = [];

    public float?[]? Floats { get; set; }

    public List<long?>? Longs { get; set; }

    public List<ReadOnlyMemory<byte>?>? Mems { get; set; }
}

static class RowFuzzDeepOps
{
    internal const int ColumnCount = 14;

    internal static RowFuzzDeep Generate(ref PlankRowApiFuzzTarget.Cursor c, int seq)
    {
        var v = new RowFuzzDeep { Seq = seq };
        var n = c.NextInt(0, 5);
        v.Ints = [];
        for (var i = 0; i < n; i++)
            v.Ints.Add(c.NextInt32());
        v.Array = c.NextInt(0, 4) == 0 ? null : NewArray(ref c, static (ref PlankRowApiFuzzTarget.Cursor k) => k.NextInt(0, 3) == 0 ? (int?)null : k.NextInt32());
        if (c.NextInt(0, 4) != 0)
        {
            v.Grid = new string?[c.NextInt(0, 4)][];
            for (var i = 0; i < v.Grid.Length; i++)
                v.Grid[i] = null!;
            for (var i = 0; i < v.Grid.Length; i++)
                v.Grid[i] = NewArray(ref c, static (ref PlankRowApiFuzzTarget.Cursor k) => k.NextInt(0, 3) == 0 ? null : k.NextLabel());
        }
        if (c.NextInt(0, 4) != 0)
        {
            v.Lookup = [];
            for (var i = c.NextInt(0, 4); i > 0; i--)
                v.Lookup["k" + c.NextInt(0, 50)] = c.NextInt(0, 3) == 0 ? null : c.NextInt32();
        }
        if (c.NextInt(0, 4) != 0)
        {
            v.Series = [];
            for (var i = c.NextInt(0, 4); i > 0; i--)
                v.Series[c.NextInt64()] = c.NextDouble();
        }
        v.Outer = c.NextInt(0, 3) == 0 ? null : NewOuter(ref c);
        if (c.NextInt(0, 4) != 0)
        {
            v.Outers = [];
            for (var i = c.NextInt(0, 4); i > 0; i--)
                v.Outers.Add(new RowFuzzMixed
                {
                    A = c.NextInt32(),
                    B = c.NextInt64(),
                    C = c.NextLabel(),
                    D = c.NextGuid(),
                    E = c.NextDouble(),
                    F = c.NextBool(),
                    G = (byte)c.NextInt32(),
                    H = c.NextDate()
                });
        }
        v.Ids = NewArray(ref c, static (ref PlankRowApiFuzzTarget.Cursor k) => k.NextGuid());
        if (c.NextInt(0, 4) != 0)
        {
            v.Blobs = [];
            for (var i = c.NextInt(0, 4); i > 0; i--)
                v.Blobs.Add(c.NextInt(0, 3) == 0 ? null : c.NextBytes(12));
        }
        v.Flags = [];
        for (var i = c.NextInt(0, 5); i > 0; i--)
            v.Flags.Add(c.NextBool());
        v.Floats = c.NextInt(0, 4) == 0 ? null : NewArray(ref c, static (ref PlankRowApiFuzzTarget.Cursor k) => k.NextInt(0, 3) == 0 ? (float?)null : BitConverter.Int32BitsToSingle(k.NextInt32()));
        if (c.NextInt(0, 4) != 0)
        {
            v.Longs = [];
            for (var i = c.NextInt(0, 5); i > 0; i--)
                v.Longs.Add(c.NextInt(0, 3) == 0 ? null : c.NextInt64());
        }
        if (c.NextInt(0, 4) != 0)
        {
            v.Mems = [];
            for (var i = c.NextInt(0, 4); i > 0; i--)
                v.Mems.Add(c.NextInt(0, 3) == 0 ? null : new ReadOnlyMemory<byte>(c.NextBytes(10)));
        }
        return v;
    }

    delegate T Make<T>(ref PlankRowApiFuzzTarget.Cursor c);

    static T[] NewArray<T>(ref PlankRowApiFuzzTarget.Cursor c, Make<T> make)
    {
        var items = new T[c.NextInt(0, 5)];
        for (var i = 0; i < items.Length; i++)
            items[i] = make(ref c);
        return items;
    }

    static RowFuzzOuter NewOuter(ref PlankRowApiFuzzTarget.Cursor c)
    {
        return new RowFuzzOuter
        {
            Home = new RowFuzzAddress
            {
                Zip = c.NextInt32(),
                Rank = (byte)c.NextInt32(),
                City = c.NextLabel(),
                Token = c.NextGuid()
            },
            Note = c.NextLabel(),
            Balance = c.NextDecimal(12, 3)
        };
    }

    internal static void Set(RowFuzzDeep.Row r, RowFuzzDeep v)
    {
        r.Seq = v.Seq;
        r.Ints = v.Ints;
        r.Array = v.Array;
        r.Grid = v.Grid;
        r.Lookup = v.Lookup;
        r.Series = v.Series;
        r.Outer = v.Outer;
        r.Outers = v.Outers;
        r.Ids = v.Ids;
        r.Blobs = v.Blobs;
        r.Flags = v.Flags;
        r.Floats = v.Floats;
        r.Longs = v.Longs;
        r.Mems = v.Mems;
    }

    internal static void SetCursor(ref RowFuzzDeep.RowCursor r, RowFuzzDeep v)
    {
        r.NextRow();
        r.Seq = v.Seq;
        r.Ints = v.Ints;
        r.Array = v.Array;
        r.Grid = v.Grid;
        r.Lookup = v.Lookup;
        r.Series = v.Series;
        r.Outer = v.Outer;
        r.Outers = v.Outers;
        r.Ids = v.Ids;
        r.Blobs = v.Blobs;
        r.Flags = v.Flags;
        r.Floats = v.Floats;
        r.Longs = v.Longs;
        r.Mems = v.Mems;
    }

    internal static RowFuzzDeep.Projection Project(int mask)
    {
        var p = RowFuzzDeep.Projection.None;
        if ((mask & 1) != 0) p |= RowFuzzDeep.Projection.Seq;
        if ((mask & 2) != 0) p |= RowFuzzDeep.Projection.Ints;
        if ((mask & 4) != 0) p |= RowFuzzDeep.Projection.Array;
        if ((mask & 8) != 0) p |= RowFuzzDeep.Projection.Grid;
        if ((mask & 16) != 0) p |= RowFuzzDeep.Projection.Lookup;
        if ((mask & 32) != 0) p |= RowFuzzDeep.Projection.Series;
        if ((mask & 64) != 0) p |= RowFuzzDeep.Projection.Outer;
        if ((mask & 128) != 0) p |= RowFuzzDeep.Projection.Outers;
        if ((mask & 256) != 0) p |= RowFuzzDeep.Projection.Ids;
        if ((mask & 512) != 0) p |= RowFuzzDeep.Projection.Blobs;
        if ((mask & 1024) != 0) p |= RowFuzzDeep.Projection.Flags;
        if ((mask & 2048) != 0) p |= RowFuzzDeep.Projection.Floats;
        if ((mask & 4096) != 0) p |= RowFuzzDeep.Projection.Longs;
        if ((mask & 8192) != 0) p |= RowFuzzDeep.Projection.Mems;
        return p;
    }

    internal static string? Compare(RowFuzzDeep.ReadRow r, RowFuzzDeep v, int mask)
    {
        if ((mask & 1) != 0 && r.Seq != v.Seq) return "Seq";
        if ((mask & 2) != 0 && !SeqEq(r.Ints, v.Ints)) return "Ints";
        if ((mask & 4) != 0 && !SeqEq(r.Array, v.Array)) return "Array";
        if ((mask & 8) != 0 && !GridEq(r.Grid, v.Grid)) return "Grid";
        if ((mask & 16) != 0 && !DictEq(r.Lookup, v.Lookup)) return "Lookup";
        if ((mask & 32) != 0 && !SeriesEq(r.Series, v.Series)) return "Series";
        if ((mask & 64) != 0 && !OuterEq(r.Outer, v.Outer)) return "Outer";
        if ((mask & 128) != 0 && !ListEq(r.Outers, v.Outers, MixedEq)) return "Outers";
        if ((mask & 256) != 0 && !SeqEq(r.Ids, v.Ids)) return "Ids";
        if ((mask & 512) != 0 && !ListEq(r.Blobs, v.Blobs, static (a, b) => a is null ? b is null : b is not null && a.AsSpan().SequenceEqual(b))) return "Blobs";
        if ((mask & 1024) != 0 && !SeqEq(r.Flags, v.Flags)) return "Flags";
        if ((mask & 2048) != 0 && !FloatsEq(r.Floats, v.Floats)) return "Floats";
        if ((mask & 4096) != 0 && !SeqEq(r.Longs, v.Longs)) return "Longs";
        if ((mask & 8192) != 0 && !ListEq(r.Mems, v.Mems, static (a, b) => a is null ? b is null : b is not null && a.Value.Span.SequenceEqual(b.Value.Span))) return "Mems";
        return null;
    }

    static bool SeqEq<T>(IEnumerable<T>? a, IEnumerable<T>? b)
        => a is null ? b is null : b is not null && a.SequenceEqual(b);

    static bool ListEq<T>(IReadOnlyList<T>? a, IReadOnlyList<T>? b, Func<T, T, bool> eq)
    {
        if (a is null || b is null)
            return a is null && b is null;
        if (a.Count != b.Count)
            return false;
        for (var i = 0; i < a.Count; i++)
            if (!eq(a[i], b[i]))
                return false;
        return true;
    }

    static bool FloatsEq(float?[]? a, float?[]? b)
        => ListEq(a, b, static (x, y) => x is null ? y is null : y is not null
            && BitConverter.SingleToInt32Bits(x.Value) == BitConverter.SingleToInt32Bits(y.Value));

    static bool GridEq(string?[][]? a, string?[][]? b)
        => ListEq(a, b, static (x, y) => ListEq(x, y, static (p, q) => string.Equals(p, q, StringComparison.Ordinal)));

    static bool DictEq(Dictionary<string, int?>? a, Dictionary<string, int?>? b)
    {
        if (a is null || b is null)
            return a is null && b is null;
        return a.Count == b.Count && a.All(p => b.TryGetValue(p.Key, out var o) && o == p.Value);
    }

    static bool SeriesEq(Dictionary<long, double>? a, Dictionary<long, double>? b)
    {
        if (a is null || b is null)
            return a is null && b is null;
        return a.Count == b.Count && a.All(p => b.TryGetValue(p.Key, out var o)
            && BitConverter.DoubleToInt64Bits(o) == BitConverter.DoubleToInt64Bits(p.Value));
    }

    static bool MixedEq(RowFuzzMixed a, RowFuzzMixed b)
        => a.A == b.A && a.B == b.B && string.Equals(a.C, b.C, StringComparison.Ordinal) && a.D == b.D
            && BitConverter.DoubleToInt64Bits(a.E) == BitConverter.DoubleToInt64Bits(b.E)
            && a.F == b.F && a.G == b.G && a.H == b.H;

    static bool OuterEq(RowFuzzOuter? a, RowFuzzOuter? b)
    {
        if (a is null || b is null)
            return a is null && b is null;
        return a.Home == b.Home
            && string.Equals(a.Note, b.Note, StringComparison.Ordinal) && a.Balance == b.Balance;
    }
}
