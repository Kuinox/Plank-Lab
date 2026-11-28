using Ps = ParquetSharp;

namespace Plank.Fuzzing.Scale;

/// <summary>
/// Large files written by Arrow C++ (ParquetSharp) with drawn writer properties — small dictionary page limits so
/// the dictionary falls back to PLAIN in the middle of a chunk, tiny or huge data pages, small write batches, DELTA / BSS
/// encodings, v1/v2 pages, page index, checksums — then read with every Plank read API (Plank's reader on page layouts its
/// own writer never produces).
/// </summary>
public static class ArrowWrite
{
    public static void Write(string path, ColSpec[] cols, long[] groups, Rng rng, List<string> describe)
    {
        var columns = cols.Select(ToColumn).ToArray();
        var b = new Ps.WriterPropertiesBuilder()
            .Compression(rng.Pick(Ps.Compression.Uncompressed, Ps.Compression.Snappy, Ps.Compression.Zstd, Ps.Compression.Gzip, Ps.Compression.Lz4))
            .DataPagesize(rng.Pick(1L, 64L, 1024L, 8192L, 1L << 20, 16L << 20))
            .DictionaryPagesizeLimit(rng.Pick(1L, 256L, 4096L, 65536L, 1L << 20))
            .WriteBatchSize(rng.Pick(1L, 7L, 1024L, 65536L))
            .MaxRowGroupLength(long.MaxValue)
            .DataPageVersion(rng.Chance(50) ? Ps.ParquetDataPageVersion.V1 : Ps.ParquetDataPageVersion.V2);
        if (rng.Chance(70)) b = b.EnableWritePageIndex(); else b = b.DisableWritePageIndex();
        if (rng.Chance(30)) b = b.EnablePageChecksum();
        if (rng.Chance(20)) b = b.DisableStatistics();
        var encodings = new List<string>();
        foreach (var c in cols)
        {
            var e = ArrowEncoding(c, rng);
            encodings.Add($"{c.Name}={e?.ToString() ?? "dict"}");
            if (e is { } enc)
                b = b.DisableDictionary(c.Name).Encoding(c.Name, enc);
            else
                b = b.EnableDictionary(c.Name);
        }
        describe.Add("arrow encodings: " + string.Join(" ", encodings));
        using var props = b.Build();
        using var writer = new Ps.ParquetFileWriter(path, columns, props);
        long start = 0;
        foreach (var n in groups)
        {
            using var rg = writer.AppendRowGroup();
            for (var i = 0; i < cols.Length; i++)
            {
                using var column = rg.NextColumn();
                WriteColumn(column, cols[i], start, n, rng);
            }
            start += n;
        }
        writer.Close();
    }

    static Ps.Encoding? ArrowEncoding(ColSpec c, Rng rng)
    {
        var pick = rng.Int(4);
        if (pick == 0) return null; // dictionary (with fallback when the dictionary page limit is reached)
        if (pick == 1 || c.Kind == Kind.Bool) return Ps.Encoding.Plain;
        return c.Kind switch
        {
            Kind.Int32 or Kind.Int64 => rng.Chance(70) ? Ps.Encoding.DeltaBinaryPacked : Ps.Encoding.ByteStreamSplit,
            Kind.Double or Kind.Float => Ps.Encoding.ByteStreamSplit,
            _ => rng.Chance(50) ? Ps.Encoding.DeltaLengthByteArray : Ps.Encoding.DeltaByteArray,
        };
    }

    static Ps.Column ToColumn(ColSpec c) => (c.Kind, c.Optional) switch
    {
        (Kind.Int32, false) => new Ps.Column<int>(c.Name),
        (Kind.Int32, true) => new Ps.Column<int?>(c.Name),
        (Kind.Int64, false) => new Ps.Column<long>(c.Name),
        (Kind.Int64, true) => new Ps.Column<long?>(c.Name),
        (Kind.Double, false) => new Ps.Column<double>(c.Name),
        (Kind.Double, true) => new Ps.Column<double?>(c.Name),
        (Kind.Float, false) => new Ps.Column<float>(c.Name),
        (Kind.Float, true) => new Ps.Column<float?>(c.Name),
        (Kind.Bool, false) => new Ps.Column<bool>(c.Name),
        (Kind.Bool, true) => new Ps.Column<bool?>(c.Name),
        // ParquetSharp's string and byte[] columns are nullable by default; the required forms use explicit nodes.
        (Kind.String, _) => new Ps.Column<string>(c.Name),
        _ => new Ps.Column<byte[]>(c.Name),
    };

    static void WriteColumn(Ps.ColumnWriter column, ColSpec s, long start, long n, Rng rng)
    {
        var batch = (int)Math.Max(1, Math.Min(n, rng.Pick(1L, 3L, 1000L, 65536L, n)));
        switch (s.Kind, s.Optional)
        {
            case (Kind.Int32, false): All(column, n, batch, r => s.Int32(start + r)); break;
            case (Kind.Int32, true): All(column, n, batch, r => s.IsNull(start + r) ? (int?)null : s.Int32(start + r)); break;
            case (Kind.Int64, false): All(column, n, batch, r => s.Int64(start + r)); break;
            case (Kind.Int64, true): All(column, n, batch, r => s.IsNull(start + r) ? (long?)null : s.Int64(start + r)); break;
            case (Kind.Double, false): All(column, n, batch, r => s.Double(start + r)); break;
            case (Kind.Double, true): All(column, n, batch, r => s.IsNull(start + r) ? (double?)null : s.Double(start + r)); break;
            case (Kind.Float, false): All(column, n, batch, r => s.Float(start + r)); break;
            case (Kind.Float, true): All(column, n, batch, r => s.IsNull(start + r) ? (float?)null : s.Float(start + r)); break;
            case (Kind.Bool, false): All(column, n, batch, r => s.Bool(start + r)); break;
            case (Kind.Bool, true): All(column, n, batch, r => s.IsNull(start + r) ? (bool?)null : s.Bool(start + r)); break;
            case (Kind.String, _): All(column, n, batch, r => s.IsNull(start + r) ? null! : s.Str(start + r)); break;
            default: All(column, n, batch, r => s.IsNull(start + r) ? null! : s.Bytes(start + r)); break;
        }
    }

    static void All<T>(Ps.ColumnWriter column, long n, int batch, Func<long, T> value)
    {
        using var writer = column.LogicalWriter<T>();
        for (long off = 0; off < n; off += batch)
        {
            var m = (int)Math.Min(batch, n - off);
            var a = new T[m];
            for (var i = 0; i < m; i++) a[i] = value(off + i);
            writer.WriteBatch(a);
        }
    }

}
