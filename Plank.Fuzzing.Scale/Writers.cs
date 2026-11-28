using System.Text;
using Plank.Dataset;
using Plank.Schema;
using Plank.Writing;

namespace Plank.Fuzzing.Scale;

public static class Writers
{
    public static ParquetWriterOptions DrawOptions(Rng rng, long rows, int tier, bool rowApi, int columns)
    {
        // Every option independent; extremes only where the result stays affordable.
        uint page = rng.Pick(1u, 7u, 1024u, 8192u, 1u << 20, 1u << 20, (1u << 20) + 1, 16u << 20, 64u << 20, 256u << 20);
        if (page < 1024 && rows * columns > 300_000)
            page = rng.Pick(1024u, 8192u, 1u << 20);
        var o = new ParquetWriterOptions
        {
            TargetDataPageSizeBytes = page,
            WritePageIndexes = rng.Chance(80),
            WritePageCrc = rng.Chance(30),
            DataPageVersion = rng.Chance(50) ? ParquetDataPageVersion.V1 : ParquetDataPageVersion.V2,
            FileVersion = rng.Chance(50) ? ParquetFileVersion.V1 : ParquetFileVersion.V2,
            Compression = rng.Pick(CompressionKind.None, CompressionKind.None, CompressionKind.Snappy, CompressionKind.Zstd,
                CompressionKind.Gzip, CompressionKind.Lz4),
            BufferChunkSizeBytes = rng.Chance(50) ? new ParquetWriterOptions().BufferChunkSizeBytes : rng.Pick(1u, 4096u, 65536u, 1u << 20, 64u << 20),
            InitialColumnBufferBytes = rng.Chance(50) ? new ParquetWriterOptions().InitialColumnBufferBytes : rng.Pick(1u, 64u, 4096u, 1u << 20),
            InitialPageBufferBytes = rng.Chance(50) ? new ParquetWriterOptions().InitialPageBufferBytes : rng.Pick(1u, 64u, 4096u, 1u << 20),
            InitialPageCapacity = rng.Chance(50) ? new ParquetWriterOptions().InitialPageCapacity : rng.Pick(1u, 2u, 16u, 4096u),
            RowApiInitialRowCapacity = rng.Pick(1, 2, 3, 1000, 1023, 1024, 1025, 4096, 65536),
            RowApiMaxParallelism = rowApi ? rng.Pick(0u, 1u, 2u, 3u, 4u, 8u) : 0u,
            Execution = new ParquetExecutionOptions
            {
                WorkerCount = rng.Pick(1, 2, 3, 4, 8, 16),
                OnWorkerStarted = rng.Chance(30) ? _ => Jitter.Maybe() : null,
            },
            TargetRowGroupSizeBytes = rng.Pick(1UL, 1000UL, 65536UL, 1UL << 20, 16UL << 20, 128UL << 20, 1UL << 31, (1UL << 32) + 5),
            TargetFileSizeBytes = rng.Chance(80) ? 512UL << 20 : rng.Pick(1UL, 4096UL, 1UL << 20, 64UL << 20),
        };
        // The segment table is InitialColumnBufferBytes / BufferChunkSizeBytes entries: a tiny chunk with the 40 MB
        // default allocates ~1 GB per column buffer. Keep that product affordable.
        if (o.BufferChunkSizeBytes < 4096 && (o.InitialColumnBufferBytes > o.BufferChunkSizeBytes * 64 || o.InitialPageBufferBytes > o.BufferChunkSizeBytes * 64))
            o = new ParquetWriterOptions
            {
                TargetDataPageSizeBytes = o.TargetDataPageSizeBytes, WritePageIndexes = o.WritePageIndexes, WritePageCrc = o.WritePageCrc,
                DataPageVersion = o.DataPageVersion, FileVersion = o.FileVersion, Compression = o.Compression,
                BufferChunkSizeBytes = o.BufferChunkSizeBytes, InitialColumnBufferBytes = Math.Min(o.InitialColumnBufferBytes, o.BufferChunkSizeBytes * 64),
                InitialPageBufferBytes = Math.Min(o.InitialPageBufferBytes, o.BufferChunkSizeBytes * 64), InitialPageCapacity = o.InitialPageCapacity,
                RowApiInitialRowCapacity = o.RowApiInitialRowCapacity, RowApiMaxParallelism = o.RowApiMaxParallelism,
                Execution = o.Execution, TargetRowGroupSizeBytes = o.TargetRowGroupSizeBytes, TargetFileSizeBytes = o.TargetFileSizeBytes,
            };
        return o;
    }

    public static long[] DrawRowGroups(Rng rng, long rows)
    {
        var groups = (int)Math.Min(rows == 0 ? 1 : rows, rng.Pick(1, 1, 2, 3, 7, 100, 1000));
        var sizes = new long[groups];
        long left = rows;
        for (var g = 0; g < groups - 1; g++)
        {
            var share = rng.Chance(5) ? 0 : rng.Chance(30) ? Math.Min(left, rng.Pick(1L, 2047L, 2048L, 2049L, 65536L)) : left / (groups - g);
            sizes[g] = Math.Min(left, share);
            left -= sizes[g];
        }
        sizes[^1] = left;
        return sizes;
    }

    // ---------------- columnar (runtime schema) ----------------

    public static ParquetSchema Schema(ColSpec[] cols) => new([.. cols.Select(c => c.Definition())]);

    public static void Columnar(Stream output, ColSpec[] cols, long[] groups, ParquetWriterOptions options, Rng rng)
    {
        var schema = Schema(cols);
        using var writer = schema.CreateWriter(output, options);
        WriteGroups(writer, schema, cols, groups, 0, rng, options.InitialPageCapacity);
        writer.CloseFile();
    }

    /// <summary>Writes row groups of global rows [start, start + sum(groups)) into an open writer (no CloseFile).</summary>
    public static void WriteGroups(ParquetWriter writer, ParquetSchema schema, ColSpec[] cols, long[] groups, long start, Rng rng, uint initialPageCapacity = 4096)
    {
        // Columns created per row group are all kept by the writer until it is disposed (known defect,
        // fuzz/repros/serialized-column-per-row-group-retained): keep that retention affordable.
        var perGroupColumns = rng.Chance(30)
            && (double)groups.Length * cols.Length * Math.Max(4u, initialPageCapacity) * 400 < 1e9;
        var shared = new object?[cols.Length];
        foreach (var n in groups)
        {
            var rg = writer.StartRowGroup();
            for (var c = 0; c < cols.Length; c++)
            {
                var leaf = schema.LeafColumns[c];
                var spec = cols[c];
                switch (spec.Kind, spec.Optional)
                {
                    case (Kind.Int32, false): Put(writer, rg, leaf, ref shared[c], perGroupColumns, Fill(n, r => spec.Int32(start + r))); break;
                    case (Kind.Int32, true): Put(writer, rg, leaf, ref shared[c], perGroupColumns, Fill(n, r => spec.IsNull(start + r) ? (int?)null : spec.Int32(start + r))); break;
                    case (Kind.Int64, false): Put(writer, rg, leaf, ref shared[c], perGroupColumns, Fill(n, r => spec.Int64(start + r))); break;
                    case (Kind.Int64, true): Put(writer, rg, leaf, ref shared[c], perGroupColumns, Fill(n, r => spec.IsNull(start + r) ? (long?)null : spec.Int64(start + r))); break;
                    case (Kind.Double, false): Put(writer, rg, leaf, ref shared[c], perGroupColumns, Fill(n, r => spec.Double(start + r))); break;
                    case (Kind.Double, true): Put(writer, rg, leaf, ref shared[c], perGroupColumns, Fill(n, r => spec.IsNull(start + r) ? (double?)null : spec.Double(start + r))); break;
                    case (Kind.Float, false): Put(writer, rg, leaf, ref shared[c], perGroupColumns, Fill(n, r => spec.Float(start + r))); break;
                    case (Kind.Float, true): Put(writer, rg, leaf, ref shared[c], perGroupColumns, Fill(n, r => spec.IsNull(start + r) ? (float?)null : spec.Float(start + r))); break;
                    case (Kind.Bool, false): Put(writer, rg, leaf, ref shared[c], perGroupColumns, Fill(n, r => spec.Bool(start + r))); break;
                    case (Kind.Bool, true): Put(writer, rg, leaf, ref shared[c], perGroupColumns, Fill(n, r => spec.IsNull(start + r) ? (bool?)null : spec.Bool(start + r))); break;
                    case (Kind.String, _): Put(writer, rg, leaf, ref shared[c], perGroupColumns, Fill(n, r => spec.IsNull(start + r) ? null! : spec.Str(start + r))); break;
                    default: Put(writer, rg, leaf, ref shared[c], perGroupColumns, Fill(n, r => spec.IsNull(start + r) ? null : spec.Bytes(start + r))); break;
                }
            }
            start += n;
        }
    }

    static T[] Fill<T>(long n, Func<long, T> f)
    {
        var a = new T[n];
        for (long i = 0; i < n; i++)
            a[i] = f(i);
        return a;
    }

    static void Put<T>(ParquetWriter writer, RowGroupWriter rg, LeafColumn leaf, ref object? shared, bool perGroup, T[] values)
    {
        SerializedColumn<T> column;
        if (perGroup)
            column = rg.CreateSerializedColumn<T>(leaf);
        else
            column = (SerializedColumn<T>)(shared ??= writer.CreateSerializedColumn<T>(leaf));
        column.Serialize(values);
        rg.Write(column);
    }

    // ---------------- row API (generated ScaleRow) ----------------

    public static ColSpec[] ScaleRowSpecs(Rng rng, long rows, bool allowHuge)
    {
        ColSpec.BudgetBytes = ColSpec.FileBudgetBytes / 2;
        var specs = new[]
        {
            ColSpec.Draw(rng, "Id", Kind.Int64, false, rows, allowHuge),
            ColSpec.Draw(rng, "Category", Kind.Int32, false, rows, allowHuge),
            ColSpec.Draw(rng, "HighCard", Kind.Int64, true, rows, allowHuge),
            ColSpec.Draw(rng, "Measure", Kind.Double, false, rows, allowHuge),
            ColSpec.Draw(rng, "Ratio", Kind.Float, true, rows, allowHuge),
            ColSpec.Draw(rng, "Flag", Kind.Bool, false, rows, allowHuge),
            ColSpec.Draw(rng, "Payload", Kind.Bytes, true, rows, allowHuge),
            ColSpec.Draw(rng, "Label", Kind.String, false, rows, allowHuge),
        };
        // Id is the row index (dataset partitions are mapped back through it).
        specs[0].Pattern = 1; specs[0].P1 = 0; specs[0].P2 = 1;
        foreach (var s in specs)
        {
            s.Encodings = [];
            s.Compression = null;
            s.Bloom = false;
        }
        return specs;
    }

    public static ScaleRow Make(ColSpec[] s, long r) => new()
    {
        Id = s[0].Int64(r),
        Category = s[1].Int32(r),
        HighCard = s[2].IsNull(r) ? null : s[2].Int64(r),
        Measure = s[3].Double(r),
        Ratio = s[4].IsNull(r) ? null : s[4].Float(r),
        Flag = s[5].Bool(r),
        Payload = s[6].IsNull(r) ? null : s[6].Bytes(r),
        Label = s[7].Str(r),
    };

    /// <summary>Row-API write; returns the onFlush row counts when the flush-callback overload was drawn, else null.</summary>
    public static List<int>? RowApi(Stream output, ColSpec[] s, long rows, ParquetWriterOptions options, Rng rng)
    {
        var parallel = rng.Chance(30) ? rng.Pick(1u, 2u, 4u, 8u) : 0u;
        List<int>? flushes = rng.Chance(30) ? [] : null;
        Action<int>? onFlush = flushes is null ? null : count =>
        {
            Jitter.Maybe();
            lock (flushes) flushes.Add(count);
        };
        using var writer = (parallel, onFlush) switch
        {
            (0, null) => ScaleRow.CreateRowWriter(output, options),
            (0, _) => ScaleRow.CreateRowWriter(output, onFlush, options),
            (_, null) => ScaleRow.CreateRowWriter(output, parallel, options),
            _ => ScaleRow.CreateRowWriter(output, parallel, onFlush, options),
        };
        var useCursor = rng.Chance(50);
        if (useCursor)
        {
            var cursor = writer.CreateCursor();
            for (long r = 0; r < rows; r++)
            {
                cursor.NextRow();
                cursor.Id = s[0].Int64(r);
                cursor.Category = s[1].Int32(r);
                cursor.HighCard = s[2].IsNull(r) ? null : s[2].Int64(r);
                cursor.Measure = s[3].Double(r);
                cursor.Ratio = s[4].IsNull(r) ? null : s[4].Float(r);
                cursor.Flag = s[5].Bool(r);
                cursor.Payload = s[6].IsNull(r) ? null : s[6].Bytes(r);
                cursor.Label = s[7].Str(r);
            }
        }
        else
        {
            for (long r = 0; r < rows; r++)
            {
                var row = writer.GetRow();
                row.Id = s[0].Int64(r);
                row.Category = s[1].Int32(r);
                row.HighCard = s[2].IsNull(r) ? null : s[2].Int64(r);
                row.Measure = s[3].Double(r);
                row.Ratio = s[4].IsNull(r) ? null : s[4].Float(r);
                row.Flag = s[5].Bool(r);
                row.Payload = s[6].IsNull(r) ? null : s[6].Bytes(r);
                row.Label = s[7].Str(r);
            }
        }
        writer.Complete();
        return flushes;
    }

    /// <summary>Row writer with file rollover (TargetFileSizeBytes) into in-memory files; returns them in order.</summary>
    public static List<byte[]> RowApiRollover(ColSpec[] s, long rows, ParquetWriterOptions options)
    {
        var files = new MemFiles();
        var source = new MemFiles.Source(files);
        var names = new List<string>();
        ReadOnlySpan<byte> Path(ulong index, IParquetBufferPool pool, out ParquetBuffer? allocation)
        {
            allocation = null;
            var name = $"part-{index:D6}.parquet";
            lock (names) names.Add(name);
            return Encoding.UTF8.GetBytes(name);
        }
        using (var writer = ScaleRow.CreateRowWriter(Path, source, options))
        {
            for (long r = 0; r < rows; r++)
            {
                var row = writer.GetRow();
                row.Id = s[0].Int64(r);
                row.Category = s[1].Int32(r);
                row.HighCard = s[2].IsNull(r) ? null : s[2].Int64(r);
                row.Measure = s[3].Double(r);
                row.Ratio = s[4].IsNull(r) ? null : s[4].Float(r);
                row.Flag = s[5].Bool(r);
                row.Payload = s[6].IsNull(r) ? null : s[6].Bytes(r);
                row.Label = s[7].Str(r);
            }
            writer.Complete();
        }
        return [.. names.Distinct().Select(n => files.Files[n].ToArray())];
    }

    // ---------------- dataset ----------------

    public static Dictionary<string, byte[]> Dataset(ColSpec[] s, long rows, ParquetWriterOptions options, Rng rng,
        out Func<long, string> partitionOf)
    {
        var partitions = rng.Pick(1, 2, 3, 7, 64, 300);
        var open = Math.Max(1, Math.Min(partitions, rng.Pick(1, 2, 3, 8, 1000)));
        var salt = rng.Next();
        var names = Enumerable.Range(0, partitions).Select(p => Encoding.UTF8.GetBytes($"p={p:D3}/data.parquet")).ToArray();
        partitionOf = id => $"p={(int)(Rng.Mix((ulong)id ^ salt) % (ulong)partitions):D3}/data.parquet";
        var files = new MemFiles();
        var sources = Enumerable.Range(0, open).Select(_ => new MemFiles.Source(files)).ToArray();
        var datasetOptions = new DatasetWriterOptions
        {
            WriterOptions = options,
            PendingRowCapacity = rng.Pick(1u, 2u, 100u, 4095u, 4096u, 4097u, 65536u),
            AppendOptions = new ParquetAppendOptions
            {
                AppendToLatestRowGroup = rng.Chance(40),
                PreserveExistingMetadata = rng.Chance(50),
                WriterOptions = options,
            },
        };
        var sessions = rng.Pick(1, 1, 2, 3);
        long r = 0;
        for (var session = 0; session < sessions; session++)
        {
            var end = session == sessions - 1 ? rows : Math.Min(rows, r + rows / sessions);
            using var writer = ScaleRow.CreateDatasetWriter(
                (ScaleRow row, IParquetBufferPool pool, out ParquetBuffer? allocation) =>
                {
                    allocation = null;
                    return names[(int)(Rng.Mix((ulong)row.Id ^ salt) % (ulong)partitions)];
                }, sources, datasetOptions);
            for (; r < end; r++)
                writer.Queue(Make(s, r));
        }
        foreach (var source in sources)
            source.Dispose();
        return files.Files.ToDictionary(kv => kv.Key, kv => kv.Value.ToArray());
    }
}
