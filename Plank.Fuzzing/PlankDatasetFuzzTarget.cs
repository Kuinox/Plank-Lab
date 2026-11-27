using System.Text;
using Plank.Dataset;
using Plank.Reading;

namespace Plank.Fuzzing;

/// <summary>
/// Routes fuzzed rows through the generated partitioned dataset writer, then
/// reads every partition back and checks the routing held.
/// </summary>
/// <remarks>
/// DatasetWriterBase measured 0/455 lines — the largest single untouched body of
/// code on the write side. It was unreachable for a structural reason rather
/// than a missing seed: it is the only writer that owns *files*, naming and
/// opening one per partition, so driving it appeared to require hitting the
/// filesystem tens of thousands of times a second. InMemoryDatasetFiles removes
/// that, keeping the path construction, partition bookkeeping, create-vs-append
/// choice and file pooling under test.
///
/// The oracle is the routing invariant, which is what this writer is *for*:
/// every row must land in the partition its key names, and no row may be lost or
/// duplicated. Both are checked by reading each partition back through the
/// generated reader.
/// </remarks>
public static class PlankDatasetFuzzTarget
{
    const int MaxRows = 64;

    // Few enough partitions that rows collide and files get appended to rather
    // than written once, which is where the interesting bookkeeping is.
    const int MaxPartitions = 4;

    public static void Execute(ReadOnlySpan<byte> data)
    {
        if (data.Length < 2)
            return;

        // No blanket filter: the only rejected input is the deliberate empty rollover path,
        // handled in Run. Any other exception is a library finding.
        Run(data);
    }

    static void Run(ReadOnlySpan<byte> data)
    {
        var partitions = (data[0] % MaxPartitions) + 1;
        var createParts = (data[0] & 0x80) != 0;
        var failRolloverPath = createParts && (data[0] & 0x40) != 0;
        var offsetOwnedPath = (data[0] & 0x20) != 0;
        var cursor = new Cursor(data[1..]);
        var count = cursor.NextInt(1, MaxRows + 1);

        var rows = new (int Id, long Sequence)[count];
        for (var i = 0; i < count; i++)
            rows[i] = (cursor.NextInt32(), cursor.NextInt64());

        // The key is derived from the row, so the expected partition of every row
        // is known independently of what the writer did with it.
        var store = new InMemoryFileStore();
        var files = new InMemoryDatasetFile[Math.Max(1, cursor.NextInt(1, 4))];
        for (var i = 0; i < files.Length; i++)
            files[i] = new InMemoryDatasetFile(store);

        // Small enough that a 64-row case flushes more than once, which is the
        // only way to reach the append path rather than a single create.
        var pending = createParts ? 0 : (uint)cursor.NextInt(1, 17);
        // Read after the original draws so existing seeds keep their meaning. Capacity, row-group
        // size and the append options are independent of the row count and of each other.
        var capacity = cursor.NextInt(1, 9);
        var rowGroupBytes = cursor.NextInt(0, 3) switch { 0 => 1UL, 1 => 64UL, _ => 128UL * 1024 * 1024 };
        var append = new Plank.Writing.ParquetAppendOptions
        {
            PreserveExistingMetadata = cursor.NextInt(0, 2) == 0,
            AppendToLatestRowGroup = cursor.NextInt(0, 2) == 0
        };
        var writerOptions = new Plank.Writing.ParquetWriterOptions
        {
            RowApiInitialRowCapacity = capacity,
            TargetRowGroupSizeBytes = createParts ? 1 : rowGroupBytes,
            TargetFileSizeBytes = createParts ? 1 : 512UL * 1024 * 1024
        };
        var options = new DatasetWriterOptions
        {
            PendingRowCapacity = pending,
            AppendOptions = append,
            WriterOptions = writerOptions
        };

        RowFuzzFixed.Route route = (RowFuzzFixed row, IParquetBufferPool pool,
            out ParquetBuffer? allocation) =>
        {
            var key = KeyFor(PartitionOf(row.Id, partitions));
            if (!offsetOwnedPath)
            {
                allocation = null;
                return key;
            }

            // Exercise DatasetWriterBase's retained-slice ownership path. Keep a
            // prefix so the returned span begins inside the allocated buffer.
            var owner = pool.Rent(checked((uint)(key.Length + 1)));
            allocation = owner;
            key.CopyTo(owner.Span[1..]);
            return owner.Span[1..(key.Length + 1)];
        };
        DatasetFilePath filePath = (ReadOnlySpan<byte> key, ulong index, IParquetBufferPool pool,
            out ParquetBuffer? allocation) =>
        {
            allocation = null;
            if (failRolloverPath && index > 0)
                return ReadOnlySpan<byte>.Empty;
            return Encoding.UTF8.GetBytes($"{Encoding.UTF8.GetString(key)}-{index}");
        };
        try
        {
            using var writer = createParts
                ? RowFuzzFixed.CreateDatasetWriter(route, filePath, files, options)
                : RowFuzzFixed.CreateDatasetWriter(route, files, options);
            foreach (var (id, sequence) in rows)
                writer.Queue(new RowFuzzFixed { Id = id, Sequence = sequence, Flag = false, Measure = 0 });
        }
        catch (InvalidOperationException exception) when (failRolloverPath
            && exception.Message == "The dataset file path selector returned an empty path.")
        {
            // Invalid input on purpose: a selector that returns an empty path for the second file part.
            return;
        }

        VerifyRouting(store, rows, partitions, createParts);
    }

    // Stable, and independent of the writer: a negative Id must not produce a
    // negative index, which is why this masks rather than taking a remainder.
    static int PartitionOf(int id, int partitions)
        => (id & int.MaxValue) % partitions;

    static readonly byte[][] Keys =
        [.. Enumerable.Range(0, MaxPartitions).Select(static i => Encoding.UTF8.GetBytes($"p{i}"))];

    static ReadOnlySpan<byte> KeyFor(int partition)
        => Keys[partition];

    static void VerifyRouting(InMemoryFileStore store, (int Id, long Sequence)[] rows, int partitions,
        bool createParts)
    {
        var seen = 0;
        var remaining = new Dictionary<(int Id, long Sequence), int>();
        for (var i = 0; i < rows.Length; i++)
        {
            var row = rows[i];
            remaining.TryGetValue(row, out var occurrences);
            remaining[row] = occurrences + 1;
        }

        var byPartition = new Dictionary<int, List<(ulong Part, List<(int Id, long Sequence)> Rows)>>();
        var partIndices = new List<ulong>();
        foreach (var (path, file) in store.Files)
        {
            if (file.Length == 0)
                continue;

            // Which partition this file belongs to is read back out of its own
            // path, so a writer that put rows in the wrong file is caught rather
            // than trusted.
            var partition = PartitionFromPath(path, partitions);
            if (partition < 0)
                throw new DatasetRoutingException($"Partition file '{path}' names no known key.");

            if (!byPartition.TryGetValue(partition, out var parts))
                byPartition.Add(partition, parts = []);
            var partIndex = PartIndexFromPath(path);
            partIndices.Add(partIndex);
            parts.Add((partIndex, ReadSequences(file)));

            using var reader = RowFuzzFixed.CreateRowReader(
                new MemoryStream(FullValueOracle.Checked(file.ToArray()), writable: false));
            while (reader.MoveNext())
            {
                var row = (reader.Current.Id, reader.Current.Sequence);
                var actual = PartitionOf(row.Id, partitions);
                if (actual != partition)
                    throw new DatasetRoutingException(
                        $"Row with Id {row.Id} belongs in partition {actual} but was written to '{path}' (partition {partition}).");
                if (!remaining.TryGetValue(row, out var occurrences) || occurrences == 0)
                    throw new DatasetRoutingException(
                        $"Unexpected or duplicated row ({row.Id}, {row.Sequence}) was read from '{path}'.");
                remaining[row] = occurrences - 1;
                seen++;
            }
        }

        if (seen != rows.Length)
            throw new DatasetRoutingException(
                $"Dataset round trip returned {seen} rows but {rows.Length} were queued.");
        if (remaining.Values.Any(static count => count != 0))
            throw new DatasetRoutingException("Dataset round trip did not return every queued row.");

        if (createParts)
        {
            partIndices.Sort();
            for (var i = 0; i < partIndices.Count; i++)
                if (partIndices[i] != (ulong)i)
                    throw new DatasetRoutingException("Dataset part indices are not contiguous.");

            for (var partition = 0; partition < partitions; partition++)
            {
                var actual = byPartition.GetValueOrDefault(partition) ?? [];
                actual.Sort(static (left, right) => left.Part.CompareTo(right.Part));
                var expected = rows.Where(row => PartitionOf(row.Id, partitions) == partition).ToArray();
                var sequenceIndex = 0;
                foreach (var part in actual)
                {
                    foreach (var row in part.Rows)
                    {
                        if (sequenceIndex >= expected.Length || expected[sequenceIndex++] != row)
                            throw new DatasetRoutingException("Dataset file parts changed per-partition row order.");
                    }
                }
                if (sequenceIndex != expected.Length)
                    throw new DatasetRoutingException("Dataset file parts omitted per-partition rows.");
            }
        }
    }

    static List<(int Id, long Sequence)> ReadSequences(MemoryStream file)
    {
        var rows = new List<(int Id, long Sequence)>();
        using var reader = RowFuzzFixed.CreateRowReader(new MemoryStream(FullValueOracle.Checked(file.ToArray()), writable: false));
        while (reader.MoveNext())
            rows.Add((reader.Current.Id, reader.Current.Sequence));
        return rows;
    }

    static ulong PartIndexFromPath(string path)
    {
        var separator = path.LastIndexOf('-');
        return separator >= 0 && ulong.TryParse(path.AsSpan(separator + 1), out var index) ? index : 0;
    }

    static int PartitionFromPath(string path, int partitions)
    {
        for (var i = 0; i < partitions; i++)
            if (path.Contains($"p{i}", StringComparison.Ordinal))
                return i;
        return -1;
    }

    /// <summary>Signals that the dataset writer lost, duplicated or misrouted a row.</summary>
    public sealed class DatasetRoutingException(string message) : Exception(message);

    ref struct Cursor(ReadOnlySpan<byte> data)
    {
        readonly ReadOnlySpan<byte> _data = data;
        int _offset;

        byte NextByte()
            => _offset < _data.Length ? _data[_offset++] : (byte)0;

        internal int NextInt(int minInclusive, int maxExclusive)
        {
            var range = maxExclusive - minInclusive;
            return range <= 0 ? minInclusive : minInclusive + (NextByte() % range);
        }

        internal int NextInt32()
            => (NextByte() << 24) | (NextByte() << 16) | (NextByte() << 8) | NextByte();

        internal long NextInt64()
            => ((long)NextInt32() << 32) | (uint)NextInt32();
    }
}
