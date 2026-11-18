using Plank;
using Plank.Dataset;
using Plank.Reading;
using Plank.RowApi;
using Plank.Writing;

namespace Plank.Fuzzing;

/// <summary>Exercises dataset snapshots for binary and memory-backed row values.</summary>
public static class PlankDatasetBinaryFuzzTarget
{
    const int NestedRowCount = 12;
    const int ScalarRowCount = 4;
    const int PendingRowCapacity = 3;
    const int PartitionCount = 3;

    static readonly byte[][] PartitionKeys = ["p0"u8.ToArray(), "p1"u8.ToArray(), "p2"u8.ToArray()];
    static readonly byte[] ScalarKey = "scalar"u8.ToArray();

    /// <summary>Executes two bounded generated-writer scenarios from a marker payload.</summary>
    public static void Execute(ReadOnlySpan<byte> data)
    {
        var salt = Fold(data);
        RunNestedBinaryRows(salt);
        RunScalarMemoryRows(salt);
    }

    static void RunNestedBinaryRows(byte salt)
    {
        var store = new InMemoryFileStore();
        using var file = new InMemoryDatasetFile(store);
        var writerOptions = new ParquetWriterOptions { RowApiInitialRowCapacity = 1 };
        var options = new DatasetWriterOptions
        {
            PendingRowCapacity = PendingRowCapacity,
            WriterOptions = writerOptions,
            AppendOptions = new ParquetAppendOptions { WriterOptions = writerOptions }
        };
        var expected = new (int Id, byte Value, int Ordinal)[NestedRowCount];
        RowFuzzDatasetBinary.Route route = static (RowFuzzDatasetBinary row,
            IParquetBufferPool bufferPool, out ParquetBuffer? allocation) =>
        {
            allocation = null;
            return PartitionKeys[row.Id % PartitionCount];
        };

        using (var writer = RowFuzzDatasetBinary.CreateDatasetWriter(route, [file], options))
        {
            var reused = new byte[4];
            for (var ordinal = 0; ordinal < NestedRowCount; ordinal++)
            {
                var id = salt + ordinal;
                var value = unchecked((byte)(salt + ordinal * 17));
                Array.Fill(reused, value);
                expected[ordinal] = (id, value, ordinal);
                writer.Queue(new RowFuzzDatasetBinary
                {
                    Id = id,
                    Payload = reused,
                    OptionalPayload = ordinal % 2 == 0 ? null : reused,
                    Items = (ordinal % 3) switch
                    {
                        0 => null,
                        1 => [],
                        _ => [reused, null, []]
                    },
                    Matrix = [[reused], [], [reused]],
                    Memories = [reused.AsMemory(1, 2), ReadOnlyMemory<byte>.Empty],
                    OptionalMemories = (ordinal % 3) switch
                    {
                        0 => null,
                        1 => [],
                        _ => [reused.AsMemory(1, 2), (ReadOnlyMemory<byte>?)null, ReadOnlyMemory<byte>.Empty]
                    }
                });
            }
        }

        VerifyNestedBinaryRows(store, expected);
    }

    static void VerifyNestedBinaryRows(InMemoryFileStore store,
        (int Id, byte Value, int Ordinal)[] expected)
    {
        var byId = expected.ToDictionary(static row => row.Id);
        var seen = new HashSet<int>();
        foreach (var (path, file) in store.Files)
        {
            if (file.Length == 0)
                continue;
            var partition = PartitionFromPath(path);
            if (partition < 0)
                throw new DatasetSnapshotException($"Unknown dataset partition path '{path}'.");

            using var reader = RowFuzzDatasetBinary.CreateRowReader(
                new MemoryStream(file.ToArray(), writable: false));
            while (reader.MoveNext())
            {
                var row = reader.Current;
                if (!byId.TryGetValue(row.Id, out var expectedRow) || !seen.Add(row.Id))
                    throw new DatasetSnapshotException($"Unexpected or repeated dataset row {row.Id}.");
                if (row.Id % PartitionCount != partition)
                    throw new DatasetSnapshotException($"Dataset row {row.Id} was written to the wrong partition.");

                var payload = Repeated(expectedRow.Value);
                RequireBinary(row.Payload, payload, $"payload for {row.Id}");
                if (expectedRow.Ordinal % 2 == 0)
                {
                    if (!row.OptionalPayload.IsNull)
                        throw new DatasetSnapshotException($"Optional payload for {row.Id} became present.");
                }
                else
                {
                    RequireBinary(row.OptionalPayload, payload, $"optional payload for {row.Id}");
                }

                var items = row.Items;
                switch (expectedRow.Ordinal % 3)
                {
                    case 0 when items is null:
                        break;
                    case 1 when items is { Count: 0 }:
                        break;
                    case 2 when items is { Count: 3 } && items[1] is null && items[2] is { Length: 0 }:
                        RequireBytes(items[0], payload, $"list payload for {row.Id}");
                        break;
                    default:
                        throw new DatasetSnapshotException($"Nested binary list changed for row {row.Id}.");
                }

                var matrix = row.Matrix;
                if (matrix is not { Count: 3 } || matrix[0] is not { Count: 1 } ||
                    matrix[1] is not { Count: 0 } || matrix[2] is not { Count: 1 })
                    throw new DatasetSnapshotException($"Nested binary matrix shape changed for row {row.Id}.");
                RequireBytes(matrix[0][0], payload, $"matrix payload for {row.Id}");
                RequireBytes(matrix[2][0], payload, $"matrix payload for {row.Id}");

                var memories = row.Memories;
                if (memories is not { Length: 2 } || !memories[1].IsEmpty ||
                    !memories[0].Span.SequenceEqual(payload.AsSpan(1, 2)))
                    throw new DatasetSnapshotException($"Binary memory array changed for row {row.Id}.");

                var optionalMemories = row.OptionalMemories;
                switch (expectedRow.Ordinal % 3)
                {
                    case 0 when optionalMemories is null:
                        break;
                    case 1 when optionalMemories is { Length: 0 }:
                        break;
                    case 2 when optionalMemories is { Length: 3 } && optionalMemories[0].HasValue &&
                                   !optionalMemories[1].HasValue && optionalMemories[2] is { IsEmpty: true }:
                        if (!optionalMemories[0]!.Value.Span.SequenceEqual(payload.AsSpan(1, 2)))
                            throw new DatasetSnapshotException($"Optional memory payload changed for row {row.Id}.");
                        break;
                    default:
                        throw new DatasetSnapshotException($"Optional memory shape changed for row {row.Id}.");
                }
            }
        }

        if (seen.Count != expected.Length)
            throw new DatasetSnapshotException($"Dataset round trip returned {seen.Count} of {expected.Length} rows.");
    }

    static void RunScalarMemoryRows(byte salt)
    {
        var store = new InMemoryFileStore();
        using var file = new InMemoryDatasetFile(store);
        var options = new DatasetWriterOptions
        {
            PendingRowCapacity = 0,
            WriterOptions = new ParquetWriterOptions { RowApiInitialRowCapacity = 1 }
        };
        var expected = new (int Id, byte Value, int Ordinal)[ScalarRowCount];
        RowFuzzDatasetMemory.Route route = static (RowFuzzDatasetMemory row,
            IParquetBufferPool bufferPool, out ParquetBuffer? allocation) =>
        {
            allocation = null;
            return ScalarKey;
        };

        using (var writer = RowFuzzDatasetMemory.CreateDatasetWriter(route, [file], options))
        {
            var reused = new byte[4];
            for (var ordinal = 0; ordinal < ScalarRowCount; ordinal++)
            {
                var id = salt + ordinal;
                var value = unchecked((byte)(salt ^ ordinal * 49));
                Array.Fill(reused, value);
                expected[ordinal] = (id, value, ordinal);
                writer.Queue(new RowFuzzDatasetMemory
                {
                    Id = id,
                    Label = $"{id:x2}-{value:x2}",
                    Memory = ordinal % 2 == 0 ? reused.AsMemory(1, 2) : ReadOnlyMemory<byte>.Empty,
                    OptionalMemory = ordinal % 3 == 0 ? (ReadOnlyMemory<byte>?)null
                        : ordinal % 3 == 1 ? ReadOnlyMemory<byte>.Empty
                        : reused.AsMemory(0, 3),
                    OptionalPayload = ordinal % 2 == 0 ? reused : null
                });
            }
        }

        VerifyScalarMemoryRows(store, expected);
    }

    static void VerifyScalarMemoryRows(InMemoryFileStore store,
        (int Id, byte Value, int Ordinal)[] expected)
    {
        var byId = expected.ToDictionary(static row => row.Id);
        var seen = new HashSet<int>();
        foreach (var (path, file) in store.Files)
        {
            if (file.Length == 0)
                continue;
            if (!string.Equals(path, "scalar", StringComparison.Ordinal))
                throw new DatasetSnapshotException($"Unknown scalar dataset path '{path}'.");

            using var reader = RowFuzzDatasetMemory.CreateRowReader(
                new MemoryStream(file.ToArray(), writable: false));
            while (reader.MoveNext())
            {
                var row = reader.Current;
                if (!byId.TryGetValue(row.Id, out var expectedRow) || !seen.Add(row.Id))
                    throw new DatasetSnapshotException($"Unexpected or repeated scalar dataset row {row.Id}.");
                var payload = Repeated(expectedRow.Value);
                if (!string.Equals(row.Label, $"{row.Id:x2}-{expectedRow.Value:x2}", StringComparison.Ordinal))
                    throw new DatasetSnapshotException($"String value changed for row {row.Id}.");
                if (expectedRow.Ordinal % 2 == 0)
                {
                    if (row.Memory.IsNull || !row.Memory.Value.SequenceEqual(payload.AsSpan(1, 2)))
                        throw new DatasetSnapshotException($"Memory value changed for row {row.Id}.");
                    RequireBinary(row.OptionalPayload, payload, $"optional scalar payload for {row.Id}");
                }
                else if (!row.Memory.IsNull && !row.Memory.Value.IsEmpty || !row.OptionalPayload.IsNull)
                {
                    throw new DatasetSnapshotException($"Empty or null scalar binary value changed for row {row.Id}.");
                }

                var optionalMemory = row.OptionalMemory;
                switch (expectedRow.Ordinal % 3)
                {
                    case 0 when optionalMemory.IsNull:
                        break;
                    case 1 when !optionalMemory.IsNull && optionalMemory.Value.IsEmpty:
                        break;
                    case 2 when !optionalMemory.IsNull && optionalMemory.Value.SequenceEqual(payload.AsSpan(0, 3)):
                        break;
                    default:
                        throw new DatasetSnapshotException($"Optional scalar memory changed for row {row.Id}.");
                }
            }
        }

        if (seen.Count != expected.Length)
            throw new DatasetSnapshotException($"Scalar round trip returned {seen.Count} of {expected.Length} rows.");
    }

    static byte Fold(ReadOnlySpan<byte> data)
    {
        byte value = 0;
        foreach (var item in data)
            value = unchecked((byte)(value * 31 + item));
        return value;
    }

    static byte[] Repeated(byte value)
        => [value, value, value, value];

    static void RequireBytes(byte[]? actual, byte[] expected, string what)
    {
        if (actual is null || !actual.AsSpan().SequenceEqual(expected))
            throw new DatasetSnapshotException($"Binary {what} changed.");
    }

    static void RequireBinary(RowReaderBinaryValue actual, byte[] expected, string what)
    {
        if (actual.IsNull || !actual.Value.SequenceEqual(expected))
            throw new DatasetSnapshotException($"Binary {what} changed.");
    }

    static int PartitionFromPath(string path)
    {
        for (var i = 0; i < PartitionKeys.Length; i++)
            if (string.Equals(path, $"p{i}", StringComparison.Ordinal))
                return i;
        return -1;
    }

    sealed class DatasetSnapshotException(string message) : Exception(message);
}
