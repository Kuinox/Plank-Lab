using System.Text;
using Plank;
using Plank.Dataset;
using Plank.Reading;
using Plank.RowApi;
using Plank.Writing;

namespace Plank.Fuzzing;

/// <summary>Bounded, validated public dataset-writer operations for gap coverage.</summary>
public static class PlankDatasetOperationalFuzzTarget
{
    static readonly byte[][] Keys = ["p0"u8.ToArray(), "p1"u8.ToArray(), "p2"u8.ToArray()];
    static readonly Guid[] FixedValues =
    [
        Guid.Parse("00000000-0000-0000-0000-000000000001"),
        Guid.Parse("12345678-1234-5678-1234-567812345678")
    ];

    public static void Execute(ReadOnlySpan<byte> data)
    {
        if (data.Length > 0 && data[0] == 0xD2)
        {
            RunParkedCopyFailures();
            return;
        }

        if (data.Length > 0 && data[0] == 0xD3)
        {
            RunPromotionRetryAfterOpenFailure();
            return;
        }

        if (data.Length > 0 && data[0] == 0xD1)
        {
            RunDisposedGuards();
            return;
        }

        var salt = Fold(data);
        RunEmptyPath();
        RunPendingRollover(salt);
        RunPendingNoRollover(salt);
        RunFixedGuidNested(salt);
    }

    static void RunParkedCopyFailures()
    {
        RunParkedCopyFailure(throwBeforeFirstPark: true);
        RunParkedCopyFailure(throwBeforeFirstPark: false);
    }

    static void RunPromotionRetryAfterOpenFailure()
    {
        using var file = new FailOnceDatasetFile("p2");
        RowFuzzFixed.Route route = static (RowFuzzFixed row,
            IParquetBufferPool pool, out ParquetBuffer? allocation) =>
        {
            allocation = null;
            return row.Id switch
            {
                0 => "p0"u8,
                1 => "p1"u8,
                2 => "p2"u8,
                _ => "p3"u8
            };
        };
        DatasetFilePath filePath = static (ReadOnlySpan<byte> key, ulong index,
            IParquetBufferPool pool, out ParquetBuffer? allocation) =>
        {
            allocation = null;
            return Encoding.UTF8.GetBytes($"{Encoding.UTF8.GetString(key)}-{index}");
        };
        var options = new DatasetWriterOptions
        {
            PendingRowCapacity = 2,
            WriterOptions = new ParquetWriterOptions
            {
                RowApiInitialRowCapacity = 1,
                TargetRowGroupSizeBytes = ulong.MaxValue,
                TargetFileSizeBytes = ulong.MaxValue
            }
        };

        using (var writer = RowFuzzFixed.CreateDatasetWriter(route, filePath, [file], options))
        {
            writer.Queue(new RowFuzzFixed { Id = 0, Sequence = 10 });
            writer.Queue(new RowFuzzFixed { Id = 1, Sequence = 11 });
            try
            {
                writer.Queue(new RowFuzzFixed { Id = 2, Sequence = 21 });
                throw new InvalidOperationException("The injected dataset Open failure was not observed.");
            }
            catch (IOException exception) when (exception.Message == "Injected dataset Open failure for p2.")
            {
            }

            // Since Plank 974f6c3 (#274, "Fault dataset writers permanently after errors") a failed
            // Queue faults the writer: every later Queue rethrows the original failure and open parts
            // are aborted, parked rows are not drained, and Dispose (below) must not throw it again.
            // (It used to recover and accept the retry.)
            try
            {
                writer.Queue(new RowFuzzFixed { Id = 1, Sequence = 12 });
                throw new InvalidOperationException("A faulted dataset writer accepted a row after an Open failure.");
            }
            catch (IOException exception) when (exception.Message == "Injected dataset Open failure for p2.")
            {
            }
        }

        // Only parts that were finalized may be readable, and they may only hold rows queued
        // before the failure, each once; neither the row whose part failed to open nor the
        // rejected retry may appear.
        var allowed = new HashSet<(int Id, long Sequence)> { (0, 10), (1, 11) };
        var seen = new HashSet<(int Id, long Sequence)>();
        foreach (var fileBytes in file.Files.Values)
        {
            if (!HasParquetTrailer(fileBytes))
                continue;
            using var reader = RowFuzzFixed.CreateRowReader(
                new MemoryStream(FullValueOracle.Checked(fileBytes.ToArray()), writable: false));
            while (reader.MoveNext())
            {
                var row = (reader.Current.Id, reader.Current.Sequence);
                if (!allowed.Contains(row))
                    throw new InvalidOperationException($"A faulted dataset writer finalized row {row} it should not hold.");
                if (!seen.Add(row))
                    throw new InvalidOperationException("A dataset row was duplicated after an Open failure.");
            }
        }
    }

    // A part the faulted writer aborted has no footer; one that ends in the PAR1 magic was
    // finalized and must be fully readable.
    static bool HasParquetTrailer(MemoryStream stream)
        => stream.Length >= 12 && stream.ToArray().AsSpan()[^4..].SequenceEqual("PAR1"u8);

    static void RunParkedCopyFailure(bool throwBeforeFirstPark)
    {
        var store = new InMemoryFileStore();
        using var file = new InMemoryDatasetFile(store);
        RowFuzzDatasetBinary.Route route = static (RowFuzzDatasetBinary row,
            IParquetBufferPool pool, out ParquetBuffer? allocation) =>
        {
            allocation = null;
            return row.Id == 0 ? "p0"u8 : "p1"u8;
        };
        var options = new DatasetWriterOptions { PendingRowCapacity = 2 };
        using (var writer = RowFuzzDatasetBinary.CreateDatasetWriter(route, [file], options))
        {
            writer.Queue(new RowFuzzDatasetBinary { Id = 0, Payload = [10] });
            if (!throwBeforeFirstPark)
                writer.Queue(new RowFuzzDatasetBinary { Id = 2, Payload = [20] });

            try
            {
                writer.Queue(new RowFuzzDatasetBinary { Id = throwBeforeFirstPark ? 1 : 3, Payload = null! });
                throw new InvalidOperationException("A null required payload was accepted in a parked row.");
            }
            catch (ArgumentNullException exception) when (exception.ParamName == "bytes")
            {
            }

            // Since Plank 974f6c3 (#274) the failed copy faults the writer: a later Queue rethrows
            // the original ArgumentNullException instead of accepting the row.
            try
            {
                writer.Queue(new RowFuzzDatasetBinary
                {
                    Id = throwBeforeFirstPark ? 2 : 4,
                    Payload = [throwBeforeFirstPark ? (byte)20 : (byte)40]
                });
                throw new InvalidOperationException("A faulted dataset writer accepted a row after a copy failure.");
            }
            catch (ArgumentNullException exception) when (exception.ParamName == "bytes")
            {
            }
        }

        // Finalized parts may only hold valid rows queued before the failure, unchanged and once.
        var allowed = throwBeforeFirstPark ? new[] { 0 } : new[] { 0, 2 };
        var seen = new HashSet<int>();
        foreach (var (path, stream) in store.Files)
        {
            if (!HasParquetTrailer(stream))
                continue;
            using var reader = RowFuzzDatasetBinary.CreateRowReader(
                new MemoryStream(FullValueOracle.Checked(stream.ToArray()), writable: false));
            while (reader.MoveNext())
            {
                var row = reader.Current;
                if (!allowed.Contains(row.Id))
                    throw new InvalidOperationException($"A faulted dataset writer finalized row {row.Id} it should not hold.");
                var payload = row.Id == 0 ? (byte)10 : (byte)20;
                if (row.Payload.IsNull || !row.Payload.Value.SequenceEqual([payload]))
                    throw new InvalidOperationException($"Parked row {row.Id} changed after a copy failure.");
                if (!seen.Add(row.Id))
                    throw new InvalidOperationException($"Parked row {row.Id} was duplicated after a copy failure.");
            }
        }
    }

    static void RunDisposedGuards()
    {
        using var file = new InMemoryDatasetFile(new InMemoryFileStore());
        RowFuzzDatasetBinary.Route route = static (RowFuzzDatasetBinary row,
            IParquetBufferPool pool, out ParquetBuffer? allocation) =>
        {
            allocation = null;
            return "disposed"u8;
        };
        var writer = RowFuzzDatasetBinary.CreateDatasetWriter(route, [file]);
        writer.Dispose();
        try
        {
            writer.Dispose();
            throw new InvalidOperationException("A disposed dataset writer accepted a second Dispose call.");
        }
        catch (InvalidOperationException exception) when (exception.Message == "The dataset writer is already disposed.")
        {
        }

        try
        {
            writer.Queue(new RowFuzzDatasetBinary { Id = 1, Payload = [1] });
            throw new InvalidOperationException("A disposed dataset writer accepted a row.");
        }
        catch (ObjectDisposedException)
        {
        }
    }

    static void RunEmptyPath()
    {
        using var file = new InMemoryDatasetFile(new InMemoryFileStore());
        RowFuzzDatasetBinary.Route route = static (RowFuzzDatasetBinary row,
            IParquetBufferPool pool, out ParquetBuffer? allocation) =>
        {
            allocation = null;
            return [];
        };
        try
        {
            using var writer = RowFuzzDatasetBinary.CreateDatasetWriter(route, [file]);
            writer.Queue(new RowFuzzDatasetBinary { Id = 1, Payload = [1] });
        }
        catch (InvalidOperationException exception) when (exception.Message == "The dataset path selector returned an empty path.")
        {
            return;
        }
        throw new InvalidOperationException("An empty dataset path was accepted.");
    }

    static void RunPendingRollover(byte salt)
    {
        var store = new InMemoryFileStore();
        using var file0 = new InMemoryDatasetFile(store);
        using var file1 = new InMemoryDatasetFile(store);
        var writerOptions = new ParquetWriterOptions
        {
            RowApiInitialRowCapacity = 1,
            TargetRowGroupSizeBytes = 1,
            TargetFileSizeBytes = 1
        };
        var options = new DatasetWriterOptions
        {
            PendingRowCapacity = 2,
            WriterOptions = writerOptions,
            AppendOptions = new ParquetAppendOptions { WriterOptions = writerOptions }
        };
        RowFuzzDatasetBinary.Route route = static (RowFuzzDatasetBinary row,
            IParquetBufferPool pool, out ParquetBuffer? allocation) =>
        {
            var key = Keys[row.Id % Keys.Length];
            var owner = pool.Rent((uint)key.Length);
            key.CopyTo(owner.Span);
            allocation = owner;
            return owner.Span[..key.Length];
        };
        DatasetFilePath filePath = static (ReadOnlySpan<byte> key, ulong index,
            IParquetBufferPool pool, out ParquetBuffer? allocation) =>
        {
            var bytes = Encoding.UTF8.GetBytes($"{Encoding.UTF8.GetString(key)}-{index}");
            var owner = pool.Rent((uint)bytes.Length);
            bytes.CopyTo(owner.Span);
            allocation = owner;
            return owner.Span[..bytes.Length];
        };
        int[] ids = [0, 1, 2, 5, 8, 11];
        var expected = ids.ToDictionary(static id => id, id => unchecked((byte)(salt + id * 7 + 3)));
        using (var writer = RowFuzzDatasetBinary.CreateDatasetWriter(route, filePath, [file0, file1], options))
        {
            var reused = new byte[4];
            foreach (var id in ids)
            {
                Array.Fill(reused, expected[id]);
                writer.Queue(new RowFuzzDatasetBinary { Id = id, Payload = reused });
            }
        }
        VerifyBinary(store, ids, expected, "rollover");
    }

    static void RunPendingNoRollover(byte salt)
    {
        var store = new InMemoryFileStore();
        using var file0 = new InMemoryDatasetFile(store);
        using var file1 = new InMemoryDatasetFile(store);
        var writerOptions = new ParquetWriterOptions
        {
            RowApiInitialRowCapacity = 1,
            TargetRowGroupSizeBytes = ulong.MaxValue,
            TargetFileSizeBytes = ulong.MaxValue
        };
        var options = new DatasetWriterOptions
        {
            PendingRowCapacity = 2,
            WriterOptions = writerOptions,
            AppendOptions = new ParquetAppendOptions { WriterOptions = writerOptions }
        };
        RowFuzzDatasetBinary.Route route = static (RowFuzzDatasetBinary row,
            IParquetBufferPool pool, out ParquetBuffer? allocation) =>
        {
            allocation = null;
            return Keys[row.Id % Keys.Length];
        };
        DatasetFilePath filePath = static (ReadOnlySpan<byte> key, ulong index,
            IParquetBufferPool pool, out ParquetBuffer? allocation) =>
        {
            allocation = null;
            return Encoding.UTF8.GetBytes($"{Encoding.UTF8.GetString(key)}-{index}");
        };
        int[] ids = [0, 1, 2, 5];
        var expected = ids.ToDictionary(static id => id, id => unchecked((byte)(salt + id * 7 + 3)));
        using (var writer = RowFuzzDatasetBinary.CreateDatasetWriter(route, filePath, [file0, file1], options))
        {
            var reused = new byte[4];
            foreach (var id in ids)
            {
                Array.Fill(reused, expected[id]);
                writer.Queue(new RowFuzzDatasetBinary { Id = id, Payload = reused });
            }
        }
        VerifyBinary(store, ids, expected, "no-rollover");
    }

    static void VerifyBinary(InMemoryFileStore store, int[] ids, Dictionary<int, byte> expected, string scenario)
    {
        var seen = new HashSet<int>();
        foreach (var (path, file) in store.Files)
        {
            if (file.Length == 0)
                continue;
            var dash = path.IndexOf('-');
            if (dash != 2 || !int.TryParse(path.AsSpan(1, 1), out var partition))
                throw new InvalidOperationException($"Bad {scenario} dataset part path '{path}'.");
            using var reader = RowFuzzDatasetBinary.CreateRowReader(new MemoryStream(FullValueOracle.Checked(file.ToArray()), writable: false));
            while (reader.MoveNext())
            {
                var row = reader.Current;
                if (!expected.TryGetValue(row.Id, out var value) || !seen.Add(row.Id) || row.Id % 3 != partition)
                    throw new InvalidOperationException($"Bad {scenario} partition or duplicate dataset row {row.Id}.");
                if (row.Payload.IsNull || !row.Payload.Value.SequenceEqual(Repeated(value)))
                    throw new InvalidOperationException($"Bad {scenario} payload for dataset row {row.Id}.");
            }
        }
        if (seen.Count != ids.Length)
            throw new InvalidOperationException($"{scenario} dataset read {seen.Count}/{ids.Length} rows.");
    }

    static void RunFixedGuidNested(byte salt)
    {
        var store = new InMemoryFileStore();
        using var file = new InMemoryDatasetFile(store);
        var values = FixedValues.Select((value, i) => SaltGuid(value, salt, i)).ToArray();
        var numbers = new[] { salt, salt + 3, salt + 7 };
        RowFuzzDatasetFixedNested.Route route = static (RowFuzzDatasetFixedNested row,
            IParquetBufferPool pool, out ParquetBuffer? allocation) =>
        {
            allocation = null;
            return "guid"u8;
        };
        using (var writer = RowFuzzDatasetFixedNested.CreateDatasetWriter(route, [file], new DatasetWriterOptions
        {
            PendingRowCapacity = 0,
            WriterOptions = new ParquetWriterOptions { RowApiInitialRowCapacity = 1 }
        }))
            writer.Queue(new RowFuzzDatasetFixedNested { Id = 42 + salt, Values = values.ToList(), NumericValues = numbers.ToList() });

        using var reader = RowFuzzDatasetFixedNested.CreateRowReader(
            new MemoryStream(store.Files["guid"].ToArray(), writable: false));
        if (!reader.MoveNext())
            throw new InvalidOperationException("Fixed nested dataset emitted no rows.");
        var row = reader.Current;
        if (row.Id != 42 + salt || !row.Values.SequenceEqual(values) || !row.NumericValues.SequenceEqual(numbers) || reader.MoveNext())
            throw new InvalidOperationException("Fixed nested dataset roundtrip changed values.");
    }

    static Guid SaltGuid(Guid value, byte salt, int index)
    {
        var bytes = value.ToByteArray();
        bytes[0] ^= salt;
        bytes[1] ^= (byte)(salt + index);
        return new Guid(bytes);
    }

    static byte Fold(ReadOnlySpan<byte> data)
    {
        byte value = 0;
        foreach (var item in data)
            value = unchecked((byte)(value * 31 + item));
        return value;
    }

    static byte[] Repeated(byte value) => [value, value, value, value];

    sealed class FailOnceDatasetFile(string failingPartition) : IParquetWriteSource
    {
        readonly Dictionary<string, MemoryStream> _files = [];
        bool _failNextOpen = true;
        MemoryStream? _current;

        internal IReadOnlyDictionary<string, MemoryStream> Files => _files;

        MemoryStream Current
            => _current ?? throw new InvalidOperationException("No dataset destination is open.");

        public void Open(ReadOnlySpan<byte> path, FileMode mode)
        {
            var name = Encoding.UTF8.GetString(path);
            var separator = name.IndexOf('-');
            var partition = separator < 0 ? name : name[..separator];
            if (_failNextOpen && string.Equals(partition, failingPartition, StringComparison.Ordinal))
            {
                _failNextOpen = false;
                throw new IOException($"Injected dataset Open failure for {failingPartition}.");
            }

            if (!_files.TryGetValue(name, out var file))
                _files.Add(name, file = new MemoryStream());
            else if (mode == FileMode.CreateNew)
                throw new IOException($"The in-memory dataset file '{name}' already exists.");
            else if (mode == FileMode.Create)
                file.SetLength(0);
            _current = file;
        }

        public void Close()
            => _current = null;

        public void Write(ulong offset, ReadOnlySpan<byte> source)
        {
            var file = Current;
            var end = checked((long)offset + source.Length);
            if (file.Length < end)
                file.SetLength(end);
            file.Position = (long)offset;
            file.Write(source);
        }

        public void SetLength(ulong length)
            => Current.SetLength(checked((long)length));

        public void Flush()
        {
        }

        public void Dispose()
            => _current = null;
    }
}
