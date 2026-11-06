using Ps = ParquetSharp;
using Parquet.Schema;
using Plank.Schema;

namespace Plank.Fuzzing;

/// <summary>
/// Checks whether an independent reader rejects a file Plank just read in full.
/// A disagreement is a finding to investigate, not proof that either reader is
/// correct: unsupported features and different validation rules are possible.
/// </summary>
internal static class ReaderAcceptanceOracle
{
    // Some readers require the opening marker and others tolerate a damaged
    // one even when the trailing marker and footer are readable. This is a
    // legitimate format rejection, but it says nothing about Plank's decoders.
    // Keep fuzzing Plank on these bytes; only skip the acceptance comparison.
    public static bool HasParquetHeader(ReadOnlySpan<byte> fileBytes)
        => fileBytes.StartsWith("PAR1"u8);

    public static void VerifyWithParquetSharp(byte[] fileBytes)
        => VerifyWithParquetSharp(fileBytes, plankTraces: null);

    /// <param name="plankTraces">
    /// What Plank decoded, per row group then per leaf column (null entries are
    /// not compared). When given, Arrow's levels and values are compared with it;
    /// otherwise Arrow only has to read the file without failing.
    /// </param>
    public static void VerifyWithParquetSharp(byte[] fileBytes, IReadOnlyList<ColumnTrace?[]>? plankTraces)
    {
        string? valueMismatch = null;
        using var stream = new MemoryStream(fileBytes, writable: false);
        Ps.ParquetFileReader reader;
        try
        {
            reader = new Ps.ParquetFileReader(stream, leaveOpen: true);
        }
        catch (Ps.ParquetException)
        {
            // An independent reader may enforce stricter file-envelope or
            // footer rules. Compare only after it has opened the file.
            return;
        }

        using var openedReader = reader;
        try
        {
            if (plankTraces is not null && plankTraces.Count != reader.FileMetaData.NumRowGroups)
                valueMismatch = "row group count differs"
                    + $"\nPlank={plankTraces.Count}, Arrow={reader.FileMetaData.NumRowGroups}";
            for (var groupIndex = 0; groupIndex < reader.FileMetaData.NumRowGroups; groupIndex++)
            {
                using var group = reader.RowGroup(groupIndex);
                for (var columnIndex = 0; columnIndex < reader.FileMetaData.NumColumns; columnIndex++)
                {
                    using var metadata = group.MetaData.GetColumnChunkMetaData(columnIndex);
                    // ParquetSharp 24 labels encoding 10 as Undefined; Plank
                    // uses it for the format's preview ALP encoding. This is
                    // a known capability gap, not a malformed-file rejection.
                    if (metadata.Encodings.Contains(Ps.Encoding.Undefined))
                        continue;

                    using var column = group.Column(columnIndex);
                    var plank = valueMismatch is null && plankTraces is not null
                        && groupIndex < plankTraces.Count && columnIndex < plankTraces[groupIndex].Length
                        ? plankTraces[groupIndex][columnIndex]
                        : null;
                    if (plank is not null)
                    {
                        var descriptor = column.ColumnDescriptor;
                        var arrow = ColumnTrace.CaptureArrow(column, descriptor.MaxRepetitionLevel > 0,
                            descriptor.MaxDefinitionLevel, descriptor.TypeLength);
                        var difference = ColumnTrace.Difference(plank, arrow);
                        if (difference is not null)
                        {
                            // First line is the bucket key: the kind of difference and
                            // the column's shape, never the values themselves.
                            var newline = difference.IndexOf('\n');
                            valueMismatch = $"{difference[..newline]}: physical={column.Type}, "
                                + $"encodings={string.Join(',', metadata.Encodings)}, "
                                + $"maxDef={descriptor.MaxDefinitionLevel}, maxRep={descriptor.MaxRepetitionLevel}"
                                + $"\nrow group {groupIndex}, column {columnIndex}, {difference[(newline + 1)..]}";
                        }
                        continue;
                    }
                    // Physical readers avoid CLR logical-type conversions and
                    // decode even repeated and unannotated binary columns.
                    switch (column.Type)
                    {
                        case Ps.PhysicalType.Boolean: Drain((Ps.ColumnReader<bool>)column); break;
                        case Ps.PhysicalType.Int32: Drain((Ps.ColumnReader<int>)column); break;
                        case Ps.PhysicalType.Int64: Drain((Ps.ColumnReader<long>)column); break;
                        case Ps.PhysicalType.Int96: Drain((Ps.ColumnReader<Ps.Int96>)column); break;
                        case Ps.PhysicalType.Float: Drain((Ps.ColumnReader<float>)column); break;
                        case Ps.PhysicalType.Double: Drain((Ps.ColumnReader<double>)column); break;
                        case Ps.PhysicalType.ByteArray: Drain((Ps.ColumnReader<Ps.ByteArray>)column); break;
                        case Ps.PhysicalType.FixedLenByteArray:
                            Drain((Ps.ColumnReader<Ps.FixedLenByteArray>)column); break;
                    }
                }
            }
        }
        catch (NotSupportedException)
        {
            // The oracle cannot judge a feature it does not implement.
        }
        catch (Exception error) when (error is not OutOfMemoryException)
        {
            if (IsKnownParquetSharpFinding(error) || IsUnknownAlpPage(error, fileBytes))
                return;
            throw new ReaderAcceptanceMismatchException("ParquetSharp rejected a file Plank read in full.", error);
        }

        // Raised only after Arrow has read the whole file, so a later Arrow
        // rejection is still reported as the rejection it is.
        if (valueMismatch is not null)
            throw new ReaderAcceptanceMismatchException("ParquetSharp decoded a file differently from Plank.",
                new InvalidDataException("Decoded value mismatch (Arrow) — " + valueMismatch));
    }

    // ALP (encoding 10) is a preview encoding Plank reads and Arrow does not
    // know. The column-metadata check in VerifyWithParquetSharp misses a page
    // that uses it while the chunk's encoding list does not say so.
    static bool IsUnknownAlpPage(Exception error, byte[] fileBytes)
        => error is Ps.ParquetException
            && error.Message.Contains("Unknown encoding type.", StringComparison.Ordinal)
            && AnyPage(fileBytes, static (header, _) => header.Encoding == EncodingKind.Alp);

    // Whether any page of the file, as Plank's own cursor reads it, matches.
    static bool AnyPage(byte[] fileBytes, Func<Plank.Reading.PageHeader, int, bool> predicate)
    {
        try
        {
            using var reader = new Plank.Reading.Logical.ParquetReader();
            reader.Reset(new Plank.Reading.MemoryReadSource(fileBytes));
            var physical = reader.PhysicalReader;
            for (var group = 0; group < physical.Metadata.RowGroupCount; group++)
                for (var column = 0; column < reader.Schema.LeafColumns.Length; column++)
                {
                    var maxDefinitionLevel = reader.Schema.LeafColumns[column].MaxDefinitionLevel;
                    using var pages = physical.OpenPages(group, column);
                    while (pages.MoveNext())
                        if (predicate(pages.CurrentHeader, maxDefinitionLevel))
                            return true;
                }
        }
        catch (Exception scan) when (scan is Plank.CorruptParquetException or InvalidOperationException
            or NotSupportedException)
        {
        }
        return false;
    }

    static bool IsKnownParquetSharpFinding(Exception error)
    {
        // Arrow rejects a negative/truncated footer length while Plank's footer
        // bounds checks deliberately accept only the readable prefix.
        if (error is ArgumentOutOfRangeException range
            && string.Equals(range.ParamName, "footerLength", StringComparison.Ordinal))
            return true;

        // These are known page-header validation differences. Do not broaden
        // these predicates to all Thrift or encoding failures: a decoded-value
        // mismatch or a new decoder rejection must remain a finding.
        if (error.Message.Contains("Deserializing page header failed", StringComparison.Ordinal)
            && error.Message.Contains("TProtocolException: Invalid data", StringComparison.Ordinal))
            return true;
        if (error is Ps.ParquetException
            && error.Message.Contains("Unknown encoding type for levels.", StringComparison.Ordinal))
            return true;

        // Snappier accepts a block whose literal overruns its input: it fills the
        // output with the bytes that are there and reports success, so Plank reads
        // what Arrow rejects as corrupt. Reported upstream; stop-gap until a fixed
        // Snappier release, then remove (reader-issues/arrow-rejections, snappy-*).
        if (error is Ps.ParquetException
            && error.Message.Contains("Corrupt snappy compressed data", StringComparison.Ordinal))
            return true;

        // A short RLE run is legal input for Plank's bounded decoder but is
        // rejected by Arrow. Keep this tied to Arrow's RLE-run diagnostic.
        return error is Ps.ParquetException
            && error.Message.Contains("RLE", StringComparison.OrdinalIgnoreCase)
            && error.Message.Contains("run", StringComparison.OrdinalIgnoreCase);
    }

    // Parquet.Net can loop for seconds on a few hundred corrupt bytes: it skips
    // an unknown list element by element and a bool element consumes nothing, so
    // a garbage count of billions never runs out of input; it also fills value
    // buffers from page num_values. Neither shows in Plank's view of the file,
    // because Parquet.Net ignores wire types and reads out of step with the bytes.
    // A run past AFL's timeout kills SharpFuzz's fork server, and on resume the
    // same queue entry kills it again, so the comparison gets a time budget. A
    // thread cannot be stopped, so an overrun comparison is left to finish in
    // the background and Parquet.Net comparisons are skipped until it has; at
    // most one is ever running behind.
    static readonly TimeSpan ParquetNetBudget = TimeSpan.FromMilliseconds(300);
    static Task? _overrunningParquetNet;

    public static void VerifyWithParquetNet(
        byte[] fileBytes, ParquetPhysicalType[] types, IReadOnlyList<Array> plankColumns)
    {
        // A previous comparison is still running past its budget; skip until it
        // ends rather than start another (see ParquetNetBudget).
        if (_overrunningParquetNet is { IsCompleted: false })
            return;
        try
        {
            var comparison = Task.Run(() => VerifyWithParquetNetAsync(fileBytes, types, plankColumns));
            // WaitAny, not Wait: Wait rethrows a faulted task as AggregateException,
            // which hid NotSupportedException and the known findings from the
            // catch clauses below and reported them as disagreements.
            if (Task.WaitAny([comparison], ParquetNetBudget) < 0)
            {
                _overrunningParquetNet = comparison;
                _ = comparison.ContinueWith(static t => _ = t.Exception, TaskContinuationOptions.OnlyOnFaulted);
                return;
            }
            comparison.GetAwaiter().GetResult();
        }
        catch (NotSupportedException)
        {
            // The oracle cannot judge a feature it does not implement.
        }
        catch (OutOfMemoryException)
        {
            // Plank has already decoded its columns, so this OOM is Parquet.Net's.
            // It ignores wire types: a mistyped field puts it out of step with the
            // bytes, and it then pre-sizes a list from whatever varint it lands on.
            // Under the fleet's GC heap limit that fails fast instead of becoming
            // a multi-GB allocation that outlasts AFL's timeout. The oracle cannot
            // judge such a file. OOMs from Plank itself still crash the worker.
        }
        catch (Exception error) when (IsKnownParquetNetFinding(error))
        {
            // A Parquet.Net bug already on file: nothing to compare.
        }
        catch (Exception error) when (error is not OutOfMemoryException)
        {
            throw new ReaderAcceptanceMismatchException("Parquet.Net rejected or decoded a file differently from Plank.", error);
        }
    }

    static readonly Type ParquetNetThriftReader = typeof(Parquet.Meta.FileMetaData).Assembly
        .GetType("Parquet.Meta.Proto.ThriftCompactProtocolReader", throwOnError: true)!;
    static readonly System.Reflection.MethodInfo ParquetNetReadFooter = typeof(Parquet.Meta.FileMetaData)
        .GetMethod("Read", System.Reflection.BindingFlags.NonPublic | System.Reflection.BindingFlags.Static)!;

    /// <summary>
    /// Parquet.Net decodes the footer from its own MemoryStream, where a varint
    /// that runs off the end reads ReadByte's -1 as 0xFF, a continuation byte,
    /// and loops forever. Replay that same parse over a guarded stream first;
    /// a footer that would spin is one this oracle cannot judge.
    /// </summary>
    static bool ParquetNetFooterWouldSpin(byte[] fileBytes)
    {
        if (fileBytes.Length < 12) return false;
        var length = BitConverter.ToInt32(fileBytes, fileBytes.Length - 8);
        if (length <= 0 || length > fileBytes.Length - 12) return false;
        using var footer = new EndOfStreamGuard(fileBytes[(fileBytes.Length - 8 - length)..(fileBytes.Length - 8)]);
        try
        {
            ParquetNetReadFooter.Invoke(null, [Activator.CreateInstance(ParquetNetThriftReader, footer)]);
            return false;
        }
        catch (System.Reflection.TargetInvocationException error) when (error.InnerException is EndOfStreamException)
        {
            return true;
        }
        catch (System.Reflection.TargetInvocationException)
        {
            // Any other footer error is Parquet.Net's ordinary verdict; let the
            // real open report it.
            return false;
        }
    }

    static bool IsKnownParquetNetFinding(Exception error)
        // Parquet.Net advertises dictionary support in some read paths but its
        // generic primitive reader rejects dictionary-backed chunks.
        => (error is InvalidOperationException
                && error.Message.Contains("dictionary", StringComparison.OrdinalIgnoreCase))
            // It decodes RLE booleans with the schema's type_length as the bit
            // width, which booleans do not have, so every such page divides by
            // zero (reader-issues/upstream/parquet-net-bool-rle-divide-by-zero).
            || (error is DivideByZeroException
                && error.StackTrace?.Contains("RleBitpackedHybridEncoder", StringComparison.Ordinal) == true)
            // Encoding 10 is ALP, a preview encoding Plank reads and Parquet.Net
            // does not know; a page can use it while the chunk's encoding list
            // does not say so, which slips past the metadata-based gate.
            || (error is Parquet.ParquetException
                && error.Message.Contains("encoding 10 is not supported", StringComparison.Ordinal));

    static async Task VerifyWithParquetNetAsync(
        byte[] fileBytes, ParquetPhysicalType[] types, IReadOnlyList<Array> plankColumns)
    {
        // Parquet.Net's Thrift reader treats a zero-byte read as more data and
        // spins forever on some truncated metadata. A hang kills the whole AFL
        // worker, since the persistent harness is its own fork server.
        using var stream = new EndOfStreamGuard(fileBytes);
        if (ParquetNetFooterWouldSpin(fileBytes))
            return;
        Parquet.ParquetReader reader;
        try
        {
            reader = await Parquet.ParquetReader.CreateAsync(stream).ConfigureAwait(false);
        }
        catch (IOException)
        {
            // This reader checks the file envelope before reading columns.
            return;
        }

        await using var openedReader = reader;
        var fields = reader.Schema.GetDataFields();
        if (fields.Length != types.Length)
            throw new InvalidDataException("Parquet.Net and Plank disagree about the number of columns.");
        var columnOrdinal = 0;
        for (var groupIndex = 0; groupIndex < reader.RowGroupCount; groupIndex++)
        {
            using var group = reader.OpenRowGroupReader(groupIndex);
            if (group.RowCount > 4096)
                throw new InvalidDataException("Parquet.Net and Plank disagree about the row count limit.");
            for (var i = 0; i < fields.Length; i++)
            {
                if (columnOrdinal >= plankColumns.Count)
                    throw new InvalidDataException("Plank did not supply every decoded column for comparison.");
                var location = $"row group {groupIndex}, column {i}";
                switch (types[i])
                {
                    case ParquetPhysicalType.Boolean:
                        await CompareParquetNet<bool>(group, fields[i], (bool[])plankColumns[columnOrdinal], location).ConfigureAwait(false);
                        break;
                    case ParquetPhysicalType.Int32:
                        await CompareParquetNet<int>(group, fields[i], (int[])plankColumns[columnOrdinal], location).ConfigureAwait(false);
                        break;
                    case ParquetPhysicalType.Int64:
                        await CompareParquetNet<long>(group, fields[i], (long[])plankColumns[columnOrdinal], location).ConfigureAwait(false);
                        break;
                    case ParquetPhysicalType.Float:
                        await CompareParquetNet<float>(group, fields[i], (float[])plankColumns[columnOrdinal], location).ConfigureAwait(false);
                        break;
                    case ParquetPhysicalType.Double:
                        await CompareParquetNet<double>(group, fields[i], (double[])plankColumns[columnOrdinal], location).ConfigureAwait(false);
                        break;
                }
                columnOrdinal++;
            }
        }
        if (columnOrdinal != plankColumns.Count)
            throw new InvalidDataException("Parquet.Net and Plank disagree about the number of decoded row groups.");
    }

    static async Task CompareParquetNet<T>(
        Parquet.ParquetRowGroupReader group, DataField field, T[] plankValues, string location)
        where T : struct
    {
        // These columns are required, so use Parquet.Net 6's non-nullable
        // overload. Its nullable overload can retain missing entries across
        // successive reads even when every definition level is present.
        var values = new T[plankValues.Length];
        await group.ReadAsync<T>(field, values, null, default).ConfigureAwait(false);
        for (var i = 0; i < values.Length; i++)
        {
            if (!EqualityComparer<T>.Default.Equals(values[i], plankValues[i]))
            {
                var encodings = group.GetMetadata(field)?.MetaData?.Encodings;
                throw new InvalidDataException(
                    $"Decoded value mismatch at {location}, row {i}: Plank={plankValues[i]}, Parquet.Net={values[i]}, " +
                    $"encodings={string.Join(',', encodings ?? [])}.");
            }
        }
    }

    static void Drain<T>(Ps.ColumnReader<T> reader) where T : unmanaged
    {
        var values = new T[1024];
        var definitions = new short[values.Length];
        var repetitions = new short[values.Length];
        while (reader.HasNext)
        {
            var levels = reader.ReadBatch(values.Length, definitions, repetitions, values, out _);
            if (levels == 0)
                throw new InvalidDataException("ParquetSharp could not finish reading the column.");
        }
    }
}

/// <summary>An independent Parquet reader rejected bytes accepted by Plank.</summary>
public sealed class ReaderAcceptanceMismatchException : Exception
{
    public ReaderAcceptanceMismatchException() { }
    public ReaderAcceptanceMismatchException(string message) : base(message) { }
    public ReaderAcceptanceMismatchException(string message, Exception innerException)
        : base(message, innerException) { }
}

/// <summary>
/// A read-only memory stream that throws once a reader keeps asking for bytes
/// past the end, instead of answering zero forever.
/// </summary>
sealed class EndOfStreamGuard(byte[] bytes) : MemoryStream(bytes, writable: false)
{
    const int EmptyReadLimit = 64;
    int _emptyReads;

    public override int Read(byte[] buffer, int offset, int count) => Check(base.Read(buffer, offset, count), count);
    public override int Read(Span<byte> buffer) => Check(base.Read(buffer), buffer.Length);
    public override int ReadByte()
    {
        var value = base.ReadByte();
        Check(value < 0 ? 0 : 1, 1);
        return value;
    }
    public override Task<int> ReadAsync(byte[] buffer, int offset, int count, CancellationToken cancellationToken)
        => Task.FromResult(Read(buffer, offset, count));
    public override ValueTask<int> ReadAsync(Memory<byte> buffer, CancellationToken cancellationToken = default)
        => ValueTask.FromResult(Read(buffer.Span));

    int Check(int read, int requested)
    {
        if (read > 0 || requested == 0) { _emptyReads = 0; return read; }
        if (++_emptyReads > EmptyReadLimit)
            throw new EndOfStreamException("Reader kept reading past the end of the file.");
        return read;
    }
}
