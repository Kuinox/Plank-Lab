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
    {
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
            throw new ReaderAcceptanceMismatchException("ParquetSharp rejected a file Plank read in full.", error);
        }
    }

    public static void VerifyWithParquetNet(byte[] fileBytes, ParquetPhysicalType[] types)
    {
        try
        {
            VerifyWithParquetNetAsync(fileBytes, types).GetAwaiter().GetResult();
        }
        catch (NotSupportedException)
        {
            // The oracle cannot judge a feature it does not implement.
        }
        catch (Exception error) when (error is not OutOfMemoryException)
        {
            throw new ReaderAcceptanceMismatchException("Parquet.Net rejected a file Plank read in full.", error);
        }
    }

    static async Task VerifyWithParquetNetAsync(byte[] fileBytes, ParquetPhysicalType[] types)
    {
        using var stream = new MemoryStream(fileBytes, writable: false);
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
        for (var groupIndex = 0; groupIndex < reader.RowGroupCount; groupIndex++)
        {
            using var group = reader.OpenRowGroupReader(groupIndex);
            if (group.RowCount > 4096)
                throw new InvalidDataException("Parquet.Net and Plank disagree about the row count limit.");
            for (var i = 0; i < fields.Length; i++)
                switch (types[i])
                {
                    case ParquetPhysicalType.Boolean:
                        await DrainParquetNet<bool>(group, fields[i], (int)group.RowCount).ConfigureAwait(false);
                        break;
                    case ParquetPhysicalType.Int32:
                        await DrainParquetNet<int>(group, fields[i], (int)group.RowCount).ConfigureAwait(false);
                        break;
                    case ParquetPhysicalType.Int64:
                        await DrainParquetNet<long>(group, fields[i], (int)group.RowCount).ConfigureAwait(false);
                        break;
                    case ParquetPhysicalType.Float:
                        await DrainParquetNet<float>(group, fields[i], (int)group.RowCount).ConfigureAwait(false);
                        break;
                    case ParquetPhysicalType.Double:
                        await DrainParquetNet<double>(group, fields[i], (int)group.RowCount).ConfigureAwait(false);
                        break;
                }
        }
    }

    static async Task DrainParquetNet<T>(Parquet.ParquetRowGroupReader group, DataField field, int rowCount)
        where T : struct
    {
        var values = new T?[rowCount];
        await group.ReadAsync<T>(field, values, null, default).ConfigureAwait(false);
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
