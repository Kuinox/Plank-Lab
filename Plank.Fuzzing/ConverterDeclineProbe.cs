using Plank.Reading;
using Plank.Reading.Logical;
using Plank.Schema;

namespace Plank.Fuzzing;

/// <summary>
/// Reads each flat leaf of an arbitrary file through a value converter whose physical type is every
/// type the batched decoders may or may not accept for that column.
/// </summary>
/// <remarks>
/// A converter changes which decoder runs: the batched fixed-width and encoded paths decline when
/// the converter's physical type cannot be batched for the column's physical type and encoding
/// (CanBatchFixedWidthProjection), and the page then falls back to the whole-page converted decoders
/// (TryDecodeConvertedRequired*, TryDecodeNullableValuesByPhysicalType). The ordinary routes bind the file's
/// own schema or a handful of fixed requested schemas, so those fallbacks were never entered.
/// Route: selector 0x72, marker "CVRT", then a Parquet file.
/// </remarks>
internal static class ConverterDeclineProbe
{
    internal readonly record struct Box<T>(T Value) where T : unmanaged;

    sealed class BoxConverter<T> : ParquetValueConverter<Box<T>, T> where T : unmanaged
    {
        public override T ConvertToPhysical(Box<T> value) => value.Value;
        public override Box<T> ConvertFromPhysical(T value) => new(value);
    }

    internal static void Run(byte[] bytes, IParquetBufferPool pool)
    {
        LeafColumn[] leaves;
        using (var source = new MemoryReadSource(bytes))
        using (var reader = new ParquetReader(new ParquetReaderOptions { BufferPool = pool }))
        {
            reader.Reset(source);
            leaves = [.. reader.Schema.LeafColumns.Where(static l => l.MaxRepetitionLevel == 0
                && l.MaxDefinitionLevel <= 1)];
        }

        foreach (var leaf in leaves)
        {
            switch (leaf.PhysicalType)
            {
                case ParquetPhysicalType.Boolean: Try<bool>(bytes, leaf, pool); break;
                case ParquetPhysicalType.Int32:
                    Try<int>(bytes, leaf, pool); Try<uint>(bytes, leaf, pool); Try<ushort>(bytes, leaf, pool);
                    Try<byte>(bytes, leaf, pool); Try<DateOnly>(bytes, leaf, pool); Try<TimeOnly>(bytes, leaf, pool);
                    Try<decimal>(bytes, leaf, pool); Try<long>(bytes, leaf, pool);
                    break;
                case ParquetPhysicalType.Int64:
                    Try<long>(bytes, leaf, pool); Try<ulong>(bytes, leaf, pool); Try<DateTime>(bytes, leaf, pool);
                    Try<DateTimeOffset>(bytes, leaf, pool); Try<TimeOnly>(bytes, leaf, pool);
                    Try<decimal>(bytes, leaf, pool); Try<int>(bytes, leaf, pool);
                    break;
                case ParquetPhysicalType.Float: Try<float>(bytes, leaf, pool); Try<double>(bytes, leaf, pool); break;
                case ParquetPhysicalType.Double: Try<double>(bytes, leaf, pool); Try<float>(bytes, leaf, pool); break;
                case ParquetPhysicalType.Int96:
                    Try<DateTime>(bytes, leaf, pool); Try<DateTimeOffset>(bytes, leaf, pool); break;
                case ParquetPhysicalType.FixedLenByteArray:
                    Try<Guid>(bytes, leaf, pool); Try<decimal>(bytes, leaf, pool); break;
            }
        }
    }

    static void Try<T>(byte[] bytes, LeafColumn leaf, IParquetBufferPool pool) where T : unmanaged
    {
        var file = leaf.Column;
        var optional = file.Options.Repetition == ParquetRepetition.Optional;
        ParquetSchema schema;
        try
        {
        var options = file.PhysicalType == ParquetPhysicalType.FixedLenByteArray
            ? new ColumnOptions(file.Options.Repetition, typeLength: file.Options.TypeLength)
            : new ColumnOptions(file.Options.Repetition);
        var definition = optional
            ? ColumnDefinition.OptionalLeaf(file.Name, file.PhysicalType, options, file.LogicalType,
                converter: new BoxConverter<T>())
            : ColumnDefinition.RequiredLeaf(file.Name, file.PhysicalType, options, file.LogicalType,
                converter: new BoxConverter<T>());
            schema = new ParquetSchema([definition]);
        }
        catch (Exception ex) when (ex is ArgumentException or NotSupportedException or InvalidOperationException)
        {
            return;
        }
        try
        {
            using var source = new MemoryReadSource(bytes);
            using var reader = schema.CreateReader(source,
                new ParquetReaderOptions { BufferPool = pool, Strict = false });
            foreach (var group in reader.RowGroups)
            {
                if (optional)
                    foreach (var buffer in group.Column<Box<T>?>(schema.LeafColumns[0]))
                        _ = buffer.Count;
                else
                    foreach (var buffer in group.Column<Box<T>>(schema.LeafColumns[0]))
                        _ = buffer.Count;
            }
        }
        catch (Exception ex) when (PlankReaderFuzzTarget.IsExpectedRejection(ex))
        {
            // A converter the column cannot take, or a corrupt file. Anything else is a finding.
        }
    }
}
