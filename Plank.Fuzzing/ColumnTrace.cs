using System.Runtime.InteropServices;
using Plank.Reading.Logical;
using Plank.Schema;
using Ps = ParquetSharp;

namespace Plank.Fuzzing;

/// <summary>
/// What one reader decoded for one leaf column of one row group, in a form two
/// independent readers can be compared on: the level streams and the raw
/// physical bytes of every present value.
/// </summary>
/// <remarks>
/// The acceptance oracle used to drain Arrow's column readers and throw the
/// values away, and the Parquet.Net comparison only covers required, flat,
/// unannotated numeric columns of PLAIN/dictionary pages. So a decoder that
/// returned wrong data without throwing was invisible for strings, nulls,
/// nesting, FIXED_LEN_BYTE_ARRAY, INT96, logical types and the DELTA,
/// BYTE_STREAM_SPLIT and ALP encodings. This compares all of them.
///
/// For a flat column only presence is compared, not the exact definition level:
/// Plank's flat API reports "null" without saying which ancestor was absent.
/// For a repeated column both level streams are compared exactly.
/// </remarks>
public sealed class ColumnTrace
{
    // Above this the comparison is skipped rather than risking the worker's
    // memory on a file that claims an enormous column.
    const int MaxBytes = 16 << 20;

    readonly List<short> _definitions = [];
    readonly List<short> _repetitions = [];
    readonly List<int> _valueEnds = [];
    readonly List<byte> _bytes = [];

    // Read by the replay driver to show the comparison actually ran.
    public static long ComparedColumns, ComparedValues;

    public bool Nested { get; }
    public bool Overflowed { get; private set; }

    ColumnTrace(bool nested) => Nested = nested;

    public int EntryCount => _definitions.Count;

    void Entry(short definition, short repetition)
    {
        _definitions.Add(definition);
        _repetitions.Add(repetition);
    }

    void Value(ReadOnlySpan<byte> bytes)
    {
        if (_bytes.Count + bytes.Length > MaxBytes)
        {
            Overflowed = true;
            return;
        }
        foreach (var b in bytes)
            _bytes.Add(b);
        _valueEnds.Add(_bytes.Count);
    }

    ReadOnlySpan<byte> ValueAt(int index)
    {
        var start = index == 0 ? 0 : _valueEnds[index - 1];
        return CollectionsMarshal.AsSpan(_bytes)[start.._valueEnds[index]];
    }

    // ---- Plank side -------------------------------------------------------

    public static ColumnTrace CapturePlank(RowGroup rowGroup, LeafColumn column)
    {
        var nested = column.MaxRepetitionLevel > 0;
        var trace = new ColumnTrace(nested);
        if (nested)
        {
            switch (column.PhysicalType)
            {
                case ParquetPhysicalType.Boolean: trace.AddNested(rowGroup.NestedColumn<bool>(column)); break;
                case ParquetPhysicalType.Int32: trace.AddNested(rowGroup.NestedColumn<int>(column)); break;
                case ParquetPhysicalType.Int64: trace.AddNested(rowGroup.NestedColumn<long>(column)); break;
                case ParquetPhysicalType.Float: trace.AddNested(rowGroup.NestedColumn<float>(column)); break;
                case ParquetPhysicalType.Double: trace.AddNested(rowGroup.NestedColumn<double>(column)); break;
                default: trace.AddNestedBinary(rowGroup.NestedColumn<byte>(column)); break;
            }
            return trace;
        }

        var optional = column.MaxDefinitionLevel > 0;
        switch (column.PhysicalType)
        {
            case ParquetPhysicalType.Boolean:
                if (optional) trace.AddOptional(rowGroup.Column<bool?>(column)); else trace.AddRequired(rowGroup.Column<bool>(column));
                break;
            case ParquetPhysicalType.Int32:
                if (optional) trace.AddOptional(rowGroup.Column<int?>(column)); else trace.AddRequired(rowGroup.Column<int>(column));
                break;
            case ParquetPhysicalType.Int64:
                if (optional) trace.AddOptional(rowGroup.Column<long?>(column)); else trace.AddRequired(rowGroup.Column<long>(column));
                break;
            case ParquetPhysicalType.Float:
                if (optional) trace.AddOptional(rowGroup.Column<float?>(column)); else trace.AddRequired(rowGroup.Column<float>(column));
                break;
            case ParquetPhysicalType.Double:
                if (optional) trace.AddOptional(rowGroup.Column<double?>(column)); else trace.AddRequired(rowGroup.Column<double>(column));
                break;
            default:
                trace.AddBinary(rowGroup.Column<byte>(column));
                break;
        }
        return trace;
    }

    void AddRequired<T>(RowGroupColumn<T> buffers) where T : unmanaged
    {
        foreach (var buffer in buffers)
            foreach (var value in buffer.Values)
            {
                Entry(1, 0);
                Value(Bytes(value));
            }
    }

    void AddOptional<T>(RowGroupColumn<T?> buffers) where T : unmanaged
    {
        foreach (var buffer in buffers)
            foreach (var value in buffer.Values)
            {
                Entry(value.HasValue ? (short)1 : (short)0, 0);
                if (value.HasValue)
                    Value(Bytes(value.GetValueOrDefault()));
            }
    }

    void AddBinary(RowGroupColumn<byte> buffers)
    {
        foreach (var buffer in buffers)
            for (var i = 0; i < buffer.Count; i++)
            {
                var isNull = buffer.IsNull(i);
                Entry(isNull ? (short)0 : (short)1, 0);
                if (!isNull)
                    Value(buffer.GetValue(i));
            }
    }

    void AddNested<T>(NestedRowGroupColumn<T> buffers) where T : unmanaged
    {
        foreach (var buffer in buffers)
        {
            AddLevels(buffer.DefinitionLevels, buffer.RepetitionLevels);
            foreach (var value in buffer.Values.Values)
                Value(Bytes(value));
        }
    }

    void AddNestedBinary(NestedRowGroupColumn<byte> buffers)
    {
        foreach (var buffer in buffers)
        {
            AddLevels(buffer.DefinitionLevels, buffer.RepetitionLevels);
            var values = buffer.Values;
            for (var i = 0; i < values.Count; i++)
                Value(values.GetValue(i));
        }
    }

    void AddLevels(ReadOnlySpan<int> definitions, ReadOnlySpan<int> repetitions)
    {
        for (var i = 0; i < definitions.Length; i++)
            Entry((short)definitions[i], i < repetitions.Length ? (short)repetitions[i] : (short)-1);
    }

    static ReadOnlySpan<byte> Bytes<T>(T value) where T : unmanaged
        => MemoryMarshal.AsBytes(new ReadOnlySpan<T>(new[] { value }));

    // ---- Arrow side -------------------------------------------------------

    public static ColumnTrace CaptureArrow(Ps.ColumnReader column, bool nested, short maxDefinition, int fixedLength)
    {
        var trace = new ColumnTrace(nested);
        switch (column.Type)
        {
            case Ps.PhysicalType.Boolean: trace.AddArrow((Ps.ColumnReader<bool>)column, nested, maxDefinition, static v => Bytes(v)); break;
            case Ps.PhysicalType.Int32: trace.AddArrow((Ps.ColumnReader<int>)column, nested, maxDefinition, static v => Bytes(v)); break;
            case Ps.PhysicalType.Int64: trace.AddArrow((Ps.ColumnReader<long>)column, nested, maxDefinition, static v => Bytes(v)); break;
            case Ps.PhysicalType.Int96: trace.AddArrow((Ps.ColumnReader<Ps.Int96>)column, nested, maxDefinition, static v => Bytes(v)); break;
            case Ps.PhysicalType.Float: trace.AddArrow((Ps.ColumnReader<float>)column, nested, maxDefinition, static v => Bytes(v)); break;
            case Ps.PhysicalType.Double: trace.AddArrow((Ps.ColumnReader<double>)column, nested, maxDefinition, static v => Bytes(v)); break;
            case Ps.PhysicalType.ByteArray:
                trace.AddArrow((Ps.ColumnReader<Ps.ByteArray>)column, nested, maxDefinition, static v => ByteArrayBytes(v));
                break;
            case Ps.PhysicalType.FixedLenByteArray:
                trace.AddArrow((Ps.ColumnReader<Ps.FixedLenByteArray>)column, nested, maxDefinition,
                    v => FixedBytes(v, fixedLength));
                break;
        }
        return trace;
    }

    delegate ReadOnlySpan<byte> ToBytes<T>(T value);

    void AddArrow<T>(Ps.ColumnReader<T> reader, bool nested, short maxDefinition, ToBytes<T> toBytes) where T : unmanaged
    {
        var values = new T[1024];
        var definitions = new short[values.Length];
        var repetitions = new short[values.Length];
        while (reader.HasNext)
        {
            var levels = reader.ReadBatch(values.Length, definitions, repetitions, values, out var valuesRead);
            if (levels == 0)
                throw new InvalidDataException("ParquetSharp could not finish reading the column.");
            // A required flat column has no definition levels: every entry is a value.
            if (maxDefinition == 0 && !nested)
            {
                for (var i = 0; i < valuesRead; i++)
                {
                    Entry(1, 0);
                    Value(toBytes(values[i]));
                }
                continue;
            }
            for (var i = 0; i < levels; i++)
            {
                var present = definitions[i] == maxDefinition;
                if (nested) Entry(definitions[i], repetitions[i]);
                else Entry(present ? (short)1 : (short)0, 0);
            }
            for (var i = 0; i < valuesRead; i++)
                Value(toBytes(values[i]));
        }
    }

    // Arrow's pointers are only valid until the next batch, so copy now.
    static ReadOnlySpan<byte> ByteArrayBytes(Ps.ByteArray value)
        => Copy(value.Pointer, value.Length);

    static ReadOnlySpan<byte> FixedBytes(Ps.FixedLenByteArray value, int length)
        => Copy(value.Pointer, length);

    static byte[] Copy(IntPtr pointer, int length)
    {
        if (length <= 0 || pointer == IntPtr.Zero)
            return [];
        var bytes = new byte[length];
        Marshal.Copy(pointer, bytes, 0, length);
        return bytes;
    }

    // ---- Comparison -------------------------------------------------------

    /// <summary>Returns null when equal, else a two-line description: kind, then detail.</summary>
    public static string? Difference(ColumnTrace plank, ColumnTrace arrow)
    {
        if (plank.Overflowed || arrow.Overflowed)
            return null;
        ComparedColumns++;
        ComparedValues += plank._valueEnds.Count;
        if (plank.EntryCount != arrow.EntryCount)
            return $"entry count differs\nPlank={plank.EntryCount}, Arrow={arrow.EntryCount}";
        for (var i = 0; i < plank.EntryCount; i++)
        {
            if (plank._definitions[i] != arrow._definitions[i])
                return (plank.Nested ? "definition level differs" : "null-ness differs")
                    + $"\nentry {i}: Plank={plank._definitions[i]}, Arrow={arrow._definitions[i]}";
            if (plank.Nested && plank._repetitions[i] != arrow._repetitions[i])
                return $"repetition level differs\nentry {i}: Plank={plank._repetitions[i]}, Arrow={arrow._repetitions[i]}";
        }
        if (plank._valueEnds.Count != arrow._valueEnds.Count)
            return $"value count differs\nPlank={plank._valueEnds.Count}, Arrow={arrow._valueEnds.Count}";
        for (var i = 0; i < plank._valueEnds.Count; i++)
        {
            var a = plank.ValueAt(i);
            var b = arrow.ValueAt(i);
            if (!a.SequenceEqual(b))
                return (a.Length != b.Length ? "value length differs" : "value bytes differ")
                    + $"\nvalue {i}: Plank={Convert.ToHexString(a[..Math.Min(a.Length, 32)])}, "
                    + $"Arrow={Convert.ToHexString(b[..Math.Min(b.Length, 32)])}";
        }
        return null;
    }
}
