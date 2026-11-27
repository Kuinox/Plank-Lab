namespace Plank.Fuzzing;

/// <summary>
/// A deliberately naive Thrift compact-protocol reader for the Parquet footer: a third,
/// independent reading of the same bytes, used by <see cref="FullValueOracle"/> to arbitrate
/// where Plank and Arrow legitimately differ (Arrow prefers the deprecated <c>min</c>/<c>max</c>
/// statistics fields in some cases; Plank uses <c>min_value</c>/<c>max_value</c>).
/// Structs are field-id → value maps; lists are lists. Any malformation returns null.
/// </summary>
internal static class RawFooter
{
    const int MaxDepth = 48;
    const int MaxElements = 1 << 20;

    public static Dictionary<short, object?>? TryParse(ReadOnlySpan<byte> file)
    {
        if (file.Length < 12 || !file[^4..].SequenceEqual("PAR1"u8))
            return null;
        var length = BitConverter.ToInt32(file[^8..^4]);
        if (length <= 0 || length > file.Length - 8)
            return null;
        var reader = new Reader(file.Slice(file.Length - 8 - length, length).ToArray());
        try
        {
            return reader.Struct(0);
        }
        catch (Exception error) when (error is InvalidDataException or IndexOutOfRangeException or ArgumentException
                                          or OverflowException)
        {
            return null;
        }
    }

    public static Dictionary<short, object?>? Struct(object? value, short field)
        => value is Dictionary<short, object?> s && s.TryGetValue(field, out var f) ? f as Dictionary<short, object?> : null;

    public static List<object?>? List(object? value, short field)
        => value is Dictionary<short, object?> s && s.TryGetValue(field, out var f) ? f as List<object?> : null;

    public static byte[]? Binary(object? value, short field)
        => value is Dictionary<short, object?> s && s.TryGetValue(field, out var f) ? f as byte[] : null;

    public static long? Integer(object? value, short field)
        => value is Dictionary<short, object?> s && s.TryGetValue(field, out var f) && f is long l ? l : null;

    public static bool Has(object? value, short field)
        => value is Dictionary<short, object?> s && s.ContainsKey(field);

    /// <summary>ColumnMetaData.statistics of a chunk, or null.</summary>
    public static Dictionary<short, object?>? ChunkStatistics(Dictionary<short, object?> footer, int rowGroup, int column)
    {
        var groups = List(footer, 4);
        if (groups is null || rowGroup >= groups.Count)
            return null;
        var columns = List(groups[rowGroup], 1);
        if (columns is null || column >= columns.Count)
            return null;
        return Struct(Struct(columns[column], 3), 12);
    }

    /// <summary>The schema elements of the leaves, in leaf order (elements without num_children).</summary>
    public static List<Dictionary<short, object?>> Leaves(Dictionary<short, object?> footer)
    {
        var leaves = new List<Dictionary<short, object?>>();
        var schema = List(footer, 2);
        if (schema is null)
            return leaves;
        for (var i = 1; i < schema.Count; i++)
            if (schema[i] is Dictionary<short, object?> element && Integer(element, 5) is null or 0)
                leaves.Add(element);
        return leaves;
    }

    sealed class Reader(byte[] bytes)
    {
        int _position;
        int _elements;

        byte Byte() => _position < bytes.Length ? bytes[_position++] : throw new InvalidDataException("eof");

        ulong Varint()
        {
            ulong value = 0;
            for (var shift = 0; shift < 64; shift += 7)
            {
                var b = Byte();
                value |= (ulong)(b & 0x7F) << shift;
                if (b < 0x80)
                    return value;
            }
            throw new InvalidDataException("varint");
        }

        long ZigZag() { var v = Varint(); return (long)(v >> 1) ^ -(long)(v & 1); }

        public Dictionary<short, object?> Struct(int depth)
        {
            if (depth > MaxDepth)
                throw new InvalidDataException("depth");
            var fields = new Dictionary<short, object?>();
            short last = 0;
            while (true)
            {
                var header = Byte();
                if (header == 0)
                    return fields;
                var type = header & 0x0F;
                var delta = header >> 4;
                var id = delta == 0 ? checked((short)ZigZag()) : checked((short)(last + delta));
                last = id;
                fields[id] = type switch
                {
                    1 => true,
                    2 => false,
                    _ => Value(type, depth),
                };
            }
        }

        object? Value(int type, int depth)
        {
            if (++_elements > MaxElements)
                throw new InvalidDataException("size");
            switch (type)
            {
                case 1: return true;
                case 2: return false;
                case 3: return (long)(sbyte)Byte();
                case 4 or 5 or 6: return ZigZag();
                case 7: _position += 8; if (_position > bytes.Length) throw new InvalidDataException("eof"); return null;
                case 8:
                {
                    var length = checked((int)Varint());
                    if (length < 0 || length > bytes.Length - _position)
                        throw new InvalidDataException("binary");
                    var value = bytes.AsSpan(_position, length).ToArray();
                    _position += length;
                    return value;
                }
                case 9 or 10:
                {
                    var header = Byte();
                    var size = header >> 4 == 15 ? checked((int)Varint()) : header >> 4;
                    var elementType = header & 0x0F;
                    if (size < 0 || size > bytes.Length - _position + 1)
                        throw new InvalidDataException("list");
                    var list = new List<object?>(size);
                    for (var i = 0; i < size; i++)
                        list.Add(elementType is 1 or 2 ? Byte() == 1 : Value(elementType, depth + 1));
                    return list;
                }
                case 11:
                {
                    var size = checked((int)Varint());
                    if (size == 0)
                        return null;
                    if (size < 0 || size > bytes.Length - _position)
                        throw new InvalidDataException("map");
                    var kinds = Byte();
                    for (var i = 0; i < size; i++)
                    {
                        _ = Value(kinds >> 4, depth + 1);
                        _ = Value(kinds & 0x0F, depth + 1);
                    }
                    return null;
                }
                case 12: return Struct(depth + 1);
                default: throw new InvalidDataException("type");
            }
        }
    }
}
