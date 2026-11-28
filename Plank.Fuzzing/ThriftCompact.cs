namespace Plank.Fuzzing;

/// <summary>
/// A lossless Thrift compact-protocol model (read and write) for rewriting Parquet page headers and
/// footers: every field keeps its wire type and order; maps and doubles are carried as raw bytes.
/// Used by <see cref="StructuredPageMutator"/>, which has to re-serialize headers it edited.
/// </summary>
internal static class ThriftCompact
{
    public const byte Bool = 1, Byte = 3, I16 = 4, I32 = 5, I64 = 6, Double = 7, Binary = 8, List = 9, Set = 10, Map = 11, Struct = 12;

    public sealed class TField(short id, byte type, object? value)
    {
        public short Id = id;
        public byte Type = type; // 1 = bool (value carries true/false), else the compact type
        public object? Value = value;
    }

    public sealed class TList(byte elementType, List<object?> items)
    {
        public byte ElementType = elementType;
        public List<object?> Items = items;
    }

    public sealed class TRaw(byte[] bytes)
    {
        public byte[] Bytes = bytes;
    }

    public sealed class TStruct
    {
        public List<TField> Fields = [];

        public TField? Field(short id) => Fields.Find(f => f.Id == id);
        public object? Get(short id) => Field(id)?.Value;
        public long? Long(short id) => Get(id) is long l ? l : null;
        public TStruct? Child(short id) => Get(id) as TStruct;
        public TList? ListOf(short id) => Get(id) as TList;

        public void Remove(short id) => Fields.RemoveAll(f => f.Id == id);

        public void Set(short id, byte type, object? value)
        {
            var field = Field(id);
            if (field is null)
            {
                Fields.Add(new TField(id, type, value));
                Fields.Sort(static (a, b) => a.Id.CompareTo(b.Id));
            }
            else
            {
                field.Type = type;
                field.Value = value;
            }
        }

        public void SetLong(short id, byte type, long value) => Set(id, type, value);

        public TStruct Clone()
        {
            var copy = new TStruct();
            foreach (var f in Fields)
                copy.Fields.Add(new TField(f.Id, f.Type, CloneValue(f.Value)));
            return copy;
        }

        static object? CloneValue(object? value) => value switch
        {
            TStruct s => s.Clone(),
            TList l => new TList(l.ElementType, l.Items.Select(CloneValue).ToList()),
            byte[] b => b.ToArray(),
            TRaw r => new TRaw(r.Bytes.ToArray()),
            _ => value,
        };
    }

    // ---- Reading ----------------------------------------------------------------

    public sealed class Reader(byte[] bytes, int position)
    {
        public int Position = position;
        int _elements;

        byte ReadByte() => Position < bytes.Length ? bytes[Position++] : throw new InvalidDataException("thrift: eof");

        ulong Varint()
        {
            ulong value = 0;
            for (var shift = 0; shift < 64; shift += 7)
            {
                var b = ReadByte();
                value |= (ulong)(b & 0x7F) << shift;
                if (b < 0x80)
                    return value;
            }
            throw new InvalidDataException("thrift: varint");
        }

        long ZigZag() { var v = Varint(); return (long)(v >> 1) ^ -(long)(v & 1); }

        public TStruct ReadStruct(int depth = 0)
        {
            if (depth > 32)
                throw new InvalidDataException("thrift: depth");
            var result = new TStruct();
            short last = 0;
            while (true)
            {
                var header = ReadByte();
                if (header == 0)
                    return result;
                var type = (byte)(header & 0x0F);
                var delta = header >> 4;
                var id = delta == 0 ? checked((short)ZigZag()) : checked((short)(last + delta));
                last = id;
                if (type is 1 or 2)
                    result.Fields.Add(new TField(id, Bool, type == 1));
                else
                    result.Fields.Add(new TField(id, type, ReadValue(type, depth)));
            }
        }

        object? ReadValue(int type, int depth)
        {
            if (++_elements > 1 << 20)
                throw new InvalidDataException("thrift: size");
            switch (type)
            {
                case 1: return true;
                case 2: return false;
                case Byte: return (long)(sbyte)ReadByte();
                case I16 or I32 or I64: return ZigZag();
                case Double:
                {
                    if (Position + 8 > bytes.Length) throw new InvalidDataException("thrift: eof");
                    var raw = bytes.AsSpan(Position, 8).ToArray();
                    Position += 8;
                    return raw;
                }
                case Binary:
                {
                    var length = checked((int)Varint());
                    if (length < 0 || length > bytes.Length - Position) throw new InvalidDataException("thrift: binary");
                    var value = bytes.AsSpan(Position, length).ToArray();
                    Position += length;
                    return value;
                }
                case List or Set:
                {
                    var header = ReadByte();
                    var size = header >> 4 == 15 ? checked((int)Varint()) : header >> 4;
                    var elementType = (byte)(header & 0x0F);
                    if (size < 0 || size > bytes.Length - Position + 1) throw new InvalidDataException("thrift: list");
                    var items = new List<object?>(size);
                    for (var i = 0; i < size; i++)
                        items.Add(elementType is 1 or 2 ? ReadByte() == 1 : ReadValue(elementType, depth + 1));
                    return new TList(elementType, items);
                }
                case Map:
                {
                    var start = Position;
                    var size = checked((int)Varint());
                    if (size > 0)
                    {
                        var kinds = ReadByte();
                        for (var i = 0; i < size; i++)
                        {
                            _ = ReadValue(kinds >> 4, depth + 1);
                            _ = ReadValue(kinds & 0x0F, depth + 1);
                        }
                    }
                    return new TRaw(bytes.AsSpan(start, Position - start).ToArray());
                }
                case Struct: return ReadStruct(depth + 1);
                default: throw new InvalidDataException("thrift: type");
            }
        }
    }

    // ---- Writing ----------------------------------------------------------------

    public static void Write(List<byte> output, TStruct value)
    {
        short last = 0;
        foreach (var field in value.Fields)
        {
            var wireType = field.Type == Bool ? (byte)(field.Value is true ? 1 : 2) : field.Type;
            var delta = field.Id - last;
            if (delta is > 0 and <= 15)
                output.Add((byte)((delta << 4) | wireType));
            else
            {
                output.Add(wireType);
                WriteVarint(output, ZigZagEncode(field.Id));
            }
            last = field.Id;
            if (field.Type != Bool)
                WriteValue(output, field.Type, field.Value);
        }
        output.Add(0);
    }

    static void WriteValue(List<byte> output, byte type, object? value)
    {
        switch (type)
        {
            case Byte: output.Add((byte)(long)value!); break;
            case I16 or I32 or I64: WriteVarint(output, ZigZagEncode((long)value!)); break;
            case Double: output.AddRange((byte[])value!); break;
            case Binary:
            {
                var bytes = (byte[])value!;
                WriteVarint(output, (ulong)bytes.Length);
                output.AddRange(bytes);
                break;
            }
            case List or Set:
            {
                var list = (TList)value!;
                if (list.Items.Count < 15)
                    output.Add((byte)((list.Items.Count << 4) | list.ElementType));
                else
                {
                    output.Add((byte)(0xF0 | list.ElementType));
                    WriteVarint(output, (ulong)list.Items.Count);
                }
                foreach (var item in list.Items)
                {
                    if (list.ElementType is 1 or 2)
                        output.Add((byte)(item is true ? 1 : 2));
                    else
                        WriteValue(output, list.ElementType, item);
                }
                break;
            }
            case Map: output.AddRange(((TRaw)value!).Bytes); break;
            case Struct: Write(output, (TStruct)value!); break;
            default: throw new InvalidOperationException($"thrift: cannot write type {type}");
        }
    }

    public static ulong ZigZagEncode(long value) => (ulong)((value << 1) ^ (value >> 63));

    public static void WriteVarint(List<byte> output, ulong value)
    {
        while (value >= 0x80)
        {
            output.Add((byte)(value | 0x80));
            value >>= 7;
        }
        output.Add((byte)value);
    }
}
