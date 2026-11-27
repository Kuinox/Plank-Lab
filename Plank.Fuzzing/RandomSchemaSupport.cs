using System.Collections;
using System.Reflection;
using Plank.RowApi;
using Plank.Schema;
using Plank.Writing;

namespace Plank.Fuzzing;

/// <summary>One randomly shaped generated schema (see fuzz/tools/gen_random_schemas.py) and everything the route needs to drive it.</summary>
public abstract class RandomSchemaCase
{
    public abstract string Name { get; }
    public abstract Type RowType { get; }
    public abstract int ColumnCount { get; }
    public abstract ParquetSchema Schema { get; }
    public abstract void SetSeq(object row, int seq);

    /// <summary>Writes the rows through one generated writer entry point: 0 pipeline GetRow, 1 pipeline cursor, 2 several direct row groups.</summary>
    public abstract byte[] Write(object[] rows, ParquetWriterOptions options, int route, int groups);

    /// <summary>Reads the file back through the generated reader, projected to the columns in <paramref name="mask"/>, comparing every row.</summary>
    public abstract void Check(byte[] bytes, object[] rows, int mask, RowReaderOptions options, bool viaSource, bool reuse);
}

/// <summary>Draws fuzzer-chosen values for any CLR shape a generated schema can hold, honouring nullability annotations.</summary>
public sealed class ValueSource(byte[] data, int start)
{
    readonly byte[] _data = data;
    int _position = start;
    readonly NullabilityInfoContext _nullability = new();

    delegate T CursorRead<T>(ref PlankRowApiFuzzTarget.Cursor cursor);

    T Take<T>(CursorRead<T> read)
    {
        var cursor = new PlankRowApiFuzzTarget.Cursor(_position < _data.Length ? _data.AsSpan(_position) : []);
        var value = read(ref cursor);
        _position += cursor.Offset;
        return value;
    }

    public int NextInt(int min, int max) => Take((ref PlankRowApiFuzzTarget.Cursor c) => c.NextInt(min, max));

    public object? MakeValue(Type type, NullabilityInfo? info, PropertyInfo? property)
    {
        var underlying = Nullable.GetUnderlyingType(type);
        if (underlying is not null)
            return NextInt(0, 4) == 0 ? null : MakeValue(underlying, null, property);

        if (!type.IsValueType && info?.ReadState == NullabilityState.Nullable && NextInt(0, 4) == 0)
            return null;

        if (type == typeof(bool)) return Take((ref PlankRowApiFuzzTarget.Cursor c) => c.NextBool());
        if (type == typeof(byte)) return (byte)Take((ref PlankRowApiFuzzTarget.Cursor c) => c.NextInt32());
        if (type == typeof(ushort)) return (ushort)Take((ref PlankRowApiFuzzTarget.Cursor c) => c.NextInt32());
        if (type == typeof(uint)) return (uint)Take((ref PlankRowApiFuzzTarget.Cursor c) => c.NextInt32());
        if (type == typeof(ulong)) return (ulong)Take((ref PlankRowApiFuzzTarget.Cursor c) => c.NextInt64());
        if (type == typeof(int)) return Take((ref PlankRowApiFuzzTarget.Cursor c) => c.NextInt32());
        if (type == typeof(long)) return Take((ref PlankRowApiFuzzTarget.Cursor c) => c.NextInt64());
        if (type == typeof(float)) return BitConverter.Int32BitsToSingle(Take((ref PlankRowApiFuzzTarget.Cursor c) => c.NextInt32()));
        if (type == typeof(double)) return Take((ref PlankRowApiFuzzTarget.Cursor c) => c.NextDouble());
        if (type == typeof(decimal))
        {
            var column = property?.GetCustomAttribute<ParquetColumnAttribute>();
            var precision = column is { Precision: > 0 } ? Math.Min(column.Precision, 28) : 9;
            var scale = column is { Precision: > 0 } ? Math.Min(column.Scale, precision) : 2;
            return Take((ref PlankRowApiFuzzTarget.Cursor c) => c.NextDecimal(precision, scale));
        }
        if (type == typeof(string)) return Take((ref PlankRowApiFuzzTarget.Cursor c) => c.NextLabel());
        if (type == typeof(byte[])) return Take((ref PlankRowApiFuzzTarget.Cursor c) => c.NextBytes(16));
        if (type == typeof(ReadOnlyMemory<byte>)) return new ReadOnlyMemory<byte>(Take((ref PlankRowApiFuzzTarget.Cursor c) => c.NextBytes(16)));
        if (type == typeof(Guid)) return Take((ref PlankRowApiFuzzTarget.Cursor c) => c.NextGuid());
        if (type == typeof(DateOnly)) return Take((ref PlankRowApiFuzzTarget.Cursor c) => c.NextDate());
        if (type == typeof(TimeOnly)) return Take((ref PlankRowApiFuzzTarget.Cursor c) => c.NextTime());
        if (type == typeof(DateTime)) return Take((ref PlankRowApiFuzzTarget.Cursor c) => c.NextTimestamp());
        if (type == typeof(DateTimeOffset)) return Take((ref PlankRowApiFuzzTarget.Cursor c) => c.NextTimestampOffset());
        if (type == typeof(RowFuzzId)) return new RowFuzzId(Take((ref PlankRowApiFuzzTarget.Cursor c) => c.NextInt32()));

        if (type.IsArray)
        {
            var element = type.GetElementType()!;
            var count = NextInt(0, 4);
            var array = Array.CreateInstance(element, count);
            for (var i = 0; i < count; i++)
                array.SetValue(MakeValue(element, info?.ElementType, property), i);
            return array;
        }

        if (type.IsGenericType)
        {
            var definition = type.GetGenericTypeDefinition();
            var arguments = type.GetGenericArguments();
            if (definition == typeof(Dictionary<,>) || definition == typeof(IDictionary<,>) || definition == typeof(IReadOnlyDictionary<,>))
            {
                var dictionary = (IDictionary)Activator.CreateInstance(typeof(Dictionary<,>).MakeGenericType(arguments))!;
                for (var i = NextInt(0, 4); i > 0; i--)
                {
                    var key = MakeValue(arguments[0], info?.GenericTypeArguments[0], property)
                        ?? throw new InvalidOperationException("Dictionary key drawn as null.");
                    dictionary[key] = MakeValue(arguments[1], info?.GenericTypeArguments[1], property);
                }
                return dictionary;
            }

            if (definition == typeof(List<>) || definition == typeof(IList<>) || definition == typeof(ICollection<>)
                || definition == typeof(IEnumerable<>) || definition == typeof(IReadOnlyList<>) || definition == typeof(IReadOnlyCollection<>))
            {
                var list = (IList)Activator.CreateInstance(typeof(List<>).MakeGenericType(arguments[0]))!;
                for (var i = NextInt(0, 4); i > 0; i--)
                    list.Add(MakeValue(arguments[0], info?.GenericTypeArguments[0], property));
                return list;
            }
        }

        if (type.IsClass || (type.IsValueType && !type.IsPrimitive && !type.IsEnum))
        {
            var instance = Activator.CreateInstance(type)!;
            foreach (var member in type.GetProperties(BindingFlags.Public | BindingFlags.Instance))
            {
                if (member.SetMethod is null)
                    continue;
                member.SetValue(instance, MakeValue(member.PropertyType, _nullability.Create(member), member));
            }
            return instance;
        }

        throw new NotSupportedException($"RandomSchema: no value generator for {type}.");
    }

    /// <summary>Fills every settable property of a row object except Seq.</summary>
    public void Fill(object row)
    {
        foreach (var member in row.GetType().GetProperties(BindingFlags.Public | BindingFlags.Instance))
        {
            if (member.SetMethod is null || member.Name == "Seq")
                continue;
            member.SetValue(row, MakeValue(member.PropertyType, _nullability.Create(member), member));
        }
    }
}

/// <summary>Exact structural equality for generated row values (floats by bit pattern, instants by UTC ticks).</summary>
public static class DeepEq
{
    public static bool Of(object? actual, object? expected)
    {
        if (actual is null || expected is null)
            return actual is null && expected is null;
        switch (expected)
        {
            case double d: return actual is double ad && BitConverter.DoubleToInt64Bits(ad) == BitConverter.DoubleToInt64Bits(d);
            case float f: return actual is float af && BitConverter.SingleToInt32Bits(af) == BitConverter.SingleToInt32Bits(f);
            case string s: return actual is string a && string.Equals(a, s, StringComparison.Ordinal);
            case DateTime t: return actual is DateTime at && at.Ticks == t.Ticks;
            case DateTimeOffset o: return actual is DateTimeOffset ao && ao.UtcTicks == o.UtcTicks;
            case ReadOnlyMemory<byte> m: return Bytes(actual) is { } ab && ab.AsSpan().SequenceEqual(m.Span);
            case byte[] b: return Bytes(actual) is { } bb && bb.AsSpan().SequenceEqual(b);
            case IDictionary expectedMap:
                return actual is IDictionary actualMap && actualMap.Count == expectedMap.Count
                    && expectedMap.Keys.Cast<object>().All(k => actualMap.Contains(k) && Of(actualMap[k], expectedMap[k]));
            case IEnumerable expectedSeq:
            {
                if (actual is not IEnumerable actualSeq)
                    return false;
                var left = actualSeq.Cast<object?>().ToArray();
                var right = expectedSeq.Cast<object?>().ToArray();
                return left.Length == right.Length && left.Zip(right).All(pair => Of(pair.First, pair.Second));
            }
        }

        var type = expected.GetType();
        if (type.IsPrimitive || type.IsEnum || expected is decimal or Guid or DateOnly or TimeOnly)
            return expected.Equals(actual);
        if (actual.GetType() != type)
            return false;
        return type.GetProperties(BindingFlags.Public | BindingFlags.Instance)
            .Where(static p => p.GetMethod is not null && p.GetIndexParameters().Length == 0)
            .All(p => Of(p.GetValue(actual), p.GetValue(expected)));
    }

    static byte[]? Bytes(object value) => value switch
    {
        byte[] b => b,
        ReadOnlyMemory<byte> m => m.ToArray(),
        _ => null
    };

    /// <summary>Compares a generated binary property read back (<c>null</c> when SQL-null) with the expected byte[] / ReadOnlyMemory value.</summary>
    public static bool Binary(byte[]? actual, object? expected)
        => Of(actual, expected is ReadOnlyMemory<byte> m ? m.ToArray() : expected);
}
