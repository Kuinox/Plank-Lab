using System.Collections.Immutable;
using System.Reflection;
using Plank.Reading.Logical;
using Plank.Schema;
using Plank.Writing;
using PlankSchema = Plank.Schema.ParquetSchema;

namespace Plank.Fuzzing;

/// <summary>
/// Structs, lists of structs, maps with struct values and nested lists with int / string / binary / FLBA / decimal
/// leaves, written one leaf column at a time through the columnar writer. The data is a tree of logical values; a
/// small reference shredder turns it into the expected repetition / definition levels and leaf values (Dremel),
/// and the CLR arrays handed to the writer are built from the same tree. Everything is compared after the read back.
/// </summary>
/// <remarks>
/// The columnar API encodes a null with a CLR null, so a null cannot say which optional ancestor it came from.
/// To keep every case unambiguous the schema generator allows at most one optional node between two repeated
/// groups on any root-to-leaf path (the nearest optional node is the one that is null).
/// </remarks>
internal static class WriterGroupCases
{
    sealed class Cur(ReadOnlySpan<byte> data)
    {
        readonly byte[] _d = data.ToArray();
        int _i;

        public byte Byte() => _d.Length == 0 ? (byte)0 : _d[_i++ % _d.Length];

        public int Int(int min, int maxExclusive)
        {
            uint v = Byte();
            v |= (uint)Byte() << 8;
            v |= (uint)Byte() << 16;
            v |= (uint)Byte() << 24;
            return min + (int)(v % (uint)(maxExclusive - min));
        }

        public bool Chance(int oneIn) => Int(0, oneIn) == 0;

        public T Pick<T>(params T[] choices) => choices[Int(0, choices.Length)];
    }

    static long _cases, _leavesCompared, _entriesCompared, _rejectedDecimals;

    static WriterGroupCases()
    {
        if (Environment.GetEnvironmentVariable("PLANK_ORACLE_COUNTERS") == "1")
            AppDomain.CurrentDomain.ProcessExit += (_, _) => Console.Error.WriteLine(
                $"GROUPS cases={_cases} leaves={_leavesCompared} levelEntries={_entriesCompared} " +
                $"repeatedDecimalRejections={_rejectedDecimals}");
    }

    enum Kind { Int32, String, Binary, Flba, Decimal }

    abstract record Node(string Name, bool Optional);

    sealed record LeafNode(string Name, bool Optional, Kind Kind, int Precision, int Scale, ParquetPhysicalType Physical,
        int Width, EncodingKind Encoding) : Node(Name, Optional);

    sealed record GroupNode(string Name, bool Optional, Node[] Children) : Node(Name, Optional);

    sealed record ListNode(string Name, bool Optional, Node Element) : Node(Name, Optional);

    sealed record MapNode(string Name, bool Optional, LeafNode Key, Node Value) : Node(Name, Optional);

    sealed class Struct(object?[] children)
    {
        public object?[] Children { get; } = children;
    }

    sealed class Items(List<object?> values)
    {
        public List<object?> Values { get; } = values;
    }

    sealed class Entries(List<(object Key, object? Value)> values)
    {
        public List<(object Key, object? Value)> Values { get; } = values;
    }

    sealed class Emitted
    {
        public readonly List<int> Rep = [];
        public readonly List<int> Def = [];
        public readonly List<object> Values = [];
        public int Rows;

        // Decimal leaves are compared as unscaled integers (the reader exposes their physical form).
        public Emitted With(Emitted source, LeafNode leaf)
        {
            Rep.AddRange(source.Rep);
            Def.AddRange(source.Def);
            foreach (var value in source.Values)
            {
                var scaled = (decimal)value;
                for (var i = 0; i < leaf.Scale; i++)
                    scaled *= 10m;
                Values.Add(new System.Numerics.BigInteger(Math.Truncate(scaled)));
            }

            return this;
        }
    }

    internal static void Execute(ReadOnlySpan<byte> data)
    {
        var c = new Cur(data);
        _cases++;
        var counter = 0;
        var root = Template(c);
        var fieldList = new List<ColumnDefinition> { ColumnDefinition.RequiredLeaf("id", ParquetPhysicalType.Int32) };
        fieldList.Add(ToDefinition(root));
        var schema = new PlankSchema(fieldList.ToImmutableArray());
        var leaves = Leaves(root).ToList();
        if (leaves.Count != schema.LeafColumns.Length - 1)
            throw new InvalidOperationException("Leaf count of the model differs from the schema.");

        // The model of the levels must agree with the library's own schema analysis.
        for (var i = 0; i < leaves.Count; i++)
        {
            var column = schema.LeafColumns[i + 1];
            var (maxRep, maxDef) = MaxLevels(root, leaves[i]);
            if (column.MaxRepetitionLevel != maxRep || column.MaxDefinitionLevel != maxDef)
                throw new InvalidOperationException(
                    $"Levels of '{leaves[i].Name}' are rep {column.MaxRepetitionLevel} / def {column.MaxDefinitionLevel}, " +
                    $"the Dremel rules give {maxRep} / {maxDef}.");
        }

        var groups = c.Int(1, 4);
        var rowsPerGroup = c.Pick(1, 2, 7, 33, 120);
        var maxLength = c.Pick(0, 1, 2, 4);
        var nullChance = c.Pick(2, 3, 6, 1000);
        var data1 = new List<List<object?>>();
        for (var g = 0; g < groups; g++)
        {
            var rows = new List<object?>();
            for (var r = 0; r < rowsPerGroup; r++)
                rows.Add(Gen(root, c, maxLength, nullChance, ref counter));
            data1.Add(rows);
        }

        using var pool = WriterFuzzPool.Create((WriterPoolKind)c.Int(0, 7));
        var options = new ParquetWriterOptions
        {
            Compression = c.Pick(CompressionKind.None, CompressionKind.Snappy, CompressionKind.Gzip, CompressionKind.Zstd),
            DataPageVersion = c.Int(0, 2) == 0 ? ParquetDataPageVersion.V2 : ParquetDataPageVersion.V1,
            TargetDataPageSizeBytes = c.Pick(1u, 64u, 512u, 1u << 20),
            BufferChunkSizeBytes = c.Pick(1u, 64u, 65536u),
            InitialPageBufferBytes = c.Pick(1u, 64u, 4096u),
            InitialColumnBufferBytes = c.Pick(1u, 4096u),
            WritePageIndexes = c.Int(0, 4) != 0,
            WritePageCrc = c.Int(0, 3) == 0,
            BufferPool = pool
        };

        using var stream = new MemoryStream();
        var writer = schema.CreateWriter(stream, options);
        var expected = new List<Emitted[]>();
        for (var g = 0; g < groups; g++)
        {
            var group = writer.StartRowGroup();
            var ids = group.CreateSerializedColumn<int>(schema.LeafColumns[0]);
            ids.Serialize(Enumerable.Range(0, rowsPerGroup).ToArray());
            group.Write(ids);
            var emitted = new Emitted[leaves.Count];
            for (var l = 0; l < leaves.Count; l++)
            {
                emitted[l] = new Emitted { Rows = rowsPerGroup };
                var rowType = ClrType(root, leaves[l], false);
                var array = Array.CreateInstance(rowType, rowsPerGroup);
                for (var r = 0; r < rowsPerGroup; r++)
                {
                    array.SetValue(BuildClr(root, data1[g][r], leaves[l]), r);
                    Shred(root, data1[g][r], leaves[l], 0, 0, 0, emitted[l]);
                }

                try
                {
                    typeof(WriterGroupCases).GetMethod(nameof(WriteColumn), BindingFlags.NonPublic | BindingFlags.Static)!
                        .MakeGenericMethod(rowType)
                        .Invoke(null, [group, schema.LeafColumns[l + 1], array]);
                }
                catch (TargetInvocationException error) when (leaves[l].Kind == Kind.Decimal
                    && schema.LeafColumns[l + 1].MaxRepetitionLevel > 0
                    && error.InnerException is InvalidOperationException inner
                    && inner.Message.Contains("is incompatible with column", StringComparison.Ordinal))
                {
                    _rejectedDecimals++;
                    return; // documented limitation: CLR decimal in a repeated column; the case ends here.
                }
            }

            expected.Add(emitted);
        }

        writer.CloseFile();
        using var reader = schema.CreateReader(new MemoryStream(FullValueOracle.Checked(stream.ToArray()), writable: false));
        if (reader.RowGroups.Count != groups)
            throw new InvalidOperationException($"Expected {groups} row groups, read {reader.RowGroups.Count}.");
        for (var g = 0; g < groups; g++)
            for (var l = 0; l < leaves.Count; l++)
                Compare(root.Name, g, leaves[l], reader.RowGroups[g], schema.LeafColumns[l + 1], expected[g][l]);
    }

    static void WriteColumn<TRow>(RowGroupWriter group, LeafColumn leaf, Array rows)
    {
        var column = group.CreateSerializedColumn<TRow>(leaf);
        column.Serialize((TRow[])rows);
        group.Write(column);
    }

    // ---- schema ------------------------------------------------------------------------------------------

    static Node Template(Cur c)
    {
        var id = 0;
        LeafNode Leaf(string name, bool allowOptional, bool repeated)
        {
            var optional = allowOptional && c.Chance(2);
            var kind = c.Pick(Kind.Int32, Kind.String, Kind.Binary, Kind.Flba, Kind.Decimal);
            // Decimals in repeated columns are rejected by the writer ("Array type ... is incompatible"); that
            // rejection is asserted for a minority of cases, the rest keep decimals where they are supported.
            if (kind == Kind.Decimal && repeated && !c.Chance(8))
                kind = Kind.Int32;
            var physical = ParquetPhysicalType.Int32;
            var precision = 0;
            var scale = 0;
            var width = 0;
            EncodingKind encoding;
            switch (kind)
            {
                case Kind.Int32:
                    encoding = c.Pick(EncodingKind.Plain, EncodingKind.DeltaBinaryPacked, EncodingKind.RleDictionary);
                    break;
                case Kind.String or Kind.Binary:
                    physical = ParquetPhysicalType.ByteArray;
                    encoding = c.Pick(EncodingKind.Plain, EncodingKind.DeltaLengthByteArray,
                        EncodingKind.DeltaByteArray, EncodingKind.RleDictionary);
                    break;
                case Kind.Flba:
                    physical = ParquetPhysicalType.FixedLenByteArray;
                    width = c.Int(1, 21);
                    encoding = c.Pick(EncodingKind.Plain, EncodingKind.RleDictionary);
                    break;
                default:
                {
                    var form = c.Int(0, 4);
                    precision = form switch { 0 => c.Int(1, 10), 1 => c.Int(10, 19), _ => c.Int(1, 29) };
                    scale = c.Int(0, precision + 1);
                    physical = form switch
                    {
                        0 => ParquetPhysicalType.Int32,
                        1 => ParquetPhysicalType.Int64,
                        2 => ParquetPhysicalType.FixedLenByteArray,
                        _ => ParquetPhysicalType.ByteArray
                    };
                    width = (int)Math.Max(1, Math.Ceiling((precision * 3.3219280948873626 + 1) / 8d));
                    encoding = c.Pick(EncodingKind.Plain, EncodingKind.RleDictionary);
                    break;
                }
            }

            return new LeafNode($"{name}{id++}", optional, kind, precision, scale, physical, width, encoding);
        }

        GroupNode Group(string name, bool budget, Func<bool, Node[]> children)
        {
            var optional = budget && c.Chance(2);
            return new GroupNode($"{name}{id++}", optional, children(budget && !optional));
        }

        ListNode List(string name, bool budget, Func<Node> element)
            => new($"{name}{id++}", budget && c.Chance(2), element());

        switch (c.Int(0, 4))
        {
            case 0:
                return Group("g", true, b =>
                [
                    Leaf("a", b, false),
                    Leaf("b", b, false),
                    List("xs", b, () => Leaf("x", true, true)),
                    Group("inner", b, bb => [Leaf("i", bb, false)])
                ]);
            case 1:
                return List("items", true, () => Group("e", true, b =>
                [
                    Leaf("a", b, true),
                    Leaf("b", b, true),
                    List("ys", b, () => Leaf("y", true, true))
                ]));
            case 2:
            {
                var optionalMap = c.Chance(2);
                var key = Leaf("k", false, true) with { Optional = false };
                return new MapNode($"m{id++}", optionalMap, key, Group("v", true, b =>
                [
                    Leaf("a", b, true),
                    List("w", b, () => Leaf("z", true, true))
                ]));
            }
            default:
                return List("outer", true, () => List("mid", true, () => Group("e", true, b =>
                [
                    Leaf("a", b, true),
                    Leaf("b", b, true)
                ])));
        }
    }

    static IEnumerable<LeafNode> Leaves(Node node)
    {
        switch (node)
        {
            case LeafNode leaf:
                yield return leaf;
                break;
            case GroupNode group:
                foreach (var child in group.Children)
                foreach (var leaf in Leaves(child))
                    yield return leaf;
                break;
            case ListNode list:
                foreach (var leaf in Leaves(list.Element))
                    yield return leaf;
                break;
            case MapNode map:
                yield return map.Key;
                foreach (var leaf in Leaves(map.Value))
                    yield return leaf;
                break;
        }
    }

    static bool Contains(Node node, LeafNode target)
        => node switch
        {
            LeafNode leaf => ReferenceEquals(leaf, target),
            GroupNode group => group.Children.Any(child => Contains(child, target)),
            ListNode list => Contains(list.Element, target),
            MapNode map => ReferenceEquals(map.Key, target) || Contains(map.Value, target),
            _ => false
        };

    static ColumnDefinition ToDefinition(Node node)
    {
        var repetition = node.Optional ? ParquetRepetition.Optional : ParquetRepetition.Required;
        switch (node)
        {
            case LeafNode leaf:
                LogicalType? logical = leaf.Kind switch
                {
                    Kind.String => new LogicalType.String(),
                    Kind.Decimal => new LogicalType.Decimal(leaf.Precision, leaf.Scale),
                    _ => null
                };
                return ColumnDefinition.Leaf(leaf.Name, leaf.Physical,
                    new ColumnOptions(repetition, ImmutableArray.Create(leaf.Encoding),
                        leaf.Physical == ParquetPhysicalType.FixedLenByteArray ? (uint)leaf.Width : 0), logical);
            case GroupNode group:
                var children = group.Children.Select(ToDefinition).ToArray();
                return node.Optional
                    ? ColumnDefinition.OptionalGroup(group.Name, children)
                    : ColumnDefinition.RequiredGroup(group.Name, children);
            case ListNode list:
                return ColumnDefinition.List(list.Name, ToDefinition(list.Element), repetition);
            case MapNode map:
                return ColumnDefinition.Map(map.Name, ToDefinition(map.Key), ToDefinition(map.Value), repetition);
            default:
                throw new InvalidOperationException();
        }
    }

    // (max repetition, max definition) of `target` from the Dremel rules.
    static (int Rep, int Def) MaxLevels(Node node, LeafNode target)
    {
        var (rep, def) = (0, node.Optional ? 1 : 0);
        switch (node)
        {
            case GroupNode group:
                var child = group.Children.First(x => Contains(x, target));
                var inner = MaxLevels(child, target);
                return (rep + inner.Rep, def + inner.Def);
            case ListNode list:
                inner = MaxLevels(list.Element, target);
                return (rep + 1 + inner.Rep, def + 1 + inner.Def);
            case MapNode map:
                if (ReferenceEquals(map.Key, target))
                    return (rep + 1, def + 1);
                inner = MaxLevels(map.Value, target);
                return (rep + 1 + inner.Rep, def + 1 + inner.Def);
            default:
                return (rep, def);
        }
    }

    // ---- data model --------------------------------------------------------------------------------------

    static object? Gen(Node node, Cur c, int maxLength, int nullChance, ref int counter)
    {
        if (node.Optional && c.Chance(nullChance))
            return null;
        switch (node)
        {
            case LeafNode leaf:
                return LeafValue(leaf, c, ref counter);
            case GroupNode group:
            {
                var values = new object?[group.Children.Length];
                for (var i = 0; i < values.Length; i++)
                    values[i] = Gen(group.Children[i], c, maxLength, nullChance, ref counter);
                return new Struct(values);
            }
            case ListNode list:
            {
                var length = c.Int(0, maxLength + 1);
                var values = new List<object?>();
                for (var i = 0; i < length; i++)
                    values.Add(Gen(list.Element, c, maxLength, nullChance, ref counter));
                return new Items(values);
            }
            default:
            {
                var map = (MapNode)node;
                var length = c.Int(0, maxLength + 1);
                var values = new List<(object, object?)>();
                for (var i = 0; i < length; i++)
                    values.Add((LeafValue(map.Key, c, ref counter)!,
                        Gen(map.Value, c, maxLength, nullChance, ref counter)));
                return new Entries(values);
            }
        }
    }

    static object? LeafValue(LeafNode leaf, Cur c, ref int counter)
    {
        counter++;
        var pool = c.Int(0, 6) == 0 ? 3 : 1000;
        var n = counter % pool;
        switch (leaf.Kind)
        {
            case Kind.Int32:
                return n * 7 - 20;
            case Kind.String:
                return System.Text.Encoding.UTF8.GetBytes($"s{n}-{(n % 3 == 0 ? "" : new string('x', n % 5))}");
            case Kind.Binary:
            {
                var bytes = new byte[n % 9];
                for (var i = 0; i < bytes.Length; i++)
                    bytes[i] = (byte)(n * 31 + i * 17);
                return bytes;
            }
            case Kind.Flba:
            {
                var bytes = new byte[leaf.Width];
                for (var i = 0; i < bytes.Length; i++)
                    bytes[i] = (byte)(n * 13 + i * 29);
                return bytes;
            }
            default:
            {
                var digits = Math.Min(leaf.Precision, 18);
                var limit = (long)Math.Pow(10, digits) - 1;
                var unscaled = (n * 2654435761L % (limit + 1)) * (n % 2 == 0 ? 1 : -1);
                var value = (decimal)unscaled;
                for (var i = 0; i < leaf.Scale; i++)
                    value /= 10m;
                return value;
            }
        }
    }

    // ---- reference shredder --------------------------------------------------------------------------------

    static void Shred(Node node, object? value, LeafNode target, int repBase, int defBase, int repLevel, Emitted output)
    {
        if (value is null)
        {
            output.Rep.Add(repBase);
            output.Def.Add(defBase);
            return;
        }

        var d = defBase + (node.Optional ? 1 : 0);
        switch (node)
        {
            case LeafNode:
                output.Rep.Add(repBase);
                output.Def.Add(d);
                output.Values.Add(value);
                break;
            case GroupNode group:
            {
                var index = Array.FindIndex(group.Children, x => Contains(x, target));
                Shred(group.Children[index], ((Struct)value).Children[index], target, repBase, d, repLevel, output);
                break;
            }
            case ListNode list:
            {
                var items = ((Items)value).Values;
                if (items.Count == 0)
                {
                    output.Rep.Add(repBase);
                    output.Def.Add(d);
                    break;
                }

                for (var i = 0; i < items.Count; i++)
                    Shred(list.Element, items[i], target, i == 0 ? repBase : repLevel + 1, d + 1, repLevel + 1, output);
                break;
            }
            default:
            {
                var map = (MapNode)node;
                var entries = ((Entries)value).Values;
                if (entries.Count == 0)
                {
                    output.Rep.Add(repBase);
                    output.Def.Add(d);
                    break;
                }

                for (var i = 0; i < entries.Count; i++)
                {
                    var rep = i == 0 ? repBase : repLevel + 1;
                    if (ReferenceEquals(map.Key, target))
                        Shred(map.Key, entries[i].Key, target, rep, d + 1, repLevel + 1, output);
                    else
                        Shred(map.Value, entries[i].Value, target, rep, d + 1, repLevel + 1, output);
                }

                break;
            }
        }
    }

    // ---- CLR shape handed to the writer ------------------------------------------------------------------------

    static Type LeafClr(LeafNode leaf)
        => leaf.Kind switch
        {
            Kind.Int32 => typeof(int),
            Kind.Decimal => typeof(decimal),
            _ => typeof(byte[])
        };

    static Type ClrType(Node node, LeafNode target, bool nullable)
    {
        switch (node)
        {
            case LeafNode leaf:
            {
                var type = LeafClr(leaf);
                return type.IsValueType && (nullable || leaf.Optional) ? typeof(Nullable<>).MakeGenericType(type) : type;
            }
            case GroupNode group:
                return ClrType(group.Children.First(x => Contains(x, target)), target, nullable || group.Optional);
            case ListNode list:
                return ClrType(list.Element, target, false).MakeArrayType();
            default:
            {
                var map = (MapNode)node;
                return (ReferenceEquals(map.Key, target) ? LeafClr(map.Key) : ClrType(map.Value, target, false))
                    .MakeArrayType();
            }
        }
    }

    static object? BuildClr(Node node, object? value, LeafNode target)
    {
        if (value is null)
            return null;
        switch (node)
        {
            case LeafNode:
                return value;
            case GroupNode group:
            {
                var index = Array.FindIndex(group.Children, x => Contains(x, target));
                return BuildClr(group.Children[index], ((Struct)value).Children[index], target);
            }
            case ListNode list:
            {
                var items = ((Items)value).Values;
                var array = Array.CreateInstance(ClrType(list.Element, target, false), items.Count);
                for (var i = 0; i < items.Count; i++)
                    array.SetValue(BuildClr(list.Element, items[i], target), i);
                return array;
            }
            default:
            {
                var map = (MapNode)node;
                var entries = ((Entries)value).Values;
                var elementType = ReferenceEquals(map.Key, target) ? LeafClr(map.Key) : ClrType(map.Value, target, false);
                var array = Array.CreateInstance(elementType, entries.Count);
                for (var i = 0; i < entries.Count; i++)
                    array.SetValue(ReferenceEquals(map.Key, target)
                        ? entries[i].Key
                        : BuildClr(map.Value, entries[i].Value, target), i);
                return array;
            }
        }
    }

    // ---- read back ------------------------------------------------------------------------------------------

    static void Compare(string what, int group, LeafNode leaf, RowGroup rowGroup, LeafColumn column, Emitted expected)
    {
        var rep = new List<int>();
        var def = new List<int>();
        var values = new List<object>();
        var rows = 0;
        if (leaf.Kind is Kind.Int32)
            Read<int>(rowGroup, column, rep, def, values, ref rows);
        else if (leaf.Kind is Kind.Decimal && leaf.Physical == ParquetPhysicalType.Int32)
            Read<int>(rowGroup, column, rep, def, values, ref rows, static v => new System.Numerics.BigInteger(v));
        else if (leaf.Kind is Kind.Decimal && leaf.Physical == ParquetPhysicalType.Int64)
            Read<long>(rowGroup, column, rep, def, values, ref rows, static v => new System.Numerics.BigInteger(v));
        else
        {
            foreach (var buffer in rowGroup.NestedColumn<byte>(column))
            {
                rows += buffer.RowCount;
                var valueIndex = 0;
                for (var i = 0; i < buffer.Count; i++)
                {
                    rep.Add(buffer.RepetitionLevels[i]);
                    def.Add(buffer.DefinitionLevels[i]);
                    if (buffer.DefinitionLevels[i] == buffer.MaxDefinitionLevel)
                    {
                        var bytes = buffer.Values.GetValue(valueIndex++).ToArray();
                        values.Add(leaf.Kind == Kind.Decimal
                            ? new System.Numerics.BigInteger(bytes, isUnsigned: false, isBigEndian: true)
                            : bytes);
                    }
                }
            }
        }

        if (leaf.Kind == Kind.Decimal)
            expected = new Emitted { Rows = expected.Rows }.With(expected, leaf);
        _leavesCompared++;
        _entriesCompared += rep.Count;
        if (Environment.GetEnvironmentVariable("PLANK_ORACLE_SELFTEST") == "1" && def.Count > 0)
            def[0] ^= 1; // negative test of this oracle: a corrupted level must be reported
        var label = $"{what} group {group} leaf '{leaf.Name}' ({leaf.Kind}/{leaf.Physical}/{leaf.Encoding})";
        if (rows != expected.Rows)
            throw new InvalidOperationException($"{label}: rows {rows} != {expected.Rows}.");
        if (!rep.SequenceEqual(expected.Rep))
            throw new InvalidOperationException($"{label}: repetition levels differ ({rep.Count} vs {expected.Rep.Count}).");
        if (!def.SequenceEqual(expected.Def))
            throw new InvalidOperationException($"{label}: definition levels differ ({def.Count} vs {expected.Def.Count}).");
        if (values.Count != expected.Values.Count)
            throw new InvalidOperationException($"{label}: values {values.Count} != {expected.Values.Count}.");
        for (var i = 0; i < values.Count; i++)
        {
            var same = values[i] is byte[] a && expected.Values[i] is byte[] b
                ? a.AsSpan().SequenceEqual(b)
                : Equals(values[i], expected.Values[i]);
            if (!same)
                throw new InvalidOperationException($"{label}: value {i} is {values[i]}, expected {expected.Values[i]}.");
        }
    }

    static void Read<T>(RowGroup rowGroup, LeafColumn column, List<int> rep, List<int> def, List<object> values,
        ref int rows, Func<T, object>? convert = null)
        where T : struct
    {
        foreach (var buffer in rowGroup.NestedColumn<T>(column))
        {
            rows += buffer.RowCount;
            for (var i = 0; i < buffer.Count; i++)
            {
                rep.Add(buffer.RepetitionLevels[i]);
                def.Add(buffer.DefinitionLevels[i]);
            }

            foreach (var value in buffer.Values.Values.ToArray())
                values.Add(convert is null ? value : convert(value));
        }
    }
}
