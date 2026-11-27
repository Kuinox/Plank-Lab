using System.Collections.Immutable;
using System.Reflection;
using Plank.Reading;
using Plank.Reading.Logical;
using Plank.Schema;
using Plank.Writing;
using Plank.Writing.PageStrategy;
using PlankSchema = Plank.Schema.ParquetSchema;

namespace Plank.Fuzzing;

/// <summary>
/// Nested data through the columnar writer: List / List(List) / List(List(List)) / Map, with the optionality of
/// every level, the nullness of every element, empty lists, and the page and row-group splits all drawn from the
/// input. The expected repetition and definition levels are computed here, independently from the library,
/// directly from the Dremel rules (+1 definition level per optional node and per repeated group), then compared
/// with the levels and values read back.
/// </summary>
internal static class WriterNestedCases
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

        public T Pick<T>(params T[] choices) => choices[Int(0, choices.Length)];
    }

    sealed class Levels
    {
        public readonly List<int> Repetition = [];
        public readonly List<int> Definition = [];
        public readonly List<object> Values = [];
        public int Rows;

        public void Emit(int rep, int def, object? value = null)
        {
            Repetition.Add(rep);
            Definition.Add(def);
            if (value is not null)
                Values.Add(value);
        }
    }

    internal static void Execute(ReadOnlySpan<byte> data)
    {
        var c = new Cur(data);
        if (c.Int(0, 5) == 0)
            Map(c);
        else
            Lists(c);
    }

    static ParquetWriterOptions Options(Cur c, IParquetBufferPool pool)
        => new()
        {
            Compression = c.Pick(CompressionKind.None, CompressionKind.Snappy, CompressionKind.Gzip,
                CompressionKind.Zstd, CompressionKind.Lz4),
            DataPageVersion = c.Int(0, 2) == 0 ? ParquetDataPageVersion.V2 : ParquetDataPageVersion.V1,
            TargetDataPageSizeBytes = c.Pick(1u, 16u, 64u, 256u, 4096u, 1u << 20),
            BufferChunkSizeBytes = c.Pick(1u, 17u, 64u, 4096u, 65536u),
            InitialPageBufferBytes = c.Pick(1u, 64u, 4096u),
            InitialColumnBufferBytes = c.Pick(1u, 4096u, 65536u),
            WritePageCrc = c.Int(0, 3) == 0,
            WritePageIndexes = c.Int(0, 4) != 0,
            BufferPool = pool
        };

    // ---- lists ------------------------------------------------------------------------------------------

    static void Lists(Cur c)
    {
        var depth = c.Int(1, 4);
        var optionalList = new bool[depth];
        for (var k = 0; k < depth; k++)
            optionalList[k] = c.Int(0, 2) == 0;
        var leafOptional = c.Int(0, 2) == 0;
        var useDouble = c.Int(0, 3) == 0;
        var leafType = useDouble ? typeof(double) : typeof(int);
        var encoding = useDouble
            ? c.Pick(EncodingKind.Plain, EncodingKind.ByteStreamSplit)
            : c.Pick(EncodingKind.Plain, EncodingKind.DeltaBinaryPacked, EncodingKind.RleDictionary);
        var bloom = c.Int(0, 4) == 0;
        var leaf = ColumnDefinition.Leaf("v", useDouble ? ParquetPhysicalType.Double : ParquetPhysicalType.Int32,
            new ColumnOptions(leafOptional ? ParquetRepetition.Optional : ParquetRepetition.Required,
                ImmutableArray.Create(encoding), bloomFilter: bloom ? ParquetBloomFilterOptions.Default : null));
        var node = leaf;
        for (var k = depth - 1; k >= 0; k--)
            node = ColumnDefinition.List($"l{k}", node,
                optionalList[k] ? ParquetRepetition.Optional : ParquetRepetition.Required);
        var schema = new PlankSchema([node]);
        var column = schema.LeafColumns[0];

        var expectedMaxDefinition = leafOptional ? 1 : 0;
        foreach (var optional in optionalList)
            expectedMaxDefinition += (optional ? 1 : 0) + 1;
        if (column.MaxRepetitionLevel != depth || column.MaxDefinitionLevel != expectedMaxDefinition)
            throw new InvalidOperationException(
                $"Nested schema levels differ from the Dremel rules: rep {column.MaxRepetitionLevel}/{depth}, " +
                $"def {column.MaxDefinitionLevel}/{expectedMaxDefinition}.");

        var baseGroups = c.Int(1, 4);
        // After the base file is verified, more row groups are added: 1 appended, 2 appended into the latest row
        // group (the writer rejects that for repeated columns), 3 merged from a second file. 0 = none.
        var variant = c.Int(0, 5) is var v && v > 3 ? 0 : v;
        var groups = baseGroups + (variant == 0 ? 0 : c.Int(1, 3));
        var rowsPerGroup = c.Pick(1, 2, 5, 17, 60, 300);
        var maxLength = c.Pick(0, 1, 2, 4, 9);
        var nullChance = c.Pick(2, 3, 5, 1000);
        var emptyChance = c.Pick(2, 4, 1000);
        var rowArrays = new List<Array>();
        var levels = new List<Levels>();
        var counter = 0;
        for (var g = 0; g < groups; g++)
        {
            var groupLevels = new Levels();
            var rows = new List<object?>();
            for (var r = 0; r < rowsPerGroup; r++)
            {
                rows.Add(BuildList(c, 0, depth, optionalList, leafOptional, leafType, maxLength, nullChance,
                    emptyChance, groupLevels, 0, 0, ref counter));
                groupLevels.Rows++;
            }

            var rowType = NodeType(0, depth, leafOptional, leafType);
            var array = Array.CreateInstance(rowType, rows.Count);
            for (var i = 0; i < rows.Count; i++)
                array.SetValue(rows[i], i);
            rowArrays.Add(array);
            levels.Add(groupLevels);
        }

        var rowClr = NodeType(0, depth, leafOptional, leafType);
        using var pool = WriterFuzzPool.Create((WriterPoolKind)c.Int(0, 7));
        typeof(WriterNestedCases).GetMethod(nameof(WriteAndCheck), BindingFlags.NonPublic | BindingFlags.Static)!
            .MakeGenericMethod(rowClr, leafType)
            .Invoke(null, [schema, Options(c, pool), rowArrays, levels, baseGroups, variant, bloom, $"nested depth={depth} optional=[{string.Join(',', optionalList)}] leafOpt={leafOptional} {leafType.Name} {encoding}"]);
    }

    static Type NodeType(int level, int depth, bool leafOptional, Type leafType)
        => ElementType(level + 1, depth, leafOptional, leafType).MakeArrayType();

    static Type ElementType(int level, int depth, bool leafOptional, Type leafType)
        => level == depth
            ? leafOptional ? typeof(Nullable<>).MakeGenericType(leafType) : leafType
            : ElementType(level + 1, depth, leafOptional, leafType).MakeArrayType();

    // Builds the CLR value of the list node at `level` and appends the matching expected levels.
    static object? BuildList(Cur c, int level, int depth, bool[] optionalList, bool leafOptional, Type leafType,
        int maxLength, int nullChance, int emptyChance, Levels levels, int parentRep, int definitionBase,
        ref int counter)
    {
        if (optionalList[level] && c.Int(0, nullChance) == 0)
        {
            levels.Emit(parentRep, definitionBase);
            return null;
        }

        var d1 = definitionBase + (optionalList[level] ? 1 : 0);
        var length = c.Int(0, emptyChance) == 0 ? 0 : c.Int(0, maxLength + 1);
        if (length == 0 && maxLength > 0 && c.Int(0, 2) == 0)
            length = 1;
        var elementType = ElementType(level + 1, depth, leafOptional, leafType);
        var array = Array.CreateInstance(elementType, length);
        if (length == 0)
        {
            levels.Emit(parentRep, d1);
            return array;
        }

        for (var i = 0; i < length; i++)
        {
            var rep = i == 0 ? parentRep : level + 1;
            if (level == depth - 1)
            {
                if (leafOptional && c.Int(0, 4) == 0)
                {
                    levels.Emit(rep, d1 + 1);
                    continue; // default(T?) is null
                }

                counter++;
                var value = leafType == typeof(double) ? (object)(counter * 0.25 - 3) : counter * 3 - 100;
                array.SetValue(value, i);
                levels.Emit(rep, d1 + 1 + (leafOptional ? 1 : 0), value);
            }
            else
            {
                array.SetValue(BuildList(c, level + 1, depth, optionalList, leafOptional, leafType, maxLength,
                    nullChance, emptyChance, levels, rep, d1 + 1, ref counter), i);
            }
        }

        return array;
    }

    static byte[] WriteFile<TRow>(PlankSchema schema, ParquetWriterOptions options, IEnumerable<Array> groups)
    {
        using var stream = new MemoryStream();
        var writer = schema.CreateWriter(stream, options);
        foreach (var rows in groups)
            WriteGroup<TRow>(writer, schema, rows);
        writer.CloseFile();
        return stream.ToArray();
    }

    static void WriteGroup<TRow>(ParquetWriter writer, PlankSchema schema, Array rows)
    {
        var group = writer.StartRowGroup();
        var column = group.CreateSerializedColumn<TRow>(schema.LeafColumns[0]);
        column.Serialize((TRow[])rows);
        group.Write(column);
    }

    static void VerifyFile<TLeaf>(PlankSchema schema, byte[] file, List<Levels> levels, bool bloom, string what)
        where TLeaf : struct
    {
        using var reader = schema.CreateReader(new MemoryStream(file, writable: false));
        if (reader.RowGroups.Count != levels.Count)
            throw new InvalidOperationException($"{what}: {reader.RowGroups.Count} row groups, expected {levels.Count}.");
        for (var g = 0; g < levels.Count; g++)
            CompareGroup<TLeaf>(what, g, reader.RowGroups[g], schema.LeafColumns[0], levels[g], bloom);
    }

    static Levels Concat(Levels first, Levels second)
    {
        var merged = new Levels { Rows = first.Rows + second.Rows };
        merged.Repetition.AddRange(first.Repetition);
        merged.Repetition.AddRange(second.Repetition);
        merged.Definition.AddRange(first.Definition);
        merged.Definition.AddRange(second.Definition);
        merged.Values.AddRange(first.Values);
        merged.Values.AddRange(second.Values);
        return merged;
    }

    static void WriteAndCheck<TRow, TLeaf>(PlankSchema schema, ParquetWriterOptions options, List<Array> rowArrays,
        List<Levels> levels, int baseGroups, int variant, bool bloom, string what)
        where TLeaf : struct
    {
        var file = WriteFile<TRow>(schema, options, rowArrays.Take(baseGroups));
        VerifyFile<TLeaf>(schema, file, levels.Take(baseGroups).ToList(), bloom, what);
        if (variant == 0)
            return;

        var extra = rowArrays.Skip(baseGroups).ToList();
        var extraLevels = levels.Skip(baseGroups).ToList();
        what += $" +variant{variant}";
        switch (variant)
        {
            case 1:
            {
                using var stream = new MemoryStream();
                stream.Write(file);
                stream.Position = 0;
                using (var writer = schema.CreateAppender(stream, new ParquetAppendOptions { WriterOptions = options }))
                {
                    foreach (var rows in extra)
                        WriteGroup<TRow>(writer, schema, rows);
                    writer.CloseFile();
                }

                VerifyFile<TLeaf>(schema, stream.ToArray(), levels, bloom, what);
                break;
            }
            case 2:
            {
                using var stream = new MemoryStream();
                stream.Write(file);
                stream.Position = 0;
                ParquetWriter? writer = null;
                try
                {
                    writer = schema.CreateAppender(stream, new ParquetAppendOptions
                    {
                        AppendToLatestRowGroup = true,
                        WriterOptions = options
                    });
                }
                catch (NotSupportedException error) when (error.Message.Contains(
                    "Appending to the latest row group is not supported for repeated column", StringComparison.Ordinal))
                {
                    return; // documented limitation, asserted by its exact message.
                }

                // If the library ever supports it, the first extra group must be merged into the latest group.
                using (writer)
                {
                    WriteGroup<TRow>(writer, schema, extra[0]);
                    writer.CloseFile();
                }

                var expected = levels.Take(baseGroups - 1).Append(Concat(levels[baseGroups - 1], extraLevels[0])).ToList();
                VerifyFile<TLeaf>(schema, stream.ToArray(), expected, bloom, what);
                break;
            }
            default:
            {
                var second = WriteFile<TRow>(schema, options, extra);
                var destination = new PlankMergerFuzzTarget.MemoryReadWriteSource();
                var merger = schema.CreateMerger(new MemoryReadSource(file), destination,
                    new ParquetMergeOptions { WriterOptions = options });
                merger.AppendFile(new MemoryReadSource(second));
                merger.CloseFile();
                VerifyFile<TLeaf>(schema, destination.ToArray(), levels, bloom, what);
                break;
            }
        }
    }

    static void CompareGroup<TLeaf>(string what, int group, RowGroup rowGroup, LeafColumn column, Levels expected,
        bool bloom)
        where TLeaf : struct
    {
        var values = new List<TLeaf>();
        var repetition = new List<int>();
        var definition = new List<int>();
        var rows = 0;
        foreach (var buffer in rowGroup.NestedColumn<TLeaf>(column))
        {
            rows += buffer.RowCount;
            values.AddRange(buffer.Values.Values.ToArray());
            for (var i = 0; i < buffer.Count; i++)
            {
                repetition.Add(buffer.RepetitionLevels[i]);
                definition.Add(buffer.DefinitionLevels[i]);
            }
        }

        WriterStatisticsOracle.CheckNestedChunk(what, group, column, rowGroup.GetColumnMetadata(column),
            expected.Values, bloom);
        if (rows != expected.Rows)
            throw new InvalidOperationException($"{what}: group {group} rows {rows} != {expected.Rows}.");
        if (!repetition.SequenceEqual(expected.Repetition))
            throw new InvalidOperationException(
                $"{what}: group {group} repetition levels differ ({repetition.Count} vs {expected.Repetition.Count}).");
        if (!definition.SequenceEqual(expected.Definition))
            throw new InvalidOperationException(
                $"{what}: group {group} definition levels differ ({definition.Count} vs {expected.Definition.Count}).");
        if (values.Count != expected.Values.Count)
            throw new InvalidOperationException($"{what}: group {group} values {values.Count} != {expected.Values.Count}.");
        for (var i = 0; i < values.Count; i++)
            if (!Equals(values[i], expected.Values[i]))
                throw new InvalidOperationException(
                    $"{what}: group {group} value {i} is {values[i]}, expected {expected.Values[i]}.");
    }

    // ---- maps -------------------------------------------------------------------------------------------

    static void Map(Cur c)
    {
        var mapOptional = c.Int(0, 2) == 0;
        var valueOptional = c.Int(0, 2) == 0;
        var key = ColumnDefinition.RequiredLeaf("key", ParquetPhysicalType.Int32);
        var value = valueOptional
            ? ColumnDefinition.OptionalLeaf("value", ParquetPhysicalType.Int64)
            : ColumnDefinition.RequiredLeaf("value", ParquetPhysicalType.Int64);
        var schema = new PlankSchema([ColumnDefinition.Map("m", key, value,
            mapOptional ? ParquetRepetition.Optional : ParquetRepetition.Required)]);
        var keyColumn = schema.LeafColumns[0];
        var valueColumn = schema.LeafColumns[1];
        var groups = c.Int(1, 4);
        var rowsPerGroup = c.Pick(1, 3, 20, 200);
        var maxEntries = c.Pick(0, 1, 3, 8);
        var keyRows = new List<int[]?[]>();
        var valueRows = new List<long?[]?[]>();
        var keyLevels = new List<Levels>();
        var valueLevels = new List<Levels>();
        var counter = 0;
        for (var g = 0; g < groups; g++)
        {
            var kl = new Levels();
            var vl = new Levels();
            var keys = new int[rowsPerGroup][];
            var vals = new long?[rowsPerGroup][];
            for (var r = 0; r < rowsPerGroup; r++)
            {
                kl.Rows++;
                vl.Rows++;
                if (mapOptional && c.Int(0, 4) == 0)
                {
                    kl.Emit(0, 0);
                    vl.Emit(0, 0);
                    continue;
                }

                var d1 = mapOptional ? 1 : 0;
                var length = c.Int(0, maxEntries + 1);
                keys[r] = new int[length];
                vals[r] = new long?[length];
                if (length == 0)
                {
                    kl.Emit(0, d1);
                    vl.Emit(0, d1);
                    continue;
                }

                for (var i = 0; i < length; i++)
                {
                    var rep = i == 0 ? 0 : 1;
                    counter++;
                    keys[r][i] = counter * 7 - 50;
                    kl.Emit(rep, d1 + 1, keys[r][i]);
                    if (valueOptional && c.Int(0, 3) == 0)
                    {
                        vl.Emit(rep, d1 + 1);
                        continue;
                    }

                    vals[r][i] = counter * 1_000_000_007L;
                    vl.Emit(rep, d1 + 1 + (valueOptional ? 1 : 0), vals[r][i]!.Value);
                }
            }

            keyRows.Add(keys!);
            valueRows.Add(vals!);
            keyLevels.Add(kl);
            valueLevels.Add(vl);
        }

        using var pool = WriterFuzzPool.Create((WriterPoolKind)c.Int(0, 7));
        var options = Options(c, pool);
        using var stream = new MemoryStream();
        var writer = schema.CreateWriter(stream, options);
        for (var g = 0; g < groups; g++)
        {
            var group = writer.StartRowGroup();
            var keyColumnWriter = group.CreateSerializedColumn<int[]>(keyColumn);
            keyColumnWriter.Serialize(keyRows[g]!);
            group.Write(keyColumnWriter);
            if (valueOptional)
            {
                var valueWriter = group.CreateSerializedColumn<long?[]>(valueColumn);
                valueWriter.Serialize(valueRows[g]!);
                group.Write(valueWriter);
            }
            else
            {
                var valueWriter = group.CreateSerializedColumn<long[]>(valueColumn);
                valueWriter.Serialize(valueRows[g].Select(static r => r?.Select(static v => v!.Value).ToArray()!).ToArray());
                group.Write(valueWriter);
            }
        }

        writer.CloseFile();
        using var reader = schema.CreateReader(new MemoryStream(FullValueOracle.Checked(stream.ToArray()), writable: false));
        const string what = "nested map";
        for (var g = 0; g < groups; g++)
        {
            CompareGroup<int>(what + " keys", g, reader.RowGroups[g], keyColumn, keyLevels[g], false);
            CompareGroup<long>(what + " values", g, reader.RowGroups[g], valueColumn, valueLevels[g], false);
        }
    }
}
