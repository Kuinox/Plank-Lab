using System.Collections.Immutable;
using Plank.Schema;
using Plank.Writing;

namespace Plank.Fuzzing;

/// <summary>
/// Drives the runtime (non-generated) schema API: <see cref="RowSchema"/>, <see cref="RowSchemaColumn"/>,
/// <see cref="ParquetTypeMap"/> and the converter validation. The attribute-based schemas are covered by the
/// generated wide routes; this is the same surface built by hand with fuzzer-chosen shape and values.
/// </summary>
public static partial class PlankRowApiFuzzTarget
{
    static ReadOnlySpan<byte> RowSchemaMagic => "RSC1"u8;

    static void RunRowSchema(ref Cursor c)
    {
        CheckTypeMap();

        var columnCount = c.NextInt(1, 6);
        var kinds = new int[columnCount];
        var columns = new RowSchemaColumn[columnCount];
        for (var i = 0; i < columnCount; i++)
        {
            kinds[i] = c.NextInt(0, 5);
            var name = $"c{i}_{c.NextInt(0, 3)}";
            var withFieldId = c.NextBool();
            var fieldId = c.NextInt(1, 100);
            var required = new ColumnOptions(ParquetRepetition.Required);
            var optional = new ColumnOptions(ParquetRepetition.Optional);
            columns[i] = kinds[i] switch
            {
                0 => withFieldId
                    ? RowSchema.Column<int>(name, ParquetPhysicalType.Int32, fieldId, required)
                    : RowSchema.Column<int>(name, ParquetPhysicalType.Int32, required),
                1 => RowSchema.Column<long>(name, ParquetPhysicalType.Int64, required),
                2 => RowSchema.Column<double>(name, ParquetPhysicalType.Double, required),
                3 => RowSchema.Column<int?>(name, ParquetPhysicalType.Int32, optional),
                _ => RowSchema.Column<RowFuzzId>(name, ParquetPhysicalType.Int32, required, converter: new RowFuzzIdConverter())
            };
            if (columns[i].Name != name || columns[i].ClrType is null)
                throw new RowApiRoundTripException("RowSchemaColumn did not keep its name or CLR type.");
            if (withFieldId && kinds[i] == 0 && columns[i].FieldId != fieldId)
                throw new RowApiRoundTripException("RowSchemaColumn dropped its field id.");
        }

        // The converter must be refused for a CLR type it cannot materialize.
        try
        {
            _ = RowSchema.Column<long>("bad", ParquetPhysicalType.Int32, converter: new RowFuzzIdConverter());
            throw new RowApiRoundTripException("RowSchemaColumn accepted a converter for the wrong CLR type.");
        }
        catch (ArgumentException)
        {
        }

        var names = columns.Select(static x => x.Name).ToHashSet(StringComparer.Ordinal);
        if (names.Count != columns.Length)
        {
            // Duplicate names are rejected when the schema is built.
            try
            {
                _ = (c.NextBool() ? RowSchema.Create(columns) : RowSchema.Create(columns.ToImmutableArray()));
                throw new RowApiRoundTripException("RowSchema accepted duplicate column names.");
            }
            catch (ArgumentException)
            {
            }
            return;
        }

        var rowSchema = c.NextBool() ? RowSchema.Create(columns) : RowSchema.Create(columns.ToImmutableArray());
        var schema = rowSchema.ParquetSchema;
        if (rowSchema.Columns.Length != columnCount || schema.LeafColumns.Length != columnCount)
            throw new RowApiRoundTripException("RowSchema changed the column count.");

        var rowCount = c.NextInt(0, 40);
        var ints = new int[rowCount];
        var longs = new long[rowCount];
        var doubles = new double[rowCount];
        var optionals = new int?[rowCount];
        var ids = new RowFuzzId[rowCount];
        for (var r = 0; r < rowCount; r++)
        {
            ints[r] = c.NextInt32();
            longs[r] = c.NextInt64();
            doubles[r] = c.NextDouble();
            optionals[r] = c.NextInt(0, 3) == 0 ? null : c.NextInt32();
            ids[r] = new RowFuzzId(c.NextInt32());
        }

        var split = c.NextInt(0, rowCount + 1);
        using var stream = new MemoryStream();
        var options = new ParquetWriterOptions { RowApiInitialRowCapacity = c.NextInt(1, 9) };
        var groups = split is 0 || split == rowCount ? new[] { (0, rowCount) } : new[] { (0, split), (split, rowCount) };
        using (var writer = schema.CreateWriter(stream, options))
        {
            foreach (var (from, to) in groups)
            {
                var rowGroup = writer.StartRowGroup();
                for (var i = 0; i < columnCount; i++)
                {
                    var leaf = schema.LeafColumns[i];
                    switch (kinds[i])
                    {
                        case 0: { var col = writer.CreateSerializedColumn<int>(leaf); col.Serialize(ints.AsSpan(from, to - from)); rowGroup.Write(col); break; }
                        case 1: { var col = writer.CreateSerializedColumn<long>(leaf); col.Serialize(longs.AsSpan(from, to - from)); rowGroup.Write(col); break; }
                        case 2: { var col = writer.CreateSerializedColumn<double>(leaf); col.Serialize(doubles.AsSpan(from, to - from)); rowGroup.Write(col); break; }
                        case 3: { var col = writer.CreateSerializedColumn<int?>(leaf); col.Serialize(optionals.AsSpan(from, to - from)); rowGroup.Write(col); break; }
                        default: { var col = writer.CreateSerializedColumn<RowFuzzId>(leaf); col.Serialize(ids.AsSpan(from, to - from)); rowGroup.Write(col); break; }
                    }
                }
            }
            writer.CloseFile();
        }

        using var reader = schema.CreateReader(new MemoryStream(stream.ToArray(), writable: false));
        var read = 0;
        for (var g = 0; g < reader.RowGroups.Count; g++)
        {
            var group = reader.RowGroups[g];
            var at = groups[g].Item1;
            for (var i = 0; i < columnCount; i++)
            {
                var leaf = schema.LeafColumns[i];
                var offset = at;
                switch (kinds[i])
                {
                    case 0: foreach (var b in group.Column<int>(leaf)) { Check(b.Values.SequenceEqual(ints.AsSpan(offset, b.Values.Length)), "RowSchema int", offset); offset += b.Values.Length; } break;
                    case 1: foreach (var b in group.Column<long>(leaf)) { Check(b.Values.SequenceEqual(longs.AsSpan(offset, b.Values.Length)), "RowSchema long", offset); offset += b.Values.Length; } break;
                    case 2:
                        foreach (var b in group.Column<double>(leaf))
                        {
                            for (var k = 0; k < b.Values.Length; k++)
                                Check(BitConverter.DoubleToInt64Bits(b.Values[k]) == BitConverter.DoubleToInt64Bits(doubles[offset + k]), "RowSchema double", offset + k);
                            offset += b.Values.Length;
                        }
                        break;
                    case 3: foreach (var b in group.Column<int?>(leaf)) { Check(b.Values.SequenceEqual(optionals.AsSpan(offset, b.Values.Length)), "RowSchema optional", offset); offset += b.Values.Length; } break;
                    default: foreach (var b in group.Column<RowFuzzId>(leaf)) { Check(b.Values.SequenceEqual(ids.AsSpan(offset, b.Values.Length)), "RowSchema converter", offset); offset += b.Values.Length; } break;
                }
                if (offset - at != (int)group.RowCount)
                    throw new RowApiRoundTripException($"RowSchema column {i} of group {g} returned {offset - at} rows; expected {group.RowCount}.");
            }
            read += (int)group.RowCount;
        }
        Check(read == rowCount, "RowSchema row count", read);
    }

    // ResolvePhysicalType<T>, TryGetPhysicalType<T> and GetPhysicalType<T> must agree with each other and
    // with the non-generic resolution, for supported and unsupported CLR types alike.
    static void CheckTypeMap()
    {
        Agree<bool>(); Agree<byte>(); Agree<sbyte>(); Agree<short>(); Agree<ushort>(); Agree<int>(); Agree<uint>();
        Agree<long>(); Agree<ulong>(); Agree<float>(); Agree<double>(); Agree<decimal>(); Agree<string>(); Agree<byte[]>();
        Agree<Guid>(); Agree<DateOnly>(); Agree<TimeOnly>(); Agree<DateTime>(); Agree<DateTimeOffset>(); Agree<TimeSpan>();
        Agree<char>(); Agree<object>(); Agree<int?>(); Agree<Half>(); Agree<ReadOnlyMemory<byte>>();
    }

    static void Agree<T>()
    {
        var resolution = ParquetTypeMap.ResolvePhysicalType<T>();
        var viaType = ParquetTypeMap.ResolvePhysicalType(typeof(T));
        var ok = ParquetTypeMap.TryGetPhysicalType<T>(out var physical);
        if (ok != resolution.IsSuccess || ok != viaType.IsSuccess || (ok && (physical != resolution.PhysicalType || physical != viaType.PhysicalType)))
            throw new RowApiRoundTripException($"ParquetTypeMap disagrees with itself for {typeof(T)}.");
        try
        {
            var got = ParquetTypeMap.GetPhysicalType<T>();
            if (!ok || got != physical)
                throw new RowApiRoundTripException($"ParquetTypeMap.GetPhysicalType<{typeof(T)}> succeeded where TryGet failed.");
        }
        catch (NotSupportedException)
        {
            if (ok)
                throw new RowApiRoundTripException($"ParquetTypeMap.GetPhysicalType<{typeof(T)}> threw where TryGet succeeded.");
        }
    }
}
