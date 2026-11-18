using System.Collections.Immutable;
using Plank.Reading;
using Plank.Schema;
using Plank.Writing;

namespace Plank.Fuzzing;

/// <summary>Replays public nullable INT64 dictionary empty and all-null boundaries.</summary>
internal static class OptionalInt64DictionaryCoverageCases
{
    internal static void Execute(ReadOnlySpan<byte> data)
    {
        var selector = data.IsEmpty ? (byte)0 : data[0];
        long?[] values = selector switch
        {
            0 => [],
            1 => [null, null, null, null],
            2 => [11, 22, 33],
            _ => [long.MinValue, 0, 17, null, long.MaxValue]
        };
        var schema = new ParquetSchema([
            ColumnDefinition.OptionalLeaf("optional-int64-dictionary", ParquetPhysicalType.Int64,
                new ColumnOptions(encodings: ImmutableArray.Create(EncodingKind.RleDictionary)))
        ]);

        using var stream = new MemoryStream();
        using (var writer = schema.CreateWriter(stream, new ParquetWriterOptions
        {
            Compression = CompressionKind.None,
            TargetDataPageSizeBytes = 64,
            WritePageIndexes = true
        }))
        {
            var column = writer.CreateSerializedColumn<long?>(schema.LeafColumns[0]);
            column.Serialize(values);
            writer.StartRowGroup().Write(column);
            writer.CloseFile();
        }

        using var reader = schema.CreateReader(new MemoryReadSource(stream.ToArray()));
        if (reader.RowGroups.Count != 1 || reader.RowGroups[0].RowCount != (ulong)values.Length)
            throw new InvalidOperationException("Optional INT64 dictionary boundary changed row-group shape.");
        var index = 0;
        foreach (var batch in reader.RowGroups[0].Column<long?>(schema.LeafColumns[0]))
            foreach (var actual in batch.Values)
            {
                if (index >= values.Length || actual != values[index])
                    throw new InvalidOperationException($"Optional INT64 dictionary boundary changed value {index}.");
                index++;
            }
        if (index != values.Length)
            throw new InvalidOperationException("Optional INT64 dictionary boundary returned the wrong value count.");
    }
}
