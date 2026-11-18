using System.Collections.Immutable;
using Plank.Reading;
using Plank.Schema;
using Plank.Writing;

namespace Plank.Fuzzing;

/// <summary>Exercises nullable DOUBLE dictionary fast-path boundaries and page paths.</summary>
internal static class OptionalDoubleDictionaryCoverageCases
{
    internal static void Execute(ReadOnlySpan<byte> data)
    {
        var empty = !data.IsEmpty && data[0] == 0xEE;
        var includesNull = !data.IsEmpty && data[0] == 0xEC;
        var allNan = !data.IsEmpty && data[0] == 0xE0;
        var requiredSchema = !data.IsEmpty && data[0] == 0xE1;
        var primesAscendingOrder = !data.IsEmpty && data[0] == 0xEA;
        var primesDescendingOrder = !data.IsEmpty && data[0] == 0xED;
        var descendingWithDuplicates = !data.IsEmpty && (data[0] & 1) != 0;
        var values = empty ? [] : new double?[1024];
        for (var i = 0; i < values.Length; i++)
            values[i] = includesNull && i == values.Length / 2
                ? null
                : allNan ? double.NaN
                : descendingWithDuplicates ? 1024d - i / 2 : i;

        var columnOptions = new ColumnOptions(requiredSchema ? ParquetRepetition.Required : ParquetRepetition.Optional,
            encodings: ImmutableArray.Create(EncodingKind.RleDictionary));
        var columnDefinition = requiredSchema
            ? ColumnDefinition.RequiredLeaf("nullable-double-dictionary", ParquetPhysicalType.Double, columnOptions)
            : ColumnDefinition.OptionalLeaf("nullable-double-dictionary", ParquetPhysicalType.Double, columnOptions);
        var schema = new ParquetSchema([columnDefinition]);
        using var stream = new MemoryStream();
        using (var writer = schema.CreateWriter(stream, new ParquetWriterOptions
        {
            Compression = CompressionKind.None,
            TargetDataPageSizeBytes = 64,
            WritePageIndexes = true
        }))
        {
            var serialized = writer.CreateSerializedColumn<double?>(schema.LeafColumns[0]);
            if (requiredSchema)
            {
                try
                {
                    serialized.Serialize(values);
                }
                catch (InvalidOperationException exception)
                    when (exception.Message == "Column 'nullable-double-dictionary' does not support null values.")
                {
                    return;
                }

                throw new InvalidOperationException("Required DOUBLE accepted nullable values unexpectedly.");
            }
            if (primesAscendingOrder || primesDescendingOrder)
            {
                var primingValues = new double?[1024];
                for (var i = 0; i < primingValues.Length; i++)
                    primingValues[i] = i == primingValues.Length / 2
                        ? null
                        : primesDescendingOrder ? 1024d - i : i;
                serialized.Serialize(primingValues);
                writer.StartRowGroup().Write(serialized);
            }
            serialized.Serialize(values);
            writer.StartRowGroup().Write(serialized);
            writer.CloseFile();
        }

        var bytes = stream.ToArray();
        using (var source = new MemoryReadSource(bytes))
        using (var reader = schema.CreateReader(source))
        {
            var expectedGroups = primesAscendingOrder || primesDescendingOrder ? 2 : 1;
            if (reader.RowGroups.Count != expectedGroups)
                throw new InvalidOperationException("Nullable DOUBLE dictionary row-group count changed.");
            for (var groupIndex = 0; groupIndex < expectedGroups; groupIndex++)
            {
                var expected = groupIndex == 0 && expectedGroups == 2
                    ? CreatePrimingValues(primesDescendingOrder)
                    : values;
                if (reader.RowGroups[groupIndex].RowCount != (ulong)expected.Length)
                    throw new InvalidOperationException("Nullable DOUBLE dictionary row-group shape changed.");
                var index = 0;
                foreach (var batch in reader.RowGroups[groupIndex].Column<double?>(schema.LeafColumns[0]))
                    foreach (var actual in batch.Values)
                    {
                        if (index >= expected.Length || !SameDouble(actual, expected[index]))
                            throw new InvalidOperationException($"Nullable DOUBLE dictionary value {index} changed.");
                        index++;
                    }
                if (index != expected.Length)
                    throw new InvalidOperationException("Nullable DOUBLE dictionary value count changed.");
            }
        }

        var path = Path.Combine(Path.GetTempPath(), $"plank-optional-double-dict-{Guid.NewGuid():N}.parquet");
        try
        {
            File.WriteAllBytes(path, bytes);
            using var reader = new ParquetSharp.ParquetFileReader(path);
            for (var groupIndex = 0; groupIndex < (primesAscendingOrder || primesDescendingOrder ? 2 : 1); groupIndex++)
            {
                using var group = reader.RowGroup(groupIndex);
                var expected = groupIndex == 0 && (primesAscendingOrder || primesDescendingOrder)
                    ? CreatePrimingValues(primesDescendingOrder)
                    : values;
                var actual = group.Column(0).LogicalReader<double?>().ReadAll(expected.Length);
                if (actual.Length != expected.Length
                    || actual.Where((value, index) => !SameDouble(value, expected[index])).Any())
                    throw new InvalidOperationException("ParquetSharp nullable DOUBLE dictionary values changed.");
            }
        }
        finally
        {
            File.Delete(path);
        }
    }

    static double?[] CreatePrimingValues(bool descending)
    {
        var values = new double?[1024];
        for (var i = 0; i < values.Length; i++)
            values[i] = i == values.Length / 2 ? null : descending ? 1024d - i : i;
        return values;
    }

    static bool SameDouble(double? left, double? right)
        => left.HasValue == right.HasValue
           && (!left.HasValue || BitConverter.DoubleToInt64Bits(left.Value)
               == BitConverter.DoubleToInt64Bits(right!.Value));
}
