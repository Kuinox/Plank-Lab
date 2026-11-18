using Plank.Writing;

namespace Plank.Fuzzing;

/// <summary>Strict public-writer coverage for variable-width Row API slot growth.</summary>
internal static class RowApiGrowthWriterCases
{
    const int RowCount = 6;
    const int MaximumPayloadLength = 92;

    internal static void Execute(ReadOnlySpan<byte> data)
    {
        // Keep the input influence bounded and guarantee distinct row sizes so the
        // initial one-row slot must grow before the very large row-group boundary.
        var salt = data.IsEmpty ? (byte)0 : data[0];
        var expected = new (int Id, string Label, byte[] Payload)[RowCount];
        for (var i = 0; i < expected.Length; i++)
        {
            var length = 37 + i * 11;
            var payload = new byte[length];
            for (var j = 0; j < payload.Length; j++)
                payload[j] = unchecked((byte)(j * 17 + i + salt));
            expected[i] = (100 + i, $"growth-{i}-é", payload);
        }

        var bytes = new MemoryStream();
        using (var writer = RowFuzzBinary.CreateRowWriter(bytes, new ParquetWriterOptions
        {
            TargetRowGroupSizeBytes = ulong.MaxValue,
            RowApiInitialRowCapacity = 1,
            RowApiMaxParallelism = 1
        }))
        {
            foreach (var want in expected)
            {
                var row = writer.GetRow();
                row.Id = want.Id;
                row.Label = want.Label;
                row.Payload = want.Payload;
            }
            writer.Complete();
        }

        using var reader = RowFuzzBinary.CreateRowReader(new MemoryStream(bytes.ToArray(), writable: false));
        var index = 0;
        while (reader.MoveNext())
        {
            if (index >= expected.Length)
                throw new InvalidOperationException("Row API growth writer produced extra rows.");
            var actual = reader.Current;
            var want = expected[index];
            if (actual.Id != want.Id || !string.Equals(actual.Label, want.Label, StringComparison.Ordinal)
                || !actual.Payload.Value.SequenceEqual(want.Payload))
                throw new InvalidOperationException($"Row API growth writer changed row {index}.");
            index++;
        }

        if (index != expected.Length)
            throw new InvalidOperationException($"Row API growth writer returned {index} rows; expected {expected.Length}.");
    }
}
