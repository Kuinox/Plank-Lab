using System.Collections.Immutable;
using Plank.Reading;
using Plank.Schema;
using Plank.Writing;
using Plank.Writing.PageStrategy;

namespace Plank.Fuzzing;

/// <summary>Writes a required INT32 dictionary with a 17-bit literal-index stream.</summary>
internal static class RequiredInt32Dictionary17WriterCase
{
    internal static void Execute()
    {
        const int uniqueCount = 65_537;
        var expected = new int[uniqueCount];
        for (var i = 0; i < expected.Length; i++)
            expected[i] = i;

        var schema = new ParquetSchema([
            ColumnDefinition.Leaf("required-int32-dictionary-17-bit", ParquetPhysicalType.Int32,
                new ColumnOptions(encodings: ImmutableArray.Create(EncodingKind.RleDictionary)),
                pageStrategy: ForceDictionaryPageStrategy.Shared)
        ]);
        using var stream = new MemoryStream();
        var writer = schema.CreateWriter(stream, new ParquetWriterOptions { Compression = CompressionKind.None });
        var column = writer.CreateSerializedColumn<int>(schema.LeafColumns[0]);
        column.Serialize(expected);
        writer.StartRowGroup().Write(column);
        writer.CloseFile();
        var bytes = stream.ToArray();

        using (var source = new MemoryReadSource(bytes))
        using (var reader = schema.CreateReader(source))
        {
            if (reader.RowGroups.Count != 1 || reader.RowGroups[0].RowCount != (ulong)uniqueCount)
                throw new InvalidOperationException("Required INT32 17-bit dictionary changed row-group shape.");
            var offset = 0;
            foreach (var page in reader.RowGroups[0].Column<int>(schema.LeafColumns[0]))
            {
                foreach (var value in page.Values)
                {
                    if (offset >= expected.Length || value != expected[offset])
                        throw new InvalidOperationException($"Required INT32 17-bit dictionary changed value {offset}.");
                    offset++;
                }
            }
            if (offset != expected.Length)
                throw new InvalidOperationException($"Required INT32 17-bit dictionary returned {offset} values.");
        }

        VerifyParquetSharpReadback(bytes, expected);
    }

    static void VerifyParquetSharpReadback(byte[] bytes, int[] expected)
    {
        var path = Path.Combine(Path.GetTempPath(), $"plank-required-int32-dictionary17-{Guid.NewGuid():N}.parquet");
        try
        {
            File.WriteAllBytes(path, bytes);
            using var reader = new ParquetSharp.ParquetFileReader(path);
            if (reader.FileMetaData.NumRowGroups != 1)
                throw new InvalidOperationException("ParquetSharp required INT32 dictionary row-group count changed.");
            using var rowGroup = reader.RowGroup(0);
            if (rowGroup.MetaData.NumRows != expected.Length)
                throw new InvalidOperationException("ParquetSharp required INT32 dictionary row count changed.");
            var actual = rowGroup.Column(0).LogicalReader<int>().ReadAll(expected.Length);
            if (!actual.AsSpan().SequenceEqual(expected))
                throw new InvalidOperationException("ParquetSharp required INT32 dictionary values changed.");
        }
        finally
        {
            File.Delete(path);
        }
    }
}
