using Plank.Schema;
using Plank.Writing;
using System.Collections.Immutable;
using Plank.Reading;
using Plank.Reading.Logical;
using PlankColumn = Plank.Schema.ColumnDefinition;
using PlankSchema = Plank.Schema.ParquetSchema;

namespace Plank.Tests;

/// <summary>
/// Repro for fuzz/repros/append-floating-sort-metadata: appending correctly ordered values
/// to a sorted FLOAT/DOUBLE row group must keep its sorting metadata.
/// </summary>
internal sealed class AppendFloatingSortMetadataTests
{
    static int SortingAfterAppend<T>(ParquetPhysicalType type, T[] retained, T[] incoming, bool descending,
        EncodingKind? encoding,
        Func<ParquetSortingColumn[], ParquetWriterOptions> make)
    {
        var schema = new PlankSchema([encoding is { } e ? PlankColumn.RequiredLeaf("key", type, new ColumnOptions(encodings: ImmutableArray.Create(e))) : PlankColumn.RequiredLeaf("key", type)]);
        var sorting = new ParquetSortingColumn(0, descending, false);
        var options = make([sorting]);
        using var initial = new MemoryStream();
        var writer = schema.CreateWriter(initial, options);
        var col = writer.CreateSerializedColumn<T>(schema.LeafColumns[0]);
        col.Serialize(retained);
        writer.StartRowGroup().Write(col);
        writer.CloseFile();

        var stream = new MemoryStream();
        stream.Write(initial.ToArray());
        stream.Position = 0;
        var appender = schema.CreateAppender(stream, new ParquetAppendOptions
        {
            AppendToLatestRowGroup = true,
            WriterOptions = options
        });
        var appended = appender.CreateSerializedColumn<T>(schema.LeafColumns[0]);
        appended.Serialize(incoming);
        appender.StartRowGroup().Write(appended);
        appender.CloseFile();
        using var reader = new Plank.Reading.Physical.ParquetFileReader();
        reader.Reset(new MemoryStream(stream.ToArray()));
        return reader.Metadata.RowGroupSortingColumns(0).Length;
    }

    static Func<ParquetSortingColumn[], ParquetWriterOptions> Options(bool crc, bool idx, int page, int chunk) => s => new()
    {
        SortingColumns = [.. s], WritePageCrc = crc, WritePageIndexes = idx,
        TargetDataPageSizeBytes = (uint)page, BufferChunkSizeBytes = (uint)chunk
    };

    // The library is correct: ordered appended values keep the metadata, whatever the page/encoding options.
    [Test]
    public void OrderedAppend_KeepsSortingMetadata()
    {
        var paged = Options(true, true, 64, 128);
        foreach (var enc in new EncodingKind?[] { null, EncodingKind.Plain, EncodingKind.ByteStreamSplit })
        {
            Assert(SortingAfterAppend(ParquetPhysicalType.Double, new[] { 0d, 1.75, 3.5, 5.25, 7 },
                new[] { 8.75, 10.5, 12.25, 14, 15.75 }, false, enc, paged));
            Assert(SortingAfterAppend(ParquetPhysicalType.Float, new[] { 0f, -2.25f, -4.5f },
                new[] { -6.75f, -9f, -11.25f }, true, enc, paged));
        }
    }

    // What the old harness actually generated: incoming was derived from a not yet filled retained[^1] (== 0),
    // so incoming[0..] = 1.75, 3.5, ... sits BELOW the last retained value 7. Dropping the metadata is correct.
    [Test]
    public void UnorderedAppend_DropsSortingMetadata()
    {
        var paged = Options(true, true, 64, 128);
        if (SortingAfterAppend(ParquetPhysicalType.Double, new[] { 0d, 1.75, 3.5, 5.25, 7 },
                new[] { 1.75, 3.5, 5.25, 7, 8.75 }, false, null, paged) != 0)
            throw new InvalidOperationException("Out-of-order append kept sorting metadata.");
        if (SortingAfterAppend(ParquetPhysicalType.Float, new[] { 0f, -2.25f, -4.5f },
                new[] { -2.25f, -4.5f, -6.75f }, true, null, paged) != 0)
            throw new InvalidOperationException("Out-of-order append kept sorting metadata.");
    }

    // The two seeds of fuzz/repros/append-floating-sort-metadata; they faulted before the harness fix.
    [Test]
    public void ReproSeeds_NoLongerFault()
    {
        Plank.Fuzzing.PlankWriterFuzzTarget.Execute(new byte[] { 0xF8, 0x03, 0x00, 0x02, 0x02, 0x80 });
        Plank.Fuzzing.PlankWriterFuzzTarget.Execute(new byte[] { 0xF8, 0x04, 0x01, 0x03, 0x04, 0x80 });
    }

    static void Assert(int sortingColumns)
    {
        if (sortingColumns != 1)
            throw new InvalidOperationException($"Ordered append wrote {sortingColumns} sorting columns; expected 1.");
    }
}
