using Plank.Schema;
using Plank.Reading;
using Plank.Writing;

namespace Plank.Fuzzing;

/// <summary>Exercises the public append/merge schema checks with matching and mismatching definitions.</summary>
internal static class MutationSchemaCoverageCases
{
    internal static void Run()
    {
        CheckCompositeSchema();
        CheckMatchPair("logical-match", ColumnDefinition.RequiredLeaf("value", ParquetPhysicalType.Int32,
            logicalType: new LogicalType.Date()));
        CheckMatchPair("fixed-length-match", ColumnDefinition.RequiredLeaf("value",
            ParquetPhysicalType.FixedLenByteArray, options: new ColumnOptions(typeLength: 4)));
        CheckUnspecifiedRepetition();
        CheckReorderedFields();
        CheckOmittedGroupChild();
        CheckPair("name", ColumnDefinition.RequiredLeaf("value", ParquetPhysicalType.Int32),
            ColumnDefinition.RequiredLeaf("renamed", ParquetPhysicalType.Int32));
        CheckPair("physical-type", ColumnDefinition.RequiredLeaf("value", ParquetPhysicalType.Int32),
            ColumnDefinition.RequiredLeaf("value", ParquetPhysicalType.Int64));
        CheckPair("repetition", ColumnDefinition.RequiredLeaf("value", ParquetPhysicalType.Int32),
            ColumnDefinition.OptionalLeaf("value", ParquetPhysicalType.Int32));
        CheckPair("field-id", ColumnDefinition.RequiredLeaf("value", ParquetPhysicalType.Int32, 3),
            ColumnDefinition.RequiredLeaf("value", ParquetPhysicalType.Int32, 4));
        CheckPair("logical-type", ColumnDefinition.RequiredLeaf("value", ParquetPhysicalType.Int32,
                logicalType: new LogicalType.Date()),
            ColumnDefinition.RequiredLeaf("value", ParquetPhysicalType.Int32));
        CheckPair("fixed-length", ColumnDefinition.RequiredLeaf("value", ParquetPhysicalType.FixedLenByteArray,
                options: new ColumnOptions(typeLength: 4)),
            ColumnDefinition.RequiredLeaf("value", ParquetPhysicalType.FixedLenByteArray,
                options: new ColumnOptions(typeLength: 8)));
    }

    static void CheckCompositeSchema()
    {
        var schema = new ParquetSchema([
            ColumnDefinition.RequiredGroup("group", ColumnDefinition.RequiredLeaf("inside", ParquetPhysicalType.Int32)),
            ColumnDefinition.List("items", ColumnDefinition.RequiredLeaf("element", ParquetPhysicalType.Int32)),
            ColumnDefinition.Map("lookup", ColumnDefinition.RequiredLeaf("key", ParquetPhysicalType.Int32),
                ColumnDefinition.OptionalLeaf("value", ParquetPhysicalType.ByteArray))
        ]);
        Check(schema, WriteEmptyFile(schema), shouldMatch: true, "matching-group-list-map");
    }

    static void CheckPair(string label, ColumnDefinition sourceDefinition, ColumnDefinition proposedDefinition)
    {
        var sourceSchema = new ParquetSchema([sourceDefinition]);
        Check(new ParquetSchema([proposedDefinition]), WriteEmptyFile(sourceSchema), shouldMatch: false, label);
    }

    static void CheckMatchPair(string label, ColumnDefinition definition)
    {
        var schema = new ParquetSchema([definition]);
        Check(schema, WriteEmptyFile(schema), shouldMatch: true, label);
    }

    static void CheckUnspecifiedRepetition()
    {
        var sourceDefinition = ColumnDefinition.RequiredLeaf("value", ParquetPhysicalType.Int32);
        var sourceSchema = new ParquetSchema([sourceDefinition]);
        var proposed = new ParquetSchema([sourceDefinition with { Repetition = ParquetRepetition.Unspecified }]);
        Check(proposed, WriteEmptyFile(sourceSchema), shouldMatch: true, "unspecified-repetition");
    }

    static void CheckReorderedFields()
    {
        var first = ColumnDefinition.RequiredLeaf("first", ParquetPhysicalType.Int32);
        var second = ColumnDefinition.RequiredLeaf("second", ParquetPhysicalType.Int64);
        var sourceSchema = new ParquetSchema([first, second]);
        Check(new ParquetSchema([second, first]), WriteEmptyFile(sourceSchema), shouldMatch: false,
            "reordered-fields");
    }

    static void CheckOmittedGroupChild()
    {
        var first = ColumnDefinition.RequiredLeaf("first", ParquetPhysicalType.Int32);
        var second = ColumnDefinition.RequiredLeaf("second", ParquetPhysicalType.Int64);
        var sourceSchema = new ParquetSchema([ColumnDefinition.RequiredGroup("group", first, second)]);
        var proposed = new ParquetSchema([ColumnDefinition.RequiredGroup("group", first)]);
        Check(proposed, WriteEmptyFile(sourceSchema), shouldMatch: false, "omitted-group-child");
    }

    static byte[] WriteEmptyFile(ParquetSchema schema)
    {
        using var stream = new MemoryStream();
        var writer = schema.CreateWriter(stream, new ParquetWriterOptions { Compression = CompressionKind.None });
        writer.CloseFile();
        return stream.ToArray();
    }

    static void Check(ParquetSchema schema, byte[] bytes, bool shouldMatch, string label)
    {
        using var source = FullValueOracle.Source(bytes);
        using var destination = new MemoryDestination();
        var rejected = false;
        try
        {
            var merger = schema.CreateMerger(source, destination, new ParquetMergeOptions
            {
                WriterOptions = new ParquetWriterOptions { Compression = CompressionKind.None }
            });
            merger.CloseFile();
        }
        catch (InvalidOperationException exception) when (!shouldMatch)
        {
            rejected = true;
            var kind = exception.Message.StartsWith("Cannot append or merge:", StringComparison.Ordinal)
                ? "validator" : "preempted";
            Console.WriteLine($"{label}: {kind}: {exception.Message}");
        }
        if (rejected != !shouldMatch)
            throw new PlankMergerFuzzTarget.MergeException(shouldMatch
                ? "A matching mutation schema was rejected."
                : "A mismatching mutation schema was accepted.");
    }

    sealed class MemoryDestination : IParquetReadWriteSource
    {
        readonly MemoryStream _stream = new();
        public ulong Length => (ulong)_stream.Length;
        public void Open(ReadOnlySpan<byte> path, FileMode mode) { if (mode == FileMode.Create) _stream.SetLength(0); }
        public void Close() { }
        public void Write(ulong offset, ReadOnlySpan<byte> source)
        {
            var end = offset + (ulong)source.Length;
            if (_stream.Length < (long)end) _stream.SetLength((long)end);
            _stream.Position = (long)offset;
            _stream.Write(source);
        }
        public void SetLength(ulong length) => _stream.SetLength((long)length);
        public void Flush() { }
        public void ReadExactly(ulong offset, Span<byte> destination)
        {
            _stream.Position = (long)offset;
            _stream.ReadExactly(destination);
        }
        public void Dispose() => _stream.Dispose();
    }
}
