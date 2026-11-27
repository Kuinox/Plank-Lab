using System.Runtime.InteropServices;
using Plank.Fuzzing;
using Plank.Reading;
using Plank.Reading.Logical;
using Plank.RowApi;
using Plank.Schema;
using Ps = ParquetSharp;

namespace Plank.Tests.Reading;

/// <summary>
/// Triage of the reader fault "Empty/null collection marker at position 1." on the eight
/// <c>nested-gap-map-*-rowapi</c> seeds (pyarrow-written MAP&lt;key, optional int32&gt; files, see
/// fuzz/nested-gap-generate.py). The question was whether the row API's
/// <c>RowReaderCore.GetCurrentNested</c> returns wrong levels or the harness's
/// <c>NestedRowMaterializer</c> misreads them. Here the levels and values the row API hands out
/// for each row are compared with Apache Arrow's (ParquetSharp) raw level streams of the same
/// file: they are identical, so the library is right and the fault was the harness's collection
/// levels (fixed in Plank-Lab c7c0011, which derives them from the schema).
/// </summary>
internal sealed class NestedMapRowApiLevelsTests
{
    static readonly string[] Seeds =
    [
        "reader-corpus/nested-gap-map-string-v1-rowapi",
        "reader-corpus/nested-gap-map-string-v2-rowapi",
        "reader-corpus/nested-gap-map-binary-v1-rowapi",
        "reader-corpus/nested-gap-map-binary-v2-rowapi",
        "reader-focused-seeds/nested-gap-map-string-v1-rowapi",
        "reader-focused-seeds/nested-gap-map-string-v2-rowapi",
        "reader-focused-seeds/nested-gap-map-binary-v1-rowapi",
        "reader-focused-seeds/nested-gap-map-binary-v2-rowapi",
    ];

    [Test]
    public void RowApiNestedLevelsMatchArrowOnNullMapValues()
    {
        foreach (var seed in Seeds)
        {
            // The first byte is the reader target's selector; the rest is the Parquet file.
            var file = File.ReadAllBytes(Path.Combine(FuzzDirectory(), seed))[1..];

            ParquetSchema schema;
            using (var probe = new ParquetReader())
            {
                probe.Reset(new MemoryReadSource(file));
                schema = probe.Schema;
            }
            if (schema.LeafColumns.Length != 2 || schema.LeafColumns[1].MaxDefinitionLevel != 3
                || schema.LeafColumns[1].MaxRepetitionLevel != 1)
                throw new InvalidOperationException($"{seed}: not the expected MAP<key, optional int32> schema.");

            // optional group c (MAP) { repeated group key_value { required key; optional int32 value; } }:
            // the map is defined at level 1 and has an entry at level 2; a null value is level 2 of 3.
            var key = new RowApiNestedColumnDescriptor<byte[]>("Key", schema.LeafColumns[0], new RowApiCollectionLevel(1, 1, 2));
            var value = new RowApiNestedColumnDescriptor<int>("Value", schema.LeafColumns[1], new RowApiCollectionLevel(1, 1, 2));
            var keyTrace = new Trace();
            var valueTrace = new Trace();
            var rows = 0;
            using (var reader = new RowReaderCore(new MemoryStream(file, writable: false), schema, [key, value],
                       projection: null, new RowReaderOptions(), schemaEvolution: null))
            {
                while (reader.MoveNext())
                {
                    var keyRow = reader.GetCurrentNested(key);
                    keyTrace.AddRow(keyRow.RepetitionLevels, keyRow.DefinitionLevels, keyRow.Values, static v => v);
                    var valueRow = reader.GetCurrentNested(value);
                    if (rows == 0)
                    {
                        // Row 0 is [("a", 1), ("b", null)]: the null value is definition level 2.
                        if (!valueRow.DefinitionLevels.SequenceEqual(new byte[] { 3, 2 })
                            || !valueRow.RepetitionLevels.SequenceEqual(new byte[] { 0, 1 })
                            || !valueRow.Values.SequenceEqual([1]))
                            throw new InvalidOperationException($"{seed}: row 0 value levels are not def [3,2] rep [0,1] values [1].");
                    }
                    valueTrace.AddRow(valueRow.RepetitionLevels, valueRow.DefinitionLevels, valueRow.Values,
                        static v => BitConverter.GetBytes(v));
                    rows++;
                }
            }
            if (rows != 4)
                throw new InvalidOperationException($"{seed}: row API returned {rows} rows, expected 4.");

            using var arrowStream = new MemoryStream(file, writable: false);
            using var arrow = new Ps.ParquetFileReader(arrowStream, leaveOpen: true);
            using var group = arrow.RowGroup(0);
            var arrowKey = new Trace();
            using (var column = group.Column(0))
                arrowKey.AddArrow((Ps.ColumnReader<Ps.ByteArray>)column, static v => Copy(v.Pointer, v.Length));
            var arrowValue = new Trace();
            using (var column = group.Column(1))
                arrowValue.AddArrow((Ps.ColumnReader<int>)column, static v => BitConverter.GetBytes(v));

            keyTrace.AssertEqual(arrowKey, $"{seed} key");
            valueTrace.AssertEqual(arrowValue, $"{seed} value");
        }
    }

    // The harness side: the same seeds through the reader target, which rebuilds each row's map
    // from those levels with NestedRowMaterializer and compares it with the column reader.
    [Test]
    public void ReaderTargetAcceptsNullMapValues()
    {
        foreach (var seed in Seeds)
            PlankReaderFuzzTarget.Execute(File.ReadAllBytes(Path.Combine(FuzzDirectory(), seed)));
    }

    static string FuzzDirectory()
    {
        for (var directory = new DirectoryInfo(AppContext.BaseDirectory); directory is not null; directory = directory.Parent)
        {
            var fuzz = Path.Combine(directory.FullName, "fuzz", "reader-corpus");
            if (Directory.Exists(fuzz))
                return Path.Combine(directory.FullName, "fuzz");
        }
        throw new DirectoryNotFoundException("fuzz/ not found above the test output directory.");
    }

    static byte[] Copy(IntPtr pointer, int length)
    {
        var bytes = new byte[length];
        if (length > 0)
            Marshal.Copy(pointer, bytes, 0, length);
        return bytes;
    }

    sealed class Trace
    {
        readonly List<int> _repetitions = [];
        readonly List<int> _definitions = [];
        readonly List<byte[]> _values = [];

        public void AddRow<T>(ReadOnlySpan<byte> repetitions, ReadOnlySpan<byte> definitions, ReadOnlySpan<T> values,
            Func<T, byte[]> toBytes)
        {
            if (repetitions.Length != definitions.Length || repetitions.Length == 0 || repetitions[0] != 0)
                throw new InvalidOperationException("A row API row does not start a record at repetition level 0.");
            for (var i = 1; i < repetitions.Length; i++)
                if (repetitions[i] == 0)
                    throw new InvalidOperationException("A row API row spans two records.");
            foreach (var r in repetitions) _repetitions.Add(r);
            foreach (var d in definitions) _definitions.Add(d);
            foreach (var v in values) _values.Add(toBytes(v));
        }

        public void AddArrow<T>(Ps.ColumnReader<T> reader, Func<T, byte[]> toBytes) where T : unmanaged
        {
            var values = new T[256];
            var definitions = new short[values.Length];
            var repetitions = new short[values.Length];
            while (reader.HasNext)
            {
                var levels = reader.ReadBatch(values.Length, definitions, repetitions, values, out var valuesRead);
                for (var i = 0; i < levels; i++)
                {
                    _definitions.Add(definitions[i]);
                    _repetitions.Add(repetitions[i]);
                }
                for (var i = 0; i < valuesRead; i++)
                    _values.Add(toBytes(values[i]));
            }
        }

        public void AssertEqual(Trace arrow, string what)
        {
            if (!_definitions.SequenceEqual(arrow._definitions))
                throw new InvalidOperationException($"{what}: definition levels differ: row API [{string.Join(",", _definitions)}], Arrow [{string.Join(",", arrow._definitions)}].");
            if (!_repetitions.SequenceEqual(arrow._repetitions))
                throw new InvalidOperationException($"{what}: repetition levels differ: row API [{string.Join(",", _repetitions)}], Arrow [{string.Join(",", arrow._repetitions)}].");
            if (_values.Count != arrow._values.Count || _values.Zip(arrow._values).Any(static p => !p.First.AsSpan().SequenceEqual(p.Second)))
                throw new InvalidOperationException($"{what}: values differ.");
        }
    }
}
