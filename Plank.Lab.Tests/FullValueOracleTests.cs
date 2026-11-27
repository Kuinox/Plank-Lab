using System.Collections.Immutable;
using Plank.Fuzzing;
using Plank.Schema;
using Plank.Writing;
using PlankColumn = Plank.Schema.ColumnDefinition;
using PlankSchema = Plank.Schema.ParquetSchema;

namespace Plank.Tests;

/// <summary>
/// The full-value oracle (Plank.Fuzzing/FullValueOracle.cs) must stay silent on correct
/// files, and each case here pins one of its checks on a small Plank-written file.
/// </summary>
internal sealed class FullValueOracleTests
{
    static readonly ParquetBloomFilterOptions Bloom = ParquetBloomFilterOptions.Default;

    static byte[] Write<T>(ParquetPhysicalType type, T[] values, bool optional = false, LogicalType? logical = null,
        uint typeLength = 0, EncodingKind? encoding = null, bool bloom = false, uint pageBytes = 0)
    {
        var options = new ColumnOptions(optional ? ParquetRepetition.Optional : ParquetRepetition.Required,
            encodings: encoding is { } e ? ImmutableArray.Create(e) : default, typeLength: typeLength,
            bloomFilter: bloom ? Bloom : null);
        var schema = new PlankSchema([optional
            ? PlankColumn.OptionalLeaf("c", type, options, logical)
            : PlankColumn.RequiredLeaf("c", type, options, logical)]);
        using var stream = new MemoryStream();
        var writerOptions = new ParquetWriterOptions
        {
            WritePageIndexes = true,
            TargetDataPageSizeBytes = pageBytes != 0 ? pageBytes : ParquetWriterOptions.Default.TargetDataPageSizeBytes
        };
        var writer = schema.CreateWriter(stream, writerOptions);
        var column = writer.CreateSerializedColumn<T>(schema.LeafColumns[0]);
        column.Serialize(values);
        writer.StartRowGroup().Write(column);
        writer.CloseFile();
        return stream.ToArray();
    }

    [Test]
    public void CleanFiles_ProduceNoMismatch()
    {
        var ints = Enumerable.Range(0, 3000).Select(static i => (i * 7919) % 1000 - 500).ToArray();
        FullValueOracle.VerifyWritten(Write(ParquetPhysicalType.Int32, ints, bloom: true, pageBytes: 512));
        FullValueOracle.VerifyWritten(Write(ParquetPhysicalType.Int32, ints.Select(static i => (int?)(i % 3 == 0 ? null : i)).ToArray(),
            optional: true, bloom: true, pageBytes: 256));
        FullValueOracle.VerifyWritten(Write(ParquetPhysicalType.Int64, ints.Select(static i => (long)i << 33).ToArray(),
            encoding: EncodingKind.DeltaBinaryPacked, bloom: true, pageBytes: 512));
        FullValueOracle.VerifyWritten(Write(ParquetPhysicalType.Double, ints.Select(static i => i / 3.0).ToArray(),
            encoding: EncodingKind.ByteStreamSplit, bloom: true, pageBytes: 512));
        FullValueOracle.VerifyWritten(Write(ParquetPhysicalType.ByteArray,
            ints.Select(static i => System.Text.Encoding.UTF8.GetBytes($"v{i}")).ToArray(), logical: new LogicalType.String(),
            bloom: true, pageBytes: 512));
        // Ascending data: the boundary order check runs on real pages.
        FullValueOracle.VerifyWritten(Write(ParquetPhysicalType.Int32, Enumerable.Range(0, 4000).ToArray(), pageBytes: 256));
    }

    // Parquet's Bloom filter hashes the plain encoding of the value. -0.0 and +0.0 have
    // different plain encodings (and NaN has many), so a filter built from canonicalised
    // bytes is missing values other readers will look up by their own bytes.
    [Test]
    [Arguments(0x80000000u)] // -0.0f
    [Arguments(0x7FC00001u)] // a NaN with payload
    public void FloatBloom_ContainsTheSpecHashOfEveryWrittenValue(uint bits)
    {
        var values = new[] { BitConverter.UInt32BitsToSingle(bits), 1f, 2f };
        FullValueOracle.VerifyWritten(Write(ParquetPhysicalType.Float, values, bloom: true));
    }

    [Test]
    [Arguments(0x8000000000000000ul)] // -0.0
    [Arguments(0x7FF8000000000001ul)] // a NaN with payload
    public void DoubleBloom_ContainsTheSpecHashOfEveryWrittenValue(ulong bits)
    {
        var values = new[] { BitConverter.UInt64BitsToDouble(bits), 1d, 2d };
        FullValueOracle.VerifyWritten(Write(ParquetPhysicalType.Double, values, bloom: true));
    }
}
