using System.Runtime.InteropServices;
using System.Text;
using System.Text.Json.Serialization;
using BenchmarkDotNet.Attributes;
using Parquet;
using Parquet.Serialization;
using ParquetSharp;
using ParquetSharp.IO;
using ParquetSharp.RowOriented;
using Plank.Reading;
using Plank.RowApi;
using Plank.Schema;
using Plank.Writing;
using NativeBuffer = ParquetSharp.IO.Buffer;
using Encoding = System.Text.Encoding;
using LogicalType = ParquetSharp.LogicalType;
using TimeUnit = ParquetSharp.TimeUnit;
using ParquetDataPageVersion = Plank.Writing.ParquetDataPageVersion;

namespace Plank.Benchmarks;

[ParquetSchema]
sealed partial class SyntheticStringDeltaByteArrayPlankRow
{
    [ParquetColumn("value_0", Encodings = [EncodingKind.DeltaByteArray], LogicalType = LogicalTypeKind.String), MapToColumn("value_0"), JsonPropertyName("value_0")]
    public ReadOnlyMemory<byte> Value0 { get; set; }

    [ParquetColumn("value_1", Encodings = [EncodingKind.DeltaByteArray], LogicalType = LogicalTypeKind.String), MapToColumn("value_1"), JsonPropertyName("value_1")]
    public ReadOnlyMemory<byte> Value1 { get; set; }

    [ParquetColumn("value_2", Encodings = [EncodingKind.DeltaByteArray], LogicalType = LogicalTypeKind.String), MapToColumn("value_2"), JsonPropertyName("value_2")]
    public ReadOnlyMemory<byte> Value2 { get; set; }

    [ParquetColumn("value_3", Encodings = [EncodingKind.DeltaByteArray], LogicalType = LogicalTypeKind.String), MapToColumn("value_3"), JsonPropertyName("value_3")]
    public ReadOnlyMemory<byte> Value3 { get; set; }

    [ParquetColumn("value_4", Encodings = [EncodingKind.DeltaByteArray], LogicalType = LogicalTypeKind.String), MapToColumn("value_4"), JsonPropertyName("value_4")]
    public ReadOnlyMemory<byte> Value4 { get; set; }

    [ParquetColumn("value_5", Encodings = [EncodingKind.DeltaByteArray], LogicalType = LogicalTypeKind.String), MapToColumn("value_5"), JsonPropertyName("value_5")]
    public ReadOnlyMemory<byte> Value5 { get; set; }

    [ParquetColumn("value_6", Encodings = [EncodingKind.DeltaByteArray], LogicalType = LogicalTypeKind.String), MapToColumn("value_6"), JsonPropertyName("value_6")]
    public ReadOnlyMemory<byte> Value6 { get; set; }

    [ParquetColumn("value_7", Encodings = [EncodingKind.DeltaByteArray], LogicalType = LogicalTypeKind.String), MapToColumn("value_7"), JsonPropertyName("value_7")]
    public ReadOnlyMemory<byte> Value7 { get; set; }

    [ParquetColumn("value_8", Encodings = [EncodingKind.DeltaByteArray], LogicalType = LogicalTypeKind.String), MapToColumn("value_8"), JsonPropertyName("value_8")]
    public ReadOnlyMemory<byte> Value8 { get; set; }

    [ParquetColumn("value_9", Encodings = [EncodingKind.DeltaByteArray], LogicalType = LogicalTypeKind.String), MapToColumn("value_9"), JsonPropertyName("value_9")]
    public ReadOnlyMemory<byte> Value9 { get; set; }

    [ParquetColumn("value_10", Encodings = [EncodingKind.DeltaByteArray], LogicalType = LogicalTypeKind.String), MapToColumn("value_10"), JsonPropertyName("value_10")]
    public ReadOnlyMemory<byte> Value10 { get; set; }

    [ParquetColumn("value_11", Encodings = [EncodingKind.DeltaByteArray], LogicalType = LogicalTypeKind.String), MapToColumn("value_11"), JsonPropertyName("value_11")]
    public ReadOnlyMemory<byte> Value11 { get; set; }

    [ParquetColumn("value_12", Encodings = [EncodingKind.DeltaByteArray], LogicalType = LogicalTypeKind.String), MapToColumn("value_12"), JsonPropertyName("value_12")]
    public ReadOnlyMemory<byte> Value12 { get; set; }

    [ParquetColumn("value_13", Encodings = [EncodingKind.DeltaByteArray], LogicalType = LogicalTypeKind.String), MapToColumn("value_13"), JsonPropertyName("value_13")]
    public ReadOnlyMemory<byte> Value13 { get; set; }

    [ParquetColumn("value_14", Encodings = [EncodingKind.DeltaByteArray], LogicalType = LogicalTypeKind.String), MapToColumn("value_14"), JsonPropertyName("value_14")]
    public ReadOnlyMemory<byte> Value14 { get; set; }

    [ParquetColumn("value_15", Encodings = [EncodingKind.DeltaByteArray], LogicalType = LogicalTypeKind.String), MapToColumn("value_15"), JsonPropertyName("value_15")]
    public ReadOnlyMemory<byte> Value15 { get; set; }

    [ParquetColumn("value_16", Encodings = [EncodingKind.DeltaByteArray], LogicalType = LogicalTypeKind.String), MapToColumn("value_16"), JsonPropertyName("value_16")]
    public ReadOnlyMemory<byte> Value16 { get; set; }

    [ParquetColumn("value_17", Encodings = [EncodingKind.DeltaByteArray], LogicalType = LogicalTypeKind.String), MapToColumn("value_17"), JsonPropertyName("value_17")]
    public ReadOnlyMemory<byte> Value17 { get; set; }

    [ParquetColumn("value_18", Encodings = [EncodingKind.DeltaByteArray], LogicalType = LogicalTypeKind.String), MapToColumn("value_18"), JsonPropertyName("value_18")]
    public ReadOnlyMemory<byte> Value18 { get; set; }

    [ParquetColumn("value_19", Encodings = [EncodingKind.DeltaByteArray], LogicalType = LogicalTypeKind.String), MapToColumn("value_19"), JsonPropertyName("value_19")]
    public ReadOnlyMemory<byte> Value19 { get; set; }

    [ParquetColumn("value_20", Encodings = [EncodingKind.DeltaByteArray], LogicalType = LogicalTypeKind.String), MapToColumn("value_20"), JsonPropertyName("value_20")]
    public ReadOnlyMemory<byte> Value20 { get; set; }

    [ParquetColumn("value_21", Encodings = [EncodingKind.DeltaByteArray], LogicalType = LogicalTypeKind.String), MapToColumn("value_21"), JsonPropertyName("value_21")]
    public ReadOnlyMemory<byte> Value21 { get; set; }

    public static SyntheticStringDeltaByteArrayPlankRow[] CreateRows(int count)
    {
        var rows = new SyntheticStringDeltaByteArrayPlankRow[count];
        for (var row = 0; row < rows.Length; row++)
            rows[row] = new SyntheticStringDeltaByteArrayPlankRow
            {
                Value0 = BenchmarkData.Utf8Values[(row * 37 + 0 * 1009) & 2047],
                Value1 = BenchmarkData.Utf8Values[(row * 37 + 1 * 1009) & 2047],
                Value2 = BenchmarkData.Utf8Values[(row * 37 + 2 * 1009) & 2047],
                Value3 = BenchmarkData.Utf8Values[(row * 37 + 3 * 1009) & 2047],
                Value4 = BenchmarkData.Utf8Values[(row * 37 + 4 * 1009) & 2047],
                Value5 = BenchmarkData.Utf8Values[(row * 37 + 5 * 1009) & 2047],
                Value6 = BenchmarkData.Utf8Values[(row * 37 + 6 * 1009) & 2047],
                Value7 = BenchmarkData.Utf8Values[(row * 37 + 7 * 1009) & 2047],
                Value8 = BenchmarkData.Utf8Values[(row * 37 + 8 * 1009) & 2047],
                Value9 = BenchmarkData.Utf8Values[(row * 37 + 9 * 1009) & 2047],
                Value10 = BenchmarkData.Utf8Values[(row * 37 + 10 * 1009) & 2047],
                Value11 = BenchmarkData.Utf8Values[(row * 37 + 11 * 1009) & 2047],
                Value12 = BenchmarkData.Utf8Values[(row * 37 + 12 * 1009) & 2047],
                Value13 = BenchmarkData.Utf8Values[(row * 37 + 13 * 1009) & 2047],
                Value14 = BenchmarkData.Utf8Values[(row * 37 + 14 * 1009) & 2047],
                Value15 = BenchmarkData.Utf8Values[(row * 37 + 15 * 1009) & 2047],
                Value16 = BenchmarkData.Utf8Values[(row * 37 + 16 * 1009) & 2047],
                Value17 = BenchmarkData.Utf8Values[(row * 37 + 17 * 1009) & 2047],
                Value18 = BenchmarkData.Utf8Values[(row * 37 + 18 * 1009) & 2047],
                Value19 = BenchmarkData.Utf8Values[(row * 37 + 19 * 1009) & 2047],
                Value20 = BenchmarkData.Utf8Values[(row * 37 + 20 * 1009) & 2047],
                Value21 = BenchmarkData.Utf8Values[(row * 37 + 21 * 1009) & 2047],            };
        return rows;
    }

    public static byte[] CreateReadFile(SyntheticStringDeltaByteArrayPlankRow[] rows)
    {
        using var pool = new DefaultParquetBufferPool(ParquetBufferRetentionPolicy.ZeroAllocation);
        using var output = new MemoryStream();
        using var writer = CreateRowWriter(output, new ParquetWriterOptions
        {
            Compression = CompressionKind.None,
            BufferPool = pool,
            DataPageVersion = ParquetDataPageVersion.V2,
            WritePageIndexes = true,
            WritePageCrc = false,
            TargetRowGroupSizeBytes = 10000000UL,
            RowApiInitialRowCapacity = 45_455
        });
        foreach (var value in rows)
        {
            var row = writer.GetRow();
            row.Value0 = value.Value0;
            row.Value1 = value.Value1;
            row.Value2 = value.Value2;
            row.Value3 = value.Value3;
            row.Value4 = value.Value4;
            row.Value5 = value.Value5;
            row.Value6 = value.Value6;
            row.Value7 = value.Value7;
            row.Value8 = value.Value8;
            row.Value9 = value.Value9;
            row.Value10 = value.Value10;
            row.Value11 = value.Value11;
            row.Value12 = value.Value12;
            row.Value13 = value.Value13;
            row.Value14 = value.Value14;
            row.Value15 = value.Value15;
            row.Value16 = value.Value16;
            row.Value17 = value.Value17;
            row.Value18 = value.Value18;
            row.Value19 = value.Value19;
            row.Value20 = value.Value20;
            row.Value21 = value.Value21;
        }
        writer.Complete();
        return output.ToArray();
    }
    public static SyntheticStringDeltaByteArrayPlankRow[] FromSharp(SyntheticStringDeltaByteArraySharpRow[] source)
    {
        var rows = new SyntheticStringDeltaByteArrayPlankRow[source.Length];
        for (var index = 0; index < rows.Length; index++)
        {
            var value = source[index];
            rows[index] = new SyntheticStringDeltaByteArrayPlankRow
            {
                Value0 = new ReadOnlyMemory<byte>(Encoding.UTF8.GetBytes(value.Value0)),
                Value1 = new ReadOnlyMemory<byte>(Encoding.UTF8.GetBytes(value.Value1)),
                Value2 = new ReadOnlyMemory<byte>(Encoding.UTF8.GetBytes(value.Value2)),
                Value3 = new ReadOnlyMemory<byte>(Encoding.UTF8.GetBytes(value.Value3)),
                Value4 = new ReadOnlyMemory<byte>(Encoding.UTF8.GetBytes(value.Value4)),
                Value5 = new ReadOnlyMemory<byte>(Encoding.UTF8.GetBytes(value.Value5)),
                Value6 = new ReadOnlyMemory<byte>(Encoding.UTF8.GetBytes(value.Value6)),
                Value7 = new ReadOnlyMemory<byte>(Encoding.UTF8.GetBytes(value.Value7)),
                Value8 = new ReadOnlyMemory<byte>(Encoding.UTF8.GetBytes(value.Value8)),
                Value9 = new ReadOnlyMemory<byte>(Encoding.UTF8.GetBytes(value.Value9)),
                Value10 = new ReadOnlyMemory<byte>(Encoding.UTF8.GetBytes(value.Value10)),
                Value11 = new ReadOnlyMemory<byte>(Encoding.UTF8.GetBytes(value.Value11)),
                Value12 = new ReadOnlyMemory<byte>(Encoding.UTF8.GetBytes(value.Value12)),
                Value13 = new ReadOnlyMemory<byte>(Encoding.UTF8.GetBytes(value.Value13)),
                Value14 = new ReadOnlyMemory<byte>(Encoding.UTF8.GetBytes(value.Value14)),
                Value15 = new ReadOnlyMemory<byte>(Encoding.UTF8.GetBytes(value.Value15)),
                Value16 = new ReadOnlyMemory<byte>(Encoding.UTF8.GetBytes(value.Value16)),
                Value17 = new ReadOnlyMemory<byte>(Encoding.UTF8.GetBytes(value.Value17)),
                Value18 = new ReadOnlyMemory<byte>(Encoding.UTF8.GetBytes(value.Value18)),
                Value19 = new ReadOnlyMemory<byte>(Encoding.UTF8.GetBytes(value.Value19)),
                Value20 = new ReadOnlyMemory<byte>(Encoding.UTF8.GetBytes(value.Value20)),
                Value21 = new ReadOnlyMemory<byte>(Encoding.UTF8.GetBytes(value.Value21)),            };
        }
        return rows;
    }

    public static SyntheticStringDeltaByteArrayPlankRow[] FromNet(SyntheticStringDeltaByteArrayNetRow[] source)
    {
        var rows = new SyntheticStringDeltaByteArrayPlankRow[source.Length];
        for (var index = 0; index < rows.Length; index++)
        {
            var value = source[index];
            rows[index] = new SyntheticStringDeltaByteArrayPlankRow
            {
                Value0 = new ReadOnlyMemory<byte>(Encoding.UTF8.GetBytes(value.Value0)),
                Value1 = new ReadOnlyMemory<byte>(Encoding.UTF8.GetBytes(value.Value1)),
                Value2 = new ReadOnlyMemory<byte>(Encoding.UTF8.GetBytes(value.Value2)),
                Value3 = new ReadOnlyMemory<byte>(Encoding.UTF8.GetBytes(value.Value3)),
                Value4 = new ReadOnlyMemory<byte>(Encoding.UTF8.GetBytes(value.Value4)),
                Value5 = new ReadOnlyMemory<byte>(Encoding.UTF8.GetBytes(value.Value5)),
                Value6 = new ReadOnlyMemory<byte>(Encoding.UTF8.GetBytes(value.Value6)),
                Value7 = new ReadOnlyMemory<byte>(Encoding.UTF8.GetBytes(value.Value7)),
                Value8 = new ReadOnlyMemory<byte>(Encoding.UTF8.GetBytes(value.Value8)),
                Value9 = new ReadOnlyMemory<byte>(Encoding.UTF8.GetBytes(value.Value9)),
                Value10 = new ReadOnlyMemory<byte>(Encoding.UTF8.GetBytes(value.Value10)),
                Value11 = new ReadOnlyMemory<byte>(Encoding.UTF8.GetBytes(value.Value11)),
                Value12 = new ReadOnlyMemory<byte>(Encoding.UTF8.GetBytes(value.Value12)),
                Value13 = new ReadOnlyMemory<byte>(Encoding.UTF8.GetBytes(value.Value13)),
                Value14 = new ReadOnlyMemory<byte>(Encoding.UTF8.GetBytes(value.Value14)),
                Value15 = new ReadOnlyMemory<byte>(Encoding.UTF8.GetBytes(value.Value15)),
                Value16 = new ReadOnlyMemory<byte>(Encoding.UTF8.GetBytes(value.Value16)),
                Value17 = new ReadOnlyMemory<byte>(Encoding.UTF8.GetBytes(value.Value17)),
                Value18 = new ReadOnlyMemory<byte>(Encoding.UTF8.GetBytes(value.Value18)),
                Value19 = new ReadOnlyMemory<byte>(Encoding.UTF8.GetBytes(value.Value19)),
                Value20 = new ReadOnlyMemory<byte>(Encoding.UTF8.GetBytes(value.Value20)),
                Value21 = new ReadOnlyMemory<byte>(Encoding.UTF8.GetBytes(value.Value21)),            };
        }
        return rows;
    }

}

sealed partial class SyntheticStringDeltaByteArraySharpRow
{
    [MapToColumn("value_0"), JsonPropertyName("value_0")]
    public string Value0 { get; set; } = null!;

    [MapToColumn("value_1"), JsonPropertyName("value_1")]
    public string Value1 { get; set; } = null!;

    [MapToColumn("value_2"), JsonPropertyName("value_2")]
    public string Value2 { get; set; } = null!;

    [MapToColumn("value_3"), JsonPropertyName("value_3")]
    public string Value3 { get; set; } = null!;

    [MapToColumn("value_4"), JsonPropertyName("value_4")]
    public string Value4 { get; set; } = null!;

    [MapToColumn("value_5"), JsonPropertyName("value_5")]
    public string Value5 { get; set; } = null!;

    [MapToColumn("value_6"), JsonPropertyName("value_6")]
    public string Value6 { get; set; } = null!;

    [MapToColumn("value_7"), JsonPropertyName("value_7")]
    public string Value7 { get; set; } = null!;

    [MapToColumn("value_8"), JsonPropertyName("value_8")]
    public string Value8 { get; set; } = null!;

    [MapToColumn("value_9"), JsonPropertyName("value_9")]
    public string Value9 { get; set; } = null!;

    [MapToColumn("value_10"), JsonPropertyName("value_10")]
    public string Value10 { get; set; } = null!;

    [MapToColumn("value_11"), JsonPropertyName("value_11")]
    public string Value11 { get; set; } = null!;

    [MapToColumn("value_12"), JsonPropertyName("value_12")]
    public string Value12 { get; set; } = null!;

    [MapToColumn("value_13"), JsonPropertyName("value_13")]
    public string Value13 { get; set; } = null!;

    [MapToColumn("value_14"), JsonPropertyName("value_14")]
    public string Value14 { get; set; } = null!;

    [MapToColumn("value_15"), JsonPropertyName("value_15")]
    public string Value15 { get; set; } = null!;

    [MapToColumn("value_16"), JsonPropertyName("value_16")]
    public string Value16 { get; set; } = null!;

    [MapToColumn("value_17"), JsonPropertyName("value_17")]
    public string Value17 { get; set; } = null!;

    [MapToColumn("value_18"), JsonPropertyName("value_18")]
    public string Value18 { get; set; } = null!;

    [MapToColumn("value_19"), JsonPropertyName("value_19")]
    public string Value19 { get; set; } = null!;

    [MapToColumn("value_20"), JsonPropertyName("value_20")]
    public string Value20 { get; set; } = null!;

    [MapToColumn("value_21"), JsonPropertyName("value_21")]
    public string Value21 { get; set; } = null!;

    public static SyntheticStringDeltaByteArraySharpRow[] CreateRows(int count)
    {
        var rows = new SyntheticStringDeltaByteArraySharpRow[count];
        for (var row = 0; row < rows.Length; row++)
            rows[row] = new SyntheticStringDeltaByteArraySharpRow
            {
                Value0 = BenchmarkData.StringValues[(row * 37 + 0 * 1009) & 2047],
                Value1 = BenchmarkData.StringValues[(row * 37 + 1 * 1009) & 2047],
                Value2 = BenchmarkData.StringValues[(row * 37 + 2 * 1009) & 2047],
                Value3 = BenchmarkData.StringValues[(row * 37 + 3 * 1009) & 2047],
                Value4 = BenchmarkData.StringValues[(row * 37 + 4 * 1009) & 2047],
                Value5 = BenchmarkData.StringValues[(row * 37 + 5 * 1009) & 2047],
                Value6 = BenchmarkData.StringValues[(row * 37 + 6 * 1009) & 2047],
                Value7 = BenchmarkData.StringValues[(row * 37 + 7 * 1009) & 2047],
                Value8 = BenchmarkData.StringValues[(row * 37 + 8 * 1009) & 2047],
                Value9 = BenchmarkData.StringValues[(row * 37 + 9 * 1009) & 2047],
                Value10 = BenchmarkData.StringValues[(row * 37 + 10 * 1009) & 2047],
                Value11 = BenchmarkData.StringValues[(row * 37 + 11 * 1009) & 2047],
                Value12 = BenchmarkData.StringValues[(row * 37 + 12 * 1009) & 2047],
                Value13 = BenchmarkData.StringValues[(row * 37 + 13 * 1009) & 2047],
                Value14 = BenchmarkData.StringValues[(row * 37 + 14 * 1009) & 2047],
                Value15 = BenchmarkData.StringValues[(row * 37 + 15 * 1009) & 2047],
                Value16 = BenchmarkData.StringValues[(row * 37 + 16 * 1009) & 2047],
                Value17 = BenchmarkData.StringValues[(row * 37 + 17 * 1009) & 2047],
                Value18 = BenchmarkData.StringValues[(row * 37 + 18 * 1009) & 2047],
                Value19 = BenchmarkData.StringValues[(row * 37 + 19 * 1009) & 2047],
                Value20 = BenchmarkData.StringValues[(row * 37 + 20 * 1009) & 2047],
                Value21 = BenchmarkData.StringValues[(row * 37 + 21 * 1009) & 2047],            };
        return rows;
    }
}

sealed partial class SyntheticStringDeltaByteArrayNetRow
{
    [Parquet.Serialization.Attributes.ParquetRequired, MapToColumn("value_0"), JsonPropertyName("value_0")]
    public string Value0 { get; set; } = null!;

    [Parquet.Serialization.Attributes.ParquetRequired, MapToColumn("value_1"), JsonPropertyName("value_1")]
    public string Value1 { get; set; } = null!;

    [Parquet.Serialization.Attributes.ParquetRequired, MapToColumn("value_2"), JsonPropertyName("value_2")]
    public string Value2 { get; set; } = null!;

    [Parquet.Serialization.Attributes.ParquetRequired, MapToColumn("value_3"), JsonPropertyName("value_3")]
    public string Value3 { get; set; } = null!;

    [Parquet.Serialization.Attributes.ParquetRequired, MapToColumn("value_4"), JsonPropertyName("value_4")]
    public string Value4 { get; set; } = null!;

    [Parquet.Serialization.Attributes.ParquetRequired, MapToColumn("value_5"), JsonPropertyName("value_5")]
    public string Value5 { get; set; } = null!;

    [Parquet.Serialization.Attributes.ParquetRequired, MapToColumn("value_6"), JsonPropertyName("value_6")]
    public string Value6 { get; set; } = null!;

    [Parquet.Serialization.Attributes.ParquetRequired, MapToColumn("value_7"), JsonPropertyName("value_7")]
    public string Value7 { get; set; } = null!;

    [Parquet.Serialization.Attributes.ParquetRequired, MapToColumn("value_8"), JsonPropertyName("value_8")]
    public string Value8 { get; set; } = null!;

    [Parquet.Serialization.Attributes.ParquetRequired, MapToColumn("value_9"), JsonPropertyName("value_9")]
    public string Value9 { get; set; } = null!;

    [Parquet.Serialization.Attributes.ParquetRequired, MapToColumn("value_10"), JsonPropertyName("value_10")]
    public string Value10 { get; set; } = null!;

    [Parquet.Serialization.Attributes.ParquetRequired, MapToColumn("value_11"), JsonPropertyName("value_11")]
    public string Value11 { get; set; } = null!;

    [Parquet.Serialization.Attributes.ParquetRequired, MapToColumn("value_12"), JsonPropertyName("value_12")]
    public string Value12 { get; set; } = null!;

    [Parquet.Serialization.Attributes.ParquetRequired, MapToColumn("value_13"), JsonPropertyName("value_13")]
    public string Value13 { get; set; } = null!;

    [Parquet.Serialization.Attributes.ParquetRequired, MapToColumn("value_14"), JsonPropertyName("value_14")]
    public string Value14 { get; set; } = null!;

    [Parquet.Serialization.Attributes.ParquetRequired, MapToColumn("value_15"), JsonPropertyName("value_15")]
    public string Value15 { get; set; } = null!;

    [Parquet.Serialization.Attributes.ParquetRequired, MapToColumn("value_16"), JsonPropertyName("value_16")]
    public string Value16 { get; set; } = null!;

    [Parquet.Serialization.Attributes.ParquetRequired, MapToColumn("value_17"), JsonPropertyName("value_17")]
    public string Value17 { get; set; } = null!;

    [Parquet.Serialization.Attributes.ParquetRequired, MapToColumn("value_18"), JsonPropertyName("value_18")]
    public string Value18 { get; set; } = null!;

    [Parquet.Serialization.Attributes.ParquetRequired, MapToColumn("value_19"), JsonPropertyName("value_19")]
    public string Value19 { get; set; } = null!;

    [Parquet.Serialization.Attributes.ParquetRequired, MapToColumn("value_20"), JsonPropertyName("value_20")]
    public string Value20 { get; set; } = null!;

    [Parquet.Serialization.Attributes.ParquetRequired, MapToColumn("value_21"), JsonPropertyName("value_21")]
    public string Value21 { get; set; } = null!;

    public static SyntheticStringDeltaByteArrayNetRow[] CreateRows(int count)
    {
        var rows = new SyntheticStringDeltaByteArrayNetRow[count];
        for (var row = 0; row < rows.Length; row++)
            rows[row] = new SyntheticStringDeltaByteArrayNetRow
            {
                Value0 = BenchmarkData.StringValues[(row * 37 + 0 * 1009) & 2047],
                Value1 = BenchmarkData.StringValues[(row * 37 + 1 * 1009) & 2047],
                Value2 = BenchmarkData.StringValues[(row * 37 + 2 * 1009) & 2047],
                Value3 = BenchmarkData.StringValues[(row * 37 + 3 * 1009) & 2047],
                Value4 = BenchmarkData.StringValues[(row * 37 + 4 * 1009) & 2047],
                Value5 = BenchmarkData.StringValues[(row * 37 + 5 * 1009) & 2047],
                Value6 = BenchmarkData.StringValues[(row * 37 + 6 * 1009) & 2047],
                Value7 = BenchmarkData.StringValues[(row * 37 + 7 * 1009) & 2047],
                Value8 = BenchmarkData.StringValues[(row * 37 + 8 * 1009) & 2047],
                Value9 = BenchmarkData.StringValues[(row * 37 + 9 * 1009) & 2047],
                Value10 = BenchmarkData.StringValues[(row * 37 + 10 * 1009) & 2047],
                Value11 = BenchmarkData.StringValues[(row * 37 + 11 * 1009) & 2047],
                Value12 = BenchmarkData.StringValues[(row * 37 + 12 * 1009) & 2047],
                Value13 = BenchmarkData.StringValues[(row * 37 + 13 * 1009) & 2047],
                Value14 = BenchmarkData.StringValues[(row * 37 + 14 * 1009) & 2047],
                Value15 = BenchmarkData.StringValues[(row * 37 + 15 * 1009) & 2047],
                Value16 = BenchmarkData.StringValues[(row * 37 + 16 * 1009) & 2047],
                Value17 = BenchmarkData.StringValues[(row * 37 + 17 * 1009) & 2047],
                Value18 = BenchmarkData.StringValues[(row * 37 + 18 * 1009) & 2047],
                Value19 = BenchmarkData.StringValues[(row * 37 + 19 * 1009) & 2047],
                Value20 = BenchmarkData.StringValues[(row * 37 + 20 * 1009) & 2047],
                Value21 = BenchmarkData.StringValues[(row * 37 + 21 * 1009) & 2047],            };
        return rows;
    }
}

[MemoryDiagnoser]
public class SyntheticStringDeltaByteArrayPlankBenchmarks
{
    SyntheticStringDeltaByteArrayPlankRow[] _rows = null!;
    DefaultParquetBufferPool _pool = null!;
    ParquetWriterOptions _options = null!;
    SyntheticStringDeltaByteArrayPlankRow.PipelineWriter _writer = null!;
    MemoryStream _output = null!;
    int _outputCapacity;
    MemoryReadSource _source = null!;
    SyntheticStringDeltaByteArrayPlankRow.RowReader _reader = null!;
    PlankWorkerPinning _pinning = null!;

    public IEnumerable<int> RowCounts => [BenchmarkData.SyntheticRows];

    [ParamsSource(nameof(RowCounts))]
    public int Rows { get; set; }

    [GlobalSetup]
    public void Setup()
    {
        _rows = SyntheticStringDeltaByteArrayPlankRow.CreateRows(Rows);
        _pool = new DefaultParquetBufferPool(ParquetBufferRetentionPolicy.ZeroAllocation);
        _pinning = new PlankWorkerPinning();
        _options = new ParquetWriterOptions
        {
            Compression = CompressionKind.None,
            BufferPool = _pool,
            DataPageVersion = ParquetDataPageVersion.V2,
            WritePageIndexes = true,
            WritePageCrc = false,
            TargetRowGroupSizeBytes = 10000000UL,
            RowApiInitialRowCapacity = 45_455,
            Execution = new ParquetExecutionOptions { OnWorkerStarted = _pinning.OnWorkerStarted }
        };

        _output = new MemoryStream();
        _writer = SyntheticStringDeltaByteArrayPlankRow.CreateRowWriter(_output, _options);
        Write();
        var file = _output.ToArray();
        Console.WriteLine("BENCHMARK_FILE|SyntheticStringDeltaByteArray|Plank|" + file.Length);
        _outputCapacity = BenchmarkData.OutputCapacity(file.Length);
        _output.Dispose();

        _source = new MemoryReadSource(file);
        _reader = SyntheticStringDeltaByteArrayPlankRow.CreateRowReader(_source, options: new RowReaderOptions { BufferPool = _pool });
        _ = Read();
    }

    [IterationSetup(Target = nameof(Write))]
    public void SetupWrite()
    {
        _output = new MemoryStream(_outputCapacity);
        _writer.Reset(_output);
    }

    [IterationSetup(Target = nameof(Read))]
    public void SetupRead() => _reader.Reset(_source);

    [Benchmark]
    public void Write()
    {
        foreach (var value in _rows)
        {
            var row = _writer.GetRow();
            row.Value0 = value.Value0;
            row.Value1 = value.Value1;
            row.Value2 = value.Value2;
            row.Value3 = value.Value3;
            row.Value4 = value.Value4;
            row.Value5 = value.Value5;
            row.Value6 = value.Value6;
            row.Value7 = value.Value7;
            row.Value8 = value.Value8;
            row.Value9 = value.Value9;
            row.Value10 = value.Value10;
            row.Value11 = value.Value11;
            row.Value12 = value.Value12;
            row.Value13 = value.Value13;
            row.Value14 = value.Value14;
            row.Value15 = value.Value15;
            row.Value16 = value.Value16;
            row.Value17 = value.Value17;
            row.Value18 = value.Value18;
            row.Value19 = value.Value19;
            row.Value20 = value.Value20;
            row.Value21 = value.Value21;
        }
        _writer.Complete();
    }

    [Benchmark]
    public ulong Read()
    {
        ulong sum = 0;
        foreach (var row in _reader)
        {
            sum += (ulong)row.Value0.Length;
            sum += (ulong)row.Value1.Length;
            sum += (ulong)row.Value2.Length;
            sum += (ulong)row.Value3.Length;
            sum += (ulong)row.Value4.Length;
            sum += (ulong)row.Value5.Length;
            sum += (ulong)row.Value6.Length;
            sum += (ulong)row.Value7.Length;
            sum += (ulong)row.Value8.Length;
            sum += (ulong)row.Value9.Length;
            sum += (ulong)row.Value10.Length;
            sum += (ulong)row.Value11.Length;
            sum += (ulong)row.Value12.Length;
            sum += (ulong)row.Value13.Length;
            sum += (ulong)row.Value14.Length;
            sum += (ulong)row.Value15.Length;
            sum += (ulong)row.Value16.Length;
            sum += (ulong)row.Value17.Length;
            sum += (ulong)row.Value18.Length;
            sum += (ulong)row.Value19.Length;
            sum += (ulong)row.Value20.Length;
            sum += (ulong)row.Value21.Length;
        }
        return sum;
    }

    [IterationCleanup(Target = nameof(Write))]
    public void CleanupWrite() => _output.Dispose();

    [GlobalCleanup]
    public void Cleanup()
    {
        _writer.Dispose();
        _reader.Dispose();
        _source.Dispose();
        _pool.Dispose();
        _output.Dispose();
    }
}

[MemoryDiagnoser]
public class SyntheticStringDeltaByteArrayParquetSharpBenchmarks
{
    const int RowsPerRowGroup = 45455;

    SyntheticStringDeltaByteArraySharpRow[] _rows = null!;
    ParquetSharp.Column[] _schema = null!;
    WriterProperties _properties = null!;
    MemoryStream _output = null!;
    ManagedOutputStream _managedOutput = null!;
    ParquetRowWriter<SyntheticStringDeltaByteArraySharpRow> _writer = null!;
    int _outputCapacity;
    GCHandle _pinned;
    NativeBuffer _buffer = null!;
    BufferReader _source = null!;
    ParquetRowReader<SyntheticStringDeltaByteArraySharpRow>? _reader;

    public IEnumerable<int> RowCounts => [BenchmarkData.SyntheticRows];

    [ParamsSource(nameof(RowCounts))]
    public int Rows { get; set; }

    [GlobalSetup]
    public void Setup()
    {
        _rows = SyntheticStringDeltaByteArraySharpRow.CreateRows(Rows);
        _schema =
        [
            new ParquetSharp.Column<string>("value_0", LogicalType.String()),
            new ParquetSharp.Column<string>("value_1", LogicalType.String()),
            new ParquetSharp.Column<string>("value_2", LogicalType.String()),
            new ParquetSharp.Column<string>("value_3", LogicalType.String()),
            new ParquetSharp.Column<string>("value_4", LogicalType.String()),
            new ParquetSharp.Column<string>("value_5", LogicalType.String()),
            new ParquetSharp.Column<string>("value_6", LogicalType.String()),
            new ParquetSharp.Column<string>("value_7", LogicalType.String()),
            new ParquetSharp.Column<string>("value_8", LogicalType.String()),
            new ParquetSharp.Column<string>("value_9", LogicalType.String()),
            new ParquetSharp.Column<string>("value_10", LogicalType.String()),
            new ParquetSharp.Column<string>("value_11", LogicalType.String()),
            new ParquetSharp.Column<string>("value_12", LogicalType.String()),
            new ParquetSharp.Column<string>("value_13", LogicalType.String()),
            new ParquetSharp.Column<string>("value_14", LogicalType.String()),
            new ParquetSharp.Column<string>("value_15", LogicalType.String()),
            new ParquetSharp.Column<string>("value_16", LogicalType.String()),
            new ParquetSharp.Column<string>("value_17", LogicalType.String()),
            new ParquetSharp.Column<string>("value_18", LogicalType.String()),
            new ParquetSharp.Column<string>("value_19", LogicalType.String()),
            new ParquetSharp.Column<string>("value_20", LogicalType.String()),
            new ParquetSharp.Column<string>("value_21", LogicalType.String()),
        ];
        using var builder = new WriterPropertiesBuilder();
        builder
            .Compression(Compression.Uncompressed)
            .EnableStatistics()
            .EnableWritePageIndex()
            .DataPageVersion(ParquetSharp.ParquetDataPageVersion.V2);
        _properties = builder.DisableDictionary().Encoding(ParquetSharp.Encoding.DeltaByteArray).Build();

        _output = new MemoryStream();
        _managedOutput = new ManagedOutputStream(_output, leaveOpen: true);
        _writer = ParquetFile.CreateRowWriter<SyntheticStringDeltaByteArraySharpRow>(_managedOutput, _properties, _schema);
        Write();
        _outputCapacity = BenchmarkData.OutputCapacity(checked((int)_output.Length));
        Console.WriteLine("BENCHMARK_FILE|SyntheticStringDeltaByteArray|ParquetSharp|" + _output.Length);
        _writer.Dispose();
        _managedOutput.Dispose();
        _output.Dispose();

        var file = SyntheticStringDeltaByteArrayPlankRow.CreateReadFile(SyntheticStringDeltaByteArrayPlankRow.FromSharp(_rows));
        _pinned = GCHandle.Alloc(file, GCHandleType.Pinned);
        _buffer = new NativeBuffer(_pinned.AddrOfPinnedObject(), file.LongLength);
        _source = new BufferReader(_buffer);
    }

    [IterationSetup(Target = nameof(Write))]
    public void SetupWrite()
    {
        _output = new MemoryStream(_outputCapacity);
        _managedOutput = new ManagedOutputStream(_output, leaveOpen: true);
        _writer = ParquetFile.CreateRowWriter<SyntheticStringDeltaByteArraySharpRow>(_managedOutput, _properties, _schema);
    }

    [IterationSetup(Target = nameof(Read))]
    public void SetupRead()
    {
        _reader?.Dispose();
        _reader = ParquetFile.CreateRowReader<SyntheticStringDeltaByteArraySharpRow>(_source);
    }

    [Benchmark]
    public void Write()
    {
        for (var start = 0; start < _rows.Length; start += RowsPerRowGroup)
        {
            if (start != 0) _writer.StartNewRowGroup();
            _writer.WriteRowSpan(_rows.AsSpan(start, Math.Min(RowsPerRowGroup, _rows.Length - start)));
        }
        _writer.Close();
    }

    [Benchmark]
    public ulong Read()
    {
        ulong sum = 0;
        for (var group = 0; group < _reader!.FileMetaData.NumRowGroups; group++)
        foreach (var row in _reader.ReadRows(group))
        {
            sum += (ulong)row.Value0.Length;
            sum += (ulong)row.Value1.Length;
            sum += (ulong)row.Value2.Length;
            sum += (ulong)row.Value3.Length;
            sum += (ulong)row.Value4.Length;
            sum += (ulong)row.Value5.Length;
            sum += (ulong)row.Value6.Length;
            sum += (ulong)row.Value7.Length;
            sum += (ulong)row.Value8.Length;
            sum += (ulong)row.Value9.Length;
            sum += (ulong)row.Value10.Length;
            sum += (ulong)row.Value11.Length;
            sum += (ulong)row.Value12.Length;
            sum += (ulong)row.Value13.Length;
            sum += (ulong)row.Value14.Length;
            sum += (ulong)row.Value15.Length;
            sum += (ulong)row.Value16.Length;
            sum += (ulong)row.Value17.Length;
            sum += (ulong)row.Value18.Length;
            sum += (ulong)row.Value19.Length;
            sum += (ulong)row.Value20.Length;
            sum += (ulong)row.Value21.Length;
        }
        return sum;
    }

    [IterationCleanup(Target = nameof(Write))]
    public void CleanupWrite()
    {
        _writer.Dispose();
        _managedOutput.Dispose();
        _output.Dispose();
    }

    [GlobalCleanup]
    public void Cleanup()
    {
        _reader?.Dispose();
        _source.Dispose();
        _buffer.Dispose();
        if (_pinned.IsAllocated) _pinned.Free();
        _properties.Dispose();
    }
}

[MemoryDiagnoser]
public class SyntheticStringDeltaByteArrayParquetNetBenchmarks
{
    SyntheticStringDeltaByteArrayNetRow[] _rows = null!;
    byte[] _file = null!;
    MemoryStream? _stream;

    public IEnumerable<int> RowCounts => [BenchmarkData.SyntheticRows];

    [ParamsSource(nameof(RowCounts))]
    public int Rows { get; set; }

    [GlobalSetup]
    public void Setup()
    {
        _rows = SyntheticStringDeltaByteArrayNetRow.CreateRows(Rows);

        _file = SyntheticStringDeltaByteArrayPlankRow.CreateReadFile(SyntheticStringDeltaByteArrayPlankRow.FromNet(_rows));
    }

    [IterationSetup(Target = nameof(Read))]
    public void SetupRead()
    {
        _stream?.Dispose();
        _stream = new MemoryStream(_file, writable: false);
    }

    [Benchmark]
    public async Task<ulong> Read()
    {
        var result = await ParquetSerializer.DeserializeAsync<SyntheticStringDeltaByteArrayNetRow>(_stream!);
        ulong sum = 0;
        foreach (var row in result.Data)
        {
            sum += (ulong)row.Value0.Length;
            sum += (ulong)row.Value1.Length;
            sum += (ulong)row.Value2.Length;
            sum += (ulong)row.Value3.Length;
            sum += (ulong)row.Value4.Length;
            sum += (ulong)row.Value5.Length;
            sum += (ulong)row.Value6.Length;
            sum += (ulong)row.Value7.Length;
            sum += (ulong)row.Value8.Length;
            sum += (ulong)row.Value9.Length;
            sum += (ulong)row.Value10.Length;
            sum += (ulong)row.Value11.Length;
            sum += (ulong)row.Value12.Length;
            sum += (ulong)row.Value13.Length;
            sum += (ulong)row.Value14.Length;
            sum += (ulong)row.Value15.Length;
            sum += (ulong)row.Value16.Length;
            sum += (ulong)row.Value17.Length;
            sum += (ulong)row.Value18.Length;
            sum += (ulong)row.Value19.Length;
            sum += (ulong)row.Value20.Length;
            sum += (ulong)row.Value21.Length;
        }
        return sum;
    }

    [GlobalCleanup]
    public void Cleanup() => _stream?.Dispose();
}
