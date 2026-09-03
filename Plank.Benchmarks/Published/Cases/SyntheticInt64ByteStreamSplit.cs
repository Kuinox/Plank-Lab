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
sealed partial class SyntheticInt64ByteStreamSplitRow
{
    [ParquetColumn("value_0", Encodings = [EncodingKind.ByteStreamSplit]), MapToColumn("value_0"), JsonPropertyName("value_0")]
    public long Value0 { get; set; }

    [ParquetColumn("value_1", Encodings = [EncodingKind.ByteStreamSplit]), MapToColumn("value_1"), JsonPropertyName("value_1")]
    public long Value1 { get; set; }

    [ParquetColumn("value_2", Encodings = [EncodingKind.ByteStreamSplit]), MapToColumn("value_2"), JsonPropertyName("value_2")]
    public long Value2 { get; set; }

    [ParquetColumn("value_3", Encodings = [EncodingKind.ByteStreamSplit]), MapToColumn("value_3"), JsonPropertyName("value_3")]
    public long Value3 { get; set; }

    [ParquetColumn("value_4", Encodings = [EncodingKind.ByteStreamSplit]), MapToColumn("value_4"), JsonPropertyName("value_4")]
    public long Value4 { get; set; }

    [ParquetColumn("value_5", Encodings = [EncodingKind.ByteStreamSplit]), MapToColumn("value_5"), JsonPropertyName("value_5")]
    public long Value5 { get; set; }

    [ParquetColumn("value_6", Encodings = [EncodingKind.ByteStreamSplit]), MapToColumn("value_6"), JsonPropertyName("value_6")]
    public long Value6 { get; set; }

    [ParquetColumn("value_7", Encodings = [EncodingKind.ByteStreamSplit]), MapToColumn("value_7"), JsonPropertyName("value_7")]
    public long Value7 { get; set; }

    [ParquetColumn("value_8", Encodings = [EncodingKind.ByteStreamSplit]), MapToColumn("value_8"), JsonPropertyName("value_8")]
    public long Value8 { get; set; }

    [ParquetColumn("value_9", Encodings = [EncodingKind.ByteStreamSplit]), MapToColumn("value_9"), JsonPropertyName("value_9")]
    public long Value9 { get; set; }

    [ParquetColumn("value_10", Encodings = [EncodingKind.ByteStreamSplit]), MapToColumn("value_10"), JsonPropertyName("value_10")]
    public long Value10 { get; set; }

    [ParquetColumn("value_11", Encodings = [EncodingKind.ByteStreamSplit]), MapToColumn("value_11"), JsonPropertyName("value_11")]
    public long Value11 { get; set; }

    [ParquetColumn("value_12", Encodings = [EncodingKind.ByteStreamSplit]), MapToColumn("value_12"), JsonPropertyName("value_12")]
    public long Value12 { get; set; }

    [ParquetColumn("value_13", Encodings = [EncodingKind.ByteStreamSplit]), MapToColumn("value_13"), JsonPropertyName("value_13")]
    public long Value13 { get; set; }

    [ParquetColumn("value_14", Encodings = [EncodingKind.ByteStreamSplit]), MapToColumn("value_14"), JsonPropertyName("value_14")]
    public long Value14 { get; set; }

    [ParquetColumn("value_15", Encodings = [EncodingKind.ByteStreamSplit]), MapToColumn("value_15"), JsonPropertyName("value_15")]
    public long Value15 { get; set; }

    [ParquetColumn("value_16", Encodings = [EncodingKind.ByteStreamSplit]), MapToColumn("value_16"), JsonPropertyName("value_16")]
    public long Value16 { get; set; }

    [ParquetColumn("value_17", Encodings = [EncodingKind.ByteStreamSplit]), MapToColumn("value_17"), JsonPropertyName("value_17")]
    public long Value17 { get; set; }

    [ParquetColumn("value_18", Encodings = [EncodingKind.ByteStreamSplit]), MapToColumn("value_18"), JsonPropertyName("value_18")]
    public long Value18 { get; set; }

    [ParquetColumn("value_19", Encodings = [EncodingKind.ByteStreamSplit]), MapToColumn("value_19"), JsonPropertyName("value_19")]
    public long Value19 { get; set; }

    [ParquetColumn("value_20", Encodings = [EncodingKind.ByteStreamSplit]), MapToColumn("value_20"), JsonPropertyName("value_20")]
    public long Value20 { get; set; }

    [ParquetColumn("value_21", Encodings = [EncodingKind.ByteStreamSplit]), MapToColumn("value_21"), JsonPropertyName("value_21")]
    public long Value21 { get; set; }

    public static SyntheticInt64ByteStreamSplitRow[] CreateRows(int count)
    {
        var rows = new SyntheticInt64ByteStreamSplitRow[count];
        for (var row = 0; row < rows.Length; row++)
            rows[row] = new SyntheticInt64ByteStreamSplitRow
            {
                Value0 = ((long)(row & 2_047) * 37L) + 0,
                Value1 = ((long)(row & 2_047) * 37L) + 1,
                Value2 = ((long)(row & 2_047) * 37L) + 2,
                Value3 = ((long)(row & 2_047) * 37L) + 3,
                Value4 = ((long)(row & 2_047) * 37L) + 4,
                Value5 = ((long)(row & 2_047) * 37L) + 5,
                Value6 = ((long)(row & 2_047) * 37L) + 6,
                Value7 = ((long)(row & 2_047) * 37L) + 7,
                Value8 = ((long)(row & 2_047) * 37L) + 8,
                Value9 = ((long)(row & 2_047) * 37L) + 9,
                Value10 = ((long)(row & 2_047) * 37L) + 10,
                Value11 = ((long)(row & 2_047) * 37L) + 11,
                Value12 = ((long)(row & 2_047) * 37L) + 12,
                Value13 = ((long)(row & 2_047) * 37L) + 13,
                Value14 = ((long)(row & 2_047) * 37L) + 14,
                Value15 = ((long)(row & 2_047) * 37L) + 15,
                Value16 = ((long)(row & 2_047) * 37L) + 16,
                Value17 = ((long)(row & 2_047) * 37L) + 17,
                Value18 = ((long)(row & 2_047) * 37L) + 18,
                Value19 = ((long)(row & 2_047) * 37L) + 19,
                Value20 = ((long)(row & 2_047) * 37L) + 20,
                Value21 = ((long)(row & 2_047) * 37L) + 21,            };
        return rows;
    }

    public static byte[] CreateReadFile(SyntheticInt64ByteStreamSplitRow[] rows)
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
            TargetRowGroupSizeBytes = 8000000UL,
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
}

[MemoryDiagnoser]
public class SyntheticInt64ByteStreamSplitPlankBenchmarks
{
    SyntheticInt64ByteStreamSplitRow[] _rows = null!;
    DefaultParquetBufferPool _pool = null!;
    ParquetWriterOptions _options = null!;
    SyntheticInt64ByteStreamSplitRow.PipelineWriter _writer = null!;
    MemoryStream _output = null!;
    int _outputCapacity;
    MemoryReadSource _source = null!;
    SyntheticInt64ByteStreamSplitRow.RowReader _reader = null!;
    PlankWorkerPinning _pinning = null!;

    public IEnumerable<int> RowCounts => [BenchmarkData.SyntheticRows];

    [ParamsSource(nameof(RowCounts))]
    public int Rows { get; set; }

    [GlobalSetup]
    public void Setup()
    {
        _rows = SyntheticInt64ByteStreamSplitRow.CreateRows(Rows);
        _pool = new DefaultParquetBufferPool(ParquetBufferRetentionPolicy.ZeroAllocation);
        _pinning = new PlankWorkerPinning();
        _options = new ParquetWriterOptions
        {
            Compression = CompressionKind.None,
            BufferPool = _pool,
            DataPageVersion = ParquetDataPageVersion.V2,
            WritePageIndexes = true,
            WritePageCrc = false,
            TargetRowGroupSizeBytes = 8000000UL,
            RowApiInitialRowCapacity = 45_455,
            Execution = new ParquetExecutionOptions { OnWorkerStarted = _pinning.OnWorkerStarted }
        };

        _output = new MemoryStream();
        _writer = SyntheticInt64ByteStreamSplitRow.CreateRowWriter(_output, _options);
        Write();
        var file = _output.ToArray();
        Console.WriteLine("BENCHMARK_FILE|SyntheticInt64ByteStreamSplit|Plank|" + file.Length);
        _outputCapacity = BenchmarkData.OutputCapacity(file.Length);
        _output.Dispose();

        _source = new MemoryReadSource(file);
        _reader = SyntheticInt64ByteStreamSplitRow.CreateRowReader(_source, options: new RowReaderOptions { BufferPool = _pool });
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
            sum += unchecked((ulong)row.Value0);
            sum += unchecked((ulong)row.Value1);
            sum += unchecked((ulong)row.Value2);
            sum += unchecked((ulong)row.Value3);
            sum += unchecked((ulong)row.Value4);
            sum += unchecked((ulong)row.Value5);
            sum += unchecked((ulong)row.Value6);
            sum += unchecked((ulong)row.Value7);
            sum += unchecked((ulong)row.Value8);
            sum += unchecked((ulong)row.Value9);
            sum += unchecked((ulong)row.Value10);
            sum += unchecked((ulong)row.Value11);
            sum += unchecked((ulong)row.Value12);
            sum += unchecked((ulong)row.Value13);
            sum += unchecked((ulong)row.Value14);
            sum += unchecked((ulong)row.Value15);
            sum += unchecked((ulong)row.Value16);
            sum += unchecked((ulong)row.Value17);
            sum += unchecked((ulong)row.Value18);
            sum += unchecked((ulong)row.Value19);
            sum += unchecked((ulong)row.Value20);
            sum += unchecked((ulong)row.Value21);
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
public class SyntheticInt64ByteStreamSplitParquetSharpBenchmarks
{
    const int RowsPerRowGroup = 45455;

    SyntheticInt64ByteStreamSplitRow[] _rows = null!;
    ParquetSharp.Column[] _schema = null!;
    WriterProperties _properties = null!;
    MemoryStream _output = null!;
    ManagedOutputStream _managedOutput = null!;
    ParquetRowWriter<SyntheticInt64ByteStreamSplitRow> _writer = null!;
    int _outputCapacity;
    GCHandle _pinned;
    NativeBuffer _buffer = null!;
    BufferReader _source = null!;
    ParquetRowReader<SyntheticInt64ByteStreamSplitRow>? _reader;

    public IEnumerable<int> RowCounts => [BenchmarkData.SyntheticRows];

    [ParamsSource(nameof(RowCounts))]
    public int Rows { get; set; }

    [GlobalSetup]
    public void Setup()
    {
        _rows = SyntheticInt64ByteStreamSplitRow.CreateRows(Rows);
        _schema =
        [
            new ParquetSharp.Column<long>("value_0"),
            new ParquetSharp.Column<long>("value_1"),
            new ParquetSharp.Column<long>("value_2"),
            new ParquetSharp.Column<long>("value_3"),
            new ParquetSharp.Column<long>("value_4"),
            new ParquetSharp.Column<long>("value_5"),
            new ParquetSharp.Column<long>("value_6"),
            new ParquetSharp.Column<long>("value_7"),
            new ParquetSharp.Column<long>("value_8"),
            new ParquetSharp.Column<long>("value_9"),
            new ParquetSharp.Column<long>("value_10"),
            new ParquetSharp.Column<long>("value_11"),
            new ParquetSharp.Column<long>("value_12"),
            new ParquetSharp.Column<long>("value_13"),
            new ParquetSharp.Column<long>("value_14"),
            new ParquetSharp.Column<long>("value_15"),
            new ParquetSharp.Column<long>("value_16"),
            new ParquetSharp.Column<long>("value_17"),
            new ParquetSharp.Column<long>("value_18"),
            new ParquetSharp.Column<long>("value_19"),
            new ParquetSharp.Column<long>("value_20"),
            new ParquetSharp.Column<long>("value_21"),
        ];
        using var builder = new WriterPropertiesBuilder();
        builder
            .Compression(Compression.Uncompressed)
            .EnableStatistics()
            .EnableWritePageIndex()
            .DataPageVersion(ParquetSharp.ParquetDataPageVersion.V2);
        _properties = builder.DisableDictionary().Encoding(ParquetSharp.Encoding.ByteStreamSplit).Build();

        _output = new MemoryStream();
        _managedOutput = new ManagedOutputStream(_output, leaveOpen: true);
        _writer = ParquetFile.CreateRowWriter<SyntheticInt64ByteStreamSplitRow>(_managedOutput, _properties, _schema);
        Write();
        _outputCapacity = BenchmarkData.OutputCapacity(checked((int)_output.Length));
        Console.WriteLine("BENCHMARK_FILE|SyntheticInt64ByteStreamSplit|ParquetSharp|" + _output.Length);
        _writer.Dispose();
        _managedOutput.Dispose();
        _output.Dispose();

        var file = SyntheticInt64ByteStreamSplitRow.CreateReadFile(_rows);
        _pinned = GCHandle.Alloc(file, GCHandleType.Pinned);
        _buffer = new NativeBuffer(_pinned.AddrOfPinnedObject(), file.LongLength);
        _source = new BufferReader(_buffer);
    }

    [IterationSetup(Target = nameof(Write))]
    public void SetupWrite()
    {
        _output = new MemoryStream(_outputCapacity);
        _managedOutput = new ManagedOutputStream(_output, leaveOpen: true);
        _writer = ParquetFile.CreateRowWriter<SyntheticInt64ByteStreamSplitRow>(_managedOutput, _properties, _schema);
    }

    [IterationSetup(Target = nameof(Read))]
    public void SetupRead()
    {
        _reader?.Dispose();
        _reader = ParquetFile.CreateRowReader<SyntheticInt64ByteStreamSplitRow>(_source);
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
            sum += unchecked((ulong)row.Value0);
            sum += unchecked((ulong)row.Value1);
            sum += unchecked((ulong)row.Value2);
            sum += unchecked((ulong)row.Value3);
            sum += unchecked((ulong)row.Value4);
            sum += unchecked((ulong)row.Value5);
            sum += unchecked((ulong)row.Value6);
            sum += unchecked((ulong)row.Value7);
            sum += unchecked((ulong)row.Value8);
            sum += unchecked((ulong)row.Value9);
            sum += unchecked((ulong)row.Value10);
            sum += unchecked((ulong)row.Value11);
            sum += unchecked((ulong)row.Value12);
            sum += unchecked((ulong)row.Value13);
            sum += unchecked((ulong)row.Value14);
            sum += unchecked((ulong)row.Value15);
            sum += unchecked((ulong)row.Value16);
            sum += unchecked((ulong)row.Value17);
            sum += unchecked((ulong)row.Value18);
            sum += unchecked((ulong)row.Value19);
            sum += unchecked((ulong)row.Value20);
            sum += unchecked((ulong)row.Value21);
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
public class SyntheticInt64ByteStreamSplitParquetNetBenchmarks
{
    SyntheticInt64ByteStreamSplitRow[] _rows = null!;
    ParquetOptions _options = null!;
    MemoryStream _output = null!;
    int _outputCapacity;
    byte[] _file = null!;
    MemoryStream? _stream;

    public IEnumerable<int> RowCounts => [BenchmarkData.SyntheticRows];

    [ParamsSource(nameof(RowCounts))]
    public int Rows { get; set; }

    [GlobalSetup]
    public void Setup()
    {
        _rows = SyntheticInt64ByteStreamSplitRow.CreateRows(Rows);
        _options = new ParquetOptions
        {
            CompressionMethod = CompressionMethod.None,
            DictionaryEncodingThreshold = 0,
            RowGroupSize = 45455
        };
        _options.ColumnEncodingHints["value_0"] = EncodingHint.ByteSplitStream;
        _options.ColumnEncodingHints["value_1"] = EncodingHint.ByteSplitStream;
        _options.ColumnEncodingHints["value_2"] = EncodingHint.ByteSplitStream;
        _options.ColumnEncodingHints["value_3"] = EncodingHint.ByteSplitStream;
        _options.ColumnEncodingHints["value_4"] = EncodingHint.ByteSplitStream;
        _options.ColumnEncodingHints["value_5"] = EncodingHint.ByteSplitStream;
        _options.ColumnEncodingHints["value_6"] = EncodingHint.ByteSplitStream;
        _options.ColumnEncodingHints["value_7"] = EncodingHint.ByteSplitStream;
        _options.ColumnEncodingHints["value_8"] = EncodingHint.ByteSplitStream;
        _options.ColumnEncodingHints["value_9"] = EncodingHint.ByteSplitStream;
        _options.ColumnEncodingHints["value_10"] = EncodingHint.ByteSplitStream;
        _options.ColumnEncodingHints["value_11"] = EncodingHint.ByteSplitStream;
        _options.ColumnEncodingHints["value_12"] = EncodingHint.ByteSplitStream;
        _options.ColumnEncodingHints["value_13"] = EncodingHint.ByteSplitStream;
        _options.ColumnEncodingHints["value_14"] = EncodingHint.ByteSplitStream;
        _options.ColumnEncodingHints["value_15"] = EncodingHint.ByteSplitStream;
        _options.ColumnEncodingHints["value_16"] = EncodingHint.ByteSplitStream;
        _options.ColumnEncodingHints["value_17"] = EncodingHint.ByteSplitStream;
        _options.ColumnEncodingHints["value_18"] = EncodingHint.ByteSplitStream;
        _options.ColumnEncodingHints["value_19"] = EncodingHint.ByteSplitStream;
        _options.ColumnEncodingHints["value_20"] = EncodingHint.ByteSplitStream;
        _options.ColumnEncodingHints["value_21"] = EncodingHint.ByteSplitStream;

        _output = new MemoryStream();
        Write().GetAwaiter().GetResult();
        _outputCapacity = BenchmarkData.OutputCapacity(checked((int)_output.Length));
        Console.WriteLine("BENCHMARK_FILE|SyntheticInt64ByteStreamSplit|Parquet.Net|" + _output.Length);
        _output.Dispose();

        _file = SyntheticInt64ByteStreamSplitRow.CreateReadFile(_rows);
    }

    [IterationSetup(Target = nameof(Write))]
    public void SetupWrite() => _output = new MemoryStream(_outputCapacity);
    [IterationSetup(Target = nameof(Read))]
    public void SetupRead()
    {
        _stream?.Dispose();
        _stream = new MemoryStream(_file, writable: false);
    }

    [Benchmark]
    public async Task Write()
        => await ParquetSerializer.SerializeAsync(_rows, _output, _options);
    [Benchmark]
    public async Task<ulong> Read()
    {
        var result = await ParquetSerializer.DeserializeAsync<SyntheticInt64ByteStreamSplitRow>(_stream!);
        ulong sum = 0;
        foreach (var row in result.Data)
        {
            sum += unchecked((ulong)row.Value0);
            sum += unchecked((ulong)row.Value1);
            sum += unchecked((ulong)row.Value2);
            sum += unchecked((ulong)row.Value3);
            sum += unchecked((ulong)row.Value4);
            sum += unchecked((ulong)row.Value5);
            sum += unchecked((ulong)row.Value6);
            sum += unchecked((ulong)row.Value7);
            sum += unchecked((ulong)row.Value8);
            sum += unchecked((ulong)row.Value9);
            sum += unchecked((ulong)row.Value10);
            sum += unchecked((ulong)row.Value11);
            sum += unchecked((ulong)row.Value12);
            sum += unchecked((ulong)row.Value13);
            sum += unchecked((ulong)row.Value14);
            sum += unchecked((ulong)row.Value15);
            sum += unchecked((ulong)row.Value16);
            sum += unchecked((ulong)row.Value17);
            sum += unchecked((ulong)row.Value18);
            sum += unchecked((ulong)row.Value19);
            sum += unchecked((ulong)row.Value20);
            sum += unchecked((ulong)row.Value21);
        }
        return sum;
    }

    [IterationCleanup(Target = nameof(Write))]
    public void CleanupWrite() => _output.Dispose();
    [GlobalCleanup]
    public void Cleanup() => _stream?.Dispose();
}
