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
sealed partial class SyntheticInt32PlainRow
{
    [ParquetColumn("value_0", Encodings = [EncodingKind.Plain]), MapToColumn("value_0"), JsonPropertyName("value_0")]
    public int Value0 { get; set; }

    [ParquetColumn("value_1", Encodings = [EncodingKind.Plain]), MapToColumn("value_1"), JsonPropertyName("value_1")]
    public int Value1 { get; set; }

    [ParquetColumn("value_2", Encodings = [EncodingKind.Plain]), MapToColumn("value_2"), JsonPropertyName("value_2")]
    public int Value2 { get; set; }

    [ParquetColumn("value_3", Encodings = [EncodingKind.Plain]), MapToColumn("value_3"), JsonPropertyName("value_3")]
    public int Value3 { get; set; }

    [ParquetColumn("value_4", Encodings = [EncodingKind.Plain]), MapToColumn("value_4"), JsonPropertyName("value_4")]
    public int Value4 { get; set; }

    [ParquetColumn("value_5", Encodings = [EncodingKind.Plain]), MapToColumn("value_5"), JsonPropertyName("value_5")]
    public int Value5 { get; set; }

    [ParquetColumn("value_6", Encodings = [EncodingKind.Plain]), MapToColumn("value_6"), JsonPropertyName("value_6")]
    public int Value6 { get; set; }

    [ParquetColumn("value_7", Encodings = [EncodingKind.Plain]), MapToColumn("value_7"), JsonPropertyName("value_7")]
    public int Value7 { get; set; }

    [ParquetColumn("value_8", Encodings = [EncodingKind.Plain]), MapToColumn("value_8"), JsonPropertyName("value_8")]
    public int Value8 { get; set; }

    [ParquetColumn("value_9", Encodings = [EncodingKind.Plain]), MapToColumn("value_9"), JsonPropertyName("value_9")]
    public int Value9 { get; set; }

    [ParquetColumn("value_10", Encodings = [EncodingKind.Plain]), MapToColumn("value_10"), JsonPropertyName("value_10")]
    public int Value10 { get; set; }

    [ParquetColumn("value_11", Encodings = [EncodingKind.Plain]), MapToColumn("value_11"), JsonPropertyName("value_11")]
    public int Value11 { get; set; }

    [ParquetColumn("value_12", Encodings = [EncodingKind.Plain]), MapToColumn("value_12"), JsonPropertyName("value_12")]
    public int Value12 { get; set; }

    [ParquetColumn("value_13", Encodings = [EncodingKind.Plain]), MapToColumn("value_13"), JsonPropertyName("value_13")]
    public int Value13 { get; set; }

    [ParquetColumn("value_14", Encodings = [EncodingKind.Plain]), MapToColumn("value_14"), JsonPropertyName("value_14")]
    public int Value14 { get; set; }

    [ParquetColumn("value_15", Encodings = [EncodingKind.Plain]), MapToColumn("value_15"), JsonPropertyName("value_15")]
    public int Value15 { get; set; }

    [ParquetColumn("value_16", Encodings = [EncodingKind.Plain]), MapToColumn("value_16"), JsonPropertyName("value_16")]
    public int Value16 { get; set; }

    [ParquetColumn("value_17", Encodings = [EncodingKind.Plain]), MapToColumn("value_17"), JsonPropertyName("value_17")]
    public int Value17 { get; set; }

    [ParquetColumn("value_18", Encodings = [EncodingKind.Plain]), MapToColumn("value_18"), JsonPropertyName("value_18")]
    public int Value18 { get; set; }

    [ParquetColumn("value_19", Encodings = [EncodingKind.Plain]), MapToColumn("value_19"), JsonPropertyName("value_19")]
    public int Value19 { get; set; }

    [ParquetColumn("value_20", Encodings = [EncodingKind.Plain]), MapToColumn("value_20"), JsonPropertyName("value_20")]
    public int Value20 { get; set; }

    [ParquetColumn("value_21", Encodings = [EncodingKind.Plain]), MapToColumn("value_21"), JsonPropertyName("value_21")]
    public int Value21 { get; set; }

    public static SyntheticInt32PlainRow[] CreateRows(int count)
    {
        var rows = new SyntheticInt32PlainRow[count];
        for (var row = 0; row < rows.Length; row++)
            rows[row] = new SyntheticInt32PlainRow
            {
                Value0 = (row * 37 + 0 * 1009) & 2_047,
                Value1 = (row * 37 + 1 * 1009) & 2_047,
                Value2 = (row * 37 + 2 * 1009) & 2_047,
                Value3 = (row * 37 + 3 * 1009) & 2_047,
                Value4 = (row * 37 + 4 * 1009) & 2_047,
                Value5 = (row * 37 + 5 * 1009) & 2_047,
                Value6 = (row * 37 + 6 * 1009) & 2_047,
                Value7 = (row * 37 + 7 * 1009) & 2_047,
                Value8 = (row * 37 + 8 * 1009) & 2_047,
                Value9 = (row * 37 + 9 * 1009) & 2_047,
                Value10 = (row * 37 + 10 * 1009) & 2_047,
                Value11 = (row * 37 + 11 * 1009) & 2_047,
                Value12 = (row * 37 + 12 * 1009) & 2_047,
                Value13 = (row * 37 + 13 * 1009) & 2_047,
                Value14 = (row * 37 + 14 * 1009) & 2_047,
                Value15 = (row * 37 + 15 * 1009) & 2_047,
                Value16 = (row * 37 + 16 * 1009) & 2_047,
                Value17 = (row * 37 + 17 * 1009) & 2_047,
                Value18 = (row * 37 + 18 * 1009) & 2_047,
                Value19 = (row * 37 + 19 * 1009) & 2_047,
                Value20 = (row * 37 + 20 * 1009) & 2_047,
                Value21 = (row * 37 + 21 * 1009) & 2_047,            };
        return rows;
    }

    public static byte[] CreateReadFile(SyntheticInt32PlainRow[] rows)
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
            TargetRowGroupSizeBytes = 4000000UL,
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
public class SyntheticInt32PlainPlankBenchmarks
{
    SyntheticInt32PlainRow[] _rows = null!;
    DefaultParquetBufferPool _pool = null!;
    ParquetWriterOptions _options = null!;
    SyntheticInt32PlainRow.PipelineWriter _writer = null!;
    MemoryStream _output = null!;
    int _outputCapacity;
    MemoryReadSource _source = null!;
    SyntheticInt32PlainRow.RowReader _reader = null!;
    PlankWorkerPinning _pinning = null!;

    public IEnumerable<int> RowCounts => [BenchmarkData.SyntheticRows];

    [ParamsSource(nameof(RowCounts))]
    public int Rows { get; set; }

    [GlobalSetup]
    public void Setup()
    {
        _rows = SyntheticInt32PlainRow.CreateRows(Rows);
        _pool = new DefaultParquetBufferPool(ParquetBufferRetentionPolicy.ZeroAllocation);
        _pinning = new PlankWorkerPinning();
        _options = new ParquetWriterOptions
        {
            Compression = CompressionKind.None,
            BufferPool = _pool,
            DataPageVersion = ParquetDataPageVersion.V2,
            WritePageIndexes = true,
            WritePageCrc = false,
            TargetRowGroupSizeBytes = 4000000UL,
            RowApiInitialRowCapacity = 45_455,
            Execution = new ParquetExecutionOptions { OnWorkerStarted = _pinning.OnWorkerStarted }
        };

        _output = new MemoryStream();
        _pinning.Reset();
        _writer = SyntheticInt32PlainRow.CreateRowWriter(_output, _options);
        _pinning.Wait();
        Write();
        var file = _output.ToArray();
        Console.WriteLine("BENCHMARK_FILE|SyntheticInt32Plain|Plank|" + file.Length);
        _outputCapacity = BenchmarkData.OutputCapacity(file.Length);
        _output.Dispose();

        _source = new MemoryReadSource(file);
        _reader = SyntheticInt32PlainRow.CreateRowReader(_source, options: new RowReaderOptions { BufferPool = _pool });
        _ = Read();
    }

    [IterationSetup(Target = nameof(Write))]
    public void SetupWrite()
    {
        _output = new MemoryStream(_outputCapacity);
        _pinning.Reset();
        _writer.Reset(_output);
        _pinning.Wait();
    }

    [IterationSetup(Target = nameof(Read))]
    public void SetupRead() => _reader.Reset(_source);

    [Benchmark]
    public void Write()
    {
#if PLANK_ROW_CURSOR
        var row = _writer.CreateCursor();
#endif
        foreach (var value in _rows)
        {
#if PLANK_ROW_CURSOR
            row.NextRow();
#else
            var row = _writer.GetRow();
#endif
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
            sum += unchecked((uint)row.Value0);
            sum += unchecked((uint)row.Value1);
            sum += unchecked((uint)row.Value2);
            sum += unchecked((uint)row.Value3);
            sum += unchecked((uint)row.Value4);
            sum += unchecked((uint)row.Value5);
            sum += unchecked((uint)row.Value6);
            sum += unchecked((uint)row.Value7);
            sum += unchecked((uint)row.Value8);
            sum += unchecked((uint)row.Value9);
            sum += unchecked((uint)row.Value10);
            sum += unchecked((uint)row.Value11);
            sum += unchecked((uint)row.Value12);
            sum += unchecked((uint)row.Value13);
            sum += unchecked((uint)row.Value14);
            sum += unchecked((uint)row.Value15);
            sum += unchecked((uint)row.Value16);
            sum += unchecked((uint)row.Value17);
            sum += unchecked((uint)row.Value18);
            sum += unchecked((uint)row.Value19);
            sum += unchecked((uint)row.Value20);
            sum += unchecked((uint)row.Value21);
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
public class SyntheticInt32PlainParquetSharpBenchmarks
{
    const int RowsPerRowGroup = 45455;

    SyntheticInt32PlainRow[] _rows = null!;
    ParquetSharp.Column[] _schema = null!;
    WriterProperties _properties = null!;
    MemoryStream _output = null!;
    ManagedOutputStream _managedOutput = null!;
    ParquetRowWriter<SyntheticInt32PlainRow> _writer = null!;
    int _outputCapacity;
    GCHandle _pinned;
    NativeBuffer _buffer = null!;
    BufferReader _source = null!;
    ParquetRowReader<SyntheticInt32PlainRow>? _reader;

    public IEnumerable<int> RowCounts => [BenchmarkData.SyntheticRows];

    [ParamsSource(nameof(RowCounts))]
    public int Rows { get; set; }

    [GlobalSetup]
    public void Setup()
    {
        _rows = SyntheticInt32PlainRow.CreateRows(Rows);
        _schema =
        [
            new ParquetSharp.Column<int>("value_0"),
            new ParquetSharp.Column<int>("value_1"),
            new ParquetSharp.Column<int>("value_2"),
            new ParquetSharp.Column<int>("value_3"),
            new ParquetSharp.Column<int>("value_4"),
            new ParquetSharp.Column<int>("value_5"),
            new ParquetSharp.Column<int>("value_6"),
            new ParquetSharp.Column<int>("value_7"),
            new ParquetSharp.Column<int>("value_8"),
            new ParquetSharp.Column<int>("value_9"),
            new ParquetSharp.Column<int>("value_10"),
            new ParquetSharp.Column<int>("value_11"),
            new ParquetSharp.Column<int>("value_12"),
            new ParquetSharp.Column<int>("value_13"),
            new ParquetSharp.Column<int>("value_14"),
            new ParquetSharp.Column<int>("value_15"),
            new ParquetSharp.Column<int>("value_16"),
            new ParquetSharp.Column<int>("value_17"),
            new ParquetSharp.Column<int>("value_18"),
            new ParquetSharp.Column<int>("value_19"),
            new ParquetSharp.Column<int>("value_20"),
            new ParquetSharp.Column<int>("value_21"),
        ];
        using var builder = new WriterPropertiesBuilder();
        builder
            .Compression(Compression.Uncompressed)
            .EnableStatistics()
            .EnableWritePageIndex()
            .DataPageVersion(ParquetSharp.ParquetDataPageVersion.V2);
        _properties = builder.DisableDictionary().Encoding(ParquetSharp.Encoding.Plain).Build();

        _output = new MemoryStream();
        _managedOutput = new ManagedOutputStream(_output, leaveOpen: true);
        _writer = ParquetFile.CreateRowWriter<SyntheticInt32PlainRow>(_managedOutput, _properties, _schema);
        Write();
        _outputCapacity = BenchmarkData.OutputCapacity(checked((int)_output.Length));
        Console.WriteLine("BENCHMARK_FILE|SyntheticInt32Plain|ParquetSharp|" + _output.Length);
        _writer.Dispose();
        _managedOutput.Dispose();
        _output.Dispose();

        var file = SyntheticInt32PlainRow.CreateReadFile(_rows);
        _pinned = GCHandle.Alloc(file, GCHandleType.Pinned);
        _buffer = new NativeBuffer(_pinned.AddrOfPinnedObject(), file.LongLength);
        _source = new BufferReader(_buffer);
    }

    [IterationSetup(Target = nameof(Write))]
    public void SetupWrite()
    {
        _output = new MemoryStream(_outputCapacity);
        _managedOutput = new ManagedOutputStream(_output, leaveOpen: true);
        _writer = ParquetFile.CreateRowWriter<SyntheticInt32PlainRow>(_managedOutput, _properties, _schema);
    }

    [IterationSetup(Target = nameof(Read))]
    public void SetupRead()
    {
        _reader?.Dispose();
        _reader = ParquetFile.CreateRowReader<SyntheticInt32PlainRow>(_source);
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
            sum += unchecked((uint)row.Value0);
            sum += unchecked((uint)row.Value1);
            sum += unchecked((uint)row.Value2);
            sum += unchecked((uint)row.Value3);
            sum += unchecked((uint)row.Value4);
            sum += unchecked((uint)row.Value5);
            sum += unchecked((uint)row.Value6);
            sum += unchecked((uint)row.Value7);
            sum += unchecked((uint)row.Value8);
            sum += unchecked((uint)row.Value9);
            sum += unchecked((uint)row.Value10);
            sum += unchecked((uint)row.Value11);
            sum += unchecked((uint)row.Value12);
            sum += unchecked((uint)row.Value13);
            sum += unchecked((uint)row.Value14);
            sum += unchecked((uint)row.Value15);
            sum += unchecked((uint)row.Value16);
            sum += unchecked((uint)row.Value17);
            sum += unchecked((uint)row.Value18);
            sum += unchecked((uint)row.Value19);
            sum += unchecked((uint)row.Value20);
            sum += unchecked((uint)row.Value21);
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
public class SyntheticInt32PlainParquetNetBenchmarks
{
    SyntheticInt32PlainRow[] _rows = null!;
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
        _rows = SyntheticInt32PlainRow.CreateRows(Rows);
        _options = new ParquetOptions
        {
            CompressionMethod = CompressionMethod.None,
            DictionaryEncodingThreshold = 0,
            RowGroupSize = 45455
        };
        _options.ColumnEncodingHints["value_0"] = EncodingHint.Default;
        _options.ColumnEncodingHints["value_1"] = EncodingHint.Default;
        _options.ColumnEncodingHints["value_2"] = EncodingHint.Default;
        _options.ColumnEncodingHints["value_3"] = EncodingHint.Default;
        _options.ColumnEncodingHints["value_4"] = EncodingHint.Default;
        _options.ColumnEncodingHints["value_5"] = EncodingHint.Default;
        _options.ColumnEncodingHints["value_6"] = EncodingHint.Default;
        _options.ColumnEncodingHints["value_7"] = EncodingHint.Default;
        _options.ColumnEncodingHints["value_8"] = EncodingHint.Default;
        _options.ColumnEncodingHints["value_9"] = EncodingHint.Default;
        _options.ColumnEncodingHints["value_10"] = EncodingHint.Default;
        _options.ColumnEncodingHints["value_11"] = EncodingHint.Default;
        _options.ColumnEncodingHints["value_12"] = EncodingHint.Default;
        _options.ColumnEncodingHints["value_13"] = EncodingHint.Default;
        _options.ColumnEncodingHints["value_14"] = EncodingHint.Default;
        _options.ColumnEncodingHints["value_15"] = EncodingHint.Default;
        _options.ColumnEncodingHints["value_16"] = EncodingHint.Default;
        _options.ColumnEncodingHints["value_17"] = EncodingHint.Default;
        _options.ColumnEncodingHints["value_18"] = EncodingHint.Default;
        _options.ColumnEncodingHints["value_19"] = EncodingHint.Default;
        _options.ColumnEncodingHints["value_20"] = EncodingHint.Default;
        _options.ColumnEncodingHints["value_21"] = EncodingHint.Default;

        _output = new MemoryStream();
        Write().GetAwaiter().GetResult();
        _outputCapacity = BenchmarkData.OutputCapacity(checked((int)_output.Length));
        Console.WriteLine("BENCHMARK_FILE|SyntheticInt32Plain|Parquet.Net|" + _output.Length);
        _output.Dispose();

        _file = SyntheticInt32PlainRow.CreateReadFile(_rows);
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
        var result = await ParquetSerializer.DeserializeAsync<SyntheticInt32PlainRow>(_stream!);
        ulong sum = 0;
        foreach (var row in result.Data)
        {
            sum += unchecked((uint)row.Value0);
            sum += unchecked((uint)row.Value1);
            sum += unchecked((uint)row.Value2);
            sum += unchecked((uint)row.Value3);
            sum += unchecked((uint)row.Value4);
            sum += unchecked((uint)row.Value5);
            sum += unchecked((uint)row.Value6);
            sum += unchecked((uint)row.Value7);
            sum += unchecked((uint)row.Value8);
            sum += unchecked((uint)row.Value9);
            sum += unchecked((uint)row.Value10);
            sum += unchecked((uint)row.Value11);
            sum += unchecked((uint)row.Value12);
            sum += unchecked((uint)row.Value13);
            sum += unchecked((uint)row.Value14);
            sum += unchecked((uint)row.Value15);
            sum += unchecked((uint)row.Value16);
            sum += unchecked((uint)row.Value17);
            sum += unchecked((uint)row.Value18);
            sum += unchecked((uint)row.Value19);
            sum += unchecked((uint)row.Value20);
            sum += unchecked((uint)row.Value21);
        }
        return sum;
    }

    [IterationCleanup(Target = nameof(Write))]
    public void CleanupWrite() => _output.Dispose();
    [GlobalCleanup]
    public void Cleanup() => _stream?.Dispose();
}
