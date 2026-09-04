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
sealed partial class SyntheticBooleanPlainRow
{
    [ParquetColumn("value_0", Encodings = [EncodingKind.Plain]), MapToColumn("value_0"), JsonPropertyName("value_0")]
    public bool Value0 { get; set; }

    [ParquetColumn("value_1", Encodings = [EncodingKind.Plain]), MapToColumn("value_1"), JsonPropertyName("value_1")]
    public bool Value1 { get; set; }

    [ParquetColumn("value_2", Encodings = [EncodingKind.Plain]), MapToColumn("value_2"), JsonPropertyName("value_2")]
    public bool Value2 { get; set; }

    [ParquetColumn("value_3", Encodings = [EncodingKind.Plain]), MapToColumn("value_3"), JsonPropertyName("value_3")]
    public bool Value3 { get; set; }

    [ParquetColumn("value_4", Encodings = [EncodingKind.Plain]), MapToColumn("value_4"), JsonPropertyName("value_4")]
    public bool Value4 { get; set; }

    [ParquetColumn("value_5", Encodings = [EncodingKind.Plain]), MapToColumn("value_5"), JsonPropertyName("value_5")]
    public bool Value5 { get; set; }

    [ParquetColumn("value_6", Encodings = [EncodingKind.Plain]), MapToColumn("value_6"), JsonPropertyName("value_6")]
    public bool Value6 { get; set; }

    [ParquetColumn("value_7", Encodings = [EncodingKind.Plain]), MapToColumn("value_7"), JsonPropertyName("value_7")]
    public bool Value7 { get; set; }

    [ParquetColumn("value_8", Encodings = [EncodingKind.Plain]), MapToColumn("value_8"), JsonPropertyName("value_8")]
    public bool Value8 { get; set; }

    [ParquetColumn("value_9", Encodings = [EncodingKind.Plain]), MapToColumn("value_9"), JsonPropertyName("value_9")]
    public bool Value9 { get; set; }

    [ParquetColumn("value_10", Encodings = [EncodingKind.Plain]), MapToColumn("value_10"), JsonPropertyName("value_10")]
    public bool Value10 { get; set; }

    [ParquetColumn("value_11", Encodings = [EncodingKind.Plain]), MapToColumn("value_11"), JsonPropertyName("value_11")]
    public bool Value11 { get; set; }

    [ParquetColumn("value_12", Encodings = [EncodingKind.Plain]), MapToColumn("value_12"), JsonPropertyName("value_12")]
    public bool Value12 { get; set; }

    [ParquetColumn("value_13", Encodings = [EncodingKind.Plain]), MapToColumn("value_13"), JsonPropertyName("value_13")]
    public bool Value13 { get; set; }

    [ParquetColumn("value_14", Encodings = [EncodingKind.Plain]), MapToColumn("value_14"), JsonPropertyName("value_14")]
    public bool Value14 { get; set; }

    [ParquetColumn("value_15", Encodings = [EncodingKind.Plain]), MapToColumn("value_15"), JsonPropertyName("value_15")]
    public bool Value15 { get; set; }

    [ParquetColumn("value_16", Encodings = [EncodingKind.Plain]), MapToColumn("value_16"), JsonPropertyName("value_16")]
    public bool Value16 { get; set; }

    [ParquetColumn("value_17", Encodings = [EncodingKind.Plain]), MapToColumn("value_17"), JsonPropertyName("value_17")]
    public bool Value17 { get; set; }

    [ParquetColumn("value_18", Encodings = [EncodingKind.Plain]), MapToColumn("value_18"), JsonPropertyName("value_18")]
    public bool Value18 { get; set; }

    [ParquetColumn("value_19", Encodings = [EncodingKind.Plain]), MapToColumn("value_19"), JsonPropertyName("value_19")]
    public bool Value19 { get; set; }

    [ParquetColumn("value_20", Encodings = [EncodingKind.Plain]), MapToColumn("value_20"), JsonPropertyName("value_20")]
    public bool Value20 { get; set; }

    [ParquetColumn("value_21", Encodings = [EncodingKind.Plain]), MapToColumn("value_21"), JsonPropertyName("value_21")]
    public bool Value21 { get; set; }

    public static SyntheticBooleanPlainRow[] CreateRows(int count)
    {
        var rows = new SyntheticBooleanPlainRow[count];
        for (var row = 0; row < rows.Length; row++)
            rows[row] = new SyntheticBooleanPlainRow
            {
                Value0 = ((row + 0) & 1) == 0,
                Value1 = ((row + 1) & 1) == 0,
                Value2 = ((row + 2) & 1) == 0,
                Value3 = ((row + 3) & 1) == 0,
                Value4 = ((row + 4) & 1) == 0,
                Value5 = ((row + 5) & 1) == 0,
                Value6 = ((row + 6) & 1) == 0,
                Value7 = ((row + 7) & 1) == 0,
                Value8 = ((row + 8) & 1) == 0,
                Value9 = ((row + 9) & 1) == 0,
                Value10 = ((row + 10) & 1) == 0,
                Value11 = ((row + 11) & 1) == 0,
                Value12 = ((row + 12) & 1) == 0,
                Value13 = ((row + 13) & 1) == 0,
                Value14 = ((row + 14) & 1) == 0,
                Value15 = ((row + 15) & 1) == 0,
                Value16 = ((row + 16) & 1) == 0,
                Value17 = ((row + 17) & 1) == 0,
                Value18 = ((row + 18) & 1) == 0,
                Value19 = ((row + 19) & 1) == 0,
                Value20 = ((row + 20) & 1) == 0,
                Value21 = ((row + 21) & 1) == 0,            };
        return rows;
    }

    public static byte[] CreateReadFile(SyntheticBooleanPlainRow[] rows)
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
            TargetRowGroupSizeBytes = 1000000UL,
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
public class SyntheticBooleanPlainPlankBenchmarks
{
    SyntheticBooleanPlainRow[] _rows = null!;
    DefaultParquetBufferPool _pool = null!;
    ParquetWriterOptions _options = null!;
    MemoryStream _output = null!;
    int _outputCapacity;
    MemoryReadSource _source = null!;
    SyntheticBooleanPlainRow.RowReader _reader = null!;
    PlankWorkerPinning _pinning = null!;

    public IEnumerable<int> RowCounts => [BenchmarkData.SyntheticRows];

    [ParamsSource(nameof(RowCounts))]
    public int Rows { get; set; }

    [GlobalSetup]
    public void Setup()
    {
        _rows = SyntheticBooleanPlainRow.CreateRows(Rows);
        _pool = new DefaultParquetBufferPool(ParquetBufferRetentionPolicy.ZeroAllocation);
        _pinning = new PlankWorkerPinning();
        _options = new ParquetWriterOptions
        {
            Compression = CompressionKind.None,
            BufferPool = _pool,
            DataPageVersion = ParquetDataPageVersion.V2,
            WritePageIndexes = true,
            WritePageCrc = false,
            TargetRowGroupSizeBytes = 1000000UL,
            RowApiInitialRowCapacity = 45_455,
            Execution = new ParquetExecutionOptions { OnWorkerStarted = _pinning.OnWorkerStarted }
        };

        _output = new MemoryStream();
        _pinning.Reset();
        Write();
        var file = _output.ToArray();
        Console.WriteLine("BENCHMARK_FILE|SyntheticBooleanPlain|Plank|" + file.Length);
        _outputCapacity = BenchmarkData.OutputCapacity(file.Length);
        _output.Dispose();

        _source = new MemoryReadSource(file);
        _reader = SyntheticBooleanPlainRow.CreateRowReader(_source, options: new RowReaderOptions { BufferPool = _pool });
        _ = Read();
    }

    [IterationSetup(Target = nameof(Write))]
    public void SetupWrite()
    {
        _output = new MemoryStream(_outputCapacity);
        _pinning.Reset();
    }

    [IterationSetup(Target = nameof(Read))]
    public void SetupRead() => _reader.Reset(_source);

    [Benchmark]
    public void Write()
    {
        using var writer = SyntheticBooleanPlainRow.CreateRowWriter(_output, _options);
        _pinning.Wait();
        foreach (var value in _rows)
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
    }

    [Benchmark]
    public ulong Read()
    {
        ulong sum = 0;
        foreach (var row in _reader)
        {
            sum += (row.Value0 ? 1UL : 0UL);
            sum += (row.Value1 ? 1UL : 0UL);
            sum += (row.Value2 ? 1UL : 0UL);
            sum += (row.Value3 ? 1UL : 0UL);
            sum += (row.Value4 ? 1UL : 0UL);
            sum += (row.Value5 ? 1UL : 0UL);
            sum += (row.Value6 ? 1UL : 0UL);
            sum += (row.Value7 ? 1UL : 0UL);
            sum += (row.Value8 ? 1UL : 0UL);
            sum += (row.Value9 ? 1UL : 0UL);
            sum += (row.Value10 ? 1UL : 0UL);
            sum += (row.Value11 ? 1UL : 0UL);
            sum += (row.Value12 ? 1UL : 0UL);
            sum += (row.Value13 ? 1UL : 0UL);
            sum += (row.Value14 ? 1UL : 0UL);
            sum += (row.Value15 ? 1UL : 0UL);
            sum += (row.Value16 ? 1UL : 0UL);
            sum += (row.Value17 ? 1UL : 0UL);
            sum += (row.Value18 ? 1UL : 0UL);
            sum += (row.Value19 ? 1UL : 0UL);
            sum += (row.Value20 ? 1UL : 0UL);
            sum += (row.Value21 ? 1UL : 0UL);
        }
        return sum;
    }

    [IterationCleanup(Target = nameof(Write))]
    public void CleanupWrite() => _output.Dispose();

    [GlobalCleanup]
    public void Cleanup()
    {
        _reader.Dispose();
        _source.Dispose();
        _pool.Dispose();
        _output.Dispose();
    }
}

[MemoryDiagnoser]
public class SyntheticBooleanPlainParquetSharpBenchmarks
{
    const int RowsPerRowGroup = 45455;

    SyntheticBooleanPlainRow[] _rows = null!;
    ParquetSharp.Column[] _schema = null!;
    WriterProperties _properties = null!;
    MemoryStream _output = null!;
    ManagedOutputStream _managedOutput = null!;
    ParquetRowWriter<SyntheticBooleanPlainRow> _writer = null!;
    int _outputCapacity;
    GCHandle _pinned;
    NativeBuffer _buffer = null!;
    BufferReader _source = null!;
    ParquetRowReader<SyntheticBooleanPlainRow>? _reader;

    public IEnumerable<int> RowCounts => [BenchmarkData.SyntheticRows];

    [ParamsSource(nameof(RowCounts))]
    public int Rows { get; set; }

    [GlobalSetup]
    public void Setup()
    {
        _rows = SyntheticBooleanPlainRow.CreateRows(Rows);
        _schema =
        [
            new ParquetSharp.Column<bool>("value_0"),
            new ParquetSharp.Column<bool>("value_1"),
            new ParquetSharp.Column<bool>("value_2"),
            new ParquetSharp.Column<bool>("value_3"),
            new ParquetSharp.Column<bool>("value_4"),
            new ParquetSharp.Column<bool>("value_5"),
            new ParquetSharp.Column<bool>("value_6"),
            new ParquetSharp.Column<bool>("value_7"),
            new ParquetSharp.Column<bool>("value_8"),
            new ParquetSharp.Column<bool>("value_9"),
            new ParquetSharp.Column<bool>("value_10"),
            new ParquetSharp.Column<bool>("value_11"),
            new ParquetSharp.Column<bool>("value_12"),
            new ParquetSharp.Column<bool>("value_13"),
            new ParquetSharp.Column<bool>("value_14"),
            new ParquetSharp.Column<bool>("value_15"),
            new ParquetSharp.Column<bool>("value_16"),
            new ParquetSharp.Column<bool>("value_17"),
            new ParquetSharp.Column<bool>("value_18"),
            new ParquetSharp.Column<bool>("value_19"),
            new ParquetSharp.Column<bool>("value_20"),
            new ParquetSharp.Column<bool>("value_21"),
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
        _writer = ParquetFile.CreateRowWriter<SyntheticBooleanPlainRow>(_managedOutput, _properties, _schema);
        Write();
        _outputCapacity = BenchmarkData.OutputCapacity(checked((int)_output.Length));
        Console.WriteLine("BENCHMARK_FILE|SyntheticBooleanPlain|ParquetSharp|" + _output.Length);
        _writer.Dispose();
        _managedOutput.Dispose();
        _output.Dispose();

        var file = SyntheticBooleanPlainRow.CreateReadFile(_rows);
        _pinned = GCHandle.Alloc(file, GCHandleType.Pinned);
        _buffer = new NativeBuffer(_pinned.AddrOfPinnedObject(), file.LongLength);
        _source = new BufferReader(_buffer);
    }

    [IterationSetup(Target = nameof(Write))]
    public void SetupWrite()
    {
        _output = new MemoryStream(_outputCapacity);
        _managedOutput = new ManagedOutputStream(_output, leaveOpen: true);
        _writer = ParquetFile.CreateRowWriter<SyntheticBooleanPlainRow>(_managedOutput, _properties, _schema);
    }

    [IterationSetup(Target = nameof(Read))]
    public void SetupRead()
    {
        _reader?.Dispose();
        _reader = ParquetFile.CreateRowReader<SyntheticBooleanPlainRow>(_source);
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
            sum += (row.Value0 ? 1UL : 0UL);
            sum += (row.Value1 ? 1UL : 0UL);
            sum += (row.Value2 ? 1UL : 0UL);
            sum += (row.Value3 ? 1UL : 0UL);
            sum += (row.Value4 ? 1UL : 0UL);
            sum += (row.Value5 ? 1UL : 0UL);
            sum += (row.Value6 ? 1UL : 0UL);
            sum += (row.Value7 ? 1UL : 0UL);
            sum += (row.Value8 ? 1UL : 0UL);
            sum += (row.Value9 ? 1UL : 0UL);
            sum += (row.Value10 ? 1UL : 0UL);
            sum += (row.Value11 ? 1UL : 0UL);
            sum += (row.Value12 ? 1UL : 0UL);
            sum += (row.Value13 ? 1UL : 0UL);
            sum += (row.Value14 ? 1UL : 0UL);
            sum += (row.Value15 ? 1UL : 0UL);
            sum += (row.Value16 ? 1UL : 0UL);
            sum += (row.Value17 ? 1UL : 0UL);
            sum += (row.Value18 ? 1UL : 0UL);
            sum += (row.Value19 ? 1UL : 0UL);
            sum += (row.Value20 ? 1UL : 0UL);
            sum += (row.Value21 ? 1UL : 0UL);
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
public class SyntheticBooleanPlainParquetNetBenchmarks
{
    SyntheticBooleanPlainRow[] _rows = null!;
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
        _rows = SyntheticBooleanPlainRow.CreateRows(Rows);
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
        Console.WriteLine("BENCHMARK_FILE|SyntheticBooleanPlain|Parquet.Net|" + _output.Length);
        _output.Dispose();

        _file = SyntheticBooleanPlainRow.CreateReadFile(_rows);
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
        var result = await ParquetSerializer.DeserializeAsync<SyntheticBooleanPlainRow>(_stream!);
        ulong sum = 0;
        foreach (var row in result.Data)
        {
            sum += (row.Value0 ? 1UL : 0UL);
            sum += (row.Value1 ? 1UL : 0UL);
            sum += (row.Value2 ? 1UL : 0UL);
            sum += (row.Value3 ? 1UL : 0UL);
            sum += (row.Value4 ? 1UL : 0UL);
            sum += (row.Value5 ? 1UL : 0UL);
            sum += (row.Value6 ? 1UL : 0UL);
            sum += (row.Value7 ? 1UL : 0UL);
            sum += (row.Value8 ? 1UL : 0UL);
            sum += (row.Value9 ? 1UL : 0UL);
            sum += (row.Value10 ? 1UL : 0UL);
            sum += (row.Value11 ? 1UL : 0UL);
            sum += (row.Value12 ? 1UL : 0UL);
            sum += (row.Value13 ? 1UL : 0UL);
            sum += (row.Value14 ? 1UL : 0UL);
            sum += (row.Value15 ? 1UL : 0UL);
            sum += (row.Value16 ? 1UL : 0UL);
            sum += (row.Value17 ? 1UL : 0UL);
            sum += (row.Value18 ? 1UL : 0UL);
            sum += (row.Value19 ? 1UL : 0UL);
            sum += (row.Value20 ? 1UL : 0UL);
            sum += (row.Value21 ? 1UL : 0UL);
        }
        return sum;
    }

    [IterationCleanup(Target = nameof(Write))]
    public void CleanupWrite() => _output.Dispose();
    [GlobalCleanup]
    public void Cleanup() => _stream?.Dispose();
}
