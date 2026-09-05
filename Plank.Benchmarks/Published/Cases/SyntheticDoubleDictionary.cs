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
sealed partial class SyntheticDoubleDictionaryRow
{
    [ParquetColumn("value_0", Encodings = [EncodingKind.RleDictionary]), MapToColumn("value_0"), JsonPropertyName("value_0")]
    public double Value0 { get; set; }

    [ParquetColumn("value_1", Encodings = [EncodingKind.RleDictionary]), MapToColumn("value_1"), JsonPropertyName("value_1")]
    public double Value1 { get; set; }

    [ParquetColumn("value_2", Encodings = [EncodingKind.RleDictionary]), MapToColumn("value_2"), JsonPropertyName("value_2")]
    public double Value2 { get; set; }

    [ParquetColumn("value_3", Encodings = [EncodingKind.RleDictionary]), MapToColumn("value_3"), JsonPropertyName("value_3")]
    public double Value3 { get; set; }

    [ParquetColumn("value_4", Encodings = [EncodingKind.RleDictionary]), MapToColumn("value_4"), JsonPropertyName("value_4")]
    public double Value4 { get; set; }

    [ParquetColumn("value_5", Encodings = [EncodingKind.RleDictionary]), MapToColumn("value_5"), JsonPropertyName("value_5")]
    public double Value5 { get; set; }

    [ParquetColumn("value_6", Encodings = [EncodingKind.RleDictionary]), MapToColumn("value_6"), JsonPropertyName("value_6")]
    public double Value6 { get; set; }

    [ParquetColumn("value_7", Encodings = [EncodingKind.RleDictionary]), MapToColumn("value_7"), JsonPropertyName("value_7")]
    public double Value7 { get; set; }

    [ParquetColumn("value_8", Encodings = [EncodingKind.RleDictionary]), MapToColumn("value_8"), JsonPropertyName("value_8")]
    public double Value8 { get; set; }

    [ParquetColumn("value_9", Encodings = [EncodingKind.RleDictionary]), MapToColumn("value_9"), JsonPropertyName("value_9")]
    public double Value9 { get; set; }

    [ParquetColumn("value_10", Encodings = [EncodingKind.RleDictionary]), MapToColumn("value_10"), JsonPropertyName("value_10")]
    public double Value10 { get; set; }

    [ParquetColumn("value_11", Encodings = [EncodingKind.RleDictionary]), MapToColumn("value_11"), JsonPropertyName("value_11")]
    public double Value11 { get; set; }

    [ParquetColumn("value_12", Encodings = [EncodingKind.RleDictionary]), MapToColumn("value_12"), JsonPropertyName("value_12")]
    public double Value12 { get; set; }

    [ParquetColumn("value_13", Encodings = [EncodingKind.RleDictionary]), MapToColumn("value_13"), JsonPropertyName("value_13")]
    public double Value13 { get; set; }

    [ParquetColumn("value_14", Encodings = [EncodingKind.RleDictionary]), MapToColumn("value_14"), JsonPropertyName("value_14")]
    public double Value14 { get; set; }

    [ParquetColumn("value_15", Encodings = [EncodingKind.RleDictionary]), MapToColumn("value_15"), JsonPropertyName("value_15")]
    public double Value15 { get; set; }

    [ParquetColumn("value_16", Encodings = [EncodingKind.RleDictionary]), MapToColumn("value_16"), JsonPropertyName("value_16")]
    public double Value16 { get; set; }

    [ParquetColumn("value_17", Encodings = [EncodingKind.RleDictionary]), MapToColumn("value_17"), JsonPropertyName("value_17")]
    public double Value17 { get; set; }

    [ParquetColumn("value_18", Encodings = [EncodingKind.RleDictionary]), MapToColumn("value_18"), JsonPropertyName("value_18")]
    public double Value18 { get; set; }

    [ParquetColumn("value_19", Encodings = [EncodingKind.RleDictionary]), MapToColumn("value_19"), JsonPropertyName("value_19")]
    public double Value19 { get; set; }

    [ParquetColumn("value_20", Encodings = [EncodingKind.RleDictionary]), MapToColumn("value_20"), JsonPropertyName("value_20")]
    public double Value20 { get; set; }

    [ParquetColumn("value_21", Encodings = [EncodingKind.RleDictionary]), MapToColumn("value_21"), JsonPropertyName("value_21")]
    public double Value21 { get; set; }

    public static SyntheticDoubleDictionaryRow[] CreateRows(int count)
    {
        var rows = new SyntheticDoubleDictionaryRow[count];
        for (var row = 0; row < rows.Length; row++)
            rows[row] = new SyntheticDoubleDictionaryRow
            {
                Value0 = ((row & 2_047) * 0.25d) + 0,
                Value1 = ((row & 2_047) * 0.25d) + 1,
                Value2 = ((row & 2_047) * 0.25d) + 2,
                Value3 = ((row & 2_047) * 0.25d) + 3,
                Value4 = ((row & 2_047) * 0.25d) + 4,
                Value5 = ((row & 2_047) * 0.25d) + 5,
                Value6 = ((row & 2_047) * 0.25d) + 6,
                Value7 = ((row & 2_047) * 0.25d) + 7,
                Value8 = ((row & 2_047) * 0.25d) + 8,
                Value9 = ((row & 2_047) * 0.25d) + 9,
                Value10 = ((row & 2_047) * 0.25d) + 10,
                Value11 = ((row & 2_047) * 0.25d) + 11,
                Value12 = ((row & 2_047) * 0.25d) + 12,
                Value13 = ((row & 2_047) * 0.25d) + 13,
                Value14 = ((row & 2_047) * 0.25d) + 14,
                Value15 = ((row & 2_047) * 0.25d) + 15,
                Value16 = ((row & 2_047) * 0.25d) + 16,
                Value17 = ((row & 2_047) * 0.25d) + 17,
                Value18 = ((row & 2_047) * 0.25d) + 18,
                Value19 = ((row & 2_047) * 0.25d) + 19,
                Value20 = ((row & 2_047) * 0.25d) + 20,
                Value21 = ((row & 2_047) * 0.25d) + 21,            };
        return rows;
    }

    public static byte[] CreateReadFile(SyntheticDoubleDictionaryRow[] rows)
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
public class SyntheticDoubleDictionaryPlankBenchmarks
{
    SyntheticDoubleDictionaryRow[] _rows = null!;
    DefaultParquetBufferPool _pool = null!;
    ParquetWriterOptions _options = null!;
    SyntheticDoubleDictionaryRow.PipelineWriter _writer = null!;
    MemoryStream _output = null!;
    int _outputCapacity;
    MemoryReadSource _source = null!;
    SyntheticDoubleDictionaryRow.RowReader _reader = null!;
    PlankWorkerPinning _pinning = null!;

    public IEnumerable<int> RowCounts => [BenchmarkData.SyntheticRows];

    [ParamsSource(nameof(RowCounts))]
    public int Rows { get; set; }

    [GlobalSetup]
    public void Setup()
    {
        _rows = SyntheticDoubleDictionaryRow.CreateRows(Rows);
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
        _pinning.Reset();
        _writer = SyntheticDoubleDictionaryRow.CreateRowWriter(_output, _options);
        _pinning.Wait();
        Write();
        var file = _output.ToArray();
        Console.WriteLine("BENCHMARK_FILE|SyntheticDoubleDictionary|Plank|" + file.Length);
        _outputCapacity = BenchmarkData.OutputCapacity(file.Length);
        _output.Dispose();

        _source = new MemoryReadSource(file);
        _reader = SyntheticDoubleDictionaryRow.CreateRowReader(_source, options: new RowReaderOptions { BufferPool = _pool });
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
    public double Read()
    {
        double sum = 0;
        foreach (var row in _reader)
        {
            sum += row.Value0;
            sum += row.Value1;
            sum += row.Value2;
            sum += row.Value3;
            sum += row.Value4;
            sum += row.Value5;
            sum += row.Value6;
            sum += row.Value7;
            sum += row.Value8;
            sum += row.Value9;
            sum += row.Value10;
            sum += row.Value11;
            sum += row.Value12;
            sum += row.Value13;
            sum += row.Value14;
            sum += row.Value15;
            sum += row.Value16;
            sum += row.Value17;
            sum += row.Value18;
            sum += row.Value19;
            sum += row.Value20;
            sum += row.Value21;
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
public class SyntheticDoubleDictionaryParquetSharpBenchmarks
{
    const int RowsPerRowGroup = 45455;

    SyntheticDoubleDictionaryRow[] _rows = null!;
    ParquetSharp.Column[] _schema = null!;
    WriterProperties _properties = null!;
    MemoryStream _output = null!;
    ManagedOutputStream _managedOutput = null!;
    ParquetRowWriter<SyntheticDoubleDictionaryRow> _writer = null!;
    int _outputCapacity;
    GCHandle _pinned;
    NativeBuffer _buffer = null!;
    BufferReader _source = null!;
    ParquetRowReader<SyntheticDoubleDictionaryRow>? _reader;

    public IEnumerable<int> RowCounts => [BenchmarkData.SyntheticRows];

    [ParamsSource(nameof(RowCounts))]
    public int Rows { get; set; }

    [GlobalSetup]
    public void Setup()
    {
        _rows = SyntheticDoubleDictionaryRow.CreateRows(Rows);
        _schema =
        [
            new ParquetSharp.Column<double>("value_0"),
            new ParquetSharp.Column<double>("value_1"),
            new ParquetSharp.Column<double>("value_2"),
            new ParquetSharp.Column<double>("value_3"),
            new ParquetSharp.Column<double>("value_4"),
            new ParquetSharp.Column<double>("value_5"),
            new ParquetSharp.Column<double>("value_6"),
            new ParquetSharp.Column<double>("value_7"),
            new ParquetSharp.Column<double>("value_8"),
            new ParquetSharp.Column<double>("value_9"),
            new ParquetSharp.Column<double>("value_10"),
            new ParquetSharp.Column<double>("value_11"),
            new ParquetSharp.Column<double>("value_12"),
            new ParquetSharp.Column<double>("value_13"),
            new ParquetSharp.Column<double>("value_14"),
            new ParquetSharp.Column<double>("value_15"),
            new ParquetSharp.Column<double>("value_16"),
            new ParquetSharp.Column<double>("value_17"),
            new ParquetSharp.Column<double>("value_18"),
            new ParquetSharp.Column<double>("value_19"),
            new ParquetSharp.Column<double>("value_20"),
            new ParquetSharp.Column<double>("value_21"),
        ];
        using var builder = new WriterPropertiesBuilder();
        builder
            .Compression(Compression.Uncompressed)
            .EnableStatistics()
            .EnableWritePageIndex()
            .DataPageVersion(ParquetSharp.ParquetDataPageVersion.V2);
        _properties = builder.EnableDictionary().DictionaryPagesizeLimit(536_870_912).Build();

        _output = new MemoryStream();
        _managedOutput = new ManagedOutputStream(_output, leaveOpen: true);
        _writer = ParquetFile.CreateRowWriter<SyntheticDoubleDictionaryRow>(_managedOutput, _properties, _schema);
        Write();
        _outputCapacity = BenchmarkData.OutputCapacity(checked((int)_output.Length));
        Console.WriteLine("BENCHMARK_FILE|SyntheticDoubleDictionary|ParquetSharp|" + _output.Length);
        _writer.Dispose();
        _managedOutput.Dispose();
        _output.Dispose();

        var file = SyntheticDoubleDictionaryRow.CreateReadFile(_rows);
        _pinned = GCHandle.Alloc(file, GCHandleType.Pinned);
        _buffer = new NativeBuffer(_pinned.AddrOfPinnedObject(), file.LongLength);
        _source = new BufferReader(_buffer);
    }

    [IterationSetup(Target = nameof(Write))]
    public void SetupWrite()
    {
        _output = new MemoryStream(_outputCapacity);
        _managedOutput = new ManagedOutputStream(_output, leaveOpen: true);
        _writer = ParquetFile.CreateRowWriter<SyntheticDoubleDictionaryRow>(_managedOutput, _properties, _schema);
    }

    [IterationSetup(Target = nameof(Read))]
    public void SetupRead()
    {
        _reader?.Dispose();
        _reader = ParquetFile.CreateRowReader<SyntheticDoubleDictionaryRow>(_source);
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
    public double Read()
    {
        double sum = 0;
        for (var group = 0; group < _reader!.FileMetaData.NumRowGroups; group++)
        foreach (var row in _reader.ReadRows(group))
        {
            sum += row.Value0;
            sum += row.Value1;
            sum += row.Value2;
            sum += row.Value3;
            sum += row.Value4;
            sum += row.Value5;
            sum += row.Value6;
            sum += row.Value7;
            sum += row.Value8;
            sum += row.Value9;
            sum += row.Value10;
            sum += row.Value11;
            sum += row.Value12;
            sum += row.Value13;
            sum += row.Value14;
            sum += row.Value15;
            sum += row.Value16;
            sum += row.Value17;
            sum += row.Value18;
            sum += row.Value19;
            sum += row.Value20;
            sum += row.Value21;
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
public class SyntheticDoubleDictionaryParquetNetBenchmarks
{
    SyntheticDoubleDictionaryRow[] _rows = null!;
    byte[] _file = null!;
    MemoryStream? _stream;

    public IEnumerable<int> RowCounts => [BenchmarkData.SyntheticRows];

    [ParamsSource(nameof(RowCounts))]
    public int Rows { get; set; }

    [GlobalSetup]
    public void Setup()
    {
        _rows = SyntheticDoubleDictionaryRow.CreateRows(Rows);

        _file = SyntheticDoubleDictionaryRow.CreateReadFile(_rows);
    }

    [IterationSetup(Target = nameof(Read))]
    public void SetupRead()
    {
        _stream?.Dispose();
        _stream = new MemoryStream(_file, writable: false);
    }

    [Benchmark]
    public async Task<double> Read()
    {
        var result = await ParquetSerializer.DeserializeAsync<SyntheticDoubleDictionaryRow>(_stream!);
        double sum = 0;
        foreach (var row in result.Data)
        {
            sum += row.Value0;
            sum += row.Value1;
            sum += row.Value2;
            sum += row.Value3;
            sum += row.Value4;
            sum += row.Value5;
            sum += row.Value6;
            sum += row.Value7;
            sum += row.Value8;
            sum += row.Value9;
            sum += row.Value10;
            sum += row.Value11;
            sum += row.Value12;
            sum += row.Value13;
            sum += row.Value14;
            sum += row.Value15;
            sum += row.Value16;
            sum += row.Value17;
            sum += row.Value18;
            sum += row.Value19;
            sum += row.Value20;
            sum += row.Value21;
        }
        return sum;
    }

    [GlobalCleanup]
    public void Cleanup() => _stream?.Dispose();
}
