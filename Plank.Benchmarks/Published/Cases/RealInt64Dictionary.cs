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
sealed partial class RealInt64DictionaryRow
{
    [ParquetColumn("passenger_count", Encodings = [EncodingKind.RleDictionary]), MapToColumn("passenger_count"), JsonPropertyName("passenger_count")]
    public long? PassengerCount { get; set; }

    [ParquetColumn("RatecodeID", Encodings = [EncodingKind.RleDictionary]), MapToColumn("RatecodeID"), JsonPropertyName("RatecodeID")]
    public long? RatecodeId { get; set; }

    [ParquetColumn("payment_type", Encodings = [EncodingKind.RleDictionary]), MapToColumn("payment_type"), JsonPropertyName("payment_type")]
    public long? PaymentType { get; set; }

    public static byte[] CreateReadFile(RealInt64DictionaryRow[] rows)
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
            TargetRowGroupSizeBytes = 24000000UL,
            RowApiInitialRowCapacity = 45_455
        });
        foreach (var value in rows)
        {
            var row = writer.GetRow();
            row.PassengerCount = value.PassengerCount;
            row.RatecodeId = value.RatecodeId;
            row.PaymentType = value.PaymentType;
            writer.Next();
        }
        writer.Complete();
        return output.ToArray();
    }
}

[MemoryDiagnoser]
public class RealInt64DictionaryPlankBenchmarks
{
    RealInt64DictionaryRow[] _rows = null!;
    DefaultParquetBufferPool _pool = null!;
    ParquetWriterOptions _options = null!;
    RealInt64DictionaryRow.PipelineWriter _writer = null!;
    MemoryStream _output = null!;
    int _outputCapacity;
    MemoryReadSource _source = null!;
    RealInt64DictionaryRow.RowReader _reader = null!;
    PlankWorkerPinning _pinning = null!;

    public IEnumerable<int> RowCounts => [BenchmarkData.TaxiRows];

    [ParamsSource(nameof(RowCounts))]
    public int Rows { get; set; }

    [GlobalSetup]
    public void Setup()
    {
        _rows = BenchmarkData.LoadTaxiRows<RealInt64DictionaryRow>();
        _pool = new DefaultParquetBufferPool(ParquetBufferRetentionPolicy.ZeroAllocation);
        _pinning = new PlankWorkerPinning();
        _options = new ParquetWriterOptions
        {
            Compression = CompressionKind.None,
            BufferPool = _pool,
            DataPageVersion = ParquetDataPageVersion.V2,
            WritePageIndexes = true,
            WritePageCrc = false,
            TargetRowGroupSizeBytes = 24000000UL,
            RowApiInitialRowCapacity = 45_455,
            Execution = new ParquetExecutionOptions { OnWorkerStarted = _pinning.OnWorkerStarted }
        };

        _output = new MemoryStream();
        _pinning.Reset();
        _writer = RealInt64DictionaryRow.CreateRowWriter(_output, _options);
        _pinning.Wait();
        Write();
        var file = _output.ToArray();
        Console.WriteLine("BENCHMARK_FILE|RealInt64Dictionary|Plank|" + file.Length);
        _outputCapacity = BenchmarkData.OutputCapacity(file.Length);
        _output.Dispose();

        _source = new MemoryReadSource(file);
        _reader = RealInt64DictionaryRow.CreateRowReader(_source, options: new RowReaderOptions { BufferPool = _pool });
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
        foreach (var value in _rows)
        {
            var row = _writer.GetRow();
            row.PassengerCount = value.PassengerCount;
            row.RatecodeId = value.RatecodeId;
            row.PaymentType = value.PaymentType;
            _writer.Next();
        }
        _writer.Complete();
    }

    [Benchmark]
    public ulong Read()
    {
        ulong sum = 0;
        foreach (var row in _reader)
        {
            sum += unchecked((ulong)row.PassengerCount.GetValueOrDefault());
            sum += unchecked((ulong)row.RatecodeId.GetValueOrDefault());
            sum += unchecked((ulong)row.PaymentType.GetValueOrDefault());
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
public class RealInt64DictionaryParquetSharpBenchmarks
{
    const int RowsPerRowGroup = 1048576;

    RealInt64DictionaryRow[] _rows = null!;
    ParquetSharp.Column[] _schema = null!;
    WriterProperties _properties = null!;
    MemoryStream _output = null!;
    ManagedOutputStream _managedOutput = null!;
    ParquetRowWriter<RealInt64DictionaryRow> _writer = null!;
    int _outputCapacity;
    GCHandle _pinned;
    NativeBuffer _buffer = null!;
    BufferReader _source = null!;
    ParquetRowReader<RealInt64DictionaryRow>? _reader;

    public IEnumerable<int> RowCounts => [BenchmarkData.TaxiRows];

    [ParamsSource(nameof(RowCounts))]
    public int Rows { get; set; }

    [GlobalSetup]
    public void Setup()
    {
        _rows = BenchmarkData.LoadTaxiRows<RealInt64DictionaryRow>();
        _schema =
        [
            new ParquetSharp.Column<long?>("passenger_count"),
            new ParquetSharp.Column<long?>("RatecodeID"),
            new ParquetSharp.Column<long?>("payment_type"),
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
        _writer = ParquetFile.CreateRowWriter<RealInt64DictionaryRow>(_managedOutput, _properties, _schema);
        Write();
        _outputCapacity = BenchmarkData.OutputCapacity(checked((int)_output.Length));
        Console.WriteLine("BENCHMARK_FILE|RealInt64Dictionary|ParquetSharp|" + _output.Length);
        _writer.Dispose();
        _managedOutput.Dispose();
        _output.Dispose();

        var file = RealInt64DictionaryRow.CreateReadFile(_rows);
        _pinned = GCHandle.Alloc(file, GCHandleType.Pinned);
        _buffer = new NativeBuffer(_pinned.AddrOfPinnedObject(), file.LongLength);
        _source = new BufferReader(_buffer);
    }

    [IterationSetup(Target = nameof(Write))]
    public void SetupWrite()
    {
        _output = new MemoryStream(_outputCapacity);
        _managedOutput = new ManagedOutputStream(_output, leaveOpen: true);
        _writer = ParquetFile.CreateRowWriter<RealInt64DictionaryRow>(_managedOutput, _properties, _schema);
    }

    [IterationSetup(Target = nameof(Read))]
    public void SetupRead()
    {
        _reader?.Dispose();
        _reader = ParquetFile.CreateRowReader<RealInt64DictionaryRow>(_source);
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
            sum += unchecked((ulong)row.PassengerCount.GetValueOrDefault());
            sum += unchecked((ulong)row.RatecodeId.GetValueOrDefault());
            sum += unchecked((ulong)row.PaymentType.GetValueOrDefault());
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
public class RealInt64DictionaryParquetNetBenchmarks
{
    RealInt64DictionaryRow[] _rows = null!;
    byte[] _file = null!;
    MemoryStream? _stream;

    public IEnumerable<int> RowCounts => [BenchmarkData.TaxiRows];

    [ParamsSource(nameof(RowCounts))]
    public int Rows { get; set; }

    [GlobalSetup]
    public void Setup()
    {
        _rows = BenchmarkData.LoadTaxiRows<RealInt64DictionaryRow>();

        _file = RealInt64DictionaryRow.CreateReadFile(_rows);
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
        var result = await ParquetSerializer.DeserializeAsync<RealInt64DictionaryRow>(_stream!);
        ulong sum = 0;
        foreach (var row in result.Data)
        {
            sum += unchecked((ulong)row.PassengerCount.GetValueOrDefault());
            sum += unchecked((ulong)row.RatecodeId.GetValueOrDefault());
            sum += unchecked((ulong)row.PaymentType.GetValueOrDefault());
        }
        return sum;
    }

    [GlobalCleanup]
    public void Cleanup() => _stream?.Dispose();
}
