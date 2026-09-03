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
sealed partial class RealTimestampsByteStreamSplitRow
{
    [ParquetColumn("tpep_pickup_datetime", Encodings = [EncodingKind.ByteStreamSplit], LogicalType = LogicalTypeKind.Timestamp), MapToColumn("tpep_pickup_datetime"), JsonPropertyName("tpep_pickup_datetime")]
    public DateTime? Pickup { get; set; }

    [ParquetColumn("tpep_dropoff_datetime", Encodings = [EncodingKind.ByteStreamSplit], LogicalType = LogicalTypeKind.Timestamp), MapToColumn("tpep_dropoff_datetime"), JsonPropertyName("tpep_dropoff_datetime")]
    public DateTime? Dropoff { get; set; }

    public static byte[] CreateReadFile(RealTimestampsByteStreamSplitRow[] rows)
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
            TargetRowGroupSizeBytes = 16000000UL,
            RowApiInitialRowCapacity = 45_455
        });
        foreach (var value in rows)
        {
            var row = writer.GetRow();
            row.Pickup = value.Pickup.HasValue ? DateTime.SpecifyKind(value.Pickup.GetValueOrDefault(), DateTimeKind.Utc) : null;
            row.Dropoff = value.Dropoff.HasValue ? DateTime.SpecifyKind(value.Dropoff.GetValueOrDefault(), DateTimeKind.Utc) : null;
        }
        writer.Complete();
        return output.ToArray();
    }
}

[MemoryDiagnoser]
public class RealTimestampsByteStreamSplitPlankBenchmarks
{
    RealTimestampsByteStreamSplitRow[] _rows = null!;
    DefaultParquetBufferPool _pool = null!;
    ParquetWriterOptions _options = null!;
    RealTimestampsByteStreamSplitRow.PipelineWriter _writer = null!;
    MemoryStream _output = null!;
    int _outputCapacity;
    MemoryReadSource _source = null!;
    RealTimestampsByteStreamSplitRow.RowReader _reader = null!;
    PlankWorkerPinning _pinning = null!;

    public IEnumerable<int> RowCounts => [BenchmarkData.TaxiRows];

    [ParamsSource(nameof(RowCounts))]
    public int Rows { get; set; }

    [GlobalSetup]
    public void Setup()
    {
        _rows = BenchmarkData.LoadTaxiRows<RealTimestampsByteStreamSplitRow>();
        foreach (var value in _rows)
        {
            value.Pickup = value.Pickup.HasValue ? DateTime.SpecifyKind(value.Pickup.GetValueOrDefault(), DateTimeKind.Utc) : null;
            value.Dropoff = value.Dropoff.HasValue ? DateTime.SpecifyKind(value.Dropoff.GetValueOrDefault(), DateTimeKind.Utc) : null;
        }
        _pool = new DefaultParquetBufferPool(ParquetBufferRetentionPolicy.ZeroAllocation);
        _pinning = new PlankWorkerPinning();
        _options = new ParquetWriterOptions
        {
            Compression = CompressionKind.None,
            BufferPool = _pool,
            DataPageVersion = ParquetDataPageVersion.V2,
            WritePageIndexes = true,
            WritePageCrc = false,
            TargetRowGroupSizeBytes = 16000000UL,
            RowApiInitialRowCapacity = 45_455,
            Execution = new ParquetExecutionOptions { OnWorkerStarted = _pinning.OnWorkerStarted }
        };

        _output = new MemoryStream();
        _writer = RealTimestampsByteStreamSplitRow.CreateRowWriter(_output, _options);
        Write();
        var file = _output.ToArray();
        Console.WriteLine("BENCHMARK_FILE|RealTimestampsByteStreamSplit|Plank|" + file.Length);
        _outputCapacity = BenchmarkData.OutputCapacity(file.Length);
        _output.Dispose();

        _source = new MemoryReadSource(file);
        _reader = RealTimestampsByteStreamSplitRow.CreateRowReader(_source, options: new RowReaderOptions { BufferPool = _pool });
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
            row.Pickup = value.Pickup;
            row.Dropoff = value.Dropoff;
        }
        _writer.Complete();
    }

    [Benchmark]
    public long Read()
    {
        long sum = 0;
        foreach (var row in _reader)
        {
            sum += (row.Pickup?.Ticks ?? 0L);
            sum += (row.Dropoff?.Ticks ?? 0L);
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
public class RealTimestampsByteStreamSplitParquetSharpBenchmarks
{
    const int RowsPerRowGroup = 1048576;

    RealTimestampsByteStreamSplitRow[] _rows = null!;
    ParquetSharp.Column[] _schema = null!;
    WriterProperties _properties = null!;
    MemoryStream _output = null!;
    ManagedOutputStream _managedOutput = null!;
    ParquetRowWriter<RealTimestampsByteStreamSplitRow> _writer = null!;
    int _outputCapacity;
    GCHandle _pinned;
    NativeBuffer _buffer = null!;
    BufferReader _source = null!;
    ParquetRowReader<RealTimestampsByteStreamSplitRow>? _reader;

    public IEnumerable<int> RowCounts => [BenchmarkData.TaxiRows];

    [ParamsSource(nameof(RowCounts))]
    public int Rows { get; set; }

    [GlobalSetup]
    public void Setup()
    {
        _rows = BenchmarkData.LoadTaxiRows<RealTimestampsByteStreamSplitRow>();
        _schema =
        [
            new ParquetSharp.Column<DateTime?>("tpep_pickup_datetime", LogicalType.Timestamp(false, TimeUnit.Micros)),
            new ParquetSharp.Column<DateTime?>("tpep_dropoff_datetime", LogicalType.Timestamp(false, TimeUnit.Micros)),
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
        _writer = ParquetFile.CreateRowWriter<RealTimestampsByteStreamSplitRow>(_managedOutput, _properties, _schema);
        Write();
        _outputCapacity = BenchmarkData.OutputCapacity(checked((int)_output.Length));
        Console.WriteLine("BENCHMARK_FILE|RealTimestampsByteStreamSplit|ParquetSharp|" + _output.Length);
        _writer.Dispose();
        _managedOutput.Dispose();
        _output.Dispose();

        var file = RealTimestampsByteStreamSplitRow.CreateReadFile(_rows);
        _pinned = GCHandle.Alloc(file, GCHandleType.Pinned);
        _buffer = new NativeBuffer(_pinned.AddrOfPinnedObject(), file.LongLength);
        _source = new BufferReader(_buffer);
    }

    [IterationSetup(Target = nameof(Write))]
    public void SetupWrite()
    {
        _output = new MemoryStream(_outputCapacity);
        _managedOutput = new ManagedOutputStream(_output, leaveOpen: true);
        _writer = ParquetFile.CreateRowWriter<RealTimestampsByteStreamSplitRow>(_managedOutput, _properties, _schema);
    }

    [IterationSetup(Target = nameof(Read))]
    public void SetupRead()
    {
        _reader?.Dispose();
        _reader = ParquetFile.CreateRowReader<RealTimestampsByteStreamSplitRow>(_source);
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
    public long Read()
    {
        long sum = 0;
        for (var group = 0; group < _reader!.FileMetaData.NumRowGroups; group++)
        foreach (var row in _reader.ReadRows(group))
        {
            sum += (row.Pickup?.Ticks ?? 0L);
            sum += (row.Dropoff?.Ticks ?? 0L);
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
