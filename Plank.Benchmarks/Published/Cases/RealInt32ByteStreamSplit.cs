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
sealed partial class RealInt32ByteStreamSplitRow
{
    [ParquetColumn("VendorID", Encodings = [EncodingKind.ByteStreamSplit]), MapToColumn("VendorID"), JsonPropertyName("VendorID")]
    public int? VendorId { get; set; }

    [ParquetColumn("PULocationID", Encodings = [EncodingKind.ByteStreamSplit]), MapToColumn("PULocationID"), JsonPropertyName("PULocationID")]
    public int? PickupLocationId { get; set; }

    [ParquetColumn("DOLocationID", Encodings = [EncodingKind.ByteStreamSplit]), MapToColumn("DOLocationID"), JsonPropertyName("DOLocationID")]
    public int? DropoffLocationId { get; set; }

    public static byte[] CreateReadFile(RealInt32ByteStreamSplitRow[] rows)
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
            TargetRowGroupSizeBytes = 12000000UL,
            RowApiInitialRowCapacity = 45_455
        });
        foreach (var value in rows)
        {
            var row = writer.GetRow();
            row.VendorId = value.VendorId;
            row.PickupLocationId = value.PickupLocationId;
            row.DropoffLocationId = value.DropoffLocationId;
        }
        writer.Complete();
        return output.ToArray();
    }
}

[MemoryDiagnoser]
public class RealInt32ByteStreamSplitPlankBenchmarks
{
    RealInt32ByteStreamSplitRow[] _rows = null!;
    DefaultParquetBufferPool _pool = null!;
    ParquetWriterOptions _options = null!;
    RealInt32ByteStreamSplitRow.PipelineWriter _writer = null!;
    MemoryStream _output = null!;
    int _outputCapacity;
    MemoryReadSource _source = null!;
    RealInt32ByteStreamSplitRow.RowReader _reader = null!;
    PlankWorkerPinning _pinning = null!;

    public IEnumerable<int> RowCounts => [BenchmarkData.TaxiRows];

    [ParamsSource(nameof(RowCounts))]
    public int Rows { get; set; }

    [GlobalSetup]
    public void Setup()
    {
        _rows = BenchmarkData.LoadTaxiRows<RealInt32ByteStreamSplitRow>();
        _pool = new DefaultParquetBufferPool(ParquetBufferRetentionPolicy.ZeroAllocation);
        _pinning = new PlankWorkerPinning();
        _options = new ParquetWriterOptions
        {
            Compression = CompressionKind.None,
            BufferPool = _pool,
            DataPageVersion = ParquetDataPageVersion.V2,
            WritePageIndexes = true,
            WritePageCrc = false,
            TargetRowGroupSizeBytes = 12000000UL,
            RowApiInitialRowCapacity = 45_455,
            Execution = new ParquetExecutionOptions { OnWorkerStarted = _pinning.OnWorkerStarted }
        };

        _output = new MemoryStream();
        _pinning.Reset();
        _writer = RealInt32ByteStreamSplitRow.CreateRowWriter(_output, _options);
        _pinning.Wait();
        Write();
        var file = _output.ToArray();
        Console.WriteLine("BENCHMARK_FILE|RealInt32ByteStreamSplit|Plank|" + file.Length);
        _outputCapacity = BenchmarkData.OutputCapacity(file.Length);
        _output.Dispose();

        _source = new MemoryReadSource(file);
        _reader = RealInt32ByteStreamSplitRow.CreateRowReader(_source, options: new RowReaderOptions { BufferPool = _pool });
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
            row.VendorId = value.VendorId;
            row.PickupLocationId = value.PickupLocationId;
            row.DropoffLocationId = value.DropoffLocationId;
        }
        _writer.Complete();
    }

    [Benchmark]
    public ulong Read()
    {
        ulong sum = 0;
        foreach (var row in _reader)
        {
            sum += unchecked((uint)row.VendorId.GetValueOrDefault());
            sum += unchecked((uint)row.PickupLocationId.GetValueOrDefault());
            sum += unchecked((uint)row.DropoffLocationId.GetValueOrDefault());
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
public class RealInt32ByteStreamSplitParquetSharpBenchmarks
{
    const int RowsPerRowGroup = 1048576;

    RealInt32ByteStreamSplitRow[] _rows = null!;
    ParquetSharp.Column[] _schema = null!;
    WriterProperties _properties = null!;
    MemoryStream _output = null!;
    ManagedOutputStream _managedOutput = null!;
    ParquetRowWriter<RealInt32ByteStreamSplitRow> _writer = null!;
    int _outputCapacity;
    GCHandle _pinned;
    NativeBuffer _buffer = null!;
    BufferReader _source = null!;
    ParquetRowReader<RealInt32ByteStreamSplitRow>? _reader;

    public IEnumerable<int> RowCounts => [BenchmarkData.TaxiRows];

    [ParamsSource(nameof(RowCounts))]
    public int Rows { get; set; }

    [GlobalSetup]
    public void Setup()
    {
        _rows = BenchmarkData.LoadTaxiRows<RealInt32ByteStreamSplitRow>();
        _schema =
        [
            new ParquetSharp.Column<int?>("VendorID"),
            new ParquetSharp.Column<int?>("PULocationID"),
            new ParquetSharp.Column<int?>("DOLocationID"),
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
        _writer = ParquetFile.CreateRowWriter<RealInt32ByteStreamSplitRow>(_managedOutput, _properties, _schema);
        Write();
        _outputCapacity = BenchmarkData.OutputCapacity(checked((int)_output.Length));
        Console.WriteLine("BENCHMARK_FILE|RealInt32ByteStreamSplit|ParquetSharp|" + _output.Length);
        _writer.Dispose();
        _managedOutput.Dispose();
        _output.Dispose();

        var file = RealInt32ByteStreamSplitRow.CreateReadFile(_rows);
        _pinned = GCHandle.Alloc(file, GCHandleType.Pinned);
        _buffer = new NativeBuffer(_pinned.AddrOfPinnedObject(), file.LongLength);
        _source = new BufferReader(_buffer);
    }

    [IterationSetup(Target = nameof(Write))]
    public void SetupWrite()
    {
        _output = new MemoryStream(_outputCapacity);
        _managedOutput = new ManagedOutputStream(_output, leaveOpen: true);
        _writer = ParquetFile.CreateRowWriter<RealInt32ByteStreamSplitRow>(_managedOutput, _properties, _schema);
    }

    [IterationSetup(Target = nameof(Read))]
    public void SetupRead()
    {
        _reader?.Dispose();
        _reader = ParquetFile.CreateRowReader<RealInt32ByteStreamSplitRow>(_source);
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
            sum += unchecked((uint)row.VendorId.GetValueOrDefault());
            sum += unchecked((uint)row.PickupLocationId.GetValueOrDefault());
            sum += unchecked((uint)row.DropoffLocationId.GetValueOrDefault());
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
public class RealInt32ByteStreamSplitParquetNetBenchmarks
{
    RealInt32ByteStreamSplitRow[] _rows = null!;
    ParquetOptions _options = null!;
    MemoryStream _output = null!;
    int _outputCapacity;
    byte[] _file = null!;
    MemoryStream? _stream;

    public IEnumerable<int> RowCounts => [BenchmarkData.TaxiRows];

    [ParamsSource(nameof(RowCounts))]
    public int Rows { get; set; }

    [GlobalSetup]
    public void Setup()
    {
        _rows = BenchmarkData.LoadTaxiRows<RealInt32ByteStreamSplitRow>();
        _options = new ParquetOptions
        {
            CompressionMethod = CompressionMethod.None,
            DictionaryEncodingThreshold = 0,
            RowGroupSize = 1048576
        };
        _options.ColumnEncodingHints["VendorID"] = EncodingHint.ByteSplitStream;
        _options.ColumnEncodingHints["PULocationID"] = EncodingHint.ByteSplitStream;
        _options.ColumnEncodingHints["DOLocationID"] = EncodingHint.ByteSplitStream;

        _output = new MemoryStream();
        Write().GetAwaiter().GetResult();
        _outputCapacity = BenchmarkData.OutputCapacity(checked((int)_output.Length));
        Console.WriteLine("BENCHMARK_FILE|RealInt32ByteStreamSplit|Parquet.Net|" + _output.Length);
        _output.Dispose();

        _file = RealInt32ByteStreamSplitRow.CreateReadFile(_rows);
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
        var result = await ParquetSerializer.DeserializeAsync<RealInt32ByteStreamSplitRow>(_stream!);
        ulong sum = 0;
        foreach (var row in result.Data)
        {
            sum += unchecked((uint)row.VendorId.GetValueOrDefault());
            sum += unchecked((uint)row.PickupLocationId.GetValueOrDefault());
            sum += unchecked((uint)row.DropoffLocationId.GetValueOrDefault());
        }
        return sum;
    }

    [IterationCleanup(Target = nameof(Write))]
    public void CleanupWrite() => _output.Dispose();
    [GlobalCleanup]
    public void Cleanup() => _stream?.Dispose();
}
