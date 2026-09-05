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
sealed partial class RealInt32DeltaBinaryPackedRow
{
    [ParquetColumn("VendorID", Encodings = [EncodingKind.DeltaBinaryPacked]), MapToColumn("VendorID"), JsonPropertyName("VendorID")]
    public int? VendorId { get; set; }

    [ParquetColumn("PULocationID", Encodings = [EncodingKind.DeltaBinaryPacked]), MapToColumn("PULocationID"), JsonPropertyName("PULocationID")]
    public int? PickupLocationId { get; set; }

    [ParquetColumn("DOLocationID", Encodings = [EncodingKind.DeltaBinaryPacked]), MapToColumn("DOLocationID"), JsonPropertyName("DOLocationID")]
    public int? DropoffLocationId { get; set; }

    public static byte[] CreateReadFile(RealInt32DeltaBinaryPackedRow[] rows)
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
public class RealInt32DeltaBinaryPackedPlankBenchmarks
{
    RealInt32DeltaBinaryPackedRow[] _rows = null!;
    DefaultParquetBufferPool _pool = null!;
    ParquetWriterOptions _options = null!;
    RealInt32DeltaBinaryPackedRow.PipelineWriter _writer = null!;
    MemoryStream _output = null!;
    byte[] _outputBuffer = null!;
    long _expectedOutputBytes;
    MemoryReadSource _source = null!;
    RealInt32DeltaBinaryPackedRow.RowReader _reader = null!;
    PlankWorkerPinning _pinning = null!;

    public IEnumerable<int> RowCounts => [BenchmarkData.TaxiRows];

    [ParamsSource(nameof(RowCounts))]
    public int Rows { get; set; }

    [GlobalSetup(Target = nameof(Write))]
    public void GlobalSetupWrite()
    {
        _rows ??= BenchmarkData.LoadTaxiRows<RealInt32DeltaBinaryPackedRow>();
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

        _outputBuffer = new byte[BenchmarkFixtures.GetOutputCapacity("RealInt32DeltaBinaryPacked", "Plank", out _expectedOutputBytes)];
    }

    [GlobalSetup(Target = nameof(Read))]
    public void GlobalSetupRead()
    {
        _pool = new DefaultParquetBufferPool(ParquetBufferRetentionPolicy.ZeroAllocation);
        var file = BenchmarkFixtures.LoadReadFile("RealInt32DeltaBinaryPacked");
        _source = new MemoryReadSource(file);
        _reader = RealInt32DeltaBinaryPackedRow.CreateRowReader(_source, options: new RowReaderOptions { BufferPool = _pool });
    }

    [IterationSetup(Target = nameof(Write))]
    public void SetupWrite()
    {
        _output = BenchmarkFixtures.CreateOutput(_outputBuffer);
        _pinning.Reset();
        if (_writer is null)
            _writer = RealInt32DeltaBinaryPackedRow.CreateRowWriter(_output, _options);
        else
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
    public void CleanupWrite()
    {
        BenchmarkFixtures.ValidateOutput(_expectedOutputBytes, BenchmarkFixtures.OutputLength(_output));
        _output?.Dispose();
    }

    [GlobalCleanup]
    public void Cleanup()
    {
        _writer?.Dispose();
        _reader?.Dispose();
        _source?.Dispose();
        _pool?.Dispose();
        _output?.Dispose();
    }
}

[MemoryDiagnoser]
public class RealInt32DeltaBinaryPackedParquetSharpBenchmarks
{
    const int RowsPerRowGroup = 1048576;

    RealInt32DeltaBinaryPackedRow[] _rows = null!;
    ParquetSharp.Column[] _schema = null!;
    WriterProperties _properties = null!;
    MemoryStream _output = null!;
    ManagedOutputStream _managedOutput = null!;
    ParquetRowWriter<RealInt32DeltaBinaryPackedRow> _writer = null!;
    byte[] _outputBuffer = null!;
    long _expectedOutputBytes;
    GCHandle _pinned;
    NativeBuffer _buffer = null!;
    BufferReader _source = null!;
    ParquetRowReader<RealInt32DeltaBinaryPackedRow>? _reader;

    public IEnumerable<int> RowCounts => [BenchmarkData.TaxiRows];

    [ParamsSource(nameof(RowCounts))]
    public int Rows { get; set; }

    [GlobalSetup(Target = nameof(Write))]
    public void GlobalSetupWrite()
    {
        _rows ??= BenchmarkData.LoadTaxiRows<RealInt32DeltaBinaryPackedRow>();
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
        _properties = builder.DisableDictionary().Encoding(ParquetSharp.Encoding.DeltaBinaryPacked).Build();

        _outputBuffer = new byte[BenchmarkFixtures.GetOutputCapacity("RealInt32DeltaBinaryPacked", "ParquetSharp", out _expectedOutputBytes)];
    }

    [GlobalSetup(Target = nameof(Read))]
    public void GlobalSetupRead()
    {
        var file = BenchmarkFixtures.LoadReadFile("RealInt32DeltaBinaryPacked");
        _pinned = GCHandle.Alloc(file, GCHandleType.Pinned);
        _buffer = new NativeBuffer(_pinned.AddrOfPinnedObject(), file.LongLength);
        _source = new BufferReader(_buffer);
    }

    [IterationSetup(Target = nameof(Write))]
    public void SetupWrite()
    {
        _output = BenchmarkFixtures.CreateOutput(_outputBuffer);
        _managedOutput = new ManagedOutputStream(_output, leaveOpen: true);
        _writer = ParquetFile.CreateRowWriter<RealInt32DeltaBinaryPackedRow>(_managedOutput, _properties, _schema);
    }

    [IterationSetup(Target = nameof(Read))]
    public void SetupRead()
    {
        _reader?.Dispose();
        _reader = ParquetFile.CreateRowReader<RealInt32DeltaBinaryPackedRow>(_source);
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
        BenchmarkFixtures.ValidateOutput(_expectedOutputBytes, BenchmarkFixtures.OutputLength(_output));
        _writer?.Dispose();
        _managedOutput.Dispose();
        _output?.Dispose();
    }

    [GlobalCleanup]
    public void Cleanup()
    {
        _reader?.Dispose();
        _source?.Dispose();
        _buffer?.Dispose();
        if (_pinned.IsAllocated) _pinned.Free();
        _properties?.Dispose();
    }
}

[MemoryDiagnoser]
public class RealInt32DeltaBinaryPackedParquetNetBenchmarks
{
    RealInt32DeltaBinaryPackedRow[] _rows = null!;
    ParquetOptions _options = null!;
    MemoryStream _output = null!;
    byte[] _outputBuffer = null!;
    long _expectedOutputBytes;
    byte[] _file = null!;
    MemoryStream? _stream;

    public IEnumerable<int> RowCounts => [BenchmarkData.TaxiRows];

    [ParamsSource(nameof(RowCounts))]
    public int Rows { get; set; }

    [GlobalSetup(Target = nameof(Write))]
    public void GlobalSetupWrite()
    {
        _rows ??= BenchmarkData.LoadTaxiRows<RealInt32DeltaBinaryPackedRow>();
        _options = new ParquetOptions
        {
            CompressionMethod = CompressionMethod.None,
            DictionaryEncodingThreshold = 0,
            RowGroupSize = 1048576
        };
        _options.ColumnEncodingHints["VendorID"] = EncodingHint.DeltaBinaryPacked;
        _options.ColumnEncodingHints["PULocationID"] = EncodingHint.DeltaBinaryPacked;
        _options.ColumnEncodingHints["DOLocationID"] = EncodingHint.DeltaBinaryPacked;

        _outputBuffer = new byte[BenchmarkFixtures.GetOutputCapacity("RealInt32DeltaBinaryPacked", "Parquet.Net", out _expectedOutputBytes)];
    }

    [GlobalSetup(Target = nameof(Read))]
    public void GlobalSetupRead() => _file = BenchmarkFixtures.LoadReadFile("RealInt32DeltaBinaryPacked");

    [IterationSetup(Target = nameof(Write))]
    public void SetupWrite() => _output = BenchmarkFixtures.CreateOutput(_outputBuffer);
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
        var result = await ParquetSerializer.DeserializeAsync<RealInt32DeltaBinaryPackedRow>(_stream!);
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
    public void CleanupWrite()
    {
        BenchmarkFixtures.ValidateOutput(_expectedOutputBytes, BenchmarkFixtures.OutputLength(_output));
        _output?.Dispose();
    }
    [GlobalCleanup]
    public void Cleanup() => _stream?.Dispose();
}
