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
sealed partial class RealStringsDeltaByteArrayPlankRow
{
    [ParquetColumn("store_and_fwd_flag", Encodings = [EncodingKind.DeltaByteArray], LogicalType = LogicalTypeKind.String), MapToColumn("store_and_fwd_flag"), JsonPropertyName("store_and_fwd_flag")]
    public ReadOnlyMemory<byte>? StoreAndForwardFlag { get; set; }

    public static byte[] CreateReadFile(RealStringsDeltaByteArrayPlankRow[] rows)
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
            row.StoreAndForwardFlag = value.StoreAndForwardFlag;
        }
        writer.Complete();
        return output.ToArray();
    }
    public static RealStringsDeltaByteArrayPlankRow[] FromSharp(RealStringsDeltaByteArraySharpRow[] source)
    {
        var rows = new RealStringsDeltaByteArrayPlankRow[source.Length];
        for (var index = 0; index < rows.Length; index++)
        {
            var value = source[index];
            rows[index] = new RealStringsDeltaByteArrayPlankRow
            {
                StoreAndForwardFlag = value.StoreAndForwardFlag is null ? null : new ReadOnlyMemory<byte>(Encoding.UTF8.GetBytes(value.StoreAndForwardFlag)),            };
        }
        return rows;
    }

    public static RealStringsDeltaByteArrayPlankRow[] FromNet(RealStringsDeltaByteArrayNetRow[] source)
    {
        var rows = new RealStringsDeltaByteArrayPlankRow[source.Length];
        for (var index = 0; index < rows.Length; index++)
        {
            var value = source[index];
            rows[index] = new RealStringsDeltaByteArrayPlankRow
            {
                StoreAndForwardFlag = value.StoreAndForwardFlag is null ? null : new ReadOnlyMemory<byte>(Encoding.UTF8.GetBytes(value.StoreAndForwardFlag)),            };
        }
        return rows;
    }

}

sealed partial class RealStringsDeltaByteArraySharpRow
{
    [MapToColumn("store_and_fwd_flag"), JsonPropertyName("store_and_fwd_flag")]
    public string? StoreAndForwardFlag { get; set; }
}

sealed partial class RealStringsDeltaByteArrayNetRow
{
    [MapToColumn("store_and_fwd_flag"), JsonPropertyName("store_and_fwd_flag")]
    public string? StoreAndForwardFlag { get; set; }
}

[MemoryDiagnoser]
public class RealStringsDeltaByteArrayPlankBenchmarks
{
    RealStringsDeltaByteArrayPlankRow[] _rows = null!;
    DefaultParquetBufferPool _pool = null!;
    ParquetWriterOptions _options = null!;
    RealStringsDeltaByteArrayPlankRow.PipelineWriter _writer = null!;
    MemoryStream _output = null!;
    int _outputCapacity;
    MemoryReadSource _source = null!;
    RealStringsDeltaByteArrayPlankRow.RowReader _reader = null!;
    PlankWorkerPinning _pinning = null!;

    public IEnumerable<int> RowCounts => [BenchmarkData.TaxiRows];

    [ParamsSource(nameof(RowCounts))]
    public int Rows { get; set; }

    [GlobalSetup]
    public void Setup()
    {
        _rows = RealStringsDeltaByteArrayPlankRow.FromSharp(BenchmarkData.LoadTaxiRows<RealStringsDeltaByteArraySharpRow>());
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
        _writer = RealStringsDeltaByteArrayPlankRow.CreateRowWriter(_output, _options);
        Write();
        var file = _output.ToArray();
        Console.WriteLine("BENCHMARK_FILE|RealStringsDeltaByteArray|Plank|" + file.Length);
        _outputCapacity = BenchmarkData.OutputCapacity(file.Length);
        _output.Dispose();

        _source = new MemoryReadSource(file);
        _reader = RealStringsDeltaByteArrayPlankRow.CreateRowReader(_source, options: new RowReaderOptions { BufferPool = _pool });
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
            row.StoreAndForwardFlag = value.StoreAndForwardFlag;
        }
        _writer.Complete();
    }

    [Benchmark]
    public ulong Read()
    {
        ulong sum = 0;
        foreach (var row in _reader)
        {
            sum += (ulong)row.StoreAndForwardFlag.Length;
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
public class RealStringsDeltaByteArrayParquetSharpBenchmarks
{
    const int RowsPerRowGroup = 1048576;

    RealStringsDeltaByteArraySharpRow[] _rows = null!;
    ParquetSharp.Column[] _schema = null!;
    WriterProperties _properties = null!;
    MemoryStream _output = null!;
    ManagedOutputStream _managedOutput = null!;
    ParquetRowWriter<RealStringsDeltaByteArraySharpRow> _writer = null!;
    int _outputCapacity;
    GCHandle _pinned;
    NativeBuffer _buffer = null!;
    BufferReader _source = null!;
    ParquetRowReader<RealStringsDeltaByteArraySharpRow>? _reader;

    public IEnumerable<int> RowCounts => [BenchmarkData.TaxiRows];

    [ParamsSource(nameof(RowCounts))]
    public int Rows { get; set; }

    [GlobalSetup]
    public void Setup()
    {
        _rows = BenchmarkData.LoadTaxiRows<RealStringsDeltaByteArraySharpRow>();
        _schema =
        [
            new ParquetSharp.Column<string?>("store_and_fwd_flag", LogicalType.String()),
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
        _writer = ParquetFile.CreateRowWriter<RealStringsDeltaByteArraySharpRow>(_managedOutput, _properties, _schema);
        Write();
        _outputCapacity = BenchmarkData.OutputCapacity(checked((int)_output.Length));
        Console.WriteLine("BENCHMARK_FILE|RealStringsDeltaByteArray|ParquetSharp|" + _output.Length);
        _writer.Dispose();
        _managedOutput.Dispose();
        _output.Dispose();

        var file = RealStringsDeltaByteArrayPlankRow.CreateReadFile(RealStringsDeltaByteArrayPlankRow.FromSharp(_rows));
        _pinned = GCHandle.Alloc(file, GCHandleType.Pinned);
        _buffer = new NativeBuffer(_pinned.AddrOfPinnedObject(), file.LongLength);
        _source = new BufferReader(_buffer);
    }

    [IterationSetup(Target = nameof(Write))]
    public void SetupWrite()
    {
        _output = new MemoryStream(_outputCapacity);
        _managedOutput = new ManagedOutputStream(_output, leaveOpen: true);
        _writer = ParquetFile.CreateRowWriter<RealStringsDeltaByteArraySharpRow>(_managedOutput, _properties, _schema);
    }

    [IterationSetup(Target = nameof(Read))]
    public void SetupRead()
    {
        _reader?.Dispose();
        _reader = ParquetFile.CreateRowReader<RealStringsDeltaByteArraySharpRow>(_source);
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
            sum += (ulong)(row.StoreAndForwardFlag?.Length ?? 0);
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
public class RealStringsDeltaByteArrayParquetNetBenchmarks
{
    RealStringsDeltaByteArrayNetRow[] _rows = null!;
    byte[] _file = null!;
    MemoryStream? _stream;

    public IEnumerable<int> RowCounts => [BenchmarkData.TaxiRows];

    [ParamsSource(nameof(RowCounts))]
    public int Rows { get; set; }

    [GlobalSetup]
    public void Setup()
    {
        _rows = BenchmarkData.LoadTaxiRows<RealStringsDeltaByteArrayNetRow>();

        _file = RealStringsDeltaByteArrayPlankRow.CreateReadFile(RealStringsDeltaByteArrayPlankRow.FromNet(_rows));
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
        var result = await ParquetSerializer.DeserializeAsync<RealStringsDeltaByteArrayNetRow>(_stream!);
        ulong sum = 0;
        foreach (var row in result.Data)
        {
            sum += (ulong)(row.StoreAndForwardFlag?.Length ?? 0);
        }
        return sum;
    }

    [GlobalCleanup]
    public void Cleanup() => _stream?.Dispose();
}
