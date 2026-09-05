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
sealed partial class RealDoublesDictionaryRow
{
    [ParquetColumn("trip_distance", Encodings = [EncodingKind.RleDictionary]), MapToColumn("trip_distance"), JsonPropertyName("trip_distance")]
    public double? TripDistance { get; set; }

    [ParquetColumn("fare_amount", Encodings = [EncodingKind.RleDictionary]), MapToColumn("fare_amount"), JsonPropertyName("fare_amount")]
    public double? FareAmount { get; set; }

    [ParquetColumn("extra", Encodings = [EncodingKind.RleDictionary]), MapToColumn("extra"), JsonPropertyName("extra")]
    public double? Extra { get; set; }

    [ParquetColumn("mta_tax", Encodings = [EncodingKind.RleDictionary]), MapToColumn("mta_tax"), JsonPropertyName("mta_tax")]
    public double? MtaTax { get; set; }

    [ParquetColumn("tip_amount", Encodings = [EncodingKind.RleDictionary]), MapToColumn("tip_amount"), JsonPropertyName("tip_amount")]
    public double? TipAmount { get; set; }

    [ParquetColumn("tolls_amount", Encodings = [EncodingKind.RleDictionary]), MapToColumn("tolls_amount"), JsonPropertyName("tolls_amount")]
    public double? TollsAmount { get; set; }

    [ParquetColumn("improvement_surcharge", Encodings = [EncodingKind.RleDictionary]), MapToColumn("improvement_surcharge"), JsonPropertyName("improvement_surcharge")]
    public double? ImprovementSurcharge { get; set; }

    [ParquetColumn("total_amount", Encodings = [EncodingKind.RleDictionary]), MapToColumn("total_amount"), JsonPropertyName("total_amount")]
    public double? TotalAmount { get; set; }

    [ParquetColumn("congestion_surcharge", Encodings = [EncodingKind.RleDictionary]), MapToColumn("congestion_surcharge"), JsonPropertyName("congestion_surcharge")]
    public double? CongestionSurcharge { get; set; }

    [ParquetColumn("Airport_fee", Encodings = [EncodingKind.RleDictionary]), MapToColumn("Airport_fee"), JsonPropertyName("Airport_fee")]
    public double? AirportFee { get; set; }

    public static byte[] CreateReadFile(RealDoublesDictionaryRow[] rows)
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
            TargetRowGroupSizeBytes = 80000000UL,
            RowApiInitialRowCapacity = 45_455
        });
        foreach (var value in rows)
        {
            var row = writer.GetRow();
            row.TripDistance = value.TripDistance;
            row.FareAmount = value.FareAmount;
            row.Extra = value.Extra;
            row.MtaTax = value.MtaTax;
            row.TipAmount = value.TipAmount;
            row.TollsAmount = value.TollsAmount;
            row.ImprovementSurcharge = value.ImprovementSurcharge;
            row.TotalAmount = value.TotalAmount;
            row.CongestionSurcharge = value.CongestionSurcharge;
            row.AirportFee = value.AirportFee;
        }
        writer.Complete();
        return output.ToArray();
    }
}

[MemoryDiagnoser]
public class RealDoublesDictionaryPlankBenchmarks
{
    RealDoublesDictionaryRow[] _rows = null!;
    DefaultParquetBufferPool _pool = null!;
    ParquetWriterOptions _options = null!;
    RealDoublesDictionaryRow.PipelineWriter _writer = null!;
    MemoryStream _output = null!;
    int _outputCapacity;
    long _expectedOutputBytes;
    MemoryReadSource _source = null!;
    RealDoublesDictionaryRow.RowReader _reader = null!;
    PlankWorkerPinning _pinning = null!;

    public IEnumerable<int> RowCounts => [BenchmarkData.TaxiRows];

    [ParamsSource(nameof(RowCounts))]
    public int Rows { get; set; }

    [GlobalSetup(Target = nameof(Write))]
    public void GlobalSetupWrite()
    {
        _rows ??= BenchmarkData.LoadTaxiRows<RealDoublesDictionaryRow>();
        _pool = new DefaultParquetBufferPool(ParquetBufferRetentionPolicy.ZeroAllocation);
        _pinning = new PlankWorkerPinning();
        _options = new ParquetWriterOptions
        {
            Compression = CompressionKind.None,
            BufferPool = _pool,
            DataPageVersion = ParquetDataPageVersion.V2,
            WritePageIndexes = true,
            WritePageCrc = false,
            TargetRowGroupSizeBytes = 80000000UL,
            RowApiInitialRowCapacity = 45_455,
            Execution = new ParquetExecutionOptions { OnWorkerStarted = _pinning.OnWorkerStarted }
        };

        _outputCapacity = BenchmarkFixtures.GetOutputCapacity("RealDoublesDictionary", "Plank", out _expectedOutputBytes);
    }

    [GlobalSetup(Target = nameof(Read))]
    public void GlobalSetupRead()
    {
        _pool = new DefaultParquetBufferPool(ParquetBufferRetentionPolicy.ZeroAllocation);
        var file = BenchmarkFixtures.LoadReadFile("RealDoublesDictionary");
        _source = new MemoryReadSource(file);
        _reader = RealDoublesDictionaryRow.CreateRowReader(_source, options: new RowReaderOptions { BufferPool = _pool });
    }

    [IterationSetup(Target = nameof(Write))]
    public void SetupWrite()
    {
        _output = new MemoryStream(_outputCapacity);
        _pinning.Reset();
        if (_writer is null)
            _writer = RealDoublesDictionaryRow.CreateRowWriter(_output, _options);
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
            row.TripDistance = value.TripDistance;
            row.FareAmount = value.FareAmount;
            row.Extra = value.Extra;
            row.MtaTax = value.MtaTax;
            row.TipAmount = value.TipAmount;
            row.TollsAmount = value.TollsAmount;
            row.ImprovementSurcharge = value.ImprovementSurcharge;
            row.TotalAmount = value.TotalAmount;
            row.CongestionSurcharge = value.CongestionSurcharge;
            row.AirportFee = value.AirportFee;
        }
        _writer.Complete();
    }

    [Benchmark]
    public double Read()
    {
        double sum = 0;
        foreach (var row in _reader)
        {
            sum += row.TripDistance.GetValueOrDefault();
            sum += row.FareAmount.GetValueOrDefault();
            sum += row.Extra.GetValueOrDefault();
            sum += row.MtaTax.GetValueOrDefault();
            sum += row.TipAmount.GetValueOrDefault();
            sum += row.TollsAmount.GetValueOrDefault();
            sum += row.ImprovementSurcharge.GetValueOrDefault();
            sum += row.TotalAmount.GetValueOrDefault();
            sum += row.CongestionSurcharge.GetValueOrDefault();
            sum += row.AirportFee.GetValueOrDefault();
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
public class RealDoublesDictionaryParquetSharpBenchmarks
{
    const int RowsPerRowGroup = 1048576;

    RealDoublesDictionaryRow[] _rows = null!;
    ParquetSharp.Column[] _schema = null!;
    WriterProperties _properties = null!;
    MemoryStream _output = null!;
    ManagedOutputStream _managedOutput = null!;
    ParquetRowWriter<RealDoublesDictionaryRow> _writer = null!;
    int _outputCapacity;
    long _expectedOutputBytes;
    GCHandle _pinned;
    NativeBuffer _buffer = null!;
    BufferReader _source = null!;
    ParquetRowReader<RealDoublesDictionaryRow>? _reader;

    public IEnumerable<int> RowCounts => [BenchmarkData.TaxiRows];

    [ParamsSource(nameof(RowCounts))]
    public int Rows { get; set; }

    [GlobalSetup(Target = nameof(Write))]
    public void GlobalSetupWrite()
    {
        _rows ??= BenchmarkData.LoadTaxiRows<RealDoublesDictionaryRow>();
        _schema =
        [
            new ParquetSharp.Column<double?>("trip_distance"),
            new ParquetSharp.Column<double?>("fare_amount"),
            new ParquetSharp.Column<double?>("extra"),
            new ParquetSharp.Column<double?>("mta_tax"),
            new ParquetSharp.Column<double?>("tip_amount"),
            new ParquetSharp.Column<double?>("tolls_amount"),
            new ParquetSharp.Column<double?>("improvement_surcharge"),
            new ParquetSharp.Column<double?>("total_amount"),
            new ParquetSharp.Column<double?>("congestion_surcharge"),
            new ParquetSharp.Column<double?>("Airport_fee"),
        ];
        using var builder = new WriterPropertiesBuilder();
        builder
            .Compression(Compression.Uncompressed)
            .EnableStatistics()
            .EnableWritePageIndex()
            .DataPageVersion(ParquetSharp.ParquetDataPageVersion.V2);
        _properties = builder.EnableDictionary().DictionaryPagesizeLimit(536_870_912).Build();

        _outputCapacity = BenchmarkFixtures.GetOutputCapacity("RealDoublesDictionary", "ParquetSharp", out _expectedOutputBytes);
    }

    [GlobalSetup(Target = nameof(Read))]
    public void GlobalSetupRead()
    {
        var file = BenchmarkFixtures.LoadReadFile("RealDoublesDictionary");
        _pinned = GCHandle.Alloc(file, GCHandleType.Pinned);
        _buffer = new NativeBuffer(_pinned.AddrOfPinnedObject(), file.LongLength);
        _source = new BufferReader(_buffer);
    }

    [IterationSetup(Target = nameof(Write))]
    public void SetupWrite()
    {
        _output = new MemoryStream(_outputCapacity);
        _managedOutput = new ManagedOutputStream(_output, leaveOpen: true);
        _writer = ParquetFile.CreateRowWriter<RealDoublesDictionaryRow>(_managedOutput, _properties, _schema);
    }

    [IterationSetup(Target = nameof(Read))]
    public void SetupRead()
    {
        _reader?.Dispose();
        _reader = ParquetFile.CreateRowReader<RealDoublesDictionaryRow>(_source);
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
            sum += row.TripDistance.GetValueOrDefault();
            sum += row.FareAmount.GetValueOrDefault();
            sum += row.Extra.GetValueOrDefault();
            sum += row.MtaTax.GetValueOrDefault();
            sum += row.TipAmount.GetValueOrDefault();
            sum += row.TollsAmount.GetValueOrDefault();
            sum += row.ImprovementSurcharge.GetValueOrDefault();
            sum += row.TotalAmount.GetValueOrDefault();
            sum += row.CongestionSurcharge.GetValueOrDefault();
            sum += row.AirportFee.GetValueOrDefault();
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
public class RealDoublesDictionaryParquetNetBenchmarks
{
    byte[] _file = null!;
    MemoryStream? _stream;

    public IEnumerable<int> RowCounts => [BenchmarkData.TaxiRows];

    [ParamsSource(nameof(RowCounts))]
    public int Rows { get; set; }

    [GlobalSetup(Target = nameof(Read))]
    public void GlobalSetupRead() => _file = BenchmarkFixtures.LoadReadFile("RealDoublesDictionary");

    [IterationSetup(Target = nameof(Read))]
    public void SetupRead()
    {
        _stream?.Dispose();
        _stream = new MemoryStream(_file, writable: false);
    }

    [Benchmark]
    public async Task<double> Read()
    {
        var result = await ParquetSerializer.DeserializeAsync<RealDoublesDictionaryRow>(_stream!);
        double sum = 0;
        foreach (var row in result.Data)
        {
            sum += row.TripDistance.GetValueOrDefault();
            sum += row.FareAmount.GetValueOrDefault();
            sum += row.Extra.GetValueOrDefault();
            sum += row.MtaTax.GetValueOrDefault();
            sum += row.TipAmount.GetValueOrDefault();
            sum += row.TollsAmount.GetValueOrDefault();
            sum += row.ImprovementSurcharge.GetValueOrDefault();
            sum += row.TotalAmount.GetValueOrDefault();
            sum += row.CongestionSurcharge.GetValueOrDefault();
            sum += row.AirportFee.GetValueOrDefault();
        }
        return sum;
    }

    [GlobalCleanup]
    public void Cleanup() => _stream?.Dispose();
}
