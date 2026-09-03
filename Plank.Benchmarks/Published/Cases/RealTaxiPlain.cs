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
sealed partial class RealTaxiPlainPlankRow
{
    [ParquetColumn("VendorID", Encodings = [EncodingKind.Plain]), MapToColumn("VendorID"), JsonPropertyName("VendorID")]
    public int? VendorId { get; set; }

    [ParquetColumn("tpep_pickup_datetime", Encodings = [EncodingKind.Plain], LogicalType = LogicalTypeKind.Timestamp), MapToColumn("tpep_pickup_datetime"), JsonPropertyName("tpep_pickup_datetime")]
    public DateTime? Pickup { get; set; }

    [ParquetColumn("tpep_dropoff_datetime", Encodings = [EncodingKind.Plain], LogicalType = LogicalTypeKind.Timestamp), MapToColumn("tpep_dropoff_datetime"), JsonPropertyName("tpep_dropoff_datetime")]
    public DateTime? Dropoff { get; set; }

    [ParquetColumn("passenger_count", Encodings = [EncodingKind.Plain]), MapToColumn("passenger_count"), JsonPropertyName("passenger_count")]
    public long? PassengerCount { get; set; }

    [ParquetColumn("trip_distance", Encodings = [EncodingKind.Plain]), MapToColumn("trip_distance"), JsonPropertyName("trip_distance")]
    public double? TripDistance { get; set; }

    [ParquetColumn("RatecodeID", Encodings = [EncodingKind.Plain]), MapToColumn("RatecodeID"), JsonPropertyName("RatecodeID")]
    public long? RatecodeId { get; set; }

    [ParquetColumn("store_and_fwd_flag", Encodings = [EncodingKind.Plain], LogicalType = LogicalTypeKind.String), MapToColumn("store_and_fwd_flag"), JsonPropertyName("store_and_fwd_flag")]
    public ReadOnlyMemory<byte>? StoreAndForwardFlag { get; set; }

    [ParquetColumn("PULocationID", Encodings = [EncodingKind.Plain]), MapToColumn("PULocationID"), JsonPropertyName("PULocationID")]
    public int? PickupLocationId { get; set; }

    [ParquetColumn("DOLocationID", Encodings = [EncodingKind.Plain]), MapToColumn("DOLocationID"), JsonPropertyName("DOLocationID")]
    public int? DropoffLocationId { get; set; }

    [ParquetColumn("payment_type", Encodings = [EncodingKind.Plain]), MapToColumn("payment_type"), JsonPropertyName("payment_type")]
    public long? PaymentType { get; set; }

    [ParquetColumn("fare_amount", Encodings = [EncodingKind.Plain]), MapToColumn("fare_amount"), JsonPropertyName("fare_amount")]
    public double? FareAmount { get; set; }

    [ParquetColumn("extra", Encodings = [EncodingKind.Plain]), MapToColumn("extra"), JsonPropertyName("extra")]
    public double? Extra { get; set; }

    [ParquetColumn("mta_tax", Encodings = [EncodingKind.Plain]), MapToColumn("mta_tax"), JsonPropertyName("mta_tax")]
    public double? MtaTax { get; set; }

    [ParquetColumn("tip_amount", Encodings = [EncodingKind.Plain]), MapToColumn("tip_amount"), JsonPropertyName("tip_amount")]
    public double? TipAmount { get; set; }

    [ParquetColumn("tolls_amount", Encodings = [EncodingKind.Plain]), MapToColumn("tolls_amount"), JsonPropertyName("tolls_amount")]
    public double? TollsAmount { get; set; }

    [ParquetColumn("improvement_surcharge", Encodings = [EncodingKind.Plain]), MapToColumn("improvement_surcharge"), JsonPropertyName("improvement_surcharge")]
    public double? ImprovementSurcharge { get; set; }

    [ParquetColumn("total_amount", Encodings = [EncodingKind.Plain]), MapToColumn("total_amount"), JsonPropertyName("total_amount")]
    public double? TotalAmount { get; set; }

    [ParquetColumn("congestion_surcharge", Encodings = [EncodingKind.Plain]), MapToColumn("congestion_surcharge"), JsonPropertyName("congestion_surcharge")]
    public double? CongestionSurcharge { get; set; }

    [ParquetColumn("Airport_fee", Encodings = [EncodingKind.Plain]), MapToColumn("Airport_fee"), JsonPropertyName("Airport_fee")]
    public double? AirportFee { get; set; }

    public static byte[] CreateReadFile(RealTaxiPlainPlankRow[] rows)
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
            TargetRowGroupSizeBytes = 140000000UL,
            RowApiInitialRowCapacity = 45_455
        });
        foreach (var value in rows)
        {
            var row = writer.GetRow();
            row.VendorId = value.VendorId;
            row.Pickup = value.Pickup.HasValue ? DateTime.SpecifyKind(value.Pickup.GetValueOrDefault(), DateTimeKind.Utc) : null;
            row.Dropoff = value.Dropoff.HasValue ? DateTime.SpecifyKind(value.Dropoff.GetValueOrDefault(), DateTimeKind.Utc) : null;
            row.PassengerCount = value.PassengerCount;
            row.TripDistance = value.TripDistance;
            row.RatecodeId = value.RatecodeId;
            row.StoreAndForwardFlag = value.StoreAndForwardFlag;
            row.PickupLocationId = value.PickupLocationId;
            row.DropoffLocationId = value.DropoffLocationId;
            row.PaymentType = value.PaymentType;
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
    public static RealTaxiPlainPlankRow[] FromSharp(RealTaxiPlainSharpRow[] source)
    {
        var rows = new RealTaxiPlainPlankRow[source.Length];
        for (var index = 0; index < rows.Length; index++)
        {
            var value = source[index];
            rows[index] = new RealTaxiPlainPlankRow
            {
                VendorId = value.VendorId,
                Pickup = value.Pickup,
                Dropoff = value.Dropoff,
                PassengerCount = value.PassengerCount,
                TripDistance = value.TripDistance,
                RatecodeId = value.RatecodeId,
                StoreAndForwardFlag = value.StoreAndForwardFlag is null ? null : new ReadOnlyMemory<byte>(Encoding.UTF8.GetBytes(value.StoreAndForwardFlag)),
                PickupLocationId = value.PickupLocationId,
                DropoffLocationId = value.DropoffLocationId,
                PaymentType = value.PaymentType,
                FareAmount = value.FareAmount,
                Extra = value.Extra,
                MtaTax = value.MtaTax,
                TipAmount = value.TipAmount,
                TollsAmount = value.TollsAmount,
                ImprovementSurcharge = value.ImprovementSurcharge,
                TotalAmount = value.TotalAmount,
                CongestionSurcharge = value.CongestionSurcharge,
                AirportFee = value.AirportFee,            };
        }
        return rows;
    }

    public static RealTaxiPlainPlankRow[] FromNet(RealTaxiPlainNetRow[] source)
    {
        var rows = new RealTaxiPlainPlankRow[source.Length];
        for (var index = 0; index < rows.Length; index++)
        {
            var value = source[index];
            rows[index] = new RealTaxiPlainPlankRow
            {
                VendorId = value.VendorId,
                Pickup = value.Pickup,
                Dropoff = value.Dropoff,
                PassengerCount = value.PassengerCount,
                TripDistance = value.TripDistance,
                RatecodeId = value.RatecodeId,
                StoreAndForwardFlag = value.StoreAndForwardFlag is null ? null : new ReadOnlyMemory<byte>(Encoding.UTF8.GetBytes(value.StoreAndForwardFlag)),
                PickupLocationId = value.PickupLocationId,
                DropoffLocationId = value.DropoffLocationId,
                PaymentType = value.PaymentType,
                FareAmount = value.FareAmount,
                Extra = value.Extra,
                MtaTax = value.MtaTax,
                TipAmount = value.TipAmount,
                TollsAmount = value.TollsAmount,
                ImprovementSurcharge = value.ImprovementSurcharge,
                TotalAmount = value.TotalAmount,
                CongestionSurcharge = value.CongestionSurcharge,
                AirportFee = value.AirportFee,            };
        }
        return rows;
    }

}

sealed partial class RealTaxiPlainSharpRow
{
    [MapToColumn("VendorID"), JsonPropertyName("VendorID")]
    public int? VendorId { get; set; }

    [MapToColumn("tpep_pickup_datetime"), JsonPropertyName("tpep_pickup_datetime")]
    public DateTime? Pickup { get; set; }

    [MapToColumn("tpep_dropoff_datetime"), JsonPropertyName("tpep_dropoff_datetime")]
    public DateTime? Dropoff { get; set; }

    [MapToColumn("passenger_count"), JsonPropertyName("passenger_count")]
    public long? PassengerCount { get; set; }

    [MapToColumn("trip_distance"), JsonPropertyName("trip_distance")]
    public double? TripDistance { get; set; }

    [MapToColumn("RatecodeID"), JsonPropertyName("RatecodeID")]
    public long? RatecodeId { get; set; }

    [MapToColumn("store_and_fwd_flag"), JsonPropertyName("store_and_fwd_flag")]
    public string? StoreAndForwardFlag { get; set; }

    [MapToColumn("PULocationID"), JsonPropertyName("PULocationID")]
    public int? PickupLocationId { get; set; }

    [MapToColumn("DOLocationID"), JsonPropertyName("DOLocationID")]
    public int? DropoffLocationId { get; set; }

    [MapToColumn("payment_type"), JsonPropertyName("payment_type")]
    public long? PaymentType { get; set; }

    [MapToColumn("fare_amount"), JsonPropertyName("fare_amount")]
    public double? FareAmount { get; set; }

    [MapToColumn("extra"), JsonPropertyName("extra")]
    public double? Extra { get; set; }

    [MapToColumn("mta_tax"), JsonPropertyName("mta_tax")]
    public double? MtaTax { get; set; }

    [MapToColumn("tip_amount"), JsonPropertyName("tip_amount")]
    public double? TipAmount { get; set; }

    [MapToColumn("tolls_amount"), JsonPropertyName("tolls_amount")]
    public double? TollsAmount { get; set; }

    [MapToColumn("improvement_surcharge"), JsonPropertyName("improvement_surcharge")]
    public double? ImprovementSurcharge { get; set; }

    [MapToColumn("total_amount"), JsonPropertyName("total_amount")]
    public double? TotalAmount { get; set; }

    [MapToColumn("congestion_surcharge"), JsonPropertyName("congestion_surcharge")]
    public double? CongestionSurcharge { get; set; }

    [MapToColumn("Airport_fee"), JsonPropertyName("Airport_fee")]
    public double? AirportFee { get; set; }
}

sealed partial class RealTaxiPlainNetRow
{
    [MapToColumn("VendorID"), JsonPropertyName("VendorID")]
    public int? VendorId { get; set; }

    [MapToColumn("tpep_pickup_datetime"), JsonPropertyName("tpep_pickup_datetime")]
    public DateTime? Pickup { get; set; }

    [MapToColumn("tpep_dropoff_datetime"), JsonPropertyName("tpep_dropoff_datetime")]
    public DateTime? Dropoff { get; set; }

    [MapToColumn("passenger_count"), JsonPropertyName("passenger_count")]
    public long? PassengerCount { get; set; }

    [MapToColumn("trip_distance"), JsonPropertyName("trip_distance")]
    public double? TripDistance { get; set; }

    [MapToColumn("RatecodeID"), JsonPropertyName("RatecodeID")]
    public long? RatecodeId { get; set; }

    [MapToColumn("store_and_fwd_flag"), JsonPropertyName("store_and_fwd_flag")]
    public string? StoreAndForwardFlag { get; set; }

    [MapToColumn("PULocationID"), JsonPropertyName("PULocationID")]
    public int? PickupLocationId { get; set; }

    [MapToColumn("DOLocationID"), JsonPropertyName("DOLocationID")]
    public int? DropoffLocationId { get; set; }

    [MapToColumn("payment_type"), JsonPropertyName("payment_type")]
    public long? PaymentType { get; set; }

    [MapToColumn("fare_amount"), JsonPropertyName("fare_amount")]
    public double? FareAmount { get; set; }

    [MapToColumn("extra"), JsonPropertyName("extra")]
    public double? Extra { get; set; }

    [MapToColumn("mta_tax"), JsonPropertyName("mta_tax")]
    public double? MtaTax { get; set; }

    [MapToColumn("tip_amount"), JsonPropertyName("tip_amount")]
    public double? TipAmount { get; set; }

    [MapToColumn("tolls_amount"), JsonPropertyName("tolls_amount")]
    public double? TollsAmount { get; set; }

    [MapToColumn("improvement_surcharge"), JsonPropertyName("improvement_surcharge")]
    public double? ImprovementSurcharge { get; set; }

    [MapToColumn("total_amount"), JsonPropertyName("total_amount")]
    public double? TotalAmount { get; set; }

    [MapToColumn("congestion_surcharge"), JsonPropertyName("congestion_surcharge")]
    public double? CongestionSurcharge { get; set; }

    [MapToColumn("Airport_fee"), JsonPropertyName("Airport_fee")]
    public double? AirportFee { get; set; }
}

[MemoryDiagnoser]
public class RealTaxiPlainPlankBenchmarks
{
    RealTaxiPlainPlankRow[] _rows = null!;
    DefaultParquetBufferPool _pool = null!;
    ParquetWriterOptions _options = null!;
    RealTaxiPlainPlankRow.PipelineWriter _writer = null!;
    MemoryStream _output = null!;
    int _outputCapacity;
    MemoryReadSource _source = null!;
    RealTaxiPlainPlankRow.RowReader _reader = null!;
    PlankWorkerPinning _pinning = null!;

    public IEnumerable<int> RowCounts => [BenchmarkData.TaxiRows];

    [ParamsSource(nameof(RowCounts))]
    public int Rows { get; set; }

    [GlobalSetup]
    public void Setup()
    {
        _rows = RealTaxiPlainPlankRow.FromSharp(BenchmarkData.LoadTaxiRows<RealTaxiPlainSharpRow>());
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
            TargetRowGroupSizeBytes = 140000000UL,
            RowApiInitialRowCapacity = 45_455,
            Execution = new ParquetExecutionOptions { OnWorkerStarted = _pinning.OnWorkerStarted }
        };

        _output = new MemoryStream();
        _writer = RealTaxiPlainPlankRow.CreateRowWriter(_output, _options);
        Write();
        var file = _output.ToArray();
        Console.WriteLine("BENCHMARK_FILE|RealTaxiPlain|Plank|" + file.Length);
        _outputCapacity = BenchmarkData.OutputCapacity(file.Length);
        _output.Dispose();

        _source = new MemoryReadSource(file);
        _reader = RealTaxiPlainPlankRow.CreateRowReader(_source, options: new RowReaderOptions { BufferPool = _pool });
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
            row.VendorId = value.VendorId;
            row.Pickup = value.Pickup;
            row.Dropoff = value.Dropoff;
            row.PassengerCount = value.PassengerCount;
            row.TripDistance = value.TripDistance;
            row.RatecodeId = value.RatecodeId;
            row.StoreAndForwardFlag = value.StoreAndForwardFlag;
            row.PickupLocationId = value.PickupLocationId;
            row.DropoffLocationId = value.DropoffLocationId;
            row.PaymentType = value.PaymentType;
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
            sum += unchecked((uint)row.VendorId.GetValueOrDefault());
            sum += (row.Pickup?.Ticks ?? 0L);
            sum += (row.Dropoff?.Ticks ?? 0L);
            sum += unchecked((ulong)row.PassengerCount.GetValueOrDefault());
            sum += row.TripDistance.GetValueOrDefault();
            sum += unchecked((ulong)row.RatecodeId.GetValueOrDefault());
            sum += (ulong)row.StoreAndForwardFlag.Length;
            sum += unchecked((uint)row.PickupLocationId.GetValueOrDefault());
            sum += unchecked((uint)row.DropoffLocationId.GetValueOrDefault());
            sum += unchecked((ulong)row.PaymentType.GetValueOrDefault());
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
public class RealTaxiPlainParquetSharpBenchmarks
{
    const int RowsPerRowGroup = 1048576;

    RealTaxiPlainSharpRow[] _rows = null!;
    ParquetSharp.Column[] _schema = null!;
    WriterProperties _properties = null!;
    MemoryStream _output = null!;
    ManagedOutputStream _managedOutput = null!;
    ParquetRowWriter<RealTaxiPlainSharpRow> _writer = null!;
    int _outputCapacity;
    GCHandle _pinned;
    NativeBuffer _buffer = null!;
    BufferReader _source = null!;
    ParquetRowReader<RealTaxiPlainSharpRow>? _reader;

    public IEnumerable<int> RowCounts => [BenchmarkData.TaxiRows];

    [ParamsSource(nameof(RowCounts))]
    public int Rows { get; set; }

    [GlobalSetup]
    public void Setup()
    {
        _rows = BenchmarkData.LoadTaxiRows<RealTaxiPlainSharpRow>();
        _schema =
        [
            new ParquetSharp.Column<int?>("VendorID"),
            new ParquetSharp.Column<DateTime?>("tpep_pickup_datetime", LogicalType.Timestamp(false, TimeUnit.Micros)),
            new ParquetSharp.Column<DateTime?>("tpep_dropoff_datetime", LogicalType.Timestamp(false, TimeUnit.Micros)),
            new ParquetSharp.Column<long?>("passenger_count"),
            new ParquetSharp.Column<double?>("trip_distance"),
            new ParquetSharp.Column<long?>("RatecodeID"),
            new ParquetSharp.Column<string?>("store_and_fwd_flag", LogicalType.String()),
            new ParquetSharp.Column<int?>("PULocationID"),
            new ParquetSharp.Column<int?>("DOLocationID"),
            new ParquetSharp.Column<long?>("payment_type"),
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
        _properties = builder.DisableDictionary().Encoding(ParquetSharp.Encoding.Plain).Build();

        _output = new MemoryStream();
        _managedOutput = new ManagedOutputStream(_output, leaveOpen: true);
        _writer = ParquetFile.CreateRowWriter<RealTaxiPlainSharpRow>(_managedOutput, _properties, _schema);
        Write();
        _outputCapacity = BenchmarkData.OutputCapacity(checked((int)_output.Length));
        Console.WriteLine("BENCHMARK_FILE|RealTaxiPlain|ParquetSharp|" + _output.Length);
        _writer.Dispose();
        _managedOutput.Dispose();
        _output.Dispose();

        var file = RealTaxiPlainPlankRow.CreateReadFile(RealTaxiPlainPlankRow.FromSharp(_rows));
        _pinned = GCHandle.Alloc(file, GCHandleType.Pinned);
        _buffer = new NativeBuffer(_pinned.AddrOfPinnedObject(), file.LongLength);
        _source = new BufferReader(_buffer);
    }

    [IterationSetup(Target = nameof(Write))]
    public void SetupWrite()
    {
        _output = new MemoryStream(_outputCapacity);
        _managedOutput = new ManagedOutputStream(_output, leaveOpen: true);
        _writer = ParquetFile.CreateRowWriter<RealTaxiPlainSharpRow>(_managedOutput, _properties, _schema);
    }

    [IterationSetup(Target = nameof(Read))]
    public void SetupRead()
    {
        _reader?.Dispose();
        _reader = ParquetFile.CreateRowReader<RealTaxiPlainSharpRow>(_source);
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
            sum += unchecked((uint)row.VendorId.GetValueOrDefault());
            sum += (row.Pickup?.Ticks ?? 0L);
            sum += (row.Dropoff?.Ticks ?? 0L);
            sum += unchecked((ulong)row.PassengerCount.GetValueOrDefault());
            sum += row.TripDistance.GetValueOrDefault();
            sum += unchecked((ulong)row.RatecodeId.GetValueOrDefault());
            sum += (ulong)(row.StoreAndForwardFlag?.Length ?? 0);
            sum += unchecked((uint)row.PickupLocationId.GetValueOrDefault());
            sum += unchecked((uint)row.DropoffLocationId.GetValueOrDefault());
            sum += unchecked((ulong)row.PaymentType.GetValueOrDefault());
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
public class RealTaxiPlainParquetNetBenchmarks
{
    RealTaxiPlainNetRow[] _rows = null!;
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
        _rows = BenchmarkData.LoadTaxiRows<RealTaxiPlainNetRow>();
        _options = new ParquetOptions
        {
            CompressionMethod = CompressionMethod.None,
            DictionaryEncodingThreshold = 0,
            RowGroupSize = 1048576
        };
        _options.ColumnEncodingHints["VendorID"] = EncodingHint.Default;
        _options.ColumnEncodingHints["tpep_pickup_datetime"] = EncodingHint.Default;
        _options.ColumnEncodingHints["tpep_dropoff_datetime"] = EncodingHint.Default;
        _options.ColumnEncodingHints["passenger_count"] = EncodingHint.Default;
        _options.ColumnEncodingHints["trip_distance"] = EncodingHint.Default;
        _options.ColumnEncodingHints["RatecodeID"] = EncodingHint.Default;
        _options.ColumnEncodingHints["store_and_fwd_flag"] = EncodingHint.Default;
        _options.ColumnEncodingHints["PULocationID"] = EncodingHint.Default;
        _options.ColumnEncodingHints["DOLocationID"] = EncodingHint.Default;
        _options.ColumnEncodingHints["payment_type"] = EncodingHint.Default;
        _options.ColumnEncodingHints["fare_amount"] = EncodingHint.Default;
        _options.ColumnEncodingHints["extra"] = EncodingHint.Default;
        _options.ColumnEncodingHints["mta_tax"] = EncodingHint.Default;
        _options.ColumnEncodingHints["tip_amount"] = EncodingHint.Default;
        _options.ColumnEncodingHints["tolls_amount"] = EncodingHint.Default;
        _options.ColumnEncodingHints["improvement_surcharge"] = EncodingHint.Default;
        _options.ColumnEncodingHints["total_amount"] = EncodingHint.Default;
        _options.ColumnEncodingHints["congestion_surcharge"] = EncodingHint.Default;
        _options.ColumnEncodingHints["Airport_fee"] = EncodingHint.Default;

        _output = new MemoryStream();
        Write().GetAwaiter().GetResult();
        _outputCapacity = BenchmarkData.OutputCapacity(checked((int)_output.Length));
        Console.WriteLine("BENCHMARK_FILE|RealTaxiPlain|Parquet.Net|" + _output.Length);
        _output.Dispose();

        _file = RealTaxiPlainPlankRow.CreateReadFile(RealTaxiPlainPlankRow.FromNet(_rows));
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
    public async Task<double> Read()
    {
        var result = await ParquetSerializer.DeserializeAsync<RealTaxiPlainNetRow>(_stream!);
        double sum = 0;
        foreach (var row in result.Data)
        {
            sum += unchecked((uint)row.VendorId.GetValueOrDefault());
            sum += (row.Pickup?.Ticks ?? 0L);
            sum += (row.Dropoff?.Ticks ?? 0L);
            sum += unchecked((ulong)row.PassengerCount.GetValueOrDefault());
            sum += row.TripDistance.GetValueOrDefault();
            sum += unchecked((ulong)row.RatecodeId.GetValueOrDefault());
            sum += (ulong)(row.StoreAndForwardFlag?.Length ?? 0);
            sum += unchecked((uint)row.PickupLocationId.GetValueOrDefault());
            sum += unchecked((uint)row.DropoffLocationId.GetValueOrDefault());
            sum += unchecked((ulong)row.PaymentType.GetValueOrDefault());
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
    public void CleanupWrite() => _output.Dispose();
    [GlobalCleanup]
    public void Cleanup() => _stream?.Dispose();
}
