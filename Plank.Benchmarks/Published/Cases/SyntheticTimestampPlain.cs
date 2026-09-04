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
sealed partial class SyntheticTimestampPlainRow
{
    [ParquetColumn("value_0", Encodings = [EncodingKind.Plain], LogicalType = LogicalTypeKind.Timestamp), MapToColumn("value_0"), JsonPropertyName("value_0")]
    public DateTime Value0 { get; set; }

    [ParquetColumn("value_1", Encodings = [EncodingKind.Plain], LogicalType = LogicalTypeKind.Timestamp), MapToColumn("value_1"), JsonPropertyName("value_1")]
    public DateTime Value1 { get; set; }

    [ParquetColumn("value_2", Encodings = [EncodingKind.Plain], LogicalType = LogicalTypeKind.Timestamp), MapToColumn("value_2"), JsonPropertyName("value_2")]
    public DateTime Value2 { get; set; }

    [ParquetColumn("value_3", Encodings = [EncodingKind.Plain], LogicalType = LogicalTypeKind.Timestamp), MapToColumn("value_3"), JsonPropertyName("value_3")]
    public DateTime Value3 { get; set; }

    [ParquetColumn("value_4", Encodings = [EncodingKind.Plain], LogicalType = LogicalTypeKind.Timestamp), MapToColumn("value_4"), JsonPropertyName("value_4")]
    public DateTime Value4 { get; set; }

    [ParquetColumn("value_5", Encodings = [EncodingKind.Plain], LogicalType = LogicalTypeKind.Timestamp), MapToColumn("value_5"), JsonPropertyName("value_5")]
    public DateTime Value5 { get; set; }

    [ParquetColumn("value_6", Encodings = [EncodingKind.Plain], LogicalType = LogicalTypeKind.Timestamp), MapToColumn("value_6"), JsonPropertyName("value_6")]
    public DateTime Value6 { get; set; }

    [ParquetColumn("value_7", Encodings = [EncodingKind.Plain], LogicalType = LogicalTypeKind.Timestamp), MapToColumn("value_7"), JsonPropertyName("value_7")]
    public DateTime Value7 { get; set; }

    [ParquetColumn("value_8", Encodings = [EncodingKind.Plain], LogicalType = LogicalTypeKind.Timestamp), MapToColumn("value_8"), JsonPropertyName("value_8")]
    public DateTime Value8 { get; set; }

    [ParquetColumn("value_9", Encodings = [EncodingKind.Plain], LogicalType = LogicalTypeKind.Timestamp), MapToColumn("value_9"), JsonPropertyName("value_9")]
    public DateTime Value9 { get; set; }

    [ParquetColumn("value_10", Encodings = [EncodingKind.Plain], LogicalType = LogicalTypeKind.Timestamp), MapToColumn("value_10"), JsonPropertyName("value_10")]
    public DateTime Value10 { get; set; }

    [ParquetColumn("value_11", Encodings = [EncodingKind.Plain], LogicalType = LogicalTypeKind.Timestamp), MapToColumn("value_11"), JsonPropertyName("value_11")]
    public DateTime Value11 { get; set; }

    [ParquetColumn("value_12", Encodings = [EncodingKind.Plain], LogicalType = LogicalTypeKind.Timestamp), MapToColumn("value_12"), JsonPropertyName("value_12")]
    public DateTime Value12 { get; set; }

    [ParquetColumn("value_13", Encodings = [EncodingKind.Plain], LogicalType = LogicalTypeKind.Timestamp), MapToColumn("value_13"), JsonPropertyName("value_13")]
    public DateTime Value13 { get; set; }

    [ParquetColumn("value_14", Encodings = [EncodingKind.Plain], LogicalType = LogicalTypeKind.Timestamp), MapToColumn("value_14"), JsonPropertyName("value_14")]
    public DateTime Value14 { get; set; }

    [ParquetColumn("value_15", Encodings = [EncodingKind.Plain], LogicalType = LogicalTypeKind.Timestamp), MapToColumn("value_15"), JsonPropertyName("value_15")]
    public DateTime Value15 { get; set; }

    [ParquetColumn("value_16", Encodings = [EncodingKind.Plain], LogicalType = LogicalTypeKind.Timestamp), MapToColumn("value_16"), JsonPropertyName("value_16")]
    public DateTime Value16 { get; set; }

    [ParquetColumn("value_17", Encodings = [EncodingKind.Plain], LogicalType = LogicalTypeKind.Timestamp), MapToColumn("value_17"), JsonPropertyName("value_17")]
    public DateTime Value17 { get; set; }

    [ParquetColumn("value_18", Encodings = [EncodingKind.Plain], LogicalType = LogicalTypeKind.Timestamp), MapToColumn("value_18"), JsonPropertyName("value_18")]
    public DateTime Value18 { get; set; }

    [ParquetColumn("value_19", Encodings = [EncodingKind.Plain], LogicalType = LogicalTypeKind.Timestamp), MapToColumn("value_19"), JsonPropertyName("value_19")]
    public DateTime Value19 { get; set; }

    [ParquetColumn("value_20", Encodings = [EncodingKind.Plain], LogicalType = LogicalTypeKind.Timestamp), MapToColumn("value_20"), JsonPropertyName("value_20")]
    public DateTime Value20 { get; set; }

    [ParquetColumn("value_21", Encodings = [EncodingKind.Plain], LogicalType = LogicalTypeKind.Timestamp), MapToColumn("value_21"), JsonPropertyName("value_21")]
    public DateTime Value21 { get; set; }

    public static SyntheticTimestampPlainRow[] CreateRows(int count)
    {
        var rows = new SyntheticTimestampPlainRow[count];
        for (var row = 0; row < rows.Length; row++)
            rows[row] = new SyntheticTimestampPlainRow
            {
                Value0 = DateTime.UnixEpoch.AddSeconds(((long)(row & 2_047) * 37L) + 0),
                Value1 = DateTime.UnixEpoch.AddSeconds(((long)(row & 2_047) * 37L) + 1),
                Value2 = DateTime.UnixEpoch.AddSeconds(((long)(row & 2_047) * 37L) + 2),
                Value3 = DateTime.UnixEpoch.AddSeconds(((long)(row & 2_047) * 37L) + 3),
                Value4 = DateTime.UnixEpoch.AddSeconds(((long)(row & 2_047) * 37L) + 4),
                Value5 = DateTime.UnixEpoch.AddSeconds(((long)(row & 2_047) * 37L) + 5),
                Value6 = DateTime.UnixEpoch.AddSeconds(((long)(row & 2_047) * 37L) + 6),
                Value7 = DateTime.UnixEpoch.AddSeconds(((long)(row & 2_047) * 37L) + 7),
                Value8 = DateTime.UnixEpoch.AddSeconds(((long)(row & 2_047) * 37L) + 8),
                Value9 = DateTime.UnixEpoch.AddSeconds(((long)(row & 2_047) * 37L) + 9),
                Value10 = DateTime.UnixEpoch.AddSeconds(((long)(row & 2_047) * 37L) + 10),
                Value11 = DateTime.UnixEpoch.AddSeconds(((long)(row & 2_047) * 37L) + 11),
                Value12 = DateTime.UnixEpoch.AddSeconds(((long)(row & 2_047) * 37L) + 12),
                Value13 = DateTime.UnixEpoch.AddSeconds(((long)(row & 2_047) * 37L) + 13),
                Value14 = DateTime.UnixEpoch.AddSeconds(((long)(row & 2_047) * 37L) + 14),
                Value15 = DateTime.UnixEpoch.AddSeconds(((long)(row & 2_047) * 37L) + 15),
                Value16 = DateTime.UnixEpoch.AddSeconds(((long)(row & 2_047) * 37L) + 16),
                Value17 = DateTime.UnixEpoch.AddSeconds(((long)(row & 2_047) * 37L) + 17),
                Value18 = DateTime.UnixEpoch.AddSeconds(((long)(row & 2_047) * 37L) + 18),
                Value19 = DateTime.UnixEpoch.AddSeconds(((long)(row & 2_047) * 37L) + 19),
                Value20 = DateTime.UnixEpoch.AddSeconds(((long)(row & 2_047) * 37L) + 20),
                Value21 = DateTime.UnixEpoch.AddSeconds(((long)(row & 2_047) * 37L) + 21),            };
        return rows;
    }

    public static byte[] CreateReadFile(SyntheticTimestampPlainRow[] rows)
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
            row.Value0 = DateTime.SpecifyKind(value.Value0, DateTimeKind.Utc);
            row.Value1 = DateTime.SpecifyKind(value.Value1, DateTimeKind.Utc);
            row.Value2 = DateTime.SpecifyKind(value.Value2, DateTimeKind.Utc);
            row.Value3 = DateTime.SpecifyKind(value.Value3, DateTimeKind.Utc);
            row.Value4 = DateTime.SpecifyKind(value.Value4, DateTimeKind.Utc);
            row.Value5 = DateTime.SpecifyKind(value.Value5, DateTimeKind.Utc);
            row.Value6 = DateTime.SpecifyKind(value.Value6, DateTimeKind.Utc);
            row.Value7 = DateTime.SpecifyKind(value.Value7, DateTimeKind.Utc);
            row.Value8 = DateTime.SpecifyKind(value.Value8, DateTimeKind.Utc);
            row.Value9 = DateTime.SpecifyKind(value.Value9, DateTimeKind.Utc);
            row.Value10 = DateTime.SpecifyKind(value.Value10, DateTimeKind.Utc);
            row.Value11 = DateTime.SpecifyKind(value.Value11, DateTimeKind.Utc);
            row.Value12 = DateTime.SpecifyKind(value.Value12, DateTimeKind.Utc);
            row.Value13 = DateTime.SpecifyKind(value.Value13, DateTimeKind.Utc);
            row.Value14 = DateTime.SpecifyKind(value.Value14, DateTimeKind.Utc);
            row.Value15 = DateTime.SpecifyKind(value.Value15, DateTimeKind.Utc);
            row.Value16 = DateTime.SpecifyKind(value.Value16, DateTimeKind.Utc);
            row.Value17 = DateTime.SpecifyKind(value.Value17, DateTimeKind.Utc);
            row.Value18 = DateTime.SpecifyKind(value.Value18, DateTimeKind.Utc);
            row.Value19 = DateTime.SpecifyKind(value.Value19, DateTimeKind.Utc);
            row.Value20 = DateTime.SpecifyKind(value.Value20, DateTimeKind.Utc);
            row.Value21 = DateTime.SpecifyKind(value.Value21, DateTimeKind.Utc);
        }
        writer.Complete();
        return output.ToArray();
    }
}

[MemoryDiagnoser]
public class SyntheticTimestampPlainPlankBenchmarks
{
    SyntheticTimestampPlainRow[] _rows = null!;
    DefaultParquetBufferPool _pool = null!;
    ParquetWriterOptions _options = null!;
    MemoryStream _output = null!;
    int _outputCapacity;
    MemoryReadSource _source = null!;
    SyntheticTimestampPlainRow.RowReader _reader = null!;
    PlankWorkerPinning _pinning = null!;

    public IEnumerable<int> RowCounts => [BenchmarkData.SyntheticRows];

    [ParamsSource(nameof(RowCounts))]
    public int Rows { get; set; }

    [GlobalSetup]
    public void Setup()
    {
        _rows = SyntheticTimestampPlainRow.CreateRows(Rows);
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
        Write();
        var file = _output.ToArray();
        Console.WriteLine("BENCHMARK_FILE|SyntheticTimestampPlain|Plank|" + file.Length);
        _outputCapacity = BenchmarkData.OutputCapacity(file.Length);
        _output.Dispose();

        _source = new MemoryReadSource(file);
        _reader = SyntheticTimestampPlainRow.CreateRowReader(_source, options: new RowReaderOptions { BufferPool = _pool });
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
        using var writer = SyntheticTimestampPlainRow.CreateRowWriter(_output, _options);
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
    public long Read()
    {
        long sum = 0;
        foreach (var row in _reader)
        {
            sum += row.Value0.Ticks;
            sum += row.Value1.Ticks;
            sum += row.Value2.Ticks;
            sum += row.Value3.Ticks;
            sum += row.Value4.Ticks;
            sum += row.Value5.Ticks;
            sum += row.Value6.Ticks;
            sum += row.Value7.Ticks;
            sum += row.Value8.Ticks;
            sum += row.Value9.Ticks;
            sum += row.Value10.Ticks;
            sum += row.Value11.Ticks;
            sum += row.Value12.Ticks;
            sum += row.Value13.Ticks;
            sum += row.Value14.Ticks;
            sum += row.Value15.Ticks;
            sum += row.Value16.Ticks;
            sum += row.Value17.Ticks;
            sum += row.Value18.Ticks;
            sum += row.Value19.Ticks;
            sum += row.Value20.Ticks;
            sum += row.Value21.Ticks;
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
public class SyntheticTimestampPlainParquetSharpBenchmarks
{
    const int RowsPerRowGroup = 45455;

    SyntheticTimestampPlainRow[] _rows = null!;
    ParquetSharp.Column[] _schema = null!;
    WriterProperties _properties = null!;
    MemoryStream _output = null!;
    ManagedOutputStream _managedOutput = null!;
    ParquetRowWriter<SyntheticTimestampPlainRow> _writer = null!;
    int _outputCapacity;
    GCHandle _pinned;
    NativeBuffer _buffer = null!;
    BufferReader _source = null!;
    ParquetRowReader<SyntheticTimestampPlainRow>? _reader;

    public IEnumerable<int> RowCounts => [BenchmarkData.SyntheticRows];

    [ParamsSource(nameof(RowCounts))]
    public int Rows { get; set; }

    [GlobalSetup]
    public void Setup()
    {
        _rows = SyntheticTimestampPlainRow.CreateRows(Rows);
        _schema =
        [
            new ParquetSharp.Column<DateTime>("value_0", LogicalType.Timestamp(false, TimeUnit.Micros)),
            new ParquetSharp.Column<DateTime>("value_1", LogicalType.Timestamp(false, TimeUnit.Micros)),
            new ParquetSharp.Column<DateTime>("value_2", LogicalType.Timestamp(false, TimeUnit.Micros)),
            new ParquetSharp.Column<DateTime>("value_3", LogicalType.Timestamp(false, TimeUnit.Micros)),
            new ParquetSharp.Column<DateTime>("value_4", LogicalType.Timestamp(false, TimeUnit.Micros)),
            new ParquetSharp.Column<DateTime>("value_5", LogicalType.Timestamp(false, TimeUnit.Micros)),
            new ParquetSharp.Column<DateTime>("value_6", LogicalType.Timestamp(false, TimeUnit.Micros)),
            new ParquetSharp.Column<DateTime>("value_7", LogicalType.Timestamp(false, TimeUnit.Micros)),
            new ParquetSharp.Column<DateTime>("value_8", LogicalType.Timestamp(false, TimeUnit.Micros)),
            new ParquetSharp.Column<DateTime>("value_9", LogicalType.Timestamp(false, TimeUnit.Micros)),
            new ParquetSharp.Column<DateTime>("value_10", LogicalType.Timestamp(false, TimeUnit.Micros)),
            new ParquetSharp.Column<DateTime>("value_11", LogicalType.Timestamp(false, TimeUnit.Micros)),
            new ParquetSharp.Column<DateTime>("value_12", LogicalType.Timestamp(false, TimeUnit.Micros)),
            new ParquetSharp.Column<DateTime>("value_13", LogicalType.Timestamp(false, TimeUnit.Micros)),
            new ParquetSharp.Column<DateTime>("value_14", LogicalType.Timestamp(false, TimeUnit.Micros)),
            new ParquetSharp.Column<DateTime>("value_15", LogicalType.Timestamp(false, TimeUnit.Micros)),
            new ParquetSharp.Column<DateTime>("value_16", LogicalType.Timestamp(false, TimeUnit.Micros)),
            new ParquetSharp.Column<DateTime>("value_17", LogicalType.Timestamp(false, TimeUnit.Micros)),
            new ParquetSharp.Column<DateTime>("value_18", LogicalType.Timestamp(false, TimeUnit.Micros)),
            new ParquetSharp.Column<DateTime>("value_19", LogicalType.Timestamp(false, TimeUnit.Micros)),
            new ParquetSharp.Column<DateTime>("value_20", LogicalType.Timestamp(false, TimeUnit.Micros)),
            new ParquetSharp.Column<DateTime>("value_21", LogicalType.Timestamp(false, TimeUnit.Micros)),
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
        _writer = ParquetFile.CreateRowWriter<SyntheticTimestampPlainRow>(_managedOutput, _properties, _schema);
        Write();
        _outputCapacity = BenchmarkData.OutputCapacity(checked((int)_output.Length));
        Console.WriteLine("BENCHMARK_FILE|SyntheticTimestampPlain|ParquetSharp|" + _output.Length);
        _writer.Dispose();
        _managedOutput.Dispose();
        _output.Dispose();

        var file = SyntheticTimestampPlainRow.CreateReadFile(_rows);
        _pinned = GCHandle.Alloc(file, GCHandleType.Pinned);
        _buffer = new NativeBuffer(_pinned.AddrOfPinnedObject(), file.LongLength);
        _source = new BufferReader(_buffer);
    }

    [IterationSetup(Target = nameof(Write))]
    public void SetupWrite()
    {
        _output = new MemoryStream(_outputCapacity);
        _managedOutput = new ManagedOutputStream(_output, leaveOpen: true);
        _writer = ParquetFile.CreateRowWriter<SyntheticTimestampPlainRow>(_managedOutput, _properties, _schema);
    }

    [IterationSetup(Target = nameof(Read))]
    public void SetupRead()
    {
        _reader?.Dispose();
        _reader = ParquetFile.CreateRowReader<SyntheticTimestampPlainRow>(_source);
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
            sum += row.Value0.Ticks;
            sum += row.Value1.Ticks;
            sum += row.Value2.Ticks;
            sum += row.Value3.Ticks;
            sum += row.Value4.Ticks;
            sum += row.Value5.Ticks;
            sum += row.Value6.Ticks;
            sum += row.Value7.Ticks;
            sum += row.Value8.Ticks;
            sum += row.Value9.Ticks;
            sum += row.Value10.Ticks;
            sum += row.Value11.Ticks;
            sum += row.Value12.Ticks;
            sum += row.Value13.Ticks;
            sum += row.Value14.Ticks;
            sum += row.Value15.Ticks;
            sum += row.Value16.Ticks;
            sum += row.Value17.Ticks;
            sum += row.Value18.Ticks;
            sum += row.Value19.Ticks;
            sum += row.Value20.Ticks;
            sum += row.Value21.Ticks;
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
public class SyntheticTimestampPlainParquetNetBenchmarks
{
    SyntheticTimestampPlainRow[] _rows = null!;
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
        _rows = SyntheticTimestampPlainRow.CreateRows(Rows);
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
        Console.WriteLine("BENCHMARK_FILE|SyntheticTimestampPlain|Parquet.Net|" + _output.Length);
        _output.Dispose();

        _file = SyntheticTimestampPlainRow.CreateReadFile(_rows);
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
    public async Task<long> Read()
    {
        var result = await ParquetSerializer.DeserializeAsync<SyntheticTimestampPlainRow>(_stream!);
        long sum = 0;
        foreach (var row in result.Data)
        {
            sum += row.Value0.Ticks;
            sum += row.Value1.Ticks;
            sum += row.Value2.Ticks;
            sum += row.Value3.Ticks;
            sum += row.Value4.Ticks;
            sum += row.Value5.Ticks;
            sum += row.Value6.Ticks;
            sum += row.Value7.Ticks;
            sum += row.Value8.Ticks;
            sum += row.Value9.Ticks;
            sum += row.Value10.Ticks;
            sum += row.Value11.Ticks;
            sum += row.Value12.Ticks;
            sum += row.Value13.Ticks;
            sum += row.Value14.Ticks;
            sum += row.Value15.Ticks;
            sum += row.Value16.Ticks;
            sum += row.Value17.Ticks;
            sum += row.Value18.Ticks;
            sum += row.Value19.Ticks;
            sum += row.Value20.Ticks;
            sum += row.Value21.Ticks;
        }
        return sum;
    }

    [IterationCleanup(Target = nameof(Write))]
    public void CleanupWrite() => _output.Dispose();
    [GlobalCleanup]
    public void Cleanup() => _stream?.Dispose();
}
