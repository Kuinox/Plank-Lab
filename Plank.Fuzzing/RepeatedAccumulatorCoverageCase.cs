using System.Collections.Immutable;
using Plank.Reading;
using Plank.Schema;
using Plank.Writing;

namespace Plank.Fuzzing;

/// <summary>Public repeated-writer inputs for the CLR leaf conversions in repeated statistics.</summary>
internal static class RepeatedAccumulatorCoverageCase
{
    static readonly ColumnOptions Plain = new(encodings: ImmutableArray.Create(EncodingKind.Plain));

    internal static void Execute(byte selector)
    {
        if ((selector & 0x80) != 0)
        {
            ExerciseTimeOnlyStatistics(selector);
            return;
        }

        // Keep each conversion on a matching public schema. The input contains values on both sides
        // of zero so the accumulator must retain the true extrema as well as convert the CLR type.
        Write("repeated-i32-signed", ParquetPhysicalType.Int32, new LogicalType.Int(32, true),
            new[] { new[] { int.MinValue, 0 }, new[] { 1 }, new[] { int.MaxValue } }, selector);
        Write("repeated-i32-unsigned", ParquetPhysicalType.Int32, new LogicalType.Int(32, false),
            new[] { new[] { int.MinValue, 0 }, new[] { 1 }, new[] { int.MaxValue } }, selector);
        Write("repeated-i32-date", ParquetPhysicalType.Int32, new LogicalType.Date(),
            new[] { new[] { -1, 1 }, new[] { 0 } }, selector);

        Write("repeated-i64-signed", ParquetPhysicalType.Int64, new LogicalType.Int(64, true),
            new[] { new[] { long.MinValue, 0 }, new[] { 1L }, new[] { long.MaxValue } }, selector);
        Write("repeated-i64-unsigned", ParquetPhysicalType.Int64, new LogicalType.Int(64, false),
            new[] { new[] { long.MinValue, 0 }, new[] { 1L }, new[] { long.MaxValue } }, selector);
        Write("repeated-i64-datetime", ParquetPhysicalType.Int64,
            new LogicalType.Timestamp(TimeUnit.Micros, true),
            new[] { new[] { -1L, 1L }, new[] { 0L } }, selector);
        Write("repeated-i64-datetimeoffset", ParquetPhysicalType.Int64,
            new LogicalType.Timestamp(TimeUnit.Micros, true),
            new[] { new[] { -1L, 1L }, new[] { 0L } }, selector);
        Write("repeated-i64-timeonly", ParquetPhysicalType.Int64,
            new LogicalType.Time(TimeUnit.Micros, false),
            new[] { new[] { 0L, 1L }, new[] { 2L } }, selector);
    }

    static void ExerciseTimeOnlyStatistics(byte selector)
    {
        TimeOnly[][] rows =
        [
            [new TimeOnly(0, 0, 0, 1), new TimeOnly(0, 0, 0, 2)],
            [new TimeOnly(0, 0, 0, 3)]
        ];

        ExpectRepeatedTimeOnlyPreempted("repeated-time-millis", ParquetPhysicalType.Int32,
            new LogicalType.Time(TimeUnit.Millis, IsAdjustedToUtc: false), rows, selector);
        ExpectRepeatedTimeOnlyPreempted("repeated-time-micros", ParquetPhysicalType.Int64,
            new LogicalType.Time(TimeUnit.Micros, IsAdjustedToUtc: false), rows, selector);
        ExpectRepeatedTimeOnlyPreempted("repeated-time-nanos", ParquetPhysicalType.Int64,
            new LogicalType.Time(TimeUnit.Nanos, IsAdjustedToUtc: false), rows, selector);

        // Probe the repeated converter route as well: repeated encoding still validates the row
        // carrier before it can enter statistics accumulation.
        ExpectRepeatedTimeOnlyPreempted("repeated-time-converter", ParquetPhysicalType.Int64, logicalType: null,
            rows, selector, new TimeOnlyStatisticsConverter());

        // An invalid TimeUnit is also tested through the repeated writer route; the same physical
        // row-carrier check should preempt statistics before its invalid-unit switch arm.
        ExpectRepeatedTimeOnlyPreempted("repeated-time-invalid-unit", ParquetPhysicalType.Int64,
            new LogicalType.Time((TimeUnit)255, IsAdjustedToUtc: false), rows, selector,
            new TimeOnlyStatisticsConverter());
    }

    static void ExpectRepeatedTimeOnlyPreempted(string name, ParquetPhysicalType physicalType,
        LogicalType? logicalType,
        TimeOnly[][] rows, byte selector, ParquetValueConverter? converter = null)
    {
        ParquetSchema schema;
        try
        {
            schema = new ParquetSchema([
                ColumnDefinition.Leaf(name, physicalType,
                    new ColumnOptions(ParquetRepetition.Repeated, Plain.Encodings), logicalType,
                    converter: converter)
            ]);
        }
        catch (ArgumentException exception) when (converter is not null && exception.ParamName == "converter")
        {
            // Repeated converters are rejected while the schema is constructed.
            return;
        }
        using var stream = new MemoryStream();
        var writer = schema.CreateWriter(stream, new ParquetWriterOptions
        {
            Compression = CompressionKind.None,
            DataPageVersion = (selector & 1) == 0 ? ParquetDataPageVersion.V1 : ParquetDataPageVersion.V2,
            WritePageCrc = (selector & 2) != 0
        });
        var serialized = writer.CreateSerializedColumn<TimeOnly[]>(schema.LeafColumns[0]);
        // Message from Plank 80578da (#224), which rewrote repeated-row flattening
        // (RepeatedPageValues.Flatten); the rejection itself is unchanged.
        var expectedMessage = $"Array type 'System.TimeOnly[]' is incompatible with column '{name}'.";
        try
        {
            serialized.Serialize(rows);
        }
        catch (InvalidOperationException exception) when (exception.Message == expectedMessage)
        {
            return;
        }

        throw new InvalidOperationException($"Repeated TimeOnly value was not preempted before statistics for '{name}'.");
    }

    sealed class TimeOnlyStatisticsConverter : ParquetValueConverter<TimeOnly, long>
    {
        public override long ConvertToPhysical(TimeOnly value) => value.Ticks / 10;
        public override TimeOnly ConvertFromPhysical(long value) => new(value * 10);
    }

    static void Write<T>(string name, ParquetPhysicalType physicalType, LogicalType logicalType,
        T[][] rows, byte selector)
    {
        var schema = new ParquetSchema([
            ColumnDefinition.Leaf(name, physicalType,
            new ColumnOptions(ParquetRepetition.Repeated, Plain.Encodings), logicalType: logicalType)
        ]);
        using var stream = new MemoryStream();
        var writer = schema.CreateWriter(stream, new ParquetWriterOptions
        {
            Compression = CompressionKind.None,
            DataPageVersion = (selector & 1) == 0 ? ParquetDataPageVersion.V1 : ParquetDataPageVersion.V2,
            WritePageCrc = (selector & 2) != 0
        });
        var serialized = writer.CreateSerializedColumn<T[]>(schema.LeafColumns[0]);
        serialized.Serialize(rows);
        writer.StartRowGroup().Write(serialized);
        writer.CloseFile();
    }
}
