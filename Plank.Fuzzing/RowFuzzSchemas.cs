using Plank.Schema;

namespace Plank.Fuzzing;

// Row types for the row-API fuzz target.
//
// The row writer cannot be driven without these. RowWriterBase<TSlot> is
// abstract over four methods the generator emits, and RowGroupWriterCore<TSlot>
// is generic over a generated slot type — neither can be synthesized at runtime,
// which is why the whole write pipeline (RowBufferSlot, RowValueSizeEstimator,
// PipelineRowWriterBase, RowApiColumnWriteState, RowWriterBase) measured zero
// while the columnar writer was well covered.
//
// Separate shapes rather than one, because the generated code differs by property
// type in ways that matter:
//
//   fixed-width required  -> the dense, no-definition-level path
//   nullable              -> definition levels, and a separate slot layout
//   binary                -> ByteArrayRows, the length-and-offset bookkeeping
//                            the fixed-width path does not have
//   nested                -> generated collection/map descriptors, size
//                            estimation, and repeated-row write shapes

/// <summary>Fixed-width required columns: the densest row layout.</summary>
[ParquetSchema]
public sealed partial class RowFuzzFixed
{
    public bool Flag { get; set; }

    public int Id { get; set; }

    public long Sequence { get; set; }

    public double Measure { get; set; }
}

/// <summary>Nullable columns, so every row carries definition levels.</summary>
[ParquetSchema]
public sealed partial class RowFuzzNullable
{
    public int? Id { get; set; }

    public long? Sequence { get; set; }

    public double? Measure { get; set; }

    public bool? Flag { get; set; }
}

/// <summary>Variable-length columns, which is what reaches ByteArrayRows.</summary>
/// <remarks>
/// AllowAllocatingValues is on for the string column. The generator refuses
/// string by default because the UTF-8 conversion allocates, but that conversion
/// is its own encode and decode path and worth fuzzing; a byte[] column beside it
/// covers the non-allocating one.
/// </remarks>
[ParquetSchema(AllowAllocatingValues = true)]
public sealed partial class RowFuzzBinary
{
    public int Id { get; set; }

    public byte[] Payload { get; set; } = [];

    public string Label { get; set; } = string.Empty;
}

/// <summary>Optional byte arrays for null-sensitive row value-size estimation.</summary>
[ParquetSchema(AllowAllocatingValues = true)]
public sealed partial class RowFuzzNullableBinary
{
    public byte[]? Payload { get; set; }
}

/// <summary>Nested collections, maps, and records for the generated row writer.</summary>
[ParquetSchema(AllowAllocatingValues = true)]
public sealed partial class RowFuzzNested
{
    public int Sequence { get; set; }

    public Guid CorrelationId { get; set; }

    public string Label { get; set; } = string.Empty;

    public int?[][]? Values { get; set; }

    public Dictionary<int, int?>? Scores { get; set; }

    public RowFuzzAddress? Location { get; set; }

    public List<RowFuzzEntry>? Items { get; set; }

    public List<string?>? Names { get; set; }

    public List<Guid?>? Identifiers { get; set; }

    public List<DateOnly?>? Dates { get; set; }

    public List<TimeOnly?>? Times { get; set; }

    public List<DateTime?>? Timestamps { get; set; }

    public List<DateTimeOffset?>? Instants { get; set; }
}

public sealed record RowFuzzEntry
{
    public int Id { get; init; }

    public long Amount { get; init; }
}

public sealed record RowFuzzAddress
{
    public int Zip { get; init; }

    public byte Rank { get; init; }

    public string City { get; init; } = string.Empty;

    public Guid Token { get; init; }
}

/// <summary>Binary values and nested binary leaves queued through the dataset writer.</summary>
[ParquetSchema(AllowAllocatingValues = true)]
public sealed partial class RowFuzzDatasetBinary
{
    public int Id { get; set; }

    public byte[] Payload { get; set; } = [];

    public byte[]? OptionalPayload { get; set; }

    public List<byte[]?>? Items { get; set; }

    public List<List<byte[]>> Matrix { get; set; } = [];

    public ReadOnlyMemory<byte>[] Memories { get; set; } = [];

    public ReadOnlyMemory<byte>?[]? OptionalMemories { get; set; }
}

/// <summary>Scalar string and memory columns for the dataset snapshot adapter.</summary>
[ParquetSchema(AllowAllocatingValues = true)]
public sealed partial class RowFuzzDatasetMemory
{
    public int Id { get; set; }

    public string Label { get; set; } = string.Empty;

    public ReadOnlyMemory<byte> Memory { get; set; }

    public ReadOnlyMemory<byte>? OptionalMemory { get; set; }

    public byte[]? OptionalPayload { get; set; }
}

/// <summary>Fixed-width nested dataset values for operational branch coverage.</summary>
[ParquetSchema(AllowAllocatingValues = true)]
public sealed partial class RowFuzzDatasetFixedNested
{
    public int Id { get; set; }

    public List<Guid> Values { get; set; } = [];

    public List<int> NumericValues { get; set; } = [];
}
