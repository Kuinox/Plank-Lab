using Plank.Schema;

namespace Plank.Fuzzing.Scale;

/// <summary>Flat row covering the main value classes: dense required, nullable, low/high-cardinality
/// (dictionary then fallback), variable-length, floating point.</summary>
[ParquetSchema(AllowAllocatingValues = true)]
public sealed partial class ScaleRow
{
    public long Id { get; set; }
    public int Category { get; set; }
    public long? HighCard { get; set; }
    public double Measure { get; set; }
    public float? Ratio { get; set; }
    public bool Flag { get; set; }
    public byte[]? Payload { get; set; }
    public string Label { get; set; } = string.Empty;
}

/// <summary>Nested row: repeated/levels paths at scale.</summary>
[ParquetSchema(AllowAllocatingValues = true)]
public sealed partial class ScaleNested
{
    public long Id { get; set; }
    public List<int>? Values { get; set; }
    public List<string>? Tags { get; set; }
}

/// <summary>Cheap columns for files with more than int.MaxValue rows (RLE / dictionary compress them to almost nothing).</summary>
[ParquetSchema]
public sealed partial class ScaleMany
{
    public bool Flag { get; set; }
    [ParquetColumn(Encodings = [EncodingKind.RleDictionary])]
    public int Small { get; set; }
    [ParquetColumn(Encodings = [EncodingKind.RleDictionary])]
    public int? Missing { get; set; }
}

/// <summary>Semantic CLR types through the generated row writer/reader and dataset writer.</summary>
[ParquetSchema(AllowAllocatingValues = true)]
public sealed partial class ScaleTypes
{
    public long Id { get; set; }
    [ParquetColumn(Precision = 9, Scale = 2)]
    public decimal Dec9 { get; set; }
    [ParquetColumn(Precision = 18, Scale = 4)]
    public decimal? Dec18 { get; set; }
    [ParquetColumn(Precision = 28, Scale = 10)]
    public decimal Dec28 { get; set; }
    public DateTime Stamp { get; set; }
    public DateTimeOffset? StampUtc { get; set; }
    public DateOnly Day { get; set; }
    public TimeOnly? Clock { get; set; }
    public Guid Key { get; set; }
    public Guid? MaybeKey { get; set; }
    public uint U32 { get; set; }
    public ulong? U64 { get; set; }
    public byte U8 { get; set; }
    public ushort? U16 { get; set; }
    [ParquetColumn(LogicalType = LogicalTypeKind.Json)]
    public string? Doc { get; set; }
}

/// <summary>Repeated logical types.</summary>
[ParquetSchema(AllowAllocatingValues = true)]
public sealed partial class ScaleTypesNested
{
    public long Id { get; set; }
    public List<DateTime>? Stamps { get; set; }
    public List<Guid>? Keys { get; set; }
    public List<DateOnly>? Days { get; set; }
    public List<uint>? Counts { get; set; }
    public List<TimeOnly>? Clocks { get; set; }
}
