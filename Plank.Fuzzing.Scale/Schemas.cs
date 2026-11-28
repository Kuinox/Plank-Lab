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
    public int Small { get; set; }
    public int? Missing { get; set; }
}
