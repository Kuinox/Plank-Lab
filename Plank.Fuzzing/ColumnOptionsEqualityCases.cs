using System.Collections.Immutable;
using Plank.Schema;

namespace Plank.Fuzzing;

// Direct public-API sample: file-shaped writer plans do not compare options.
internal static class ColumnOptionsEqualityCases
{
    static readonly ImmutableArray<EncodingKind> Encodings =
        ImmutableArray.Create(EncodingKind.Plain, EncodingKind.RleDictionary);

    internal static void Execute(byte mode)
    {
        var left = NewOptions();
        ColumnOptions? right = (mode % 11) switch
        {
            0 => left,
            1 => null,
            2 => NewOptions(repetition: ParquetRepetition.Optional),
            3 => NewOptions(typeLength: 16),
            4 => NewOptions(compression: CompressionKind.Gzip),
            5 => NewOptions(compressionLevel: 4),
            6 => NewOptions(bloomFilter: ParquetBloomFilterOptions.Default),
            7 => NewOptions(encodings: ImmutableArray.Create(EncodingKind.Plain)),
            8 => NewOptions(encodings: ImmutableArray.Create(EncodingKind.RleDictionary, EncodingKind.RleDictionary)),
            9 => NewOptions(encodings: ImmutableArray.Create(EncodingKind.Plain, EncodingKind.Plain)),
            _ => NewOptions(),
        };

        var equal = left.Equals(right);
        var expected = mode % 11 is 0 or 10;
        if (equal != expected)
            throw new InvalidOperationException($"ColumnOptions equality changed for mode {mode % 11}.");

        if (expected && left.GetHashCode() != right!.GetHashCode())
            throw new InvalidOperationException("Equal ColumnOptions have different hashes.");
    }

    static ColumnOptions NewOptions(
        ParquetRepetition repetition = ParquetRepetition.Required,
        uint typeLength = 8,
        CompressionKind compression = CompressionKind.Snappy,
        int compressionLevel = 3,
        ParquetBloomFilterOptions? bloomFilter = null,
        ImmutableArray<EncodingKind> encodings = default)
        => new(repetition, encodings.IsDefault ? Encodings : encodings,
            typeLength, compression, compressionLevel, bloomFilter);
}
