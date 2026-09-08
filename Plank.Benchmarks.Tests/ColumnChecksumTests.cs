namespace Plank.Benchmarks.Tests;

internal sealed class ColumnChecksumTests
{
    [Test]
    public async Task ChunkingPreservesFloatingPointAdditionOrder()
    {
        double[] values = [1, -1e16, 1e16, 3, double.Epsilon, -3];
        double expected = 0;
        foreach (var value in values) expected += value;
        for (var split = 0; split <= values.Length; split++)
        {
            var actual = ColumnChecksum.Accumulate(values.AsSpan(0, split), 0d);
            actual = ColumnChecksum.Accumulate(values.AsSpan(split), actual);
            await Assert.That(BitConverter.DoubleToInt64Bits(actual))
                .IsEqualTo(BitConverter.DoubleToInt64Bits(expected));
        }
    }

    [Test]
    public async Task NullableChecksumsKeepNullsAndUnsignedConversions()
    {
        int?[] ints = [null, -1, int.MinValue, 1, null];
        long?[] longs = [null, -1, long.MinValue, 1, null];
        double?[] doubles = [1, null, -1e16, 1e16, null];
        await Assert.That(ColumnChecksum.Accumulate(ints, 0UL))
            .IsEqualTo((ulong)uint.MaxValue + 2147483648UL + 1UL);
        await Assert.That(ColumnChecksum.Accumulate(longs, 0UL))
            .IsEqualTo(9223372036854775808UL);
        await Assert.That(ColumnChecksum.Accumulate(doubles, 0d)).IsEqualTo(0d);
        await Assert.That(ColumnChecksum.Accumulate(ReadOnlySpan<double>.Empty, 17d)).IsEqualTo(17d);
    }
}
