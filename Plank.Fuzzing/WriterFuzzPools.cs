namespace Plank.Fuzzing;

/// <summary>
/// Buffer pools the generic writer target can pick. The shared default pool hands back generously
/// sized, mostly zeroed, recycled buffers; these remove each of those comfortable properties so the
/// writer's buffer-capacity assumptions are tested: exact-length buffers (no slack beyond the
/// requested size) and buffers pre-filled with garbage (the writer must never rely on zeroed memory).
/// </summary>
internal enum WriterPoolKind : byte
{
    Shared = 0,
    ZeroAllocation = 1,
    AdaptiveNoRetention = 2,
    AdaptiveSmallRetention = 3,
    ExactDirty = 4,
    PaddedDirty = 5,
    ExactClean = 6,
}

internal sealed class WriterFuzzPool : IParquetBufferPool, IDisposable
{
    readonly DefaultParquetBufferPool? _owned;
    readonly IParquetBufferPool _inner;
    readonly bool _exact;
    readonly bool _dirty;
    readonly int _pad;

    WriterFuzzPool(DefaultParquetBufferPool? owned, IParquetBufferPool inner, bool exact, bool dirty, int pad)
    {
        _owned = owned;
        _inner = inner;
        _exact = exact;
        _dirty = dirty;
        _pad = pad;
    }

    internal static WriterFuzzPool Create(WriterPoolKind kind)
        => kind switch
        {
            WriterPoolKind.ZeroAllocation => Own(new DefaultParquetBufferPool(ParquetBufferRetentionPolicy.ZeroAllocation), false, false, 0),
            WriterPoolKind.AdaptiveNoRetention => Own(new DefaultParquetBufferPool(ParquetBufferRetentionPolicy.Adaptive, 0), false, false, 0),
            WriterPoolKind.AdaptiveSmallRetention => Own(new DefaultParquetBufferPool(ParquetBufferRetentionPolicy.Adaptive, 1 << 20), false, false, 0),
            WriterPoolKind.ExactDirty => Own(new DefaultParquetBufferPool(), true, true, 0),
            WriterPoolKind.PaddedDirty => Own(new DefaultParquetBufferPool(), false, true, 61),
            WriterPoolKind.ExactClean => Own(new DefaultParquetBufferPool(), true, false, 0),
            _ => new WriterFuzzPool(null, DefaultParquetBufferPool.Shared, false, false, 0),
        };

    static WriterFuzzPool Own(DefaultParquetBufferPool pool, bool exact, bool dirty, int pad)
        => new(pool, pool, exact, dirty, pad);

    public ParquetBuffer Rent(uint minimumByteLength)
    {
        if (minimumByteLength == 0 || (!_exact && !_dirty && _pad == 0))
            return _inner.Rent(minimumByteLength);

        var rented = _inner.Rent(checked(minimumByteLength + (uint)_pad));
        try
        {
            if (_dirty)
                rented.Span.Fill(0xA5);
            if (!_exact)
                return rented.Retain();
            // A buffer of exactly the requested length: the contract only promises "at least".
            return rented.RetainSlice(0, checked((int)minimumByteLength));
        }
        finally
        {
            rented.Dispose();
        }
    }

    public void Dispose()
        => _owned?.Dispose();
}
