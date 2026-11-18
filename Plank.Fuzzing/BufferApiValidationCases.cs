using Plank;

namespace Plank.Fuzzing;

// Direct public buffer API boundaries cannot be expressed as Parquet bytes.
internal static class BufferApiValidationCases
{
    internal const int Count = 17;

    internal static void Execute(byte selector)
    {
        var mode = selector % Count;
        switch (mode)
        {
            case 11:
                ExpectArgument("retentionPolicy",
                    () => _ = new DefaultParquetBufferPool((ParquetBufferRetentionPolicy)255));
                return;
            case 12:
                ExpectArgument("maximumRetainedBytes",
                    () => _ = new DefaultParquetBufferPool(ParquetBufferRetentionPolicy.Adaptive, -1));
                return;
            case 13:
                using (var pool = new DefaultParquetBufferPool())
                    ExpectArgument("minimumByteLength", () => _ = pool.Rent(uint.MaxValue));
                return;
            case 14:
                using (var pool = new DefaultParquetBufferPool())
                {
                    using (var buffer = pool.Rent(8)) { }
                    pool.Trim();
                }
                return;
            case 15:
                using (var pool = new DefaultParquetBufferPool())
                    pool.Dispose();
                return;
            case 16:
                using (var pool = new DefaultParquetBufferPool(ParquetBufferRetentionPolicy.ZeroAllocation, 0))
                using (var buffer = pool.Rent(8)) { }
                return;
        }

        if (mode is >= 4 and <= 9)
        {
            const int allocationByteLength = 128;
            const int payloadOffset = 64;
            var (allocation, allocationSize, offset, length, expected) = mode switch
            {
                4 => ((nint)0, allocationByteLength, payloadOffset, 0, "allocation"),
                5 => ((nint)1, 0, payloadOffset, 0, "allocationByteLength"),
                6 => ((nint)1, allocationByteLength, 0, 0, "payloadOffset"),
                7 => ((nint)1, allocationByteLength, 129, 0, "payloadOffset"),
                8 => ((nint)1, allocationByteLength, payloadOffset, -1, "payloadByteLength"),
                _ => ((nint)1, allocationByteLength, payloadOffset, 65, "payloadByteLength")
            };
            ExpectArgument(expected, () => _ = ParquetBuffer.Create(allocation,
                allocationSize, offset, length, static _ => { }));
            return;
        }

        using var bufferPool = new DefaultParquetBufferPool();
        using var owner = bufferPool.Rent(8);
        switch (mode)
        {
            case 0:
                ExpectInvalid(() => _ = owner.AsSpan<string>());
                break;
            case 1:
                using (var oneByte = owner.RetainSlice(0, 1))
                    ExpectInvalid(() => _ = oneByte.AsSpan<int>());
                break;
            case 2:
                ExpectArgument("offset", () => _ = owner.RetainSlice(-1, 0));
                break;
            case 3:
                ExpectArgument("length", () => _ = owner.RetainSlice(0, owner.Length + 1));
                break;
            case 10:
                var disposed = owner.Retain();
                disposed.Dispose();
                ExpectDisposed(() => _ = disposed.AsSpan<int>());
                break;
        }
    }

    static void ExpectArgument(string parameter, Action action)
    {
        try { action(); }
        catch (ArgumentException error) when (error.ParamName == parameter) { return; }
        throw new InvalidOperationException($"Expected validation of {parameter}.");
    }

    static void ExpectInvalid(Action action)
    {
        try { action(); }
        catch (InvalidOperationException) { return; }
        throw new InvalidOperationException("Expected invalid buffer projection.");
    }

    static void ExpectDisposed(Action action)
    {
        try { action(); }
        catch (ObjectDisposedException) { return; }
        throw new InvalidOperationException("Expected disposed buffer rejection.");
    }
}
