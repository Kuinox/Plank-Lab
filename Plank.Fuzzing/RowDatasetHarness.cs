using Plank.Reading;
using Plank.Writing;

namespace Plank.Fuzzing;

/// <summary>
/// Decides which operation on a dataset file source fails. The countdown counts only
/// operations selected by <see cref="Mask"/>, so a case can target exactly the Nth write,
/// the first footer read or the file-length probe, instead of the first failure of any kind.
/// </summary>
internal sealed class DatasetFaultPlan(int failAt, int mask, bool persistent)
{
    internal const int Open = 1, Write = 2, SetLength = 4, Flush = 8, Length = 16, Read = 32;
    int _remaining = failAt;
    internal int Mask => mask;
    internal bool Fired { get; private set; }

    internal void Tick(string operation, int bit)
    {
        if (failAt <= 0 || (mask & bit) == 0)
            return;
        if (Fired)
        {
            // Persistent plans keep failing, so cleanup (ReleaseAfterFailure) runs under failure too.
            if (persistent)
                throw new IOException($"Injected {operation} fault (repeat).");
            return;
        }
        if (--_remaining > 0)
            return;
        Fired = true;
        throw new IOException($"Injected {operation} fault.");
    }

    internal static bool IsInjected(Exception exception)
        => exception is IOException io && io.Message.StartsWith("Injected ", StringComparison.Ordinal);
}

/// <summary>An in-memory dataset file whose operations fail on demand.</summary>
sealed class FaultingDatasetFile(InMemoryDatasetFile inner, DatasetFaultPlan plan) : IParquetReadSource, IParquetWriteSource
{
    public void Open(ReadOnlySpan<byte> path, FileMode mode)
    {
        plan.Tick("Open", DatasetFaultPlan.Open);
        inner.Open(path, mode);
    }

    // Cleanup paths are never failed directly: Close/Dispose must always be safe to call.
    public void Close() => inner.Close();

    public void Write(ulong offset, ReadOnlySpan<byte> source)
    {
        plan.Tick("Write", DatasetFaultPlan.Write);
        inner.Write(offset, source);
    }

    public void SetLength(ulong length)
    {
        plan.Tick("SetLength", DatasetFaultPlan.SetLength);
        inner.SetLength(length);
    }

    public void Flush()
    {
        plan.Tick("Flush", DatasetFaultPlan.Flush);
        inner.Flush();
    }

    public ulong Length
    {
        get
        {
            plan.Tick("Length", DatasetFaultPlan.Length);
            return inner.Length;
        }
    }

    public void ReadExactly(ulong offset, Span<byte> destination)
    {
        plan.Tick("ReadExactly", DatasetFaultPlan.Read);
        inner.ReadExactly(offset, destination);
    }

    public void Dispose() => inner.Dispose();
}
