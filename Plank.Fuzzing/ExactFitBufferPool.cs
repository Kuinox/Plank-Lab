using System.Runtime.InteropServices;

namespace Plank.Fuzzing;

/// <summary>
/// A buffer pool whose buffers are exactly the requested length, with canary
/// bytes before the header and after the payload that are verified on return.
/// </summary>
/// <remarks>
/// DefaultParquetBufferPool rounds every request up to a power-of-two bucket (or
/// colors it), so decoders that read or write past the length they asked for
/// always land in slack and never fail. Exact fit puts the boundary on the
/// allocation: an overrun trips the canary on return, and (with
/// <paramref name="poison"/>) a decoder that relies on a recycled zeroed buffer
/// reads 0xA5 instead and disagrees with the independent oracles.
/// </remarks>
public sealed class ExactFitBufferPool(bool poison) : IParquetBufferPool
{
    const int PayloadOffset = 64;
    const int Guard = 64;
    const byte Canary = 0xCD;
    const byte Poison = 0xA5;

    public ParquetBuffer Rent(uint minimumByteLength)
    {
        if (minimumByteLength == 0)
            return default;
        if (minimumByteLength > int.MaxValue - PayloadOffset - Guard)
            throw new ArgumentOutOfRangeException(nameof(minimumByteLength));

        var length = (int)minimumByteLength;
        var total = PayloadOffset + length + Guard;
        var allocation = Marshal.AllocHGlobal(total);
        Fill(allocation, 0, PayloadOffset, Canary);
        Fill(allocation, PayloadOffset, length, poison ? Poison : (byte)0);
        Fill(allocation, PayloadOffset + length, Guard, Canary);
        return ParquetBuffer.Create(allocation, total, PayloadOffset, length, Return);
    }

    static void Return(nint allocation)
    {
        // The header lives in the last 32 bytes of the front guard and is legitimately
        // rewritten by the buffer; only the part below it is checked. Capacity gives
        // the payload length, so the trailing canary can be located.
        var capacity = Marshal.ReadInt32(allocation, PayloadOffset - 32 + 4);
        var bad = Mismatch(allocation, 0, PayloadOffset - 32) ?? Mismatch(allocation, PayloadOffset + capacity, Guard);
        Marshal.FreeHGlobal(allocation);
        if (bad is { } at)
            throw new InvalidOperationException($"ExactFitBufferPool: guard byte at {at} (payload {capacity}) was overwritten.");
    }

    static int? Mismatch(nint allocation, int offset, int count)
    {
        for (var i = 0; i < count; i++)
            if (Marshal.ReadByte(allocation, offset + i) != Canary)
                return offset + i;
        return null;
    }

    static void Fill(nint allocation, int offset, int count, byte value)
    {
        if (count <= 0)
            return;
        var bytes = new byte[count];
        if (value != 0)
            Array.Fill(bytes, value);
        Marshal.Copy(bytes, 0, allocation + offset, count);
    }
}
