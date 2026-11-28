// Compiled INTO the Plank library ONLY by -p:PlankCheckedCanaryProbe=true (never in a normal or fuzz build): a
// partial of ColumnChunkReader that exposes the private dictionary literal decoder so the checked-access build can be
// proven to catch the canary over-read directly, independent of which reader route reaches it. The library sources
// are not edited. It reproduces the state the integer overflow in DecodeDictionaryIndexesIntoBuffer<T> produces: a
// literal run whose byte slice is far shorter than the value count it decodes, so the decoder reads past the slice.
#if PLANK_CHECKED_CANARY_PROBE
using System;

namespace Plank.Reading.Logical.Internal;

static partial class ColumnChunkReader
{
    /// <summary>
    /// Decodes <paramref name="valueCount"/> dictionary indexes of <paramref name="bitWidth"/> bits from
    /// <paramref name="payload"/> into a buffer, exactly as the generic whole-page path does after the overflow has
    /// shrunk the literal slice. With a short payload the decoder reads past it: under -p:PlankCheckedAccess=true the
    /// vector paths (Unsafe loads of the payload ref) must throw PlankOobReadException.
    /// </summary>
    public static int DecodeLiteralCanary(int bitWidth, int valueCount, byte[] payload, long[] dictionary)
    {
        var destination = new long[valueCount];
        DecodeDictionaryLiteralIndexes<long>(payload, bitWidth, dictionary, destination);
        var checksum = 0L;
        foreach (var value in destination)
            checksum ^= value;
        return (int)checksum;
    }
}
#endif
