using Plank.RowApi;

namespace Plank.Benchmarks;

static class RowReaderBinaryValueCompatibility
{
    extension(RowReaderBinaryValue value)
    {
        public int Length
            => value.Value.Length;
    }
}
