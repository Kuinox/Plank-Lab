using System.Runtime.InteropServices;
using Plank.Fuzzing;

namespace Plank.Tests.Reading;

internal sealed class ExactFitBufferPoolTests
{
    [Test]
    public async Task InBoundsUseDisposesCleanly()
    {
        var pool = new ExactFitBufferPool(poison: true);
        var buffer = pool.Rent(10);
        await Assert.That(buffer.Length).IsEqualTo(10);
        await Assert.That(buffer.Span[0]).IsEqualTo((byte)0xA5);
        buffer.Span.Fill(1);
        buffer.Dispose();
    }

    [Test]
    public async Task OverrunTripsTrailingCanary()
    {
        var pool = new ExactFitBufferPool(poison: false);
        var buffer = pool.Rent(10);
        Marshal.WriteByte(buffer.DangerousGetAddress() + 10, 7);
        await Assert.That(() => buffer.Dispose()).Throws<InvalidOperationException>();
    }

    [Test]
    public async Task UnderrunTripsLeadingCanary()
    {
        var pool = new ExactFitBufferPool(poison: false);
        var buffer = pool.Rent(10);
        Marshal.WriteByte(buffer.DangerousGetAddress() - 40, 7);
        await Assert.That(() => buffer.Dispose()).Throws<InvalidOperationException>();
    }
}
