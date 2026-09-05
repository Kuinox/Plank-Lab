using System.Buffers.Binary;
using System.Net;
using System.Net.Http.Headers;
using System.Security.Cryptography;
using Plank.Benchmarks.S3Footer;

namespace Plank.Benchmarks.Tests;

internal sealed class TaxiFooterFixtureTests
{
    [Test]
    public async Task LocalFixtureKeepsOriginalBytesAndOwnership()
    {
        var bytes = CreateObject();
        var path = Path.GetTempFileName();
        try
        {
            await File.WriteAllBytesAsync(path, bytes);
            var fixture = await TaxiFooterFixture.PrepareAsync(path);
            await Assert.That(fixture.Mode).IsEqualTo("full-file");
            await Assert.That(fixture.FileSizeBytes).IsEqualTo(256L);
            await Assert.That(fixture.FooterOffset).IsEqualTo(216L);
            await Assert.That(fixture.FooterLengthBytes).IsEqualTo(32);
            await Assert.That(fixture.FooterSha256).IsEqualTo(
                Convert.ToHexStringLower(SHA256.HashData(bytes.AsSpan(216, 32))));
            fixture.Dispose();
            await Assert.That(File.Exists(path)).IsTrue();
            await Assert.That((await File.ReadAllBytesAsync(path)).SequenceEqual(bytes)).IsTrue();
        }
        finally { File.Delete(path); }
    }

    [Test]
    public async Task LocalFixtureRejectsMissingMagicAndInvalidFooterOffsets()
    {
        var path = Path.GetTempFileName();
        try
        {
            foreach (var mutation in new Action<byte[]>[]
                     {
                         bytes => bytes[0] = 0,
                         bytes => bytes[^1] = 0,
                         bytes => BinaryPrimitives.WriteUInt32LittleEndian(bytes.AsSpan(bytes.Length - 8), 0),
                         bytes => BinaryPrimitives.WriteUInt32LittleEndian(bytes.AsSpan(bytes.Length - 8), 249)
                     })
            {
                var bytes = CreateObject();
                mutation(bytes);
                await File.WriteAllBytesAsync(path, bytes);
                await Assert.ThrowsAsync<InvalidDataException>(async () =>
                {
                    using var fixture = await TaxiFooterFixture.PrepareAsync(path);
                });
            }
            await File.WriteAllBytesAsync(path, "PAR1"u8.ToArray());
            await Assert.ThrowsAsync<InvalidDataException>(async () =>
            {
                using var fixture = await TaxiFooterFixture.PrepareAsync(path);
            });
        }
        finally { File.Delete(path); }
    }

    [Test]
    public async Task RemoteFixturePreservesRealOffsetsAndDownloadsOnlyFooterAndTrailer()
    {
        var bytes = CreateObject();
        var requests = new List<string>();
        using var client = new HttpClient(new StubHandler(request =>
        {
            requests.Add(request.Headers.Range!.ToString());
            if (requests.Count == 1) return RangeResponse(bytes[248..], 248, 255, 256);
            if (request.Headers.IfMatch.Single().Tag != "\"fixture-v1\"")
                throw new InvalidOperationException("The footer request must pin the trailer's object version.");
            return RangeResponse(bytes[216..248], 216, 247, 256);
        }));
        var fixture = await TaxiFooterFixture.PrepareRemoteAsync(client);
        var path = fixture.FilePath;
        try
        {
            await Assert.That(fixture.Mode).IsEqualTo("metadata-only");
            await Assert.That(fixture.SourceUrl).IsEqualTo(TaxiFooterFixture.DefaultSourceUrl);
            await Assert.That(fixture.FileSizeBytes).IsEqualTo(256L);
            await Assert.That(fixture.FooterOffset).IsEqualTo(216L);
            await Assert.That(requests).IsEquivalentTo(["bytes=-8", "bytes=216-247"]);
            var actual = await File.ReadAllBytesAsync(path);
            await Assert.That(actual.AsSpan(0, 4).SequenceEqual("PAR1"u8)).IsTrue();
            await Assert.That(actual.AsSpan(4, 212).IndexOfAnyExcept((byte)0)).IsEqualTo(-1);
            await Assert.That(actual.AsSpan(216).SequenceEqual(bytes.AsSpan(216))).IsTrue();
            await Assert.That(fixture.FooterSha256).IsEqualTo(
                Convert.ToHexStringLower(SHA256.HashData(bytes.AsSpan(216, 32))));
        }
        finally { fixture.Dispose(); }
        await Assert.That(File.Exists(path)).IsFalse();
    }

    [Test]
    public async Task RemoteFixtureRejectsIgnoredRangesWrongOffsetsAndChangedObjects()
    {
        var bytes = CreateObject();
        foreach (var invalidResponse in new Func<HttpResponseMessage>[]
                 {
                     () => new HttpResponseMessage(HttpStatusCode.OK) { Content = new ByteArrayContent(bytes) },
                     () => RangeResponse(bytes[248..], 247, 254, 256),
                     () => RangeResponse(bytes[248..255], 248, 255, 256),
                     () => RangeResponse(bytes[248..].Concat(new byte[] { 0 }).ToArray(), 248, 255, 256)
                 })
        {
            using var client = new HttpClient(new StubHandler(_ => invalidResponse()));
            await Assert.ThrowsAsync<InvalidDataException>(async () =>
            {
                using var fixture = await TaxiFooterFixture.PrepareRemoteAsync(client);
            });
        }

        var requestCount = 0;
        using var changedClient = new HttpClient(new StubHandler(_ => ++requestCount == 1
            ? RangeResponse(bytes[248..], 248, 255, 256)
            : RangeResponse(bytes[216..248], 216, 247, 256, "\"fixture-v2\"")));
        await Assert.ThrowsAsync<InvalidDataException>(async () =>
        {
            using var fixture = await TaxiFooterFixture.PrepareRemoteAsync(changedClient);
        });
    }

    [Test]
    public async Task RemoteFixtureRejectsTruncatedBodyEvenWhenHeadersClaimExpectedLength()
    {
        var bytes = CreateObject();
        var requestCount = 0;
        using var client = new HttpClient(new StubHandler(_ =>
        {
            if (++requestCount == 1) return RangeResponse(bytes[248..], 248, 255, 256);
            var response = RangeResponse(bytes[216..247], 216, 247, 256);
            response.Content.Headers.ContentLength = 32;
            return response;
        }));
        await Assert.ThrowsAsync<InvalidDataException>(async () =>
        {
            using var fixture = await TaxiFooterFixture.PrepareRemoteAsync(client);
        });
    }

    static byte[] CreateObject()
    {
        var bytes = Enumerable.Range(0, 256).Select(i => (byte)i).ToArray();
        "PAR1"u8.CopyTo(bytes);
        BinaryPrimitives.WriteUInt32LittleEndian(bytes.AsSpan(248), 32);
        "PAR1"u8.CopyTo(bytes.AsSpan(252));
        return bytes;
    }

    static HttpResponseMessage RangeResponse(byte[] bytes, long start, long end, long total,
        string etag = "\"fixture-v1\"")
    {
        var response = new HttpResponseMessage(HttpStatusCode.PartialContent)
        {
            Content = new ByteArrayContent(bytes)
        };
        response.Content.Headers.ContentRange = new ContentRangeHeaderValue(start, end, total);
        response.Headers.ETag = new EntityTagHeaderValue(etag);
        return response;
    }

    sealed class StubHandler(Func<HttpRequestMessage, HttpResponseMessage> respond) : HttpMessageHandler
    {
        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request,
            CancellationToken cancellationToken)
            => Task.FromResult(respond(request));
    }
}
