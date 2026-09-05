using System.Diagnostics;
using System.Net;
using System.Net.Http.Headers;
using Plank.Benchmarks.S3Footer;

namespace Plank.Benchmarks.Tests;

internal sealed class S3TransportTests
{
    [Test]
    public async Task EmulatorServesWholeObjectsHeadAndInclusiveRanges()
    {
        await using var fixture = await ObjectFixture.CreateAsync(10);
        using var client = new HttpClient();
        using (var response = await client.GetAsync(fixture.Emulator.ObjectUri))
        {
            await Assert.That(response.StatusCode).IsEqualTo(HttpStatusCode.OK);
            await Assert.That(await response.Content.ReadAsByteArrayAsync()).IsEquivalentTo(fixture.Bytes);
            await Assert.That(response.Content.Headers.ContentLength).IsEqualTo(10L);
        }

        using (var request = new HttpRequestMessage(HttpMethod.Head, fixture.Emulator.ObjectUri))
        {
            request.Headers.Range = new RangeHeaderValue(5, 8);
            using var response = await client.SendAsync(request);
            await Assert.That(response.StatusCode).IsEqualTo(HttpStatusCode.OK);
            await Assert.That(response.Content.Headers.ContentLength).IsEqualTo(10L);
            await Assert.That((await response.Content.ReadAsByteArrayAsync()).Length).IsEqualTo(0);
        }

        foreach (var (range, start, end) in new (string, int, int)[]
                 {
                     ("bytes=2-5", 2, 5), ("bytes=7-", 7, 9), ("bytes=-3", 7, 9),
                     ("bytes=8-100", 8, 9), ("bytes=-100", 0, 9), ("bytes=0-0", 0, 0)
                 })
        {
            using var request = new HttpRequestMessage(HttpMethod.Get, fixture.Emulator.ObjectUri);
            request.Headers.TryAddWithoutValidation("Range", range);
            using var response = await client.SendAsync(request);
            await Assert.That(response.StatusCode).IsEqualTo(HttpStatusCode.PartialContent);
            await Assert.That(response.Content.Headers.ContentRange!.ToString()).IsEqualTo($"bytes {start}-{end}/10");
            await Assert.That(response.Content.Headers.ContentLength).IsEqualTo((long)(end - start + 1));
            await Assert.That((await response.Content.ReadAsByteArrayAsync()).SequenceEqual(fixture.Bytes[start..(end + 1)])).IsTrue();
        }
    }

    [Test]
    public async Task EmulatorRejectsUnsatisfiableMalformedAndMultipleRanges()
    {
        await using var fixture = await ObjectFixture.CreateAsync(10);
        using var client = new HttpClient();
        foreach (var range in new[] { "bytes=10-", "bytes=11-12", "bytes=5-2", "bytes=-0", "bytes=0-1,4-5", "bytes=oops", "items=0-1" })
        {
            using var request = new HttpRequestMessage(HttpMethod.Get, fixture.Emulator.ObjectUri);
            request.Headers.TryAddWithoutValidation("Range", range);
            using var response = await client.SendAsync(request);
            await Assert.That(response.StatusCode).IsEqualTo(HttpStatusCode.RequestedRangeNotSatisfiable);
            await Assert.That(response.Content.Headers.ContentRange!.ToString()).IsEqualTo("bytes */10");
            await Assert.That((await response.Content.ReadAsByteArrayAsync()).Length).IsEqualTo(0);
        }

        await using var empty = await ObjectFixture.CreateAsync(0);
        using var full = await client.GetAsync(empty.Emulator.ObjectUri);
        await Assert.That(full.StatusCode).IsEqualTo(HttpStatusCode.OK);
        await Assert.That(full.Content.Headers.ContentLength).IsEqualTo(0L);
        using var emptyRequest = new HttpRequestMessage(HttpMethod.Get, empty.Emulator.ObjectUri);
        emptyRequest.Headers.Range = new RangeHeaderValue(0, 0);
        using var emptyRange = await client.SendAsync(emptyRequest);
        await Assert.That(emptyRange.StatusCode).IsEqualTo(HttpStatusCode.RequestedRangeNotSatisfiable);
        await Assert.That(emptyRange.Content.Headers.ContentRange!.ToString()).IsEqualTo("bytes */0");
    }

    [Test]
    public async Task StreamReadsExactRangesLazilyWithoutCachingAndPreservesClientOwnership()
    {
        await using var fixture = await ObjectFixture.CreateAsync(10);
        using var client = new HttpClient();
        var stream = new S3RangeStream(client, fixture.Emulator.ObjectUri, Stopwatch.GetTimestamp());
        await Assert.That(stream.Requests.Count).IsEqualTo(0);
        await Assert.That(stream.Read(Array.Empty<byte>(), 0, 0)).IsEqualTo(0);
        await Assert.That(stream.Seek(2, SeekOrigin.Begin)).IsEqualTo(2L);
        await Assert.That(stream.Requests.Count).IsEqualTo(0);
        await Assert.That(stream.Length).IsEqualTo(10L);
        await Assert.That(stream.Length).IsEqualTo(10L);
        await Assert.That(stream.Requests.Count).IsEqualTo(1);

        var buffer = new byte[4];
        await Assert.That(stream.Read(buffer, 0, 4)).IsEqualTo(4);
        await Assert.That(buffer.SequenceEqual(new byte[] { 2, 3, 4, 5 })).IsTrue();
        stream.Seek(-2, SeekOrigin.Current);
        await Assert.That(stream.ReadByte()).IsEqualTo(4);
        stream.Seek(-2, SeekOrigin.End);
        await Assert.That(await stream.ReadAsync(buffer)).IsEqualTo(2);
        await Assert.That(buffer[0]).IsEqualTo((byte)8);
        await Assert.That(buffer[1]).IsEqualTo((byte)9);
        await Assert.That(stream.ReadByte()).IsEqualTo(-1);
        stream.Position = 100;
        await Assert.That(await stream.ReadAsync(buffer)).IsEqualTo(0);
        stream.Position = 2;
        await Assert.That(stream.Read(buffer.AsSpan())).IsEqualTo(4);

        await Assert.That(stream.Requests.Select(request => request.Method).SequenceEqual(new[] { "HEAD", "GET", "GET", "GET", "GET" })).IsTrue();
        await Assert.That(stream.Requests.Select(request => request.Range).SequenceEqual(new[] { null, "bytes=2-5", "bytes=4-4", "bytes=8-9", "bytes=2-5" })).IsTrue();
        await Assert.That(stream.Requests.Sum(request => request.BytesReceived)).IsEqualTo(11L);
        await Assert.That(stream.Requests[0].BytesReceived).IsEqualTo(0L);
        await Assert.That(stream.Requests.All(request => request.Error is null && request.StartMs >= 0 && request.DurationMs >= 0)).IsTrue();
        await Assert.That(stream.Requests.Select(request => request.Id).SequenceEqual(Enumerable.Range(1, 5))).IsTrue();
        Assert.Throws<IOException>(() => stream.Seek(-1, SeekOrigin.Begin));
        Assert.Throws<IOException>(() => stream.Seek(long.MaxValue, SeekOrigin.Current));
        Assert.Throws<NotSupportedException>(() => stream.SetLength(5));

        stream.Dispose();
        await Assert.That(stream.CanRead).IsFalse();
        await Assert.That(stream.CanSeek).IsFalse();
        Assert.Throws<ObjectDisposedException>(() => _ = stream.Length);
        Assert.Throws<ObjectDisposedException>(() => stream.ReadByte());
        using var responseAfterDispose = await client.GetAsync(fixture.Emulator.ObjectUri);
        await Assert.That(responseAfterDispose.StatusCode).IsEqualTo(HttpStatusCode.OK);
    }

    [Test]
    [Arguments("status", 0L)]
    [Arguments("range", 0L)]
    [Arguments("length", 0L)]
    [Arguments("missing-length", 0L)]
    [Arguments("short", 2L)]
    [Arguments("long", 5L)]
    public async Task StreamRejectsInvalidResponsesAndRecordsActualReceivedBytes(string failure, long expectedBytes)
    {
        using var client = new HttpClient(new ResponseHandler(request =>
        {
            if (request.Method == HttpMethod.Head) return HeadResponse();
            var content = new StreamContent(new MemoryStream(new byte[failure == "short" ? 2 : failure == "long" ? 5 : 4]));
            if (failure != "missing-length") content.Headers.ContentLength = failure == "length" ? 3 : 4;
            content.Headers.ContentRange = new ContentRangeHeaderValue(failure == "range" ? 1 : 0, 3, 10);
            return new HttpResponseMessage(failure == "status" ? HttpStatusCode.OK : HttpStatusCode.PartialContent) { Content = content };
        }));
        using var stream = new S3RangeStream(client, new Uri("http://localhost/benchmark/taxi.parquet"), Stopwatch.GetTimestamp());
        if (failure == "short")
            await Assert.ThrowsAsync<EndOfStreamException>(() => stream.ReadAsync(new byte[4]).AsTask());
        else
            await Assert.ThrowsAsync<IOException>(() => stream.ReadAsync(new byte[4]).AsTask());
        await Assert.That(stream.Position).IsEqualTo(0L);
        await Assert.That(stream.Requests.Count).IsEqualTo(2);
        await Assert.That(stream.Requests[1].BytesReceived).IsEqualTo(expectedBytes);
        await Assert.That(stream.Requests[1].Error is not null).IsTrue();
        await Assert.That(stream.Requests[1].StartByte).IsEqualTo(0L);
        await Assert.That(stream.Requests[1].EndByte).IsEqualTo(3L);
    }

    [Test]
    public async Task StreamRecordsHeadAndTransportFailures()
    {
        using var failedHeadClient = new HttpClient(new ResponseHandler(_ => new HttpResponseMessage(HttpStatusCode.NotFound)));
        using var failedHead = new S3RangeStream(failedHeadClient, new Uri("http://localhost/missing"), Stopwatch.GetTimestamp());
        await Assert.ThrowsAsync<IOException>(() => failedHead.ReadAsync(new byte[4]).AsTask());
        await Assert.That(failedHead.Requests.Count).IsEqualTo(1);
        await Assert.That(failedHead.Requests[0].Method).IsEqualTo("HEAD");
        await Assert.That(failedHead.Requests[0].StatusCode).IsEqualTo(404);
        await Assert.That(failedHead.Requests[0].BytesReceived).IsEqualTo(0L);
        await Assert.That(failedHead.Requests[0].Error is not null).IsTrue();

        using var missingLengthClient = new HttpClient(new ResponseHandler(_ => new HttpResponseMessage(HttpStatusCode.OK)
            { Content = new ByteArrayContent([]) }));
        using var missingLength = new S3RangeStream(missingLengthClient, new Uri("http://localhost/object"), Stopwatch.GetTimestamp());
        await Assert.ThrowsAsync<IOException>(() => missingLength.ReadAsync(new byte[4]).AsTask());
        await Assert.That(missingLength.Requests[0].Error).IsEqualTo("S3 HEAD did not return a valid Content-Length.");

        using var failedGetClient = new HttpClient(new ResponseHandler(request => request.Method == HttpMethod.Head
            ? HeadResponse() : throw new HttpRequestException("Connection lost")));
        using var failedGet = new S3RangeStream(failedGetClient, new Uri("http://localhost/object"), Stopwatch.GetTimestamp());
        await Assert.ThrowsAsync<HttpRequestException>(() => failedGet.ReadAsync(new byte[4]).AsTask());
        await Assert.That(failedGet.Requests.Count).IsEqualTo(2);
        await Assert.That(failedGet.Requests[1].StatusCode).IsNull();
        await Assert.That(failedGet.Requests[1].Error).IsEqualTo("Connection lost");
    }

    [Test]
    public async Task RequestTimingIncludesConfiguredLatencyAndCompleteBodyRead()
    {
        await using var fixture = await ObjectFixture.CreateAsync(10, latencyMs: 25);
        using var client = new HttpClient();
        using var stream = new S3RangeStream(client, fixture.Emulator.ObjectUri, Stopwatch.GetTimestamp());
        await Assert.That(await stream.ReadAsync(new byte[4])).IsEqualTo(4);
        await Assert.That(stream.Requests.Count).IsEqualTo(2);
        await Assert.That(stream.Requests.All(request => request.DurationMs >= 10)).IsTrue();

        using var slowClient = new HttpClient(new ResponseHandler(request =>
        {
            if (request.Method == HttpMethod.Head) return HeadResponse();
            var content = new StreamContent(new DelayedReadStream(new byte[4]));
            content.Headers.ContentRange = new ContentRangeHeaderValue(0, 3, 10);
            content.Headers.ContentLength = 4;
            return new HttpResponseMessage(HttpStatusCode.PartialContent) { Content = content };
        }));
        using var slowStream = new S3RangeStream(slowClient, fixture.Emulator.ObjectUri, Stopwatch.GetTimestamp());
        await Assert.That(await slowStream.ReadAsync(new byte[4])).IsEqualTo(4);
        await Assert.That(slowStream.Requests[1].DurationMs >= 25).IsTrue();
        await Assert.That(slowStream.Requests[1].BytesReceived).IsEqualTo(4L);
    }

    private static HttpResponseMessage HeadResponse()
    {
        var response = new HttpResponseMessage(HttpStatusCode.OK) { Content = new ByteArrayContent([]) };
        response.Content.Headers.ContentLength = 10;
        return response;
    }

    private sealed class ResponseHandler(Func<HttpRequestMessage, HttpResponseMessage> respond) : HttpMessageHandler
    {
        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
            => Task.FromResult(respond(request));
    }

    private sealed class DelayedReadStream(byte[] bytes) : MemoryStream(bytes)
    {
        public override async ValueTask<int> ReadAsync(Memory<byte> buffer, CancellationToken cancellationToken = default)
        {
            await Task.Delay(30, cancellationToken);
            return await base.ReadAsync(buffer, cancellationToken);
        }
    }

    private sealed class ObjectFixture(string directory, byte[] bytes, S3Emulator emulator) : IAsyncDisposable
    {
        public byte[] Bytes { get; } = bytes;
        public S3Emulator Emulator { get; } = emulator;

        public static async Task<ObjectFixture> CreateAsync(int length, double latencyMs = 0)
        {
            var directory = Directory.CreateTempSubdirectory("plank-s3-test-").FullName;
            try
            {
                var bytes = Enumerable.Range(0, length).Select(value => (byte)value).ToArray();
                var path = Path.Combine(directory, "object.parquet");
                await File.WriteAllBytesAsync(path, bytes);
                return new ObjectFixture(directory, bytes, await S3Emulator.StartAsync(path, latencyMs));
            }
            catch
            {
                Directory.Delete(directory, recursive: true);
                throw;
            }
        }

        public async ValueTask DisposeAsync()
        {
            await Emulator.DisposeAsync();
            Directory.Delete(directory, recursive: true);
        }
    }
}
