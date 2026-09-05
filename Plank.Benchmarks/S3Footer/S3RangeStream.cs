using System.Buffers;
using System.Diagnostics;
using System.Net;
using System.Net.Http.Headers;

namespace Plank.Benchmarks.S3Footer;

public sealed record S3RequestTrace(int Id, string Method, string? Range, long? StartByte, long? EndByte,
    double StartMs, double DurationMs, int? StatusCode, long BytesReceived, string? Error);

/// <summary>
/// Seekable HTTP object stream: one lazy HEAD for length and one exact GET range per nonempty read.
/// No prefetching, read cache, or application retries. Like FileStream, concurrent seeks/reads are unsupported.
/// The caller owns the HttpClient.
/// </summary>
public sealed class S3RangeStream : Stream
{
    private readonly HttpClient _client;
    private readonly Uri _objectUri;
    private readonly long _startedTimestamp;
    private readonly List<S3RequestTrace> _requests = [];
    private long? _length;
    private long _position;
    private int _nextRequestId;
    private bool _disposed;

    public S3RangeStream(HttpClient client, Uri objectUri, long startedTimestamp)
    {
        ArgumentNullException.ThrowIfNull(client);
        ArgumentNullException.ThrowIfNull(objectUri);
        _client = client;
        _objectUri = objectUri;
        _startedTimestamp = startedTimestamp;
    }

    public IReadOnlyList<S3RequestTrace> Requests => _requests.AsReadOnly();
    public override bool CanRead => !_disposed;
    public override bool CanSeek => !_disposed;
    public override bool CanWrite => false;
    public override long Length => GetLengthAsync(CancellationToken.None).GetAwaiter().GetResult();
    public override long Position
    {
        get { ThrowIfDisposed(); return _position; }
        set
        {
            ThrowIfDisposed();
            ArgumentOutOfRangeException.ThrowIfNegative(value);
            _position = value;
        }
    }

    private async Task<long> GetLengthAsync(CancellationToken cancellationToken)
    {
        ThrowIfDisposed();
        if (_length is { } cached) return cached;

        var id = ++_nextRequestId;
        var start = Stopwatch.GetTimestamp();
        int? status = null;
        string? error = null;
        try
        {
            using var request = new HttpRequestMessage(HttpMethod.Head, _objectUri);
            using var response = await _client.SendAsync(request, HttpCompletionOption.ResponseHeadersRead,
                cancellationToken).ConfigureAwait(false);
            status = (int)response.StatusCode;
            if (response.StatusCode != HttpStatusCode.OK)
                throw new IOException($"S3 HEAD returned HTTP {status}; expected 200.");
            if (!response.Content.Headers.Contains("Content-Length") ||
                response.Content.Headers.ContentLength is not { } length || length < 0)
                throw new IOException("S3 HEAD did not return a valid Content-Length.");
            _length = length;
            return length;
        }
        catch (Exception exception)
        {
            error = exception.Message;
            throw;
        }
        finally
        {
            AddTrace(id, "HEAD", null, null, null, start, status, 0, error);
        }
    }

    public override int Read(byte[] buffer, int offset, int count)
    {
        ValidateBufferArguments(buffer, offset, count);
        return ReadAsync(buffer.AsMemory(offset, count), CancellationToken.None).GetAwaiter().GetResult();
    }

    public override int Read(Span<byte> buffer)
    {
        ThrowIfDisposed();
        if (buffer.IsEmpty) return 0;
        var temporary = ArrayPool<byte>.Shared.Rent(buffer.Length);
        try
        {
            var count = Read(temporary, 0, buffer.Length);
            temporary.AsSpan(0, count).CopyTo(buffer);
            return count;
        }
        finally { ArrayPool<byte>.Shared.Return(temporary); }
    }

    public override int ReadByte()
    {
        Span<byte> value = stackalloc byte[1];
        return Read(value) == 0 ? -1 : value[0];
    }

    public override Task<int> ReadAsync(byte[] buffer, int offset, int count, CancellationToken cancellationToken)
    {
        ValidateBufferArguments(buffer, offset, count);
        return ReadAsync(buffer.AsMemory(offset, count), cancellationToken).AsTask();
    }

    public override async ValueTask<int> ReadAsync(Memory<byte> buffer, CancellationToken cancellationToken = default)
    {
        ThrowIfDisposed();
        cancellationToken.ThrowIfCancellationRequested();
        if (buffer.IsEmpty) return 0;
        var length = await GetLengthAsync(cancellationToken).ConfigureAwait(false);
        if (_position >= length) return 0;

        var count = (int)Math.Min(buffer.Length, length - _position);
        var firstByte = _position;
        var lastByte = firstByte + count - 1;
        var range = new RangeHeaderValue(firstByte, lastByte);
        var id = ++_nextRequestId;
        var start = Stopwatch.GetTimestamp();
        int? status = null;
        long received = 0;
        string? error = null;
        try
        {
            using var request = new HttpRequestMessage(HttpMethod.Get, _objectUri);
            request.Headers.Range = range;
            using var response = await _client.SendAsync(request, HttpCompletionOption.ResponseHeadersRead,
                cancellationToken).ConfigureAwait(false);
            status = (int)response.StatusCode;
            if (response.StatusCode != HttpStatusCode.PartialContent)
                throw new IOException($"S3 range GET returned HTTP {status}; expected 206.");

            var contentRange = response.Content.Headers.ContentRange;
            if (contentRange is null || !string.Equals(contentRange.Unit, "bytes", StringComparison.OrdinalIgnoreCase) ||
                contentRange.From != firstByte || contentRange.To != lastByte || contentRange.Length != length)
                throw new IOException("S3 range GET returned an incorrect Content-Range.");
            if (!response.Content.Headers.Contains("Content-Length") || response.Content.Headers.ContentLength != count)
                throw new IOException("S3 range GET returned an incorrect Content-Length.");

            await using var body = await response.Content.ReadAsStreamAsync(cancellationToken).ConfigureAwait(false);
            while (received < count)
            {
                var read = await body.ReadAsync(buffer.Slice((int)received, count - (int)received),
                    cancellationToken).ConfigureAwait(false);
                if (read == 0) throw new EndOfStreamException("S3 range GET body ended before the requested range was received.");
                received += read;
            }

            var extraByte = new byte[1];
            var extra = await body.ReadAsync(extraByte, cancellationToken).ConfigureAwait(false);
            received += extra;
            if (extra != 0) throw new IOException("S3 range GET body exceeded the requested range.");

            _position += count;
            return count;
        }
        catch (Exception exception)
        {
            error = exception.Message;
            throw;
        }
        finally
        {
            AddTrace(id, "GET", range.ToString(), firstByte, lastByte, start, status, received, error);
        }
    }

    private void AddTrace(int id, string method, string? range, long? firstByte, long? lastByte,
        long start, int? status, long received, string? error)
    {
        _requests.Add(new S3RequestTrace(id, method, range, firstByte, lastByte,
            Stopwatch.GetElapsedTime(_startedTimestamp, start).TotalMilliseconds,
            Stopwatch.GetElapsedTime(start).TotalMilliseconds, status, received, error));
    }

    public override long Seek(long offset, SeekOrigin origin)
    {
        ThrowIfDisposed();
        long position;
        try
        {
            position = origin switch
            {
                SeekOrigin.Begin => offset,
                SeekOrigin.Current => checked(_position + offset),
                SeekOrigin.End => checked(Length + offset),
                _ => throw new ArgumentOutOfRangeException(nameof(origin))
            };
        }
        catch (OverflowException exception)
        {
            throw new IOException("Cannot seek outside the stream's position range.", exception);
        }
        if (position < 0) throw new IOException("Cannot seek before the beginning of the stream.");
        return _position = position;
    }

    public override void Flush() => ThrowIfDisposed();
    public override void SetLength(long value) => throw new NotSupportedException("The S3 object is read-only.");
    public override void Write(byte[] buffer, int offset, int count) => throw new NotSupportedException("The S3 object is read-only.");
    protected override void Dispose(bool disposing) { _disposed = true; base.Dispose(disposing); }
    private void ThrowIfDisposed() => ObjectDisposedException.ThrowIf(_disposed, this);
}
