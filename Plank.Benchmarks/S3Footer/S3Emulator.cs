using System.Buffers;
using System.Globalization;
using System.Net;
using System.Net.Http.Headers;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Logging;

namespace Plank.Benchmarks.S3Footer;

/// <summary>A read-only, local S3 object endpoint supporting HEAD and single-range GET.</summary>
public sealed class S3Emulator : IAsyncDisposable
{
    private const string ObjectPath = "/benchmark/taxi.parquet";
    private readonly WebApplication _application;

    private S3Emulator(WebApplication application, Uri objectUri)
    {
        _application = application;
        ObjectUri = objectUri;
    }

    public Uri ObjectUri { get; }

    public static async Task<S3Emulator> StartAsync(string filePath, double latencyMs = 0)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(filePath);
        if (!double.IsFinite(latencyMs) || latencyMs < 0 || latencyMs > int.MaxValue)
            throw new ArgumentOutOfRangeException(nameof(latencyMs));

        var path = Path.GetFullPath(filePath);
        // Verify readability now, without materializing the potentially sparse object.
        long objectLength;
        using (var source = File.OpenRead(path)) objectLength = source.Length;

        var builder = WebApplication.CreateSlimBuilder(new WebApplicationOptions { Args = [] });
        builder.Logging.ClearProviders();
        builder.WebHost.ConfigureKestrel(options => options.Listen(IPAddress.Loopback, 0));
        var application = builder.Build();
        application.Run(context => ServeAsync(context, path, objectLength, latencyMs));
        try
        {
            await application.StartAsync().ConfigureAwait(false);
            return new S3Emulator(application, new Uri(new Uri(application.Urls.Single()), ObjectPath));
        }
        catch
        {
            await application.DisposeAsync().ConfigureAwait(false);
            throw;
        }
    }

    private static async Task ServeAsync(HttpContext context, string path, long length, double latencyMs)
    {
        var response = context.Response;
        if (latencyMs > 0)
            await Task.Delay(TimeSpan.FromMilliseconds(latencyMs), context.RequestAborted).ConfigureAwait(false);

        if (context.Request.Path != ObjectPath)
        {
            response.StatusCode = StatusCodes.Status404NotFound;
            response.ContentLength = 0;
            return;
        }

        if (!HttpMethods.IsHead(context.Request.Method) && !HttpMethods.IsGet(context.Request.Method))
        {
            response.StatusCode = StatusCodes.Status405MethodNotAllowed;
            response.Headers.Allow = "GET, HEAD";
            response.ContentLength = 0;
            return;
        }

        response.Headers.AcceptRanges = "bytes";
        response.ContentType = "application/vnd.apache.parquet";
        if (HttpMethods.IsHead(context.Request.Method))
        {
            // HTTP range semantics apply to GET; HEAD advertises the entire object and no body.
            response.ContentLength = length;
            return;
        }

        long start = 0;
        long end = length - 1;
        if (context.Request.Headers.TryGetValue("Range", out var range))
        {
            if (!TryResolveRange(range.ToString(), length, out start, out end))
            {
                response.StatusCode = StatusCodes.Status416RangeNotSatisfiable;
                response.Headers.ContentRange = $"bytes */{length.ToString(CultureInfo.InvariantCulture)}";
                response.ContentLength = 0;
                return;
            }

            response.StatusCode = StatusCodes.Status206PartialContent;
            response.Headers.ContentRange = FormattableString.Invariant($"bytes {start}-{end}/{length}");
        }

        var remaining = end - start + 1;
        response.ContentLength = remaining;
        if (remaining == 0) return;

        await using var source = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.Read,
            bufferSize: 1, FileOptions.Asynchronous | FileOptions.RandomAccess);
        source.Position = start;
        var buffer = ArrayPool<byte>.Shared.Rent(64 * 1024);
        try
        {
            while (remaining > 0)
            {
                var count = await source.ReadAsync(buffer.AsMemory(0, (int)Math.Min(buffer.Length, remaining)),
                    context.RequestAborted).ConfigureAwait(false);
                if (count == 0) throw new EndOfStreamException("The S3 object changed while being served.");
                await response.Body.WriteAsync(buffer.AsMemory(0, count), context.RequestAborted).ConfigureAwait(false);
                remaining -= count;
            }
        }
        finally
        {
            ArrayPool<byte>.Shared.Return(buffer);
        }
    }

    private static bool TryResolveRange(string value, long length, out long start, out long end)
    {
        start = 0;
        end = length - 1;
        if (length == 0 || !RangeHeaderValue.TryParse(value, out var header) ||
            !string.Equals(header.Unit, "bytes", StringComparison.OrdinalIgnoreCase) || header.Ranges.Count != 1)
            return false;

        var item = header.Ranges.Single();
        if (item.From is { } from)
        {
            if (from >= length) return false;
            start = from;
            end = Math.Min(item.To ?? end, end);
            return end >= start;
        }

        if (item.To is not { } suffixLength || suffixLength <= 0) return false;
        start = Math.Max(0, length - suffixLength);
        return true;
    }

    public async ValueTask DisposeAsync()
    {
        await _application.StopAsync().ConfigureAwait(false);
        await _application.DisposeAsync().ConfigureAwait(false);
    }
}
