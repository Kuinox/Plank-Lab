using System.Buffers.Binary;
using System.Net;
using System.Net.Http.Headers;
using System.Security.Cryptography;

namespace Plank.Benchmarks.S3Footer;

/// <summary>
/// A full local file, or a sparse object retaining the real taxi footer at its original offset.
/// Metadata-only objects contain zero-filled data pages and must never be used to benchmark row reads.
/// </summary>
internal sealed class TaxiFooterFixture : IDisposable
{
    internal const string DefaultSourceUrl =
        "https://d37ci6vzurychx.cloudfront.net/trip-data/yellow_tripdata_2024-01.parquet";
    internal const string DefaultName = "yellow_tripdata_2024-01.parquet";

    readonly bool _ownsFile;
    bool _disposed;

    TaxiFooterFixture(string path, string name, string? sourceUrl, bool ownsFile)
    {
        FilePath = Path.GetFullPath(path);
        Name = name;
        SourceUrl = sourceUrl;
        _ownsFile = ownsFile;
        Mode = ownsFile ? "metadata-only" : "full-file";

        using var file = File.OpenRead(FilePath);
        FileSizeBytes = file.Length;
        if (FileSizeBytes < 12)
            throw new InvalidDataException("A Parquet fixture must contain at least 12 bytes.");
        Span<byte> header = stackalloc byte[4];
        file.ReadExactly(header);
        if (!header.SequenceEqual("PAR1"u8))
            throw new InvalidDataException("The fixture does not start with PAR1.");
        Span<byte> trailer = stackalloc byte[8];
        file.Position = FileSizeBytes - trailer.Length;
        file.ReadExactly(trailer);
        FooterLengthBytes = ValidateTrailer(trailer, FileSizeBytes);
        FooterOffset = FileSizeBytes - 8 - FooterLengthBytes;

        file.Position = FooterOffset;
        using var hash = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
        var buffer = new byte[Math.Min(FooterLengthBytes, 64 * 1024)];
        var remaining = FooterLengthBytes;
        while (remaining > 0)
        {
            var count = Math.Min(remaining, buffer.Length);
            file.ReadExactly(buffer.AsSpan(0, count));
            hash.AppendData(buffer.AsSpan(0, count));
            remaining -= count;
        }
        FooterSha256 = Convert.ToHexStringLower(hash.GetHashAndReset());
    }

    public string FilePath { get; }
    public string Name { get; }
    public string? SourceUrl { get; }
    public string Mode { get; }
    public long FileSizeBytes { get; }
    public long FooterOffset { get; }
    public int FooterLengthBytes { get; }
    public string FooterSha256 { get; }

    internal static async Task<TaxiFooterFixture> PrepareAsync(string? dataFile,
        CancellationToken ct = default)
    {
        ct.ThrowIfCancellationRequested();
        var localPath = dataFile is null ? DefaultLocalPath() : Path.GetFullPath(dataFile);
        if (dataFile is not null || File.Exists(localPath))
            return new TaxiFooterFixture(localPath, Path.GetFileName(localPath), null, ownsFile: false);

        using var client = new HttpClient { Timeout = TimeSpan.FromMinutes(2) };
        return await PrepareRemoteAsync(client, DefaultSourceUrl, ct).ConfigureAwait(false);
    }

    // The injected client keeps tests independent of network access and the public taxi endpoint.
    internal static async Task<TaxiFooterFixture> PrepareRemoteAsync(HttpClient client,
        string sourceUrl = DefaultSourceUrl, CancellationToken ct = default)
    {
        ArgumentNullException.ThrowIfNull(client);
        using var trailerRequest = new HttpRequestMessage(HttpMethod.Get, sourceUrl);
        trailerRequest.Headers.Range = new RangeHeaderValue(null, 8);
        using var trailerResponse = await client.SendAsync(trailerRequest,
            HttpCompletionOption.ResponseHeadersRead, ct).ConfigureAwait(false);
        var fileSize = trailerResponse.Content.Headers.ContentRange?.Length
            ?? throw new InvalidDataException("The taxi endpoint did not report its object size in Content-Range.");
        if (fileSize < 12)
            throw new InvalidDataException("The taxi object is too small to contain a Parquet footer.");
        ValidateRangeResponse(trailerResponse, fileSize - 8, fileSize - 1, fileSize);
        var trailer = new byte[8];
        await using (var source = await trailerResponse.Content.ReadAsStreamAsync(ct).ConfigureAwait(false))
        {
            await ReadExactlyAsync(source, trailer, ct).ConfigureAwait(false);
            await EnsureEndAsync(source, ct).ConfigureAwait(false);
        }
        var footerLength = ValidateTrailer(trailer, fileSize);
        var footerOffset = fileSize - 8 - footerLength;

        using var footerRequest = new HttpRequestMessage(HttpMethod.Get, sourceUrl);
        footerRequest.Headers.Range = new RangeHeaderValue(footerOffset, fileSize - 9);
        if (trailerResponse.Headers.ETag is { IsWeak: false } etag)
            footerRequest.Headers.IfMatch.Add(etag);
        else if (trailerResponse.Content.Headers.LastModified is { } lastModified)
            footerRequest.Headers.IfUnmodifiedSince = lastModified;
        using var footerResponse = await client.SendAsync(footerRequest,
            HttpCompletionOption.ResponseHeadersRead, ct).ConfigureAwait(false);
        ValidateRangeResponse(footerResponse, footerOffset, fileSize - 9, fileSize);
        if (trailerResponse.Headers.ETag is { } originalTag &&
            footerResponse.Headers.ETag is { } footerTag && !originalTag.Equals(footerTag))
            throw new InvalidDataException("The taxi object changed between its trailer and footer requests.");

        var path = Path.Combine(Path.GetTempPath(), $"plank-taxi-footer-{Guid.NewGuid():N}.parquet");
        try
        {
            await using (var output = new FileStream(path, FileMode.CreateNew, FileAccess.Write,
                             FileShare.None, 64 * 1024, FileOptions.Asynchronous))
            {
                // SetLength leaves an unwritten hole: offsets and GET byte counts still match the full object.
                output.SetLength(fileSize);
                await output.WriteAsync("PAR1"u8.ToArray(), ct).ConfigureAwait(false);
                output.Position = footerOffset;
                await using var source = await footerResponse.Content.ReadAsStreamAsync(ct).ConfigureAwait(false);
                var buffer = new byte[Math.Min(footerLength, 64 * 1024)];
                var remaining = footerLength;
                while (remaining > 0)
                {
                    var count = Math.Min(remaining, buffer.Length);
                    await ReadExactlyAsync(source, buffer.AsMemory(0, count), ct).ConfigureAwait(false);
                    await output.WriteAsync(buffer.AsMemory(0, count), ct).ConfigureAwait(false);
                    remaining -= count;
                }
                await EnsureEndAsync(source, ct).ConfigureAwait(false);
                await output.WriteAsync(trailer, ct).ConfigureAwait(false);
            }
            return new TaxiFooterFixture(path, DefaultName, sourceUrl, ownsFile: true);
        }
        catch
        {
            File.Delete(path);
            throw;
        }
    }

    public void Dispose()
    {
        if (_disposed) return;
        _disposed = true;
        if (_ownsFile) File.Delete(FilePath);
    }

    static string DefaultLocalPath()
    {
        for (var directory = new DirectoryInfo(Environment.CurrentDirectory); directory is not null;
             directory = directory.Parent)
        {
            var candidate = Path.Combine(directory.FullName, "Plank.Benchmarks", "nyc-data", DefaultName);
            if (File.Exists(candidate)) return candidate;
        }
        return Path.GetFullPath(Path.Combine(AppContext.BaseDirectory, "..", "..", "..", "nyc-data", DefaultName));
    }

    static int ValidateTrailer(ReadOnlySpan<byte> trailer, long fileSize)
    {
        if (!trailer[4..].SequenceEqual("PAR1"u8))
            throw new InvalidDataException("The fixture does not end with the PAR1 footer marker.");
        var footerLength = BinaryPrimitives.ReadUInt32LittleEndian(trailer);
        if (footerLength == 0 || footerLength > int.MaxValue || footerLength > fileSize - 12)
            throw new InvalidDataException("The Parquet footer length is invalid for this object size.");
        return (int)footerLength;
    }

    static void ValidateRangeResponse(HttpResponseMessage response, long start, long end, long total)
    {
        if (response.StatusCode != HttpStatusCode.PartialContent)
            throw new InvalidDataException($"Expected HTTP 206 for the taxi range request; got {(int)response.StatusCode}.");
        var range = response.Content.Headers.ContentRange;
        if (range is null || !range.Unit.Equals("bytes", StringComparison.OrdinalIgnoreCase) ||
            range.From != start || range.To != end || range.Length != total)
            throw new InvalidDataException("The taxi endpoint returned an unexpected Content-Range.");
        if (response.Content.Headers.ContentLength is { } length && length != end - start + 1)
            throw new InvalidDataException("The taxi endpoint returned an unexpected Content-Length.");
        if (response.Content.Headers.ContentEncoding.Count != 0)
            throw new InvalidDataException("Encoded HTTP responses cannot preserve Parquet byte ranges.");
    }

    static async Task ReadExactlyAsync(Stream stream, Memory<byte> destination, CancellationToken ct)
    {
        try { await stream.ReadExactlyAsync(destination, ct).ConfigureAwait(false); }
        catch (EndOfStreamException exception)
        {
            throw new InvalidDataException("The taxi endpoint returned a truncated range body.", exception);
        }
    }

    static async Task EnsureEndAsync(Stream stream, CancellationToken ct)
    {
        if (await stream.ReadAsync(new byte[1], ct).ConfigureAwait(false) != 0)
            throw new InvalidDataException("The taxi endpoint returned more bytes than its requested range.");
    }
}
