using System.Text;
using Plank.Reading;
using Plank.Writing;

namespace Plank.Fuzzing.Scale;

/// <summary>Random scheduling noise for sources, streams and worker callbacks.</summary>
public static class Jitter
{
    [ThreadStatic] static Rng? t_rng;
    public static int Percent; // probability of a pause per call

    public static void Maybe()
    {
        if (Percent == 0)
            return;
        var rng = t_rng ??= new Rng((ulong)Environment.CurrentManagedThreadId * 0x9E3779B97F4A7C15UL ^ (ulong)Environment.TickCount64);
        if (!rng.Chance(Percent))
            return;
        switch (rng.Int(16))
        {
            case < 6: Thread.Yield(); break;
            case < 10: Thread.Sleep(0); break;
            case 10: Thread.Sleep(1); break;
            default: Thread.SpinWait(rng.Int(5_000)); break;
        }
    }
}

/// <summary>A custom read source (so the row reader wraps it in its synchronized adapter), with jitter.</summary>
public sealed class JitterSource(byte[] bytes) : IParquetReadSource
{
    public void Dispose() { }

    public ulong Length { get { Jitter.Maybe(); return (ulong)bytes.Length; } }

    public void ReadExactly(ulong offset, Span<byte> destination)
    {
        Jitter.Maybe();
        if (offset > (ulong)bytes.Length || (ulong)destination.Length > (ulong)bytes.Length - offset)
            throw new EndOfStreamException($"read [{offset},+{destination.Length}) past {bytes.Length}");
        // Copy in two halves with a pause in between to widen any race on the destination.
        var half = destination.Length / 2;
        bytes.AsSpan((int)offset, half).CopyTo(destination);
        Jitter.Maybe();
        bytes.AsSpan((int)offset + half, destination.Length - half).CopyTo(destination[half..]);
    }
}

/// <summary>A seekable read-only stream over bytes with jitter, wrapped by Plank's StreamReadSource.</summary>
public sealed class JitterStream(byte[] bytes) : MemoryStream(bytes, writable: false)
{
    public override int Read(Span<byte> buffer) { Jitter.Maybe(); return base.Read(buffer); }
    public override int Read(byte[] buffer, int offset, int count) { Jitter.Maybe(); return base.Read(buffer, offset, count); }
    public override long Seek(long offset, SeekOrigin loc) { Jitter.Maybe(); return base.Seek(offset, loc); }
}

/// <summary>Write-only stream that jitters and optionally splits writes; a writer sink.</summary>
public sealed class JitterWriteStream(Stream inner) : Stream
{
    public override bool CanRead => false;
    public override bool CanSeek => inner.CanSeek;
    public override bool CanWrite => true;
    public override long Length => inner.Length;
    public override long Position { get => inner.Position; set => inner.Position = value; }
    public override void Flush() { Jitter.Maybe(); inner.Flush(); }
    public override int Read(byte[] buffer, int offset, int count) => throw new NotSupportedException();
    public override long Seek(long offset, SeekOrigin origin) => inner.Seek(offset, origin);
    public override void SetLength(long value) => inner.SetLength(value);
    public override void Write(byte[] buffer, int offset, int count) => Write(buffer.AsSpan(offset, count));
    public override void Write(ReadOnlySpan<byte> buffer) { Jitter.Maybe(); inner.Write(buffer); }
}

/// <summary>In-memory dataset files (IParquetReadWriteSource), shared by path.</summary>
public sealed class MemFiles
{
    public readonly Dictionary<string, MemoryStream> Files = new(StringComparer.Ordinal);
    public int Opens;

    public sealed class Source(MemFiles owner) : IParquetReadWriteSource
    {
        MemoryStream? _file;
        MemoryStream File => _file ?? throw new InvalidOperationException("not open");
        public ulong Length => (ulong)File.Length;

        public void Open(ReadOnlySpan<byte> path, FileMode mode)
        {
            if (_file is not null)
                throw new InvalidOperationException("source reused while open");
            var key = Encoding.UTF8.GetString(path);
            lock (owner.Files)
            {
                owner.Opens++;
                if (!owner.Files.TryGetValue(key, out var stream))
                {
                    if (mode == FileMode.Open)
                        throw new FileNotFoundException(key);
                    owner.Files[key] = stream = new MemoryStream();
                }
                else if (mode is FileMode.CreateNew)
                    throw new IOException("exists: " + key);
                else if (mode is FileMode.Create or FileMode.Truncate)
                    stream.SetLength(0);
                _file = stream;
            }
        }

        public void ReadExactly(ulong offset, Span<byte> destination)
        {
            Jitter.Maybe();
            File.Position = checked((long)offset);
            File.ReadExactly(destination);
        }

        public void Write(ulong offset, ReadOnlySpan<byte> source)
        {
            Jitter.Maybe();
            File.Position = checked((long)offset);
            File.Write(source);
        }

        public void SetLength(ulong length) => File.SetLength(checked((long)length));
        public void Flush() { }
        public void Close() => _file = null;
        public void Dispose() => Close();
    }
}

/// <summary>Native buffers with a return callback: counts what is still rented, to find buffers never returned.</summary>
public sealed class CountingPool : IParquetBufferPool
{
    const int PayloadOffset = 64;
    long _outstanding, _outstandingBytes, _rented;
    readonly System.Collections.Concurrent.ConcurrentDictionary<nint, (int Length, string? Stack)> _live = new();
    public bool CaptureStacks;

    public long Outstanding => Interlocked.Read(ref _outstanding);
    public long OutstandingBytes => Interlocked.Read(ref _outstandingBytes);
    public long Rented => Interlocked.Read(ref _rented);

    public ParquetBuffer Rent(uint minimumByteLength)
    {
        if (minimumByteLength == 0)
            return default;
        var length = checked((int)minimumByteLength);
        var allocation = System.Runtime.InteropServices.Marshal.AllocHGlobal(PayloadOffset + length);
        Interlocked.Increment(ref _outstanding);
        Interlocked.Increment(ref _rented);
        Interlocked.Add(ref _outstandingBytes, length);
        _live[allocation] = (length, CaptureStacks ? Environment.StackTrace : null);
        return ParquetBuffer.Create(allocation, PayloadOffset + length, PayloadOffset, length, Return);
    }

    void Return(nint allocation)
    {
        if (!_live.TryRemove(allocation, out var entry))
            throw new InvalidOperationException("CountingPool: buffer returned twice or unknown");
        Interlocked.Decrement(ref _outstanding);
        Interlocked.Add(ref _outstandingBytes, -entry.Length);
        System.Runtime.InteropServices.Marshal.FreeHGlobal(allocation);
    }

    public string Describe(int max = 5)
        => string.Join("\n---\n", _live.Values.Take(max).Select(v => $"{v.Length} bytes\n{v.Stack}"));
}
