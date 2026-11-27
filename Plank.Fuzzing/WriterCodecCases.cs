using System.Buffers.Binary;
using System.IO.Compression;
using Plank.Reading;
using Plank.Reading.Physical;
using PlankPhysicalReader = Plank.Reading.Physical.ParquetFileReader;
using Plank.Schema;
using Plank.Writing;
using PlankCompression = Plank.Writing.Compression.Compression;
using PlankSchema = Plank.Schema.ParquetSchema;

namespace Plank.Fuzzing;

/// <summary>
/// Route 0xDB "WCD1": every codec Plank writes, fed fuzzer-chosen raw buffers, decoded by INDEPENDENT decoders.
/// </summary>
/// <remarks>
/// Two paths. (1) Direct: the internal compressor (<c>Compression.Compress</c>) gets a source <c>BufferWriter</c>
/// filled in random pieces with a random chunk size (so the contiguous-scratch path and the single-span path are
/// both taken) and writes into a destination <c>BufferWriter</c> with its own chunk size. The bytes are decoded by
/// reference decoders written here (LZ4 block, Snappy), by System.IO.Compression (gzip, brotli), by ZstdSharp's
/// high-level decompressor, and by Plank's own <c>ParquetDecompressor</c>; declared sizes (snappy preamble, zstd
/// frame content size, gzip trailer CRC / ISIZE) and the writer's <c>ComputeCrc32</c> are checked too.
/// (2) Real pages: a file with a binary column whose values are slices of the buffer, written with the codec,
/// level, page size, page version and CRC option drawn from the input; every page payload is decoded
/// independently and compared with Plank's decompressor, header sizes and CRC are checked, and ParquetSharp (Arrow's
/// codecs) must read the same values back.
/// </remarks>
internal static partial class WriterCodecCases
{
    sealed class Cur(ReadOnlySpan<byte> data)
    {
        readonly byte[] _d = data.ToArray();
        int _i;

        public byte Byte() => _d.Length == 0 ? (byte)0 : _d[_i++ % _d.Length];

        public int Int(int min, int maxExclusive)
        {
            uint v = Byte();
            v |= (uint)Byte() << 8;
            v |= (uint)Byte() << 16;
            v |= (uint)Byte() << 24;
            return min + (int)(v % (uint)(maxExclusive - min));
        }

        public T Pick<T>(params T[] choices) => choices[Int(0, choices.Length)];
    }

    internal static void Execute(ReadOnlySpan<byte> input)
    {
        var c = new Cur(input);
        // The first four bytes pin what the input does, so a seed can ask for an LZ4 sweep or a frame directly:
        // 0-2 general rounds, 3 every LZ4 level on one boundary-size buffer, 4 LZ4 levels 10-12 on a large repetitive
        // buffer, 5 LZ4 frame / Hadoop / raw inputs for the decoder.
        switch (c.Int(0, 6))
        {
            case 3:
                Lz4LevelSweep(c);
                return;
            case 4:
                Lz4LargeRepetitive(c);
                return;
            case 5:
                Lz4DecoderInputs(c);
                return;
        }

        var rounds = c.Int(1, 4);
        for (var i = 0; i < rounds; i++)
        {
            var (kind, level) = DrawCodec(c);
            var data = DrawData(c, out var label, maxSize: c.Int(0, 8) == 0 ? (4 << 20) + 1 : (1 << 20) + 1);
            Direct(c, kind, level, data, $"{kind}/L{level} {label}");
            // Real pages cost more per byte (several writers and readers): bounded payload.
            var pageData = data.Length > 600_000 ? data[..600_000] : data;
            Pages(c, kind, level, pageData, $"pages {kind}/L{level} {label}");
        }
    }

    // ---- inputs ------------------------------------------------------------------------------------------

    static (CompressionKind Kind, int Level) DrawCodec(Cur c)
    {
        var kind = c.Pick(CompressionKind.Snappy, CompressionKind.Gzip, CompressionKind.Zstd, CompressionKind.Lz4,
            CompressionKind.Brotli, CompressionKind.None);
        var level = kind switch
        {
            CompressionKind.Gzip => c.Int(0, 10),
            CompressionKind.Zstd => c.Pick(ZstdSharp.Compressor.MinCompressionLevel, -5, -1, 0, 1, 2, 3, 5, 9, 15, 19, 20,
                ZstdSharp.Compressor.MaxCompressionLevel),
            CompressionKind.Lz4 => c.Pick(0, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12),
            CompressionKind.Brotli => c.Int(0, 12),
            _ => 0
        };
        return (kind, level);
    }

    // Sizes around the points where codecs change behaviour: 0/1, token and literal-length escapes (15, 255),
    // the 64 KiB LZ4 / snappy window, the 128 KiB zstd block, 1 MiB and 4 MiB.
    static readonly int[] BoundarySizes =
    [
        0, 1, 2, 3, 4, 5, 11, 12, 13, 14, 15, 16, 17, 31, 32, 33, 59, 60, 61, 63, 64, 65, 127, 128, 129, 255, 256, 257,
        4095, 4096, 4097, 65_534, 65_535, 65_536, 65_537, 65_540, 131_071, 131_072, 131_073, 262_144, 1_048_575,
        1_048_576, 1_048_577, 4_194_303, 4_194_304
    ];

    static byte[] DrawData(Cur c, out string label, int maxSize, int? forcedSize = null, int? forcedPattern = null)
    {
        var size = forcedSize ?? (c.Int(0, 3) == 0 ? c.Int(0, 70_000) : c.Pick(BoundarySizes));
        size = Math.Min(size, maxSize);
        var pattern = forcedPattern ?? c.Int(0, 10);
        var seed = (uint)c.Int(1, int.MaxValue);
        var data = new byte[size];
        var state = seed | 1;
        byte Next()
        {
            state ^= state << 13;
            state ^= state >> 17;
            state ^= state << 5;
            return (byte)(state >> 7);
        }

        switch (pattern)
        {
            case 0: // zeros
                break;
            case 1:
                data.AsSpan().Fill(0xFF);
                break;
            case 2: // incompressible
                for (var i = 0; i < size; i++)
                    data[i] = Next();
                break;
            case 3: // short repeating pattern
            {
                var length = c.Int(1, 301);
                var unit = new byte[length];
                for (var i = 0; i < length; i++)
                    unit[i] = Next();
                for (var i = 0; i < size; i++)
                    data[i] = unit[i % length];
                break;
            }
            case 4: // text-like
            {
                string[] words = ["parquet", "plank", "column", "row", "group", "page", "null", "value", "the", "of", "0123456789"];
                var position = 0;
                while (position < size)
                {
                    var word = System.Text.Encoding.ASCII.GetBytes(words[Next() % words.Length] + " ");
                    var take = Math.Min(word.Length, size - position);
                    word.AsSpan(0, take).CopyTo(data.AsSpan(position));
                    position += take;
                }

                break;
            }
            case 5: // back-references at window-edge distances, with overlap, between random literals
            {
                int[] distances = [1, 2, 3, 4, 7, 8, 255, 256, 257, 4095, 4096, 65_535, 65_536, 65_537];
                var position = 0;
                while (position < size)
                {
                    var literals = Math.Min(Next() % 40, size - position);
                    for (var i = 0; i < literals; i++)
                        data[position++] = Next();
                    if (position >= size)
                        break;
                    var distance = distances[Next() % distances.Length];
                    var length = Math.Min(4 + (Next() | (Next() << 8)) % 600, size - position);
                    if (distance > position)
                        distance = Math.Max(1, position);
                    if (position == 0)
                    {
                        data[position++] = Next();
                        continue;
                    }

                    for (var i = 0; i < length; i++, position++)
                        data[position] = data[position - distance];
                }

                break;
            }
            case 6: // half random, half zeros
                for (var i = 0; i < size / 2; i++)
                    data[i] = Next();
                break;
            case 7: // incrementing bytes
                for (var i = 0; i < size; i++)
                    data[i] = (byte)i;
                break;
            case 8: // ascending 32-bit integers (delta-friendly)
                for (var i = 0; i + 3 < size; i += 4)
                    BinaryPrimitives.WriteInt32LittleEndian(data.AsSpan(i), i / 4 * 3);
                break;
            default: // random bytes drawn from a tiny alphabet
                for (var i = 0; i < size; i++)
                    data[i] = (byte)(Next() % 3);
                break;
        }

        label = $"size={size} pattern={pattern}";
        return data;
    }

    // ---- direct compressor ---------------------------------------------------------------------------------

    static void Direct(Cur c, CompressionKind kind, int level, byte[] data, string what)
    {
        using var pool = WriterFuzzPool.Create((WriterPoolKind)c.Int(0, 7));
        var sourceChunk = c.Pick(64u, 1000u, 4096u, 65_536u, (uint)Math.Max(1, data.Length), (uint)data.Length + 1);
        var destinationChunk = c.Pick(1u, 64u, 4096u, 65_536u, 1u << 22);
        var factory = new BufferWriterFactory(pool, c.Pick(64u, 4096u, 65_536u), c.Pick(1u, 4096u, 65_536u),
            c.Pick(1u, 4096u), 1024);
        using var context = new CompressionContext(factory);
        var source = new BufferWriter(pool, sourceChunk, c.Pick(1u, 64u, 65_536u));
        var destination = new BufferWriter(pool, destinationChunk, c.Pick(1u, 64u, 65_536u));
        byte[] compressed;
        uint writerCrc;
        try
        {
            var position = 0;
            var maxPiece = c.Pick(1, 17, 4096, 70_000, int.MaxValue);
            while (position < data.Length)
            {
                var take = Math.Min(c.Int(1, 1 + Math.Min(maxPiece, 1 << 20)), data.Length - position);
                data.AsSpan(position, take).CopyTo(source.GetSpan(take));
                source.Advance(take);
                position += take;
            }

            if (source.WrittenLength != data.Length)
                throw new InvalidOperationException($"{what}: source buffer holds {source.WrittenLength} bytes, expected {data.Length}.");
            try
            {
                PlankCompression.Compress(kind, level, context, ref source, ref destination);
            }
            catch (InvalidOperationException error) when (kind == CompressionKind.Lz4 && data.Length == 0
                && error.Message == "LZ4 compression failed.")
            {
                // Observation (see FINDINGS): the LZ4 compressor rejects an EMPTY buffer while every other codec
                // emits a valid empty stream. Whether a real write can reach it is checked by the page path.
                RouteEvidence.Hit("codec.direct.Lz4.empty-input-rejected");
                return;
            }
            catch (InvalidOperationException error)
            {
                throw new InvalidOperationException($"{what}: compressor failed: {error.Message}", error);
            }
            compressed = new byte[destination.WrittenLength];
            destination.CopyTo(compressed);
            writerCrc = destination.ComputeCrc32();
        }
        finally
        {
            source.Dispose();
            destination.Dispose();
        }

        RouteEvidence.Hit($"codec.direct.{kind}.compressed");
        if (writerCrc != Crc32(compressed))
            throw new InvalidOperationException($"{what}: BufferWriter.ComputeCrc32 {writerCrc:x8} != CRC-32 of its bytes {Crc32(compressed):x8}.");
        if (kind == CompressionKind.None)
        {
            if (!compressed.AsSpan().SequenceEqual(data))
                throw new InvalidOperationException($"{what}: uncompressed output differs from the input.");
            return;
        }

        CheckDeclaredSizes(what, kind, compressed, data);
        var independent = IndependentDecode(kind, compressed, data.Length, what);
        if (!independent.AsSpan().SequenceEqual(data))
            throw new InvalidOperationException($"{what}: the independent decoder returned different bytes (compressed {compressed.Length}).");
        RouteEvidence.Hit($"codec.direct.{kind}.independent-ok");

        var own = new byte[data.Length];
        ParquetDecompressor.DecompressInto(compressed, kind, own);
        if (!own.AsSpan().SequenceEqual(data))
            throw new InvalidOperationException($"{what}: Plank's own decompressor returned different bytes.");
        RouteEvidence.Hit($"codec.direct.{kind}.plank-ok");

        if (kind == CompressionKind.Lz4)
            CheckHadoopFraming(what, compressed, data);
        Corrupt(c, kind, compressed, data.Length, what);
    }

    // Plank's decompressors get damaged copies of what the compressors just produced. The only acceptable outcomes
    // are decoded bytes or CorruptParquetException: any other exception type escaping a decoder (an out-of-range
    // index, an invalid-operation from a codec library, an overflow) is a bug in the read path.
    static void Corrupt(Cur c, CompressionKind kind, byte[] compressed, int expectedLength, string what)
    {
        if (compressed.Length == 0)
            return;
        for (var round = 0; round < 3; round++)
        {
            var damaged = (byte[])compressed.Clone();
            var how = c.Int(0, 5);
            switch (how)
            {
                case 0: // flip 1-4 bytes
                    for (var i = c.Int(1, 5); i > 0; i--)
                        damaged[c.Int(0, damaged.Length)] ^= (byte)c.Int(1, 256);
                    break;
                case 1: // truncate
                    damaged = damaged[..c.Int(0, damaged.Length)];
                    break;
                case 2: // append garbage
                    damaged = damaged.Concat(Enumerable.Range(0, c.Int(1, 40)).Select(_ => c.Byte())).ToArray();
                    break;
                case 3: // overwrite a run with 0xFF / 0x00 (length and offset escapes)
                {
                    var start = c.Int(0, damaged.Length);
                    var length = Math.Min(c.Int(1, 9), damaged.Length - start);
                    damaged.AsSpan(start, length).Fill(c.Int(0, 2) == 0 ? (byte)0xFF : (byte)0);
                    break;
                }
                default: // damage the head (frame / preamble / header bytes)
                    damaged[c.Int(0, Math.Min(damaged.Length, 12))] ^= (byte)c.Int(1, 256);
                    break;
            }

            // The page declares its uncompressed size, so the destination is the declared one (sometimes wrong).
            var declared = Math.Max(0, expectedLength + c.Pick(0, 0, 0, 1, -1, 4096));
            var destination = new byte[declared];
            try
            {
                ParquetDecompressor.DecompressInto(damaged, kind, destination);
                RouteEvidence.Hit($"codec.corrupt.{kind}.decoded");
            }
            catch (CorruptParquetException)
            {
                RouteEvidence.Hit($"codec.corrupt.{kind}.rejected");
            }
            catch (Exception error)
            {
                throw new InvalidOperationException(
                    $"{what}: decompressing a damaged {kind} payload (variant {how}, {damaged.Length} bytes, declared {declared}) threw {error.GetType().Name}: {error.Message}", error);
            }
        }
    }

    // Plank reads LZ4 pages written as Hadoop frames (BE uncompressed size, BE compressed size, block) by other
    // writers. It does not write them, so the frame is built here around Plank's own LZ4 block.
    static void CheckHadoopFraming(string what, byte[] block, byte[] data)
    {
        if (data.Length == 0)
            return;
        var frame = new byte[8 + block.Length];
        BinaryPrimitives.WriteInt32BigEndian(frame, data.Length);
        BinaryPrimitives.WriteInt32BigEndian(frame.AsSpan(4), block.Length);
        block.CopyTo(frame, 8);
        var destination = new byte[data.Length];
        ParquetDecompressor.DecompressInto(frame, CompressionKind.Lz4Legacy, destination);
        if (!destination.AsSpan().SequenceEqual(data))
            throw new InvalidOperationException($"{what}: the Hadoop-framed LZ4 block decoded to different bytes.");
        RouteEvidence.Hit("codec.direct.Lz4.hadoop-frame-ok");
    }

    static void CheckDeclaredSizes(string what, CompressionKind kind, byte[] compressed, byte[] data)
    {
        switch (kind)
        {
            case CompressionKind.Snappy:
            {
                var (declared, _) = ReadVarint(compressed);
                if (declared != data.Length)
                    throw new InvalidOperationException($"{what}: snappy preamble declares {declared} bytes, data has {data.Length}.");
                break;
            }
            case CompressionKind.Gzip:
            {
                if (compressed.Length < 18 || compressed[0] != 0x1F || compressed[1] != 0x8B || compressed[2] != 8)
                    throw new InvalidOperationException($"{what}: not a gzip member (header {Convert.ToHexString(compressed.AsSpan(0, Math.Min(4, compressed.Length)))}).");
                var crc = BinaryPrimitives.ReadUInt32LittleEndian(compressed.AsSpan(compressed.Length - 8));
                var isize = BinaryPrimitives.ReadUInt32LittleEndian(compressed.AsSpan(compressed.Length - 4));
                if (crc != Crc32(data) || isize != (uint)data.Length)
                    throw new InvalidOperationException($"{what}: gzip trailer crc {crc:x8} / isize {isize} != {Crc32(data):x8} / {data.Length}.");
                break;
            }
            case CompressionKind.Zstd:
            {
                if (compressed.Length < 6 || BinaryPrimitives.ReadUInt32LittleEndian(compressed) != 0xFD2FB528)
                    throw new InvalidOperationException($"{what}: not a zstd frame.");
                var declared = ZstdContentSize(compressed);
                if (declared is { } size && size != (ulong)data.Length)
                    throw new InvalidOperationException($"{what}: zstd frame declares {size} content bytes, data has {data.Length}.");
                if (declared is null)
                    throw new InvalidOperationException($"{what}: zstd frame has no content size although the whole input was known.");
                break;
            }
        }

        RouteEvidence.Hit($"codec.direct.{kind}.declared-sizes-ok");
    }

    static (int Value, int Length) ReadVarint(ReadOnlySpan<byte> bytes)
    {
        var value = 0;
        for (var i = 0; i < Math.Min(5, bytes.Length); i++)
        {
            value |= (bytes[i] & 0x7F) << (7 * i);
            if ((bytes[i] & 0x80) == 0)
                return (value, i + 1);
        }

        throw new InvalidOperationException("Bad varint.");
    }

    static ulong? ZstdContentSize(ReadOnlySpan<byte> frame)
    {
        var descriptor = frame[4];
        var sizeFlag = descriptor >> 6;
        var singleSegment = (descriptor & 0x20) != 0;
        var dictionaryIdBytes = (descriptor & 3) switch { 0 => 0, 1 => 1, 2 => 2, _ => 4 };
        var offset = 5 + (singleSegment ? 0 : 1) + dictionaryIdBytes;
        if (sizeFlag == 0 && !singleSegment)
            return null;
        return sizeFlag switch
        {
            0 => frame[offset],
            1 => (ulong)BinaryPrimitives.ReadUInt16LittleEndian(frame[offset..]) + 256,
            2 => BinaryPrimitives.ReadUInt32LittleEndian(frame[offset..]),
            _ => BinaryPrimitives.ReadUInt64LittleEndian(frame[offset..])
        };
    }

    // ---- independent decoders ---------------------------------------------------------------------------

    static byte[] IndependentDecode(CompressionKind kind, byte[] compressed, int expectedLength, string what)
    {
        switch (kind)
        {
            case CompressionKind.Snappy:
                return RefSnappy(compressed, expectedLength);
            case CompressionKind.Lz4:
                return RefLz4Block(compressed, expectedLength);
            case CompressionKind.Gzip:
            {
                using var input = new MemoryStream(compressed, writable: false);
                using var gzip = new GZipStream(input, CompressionMode.Decompress);
                using var output = new MemoryStream();
                gzip.CopyTo(output);
                return output.ToArray();
            }
            case CompressionKind.Brotli:
            {
                using var input = new MemoryStream(compressed, writable: false);
                using var brotli = new BrotliStream(input, CompressionMode.Decompress);
                using var output = new MemoryStream();
                brotli.CopyTo(output);
                return output.ToArray();
            }
            case CompressionKind.Zstd:
            {
                using var decompressor = new ZstdSharp.Decompressor();
                return decompressor.Unwrap(compressed).ToArray();
            }
            default:
                throw new InvalidOperationException($"{what}: no independent decoder for {kind}.");
        }
    }

    // Reference Snappy block decoder (format description, not Snappier).
    static byte[] RefSnappy(byte[] source, int expectedLength)
    {
        var (length, position) = ReadVarint(source);
        if (length != expectedLength)
            throw new InvalidOperationException($"snappy preamble {length} != expected {expectedLength}.");
        var output = new byte[length];
        var written = 0;
        while (position < source.Length)
        {
            var tag = source[position++];
            int count;
            int offset;
            switch (tag & 3)
            {
                case 0:
                {
                    count = (tag >> 2) + 1;
                    if (count > 60)
                    {
                        var extra = count - 60;
                        count = 0;
                        for (var i = 0; i < extra; i++)
                            count |= source[position++] << (8 * i);
                        count++;
                    }

                    if (position + count > source.Length || written + count > length)
                        throw new InvalidOperationException("snappy literal overruns.");
                    source.AsSpan(position, count).CopyTo(output.AsSpan(written));
                    position += count;
                    written += count;
                    continue;
                }
                case 1:
                    count = 4 + ((tag >> 2) & 7);
                    offset = ((tag >> 5) << 8) | source[position++];
                    break;
                case 2:
                    count = (tag >> 2) + 1;
                    offset = BinaryPrimitives.ReadUInt16LittleEndian(source.AsSpan(position));
                    position += 2;
                    break;
                default:
                    count = (tag >> 2) + 1;
                    offset = (int)BinaryPrimitives.ReadUInt32LittleEndian(source.AsSpan(position));
                    position += 4;
                    break;
            }

            if (offset <= 0 || offset > written || written + count > length)
                throw new InvalidOperationException("snappy copy is out of range.");
            for (var i = 0; i < count; i++, written++)
                output[written] = output[written - offset];
        }

        if (written != length)
            throw new InvalidOperationException($"snappy produced {written} of {length} bytes.");
        return output;
    }

    // Reference LZ4 block decoder (LZ4_RAW is a bare block). `history` is the dictionary a dependent block reaches into.
    static byte[] RefLz4Block(byte[] source, int expectedLength, byte[]? history = null)
    {
        history ??= [];
        var output = new byte[history.Length + expectedLength];
        history.CopyTo(output, 0);
        var position = 0;
        var written = history.Length;
        expectedLength += history.Length;
        while (position < source.Length)
        {
            var token = source[position++];
            var literals = token >> 4;
            if (literals == 15)
            {
                int b;
                do
                {
                    b = source[position++];
                    literals += b;
                } while (b == 255);
            }

            if (position + literals > source.Length || written + literals > expectedLength)
                throw new InvalidOperationException("lz4 literals overrun.");
            source.AsSpan(position, literals).CopyTo(output.AsSpan(written));
            position += literals;
            written += literals;
            if (position >= source.Length)
                break; // the last sequence has no match part
            var offset = BinaryPrimitives.ReadUInt16LittleEndian(source.AsSpan(position));
            position += 2;
            var length = (token & 15) + 4;
            if ((token & 15) == 15)
            {
                int b;
                do
                {
                    b = source[position++];
                    length += b;
                } while (b == 255);
            }

            if (offset == 0 || offset > written || written + length > expectedLength)
                throw new InvalidOperationException("lz4 match is out of range.");
            for (var i = 0; i < length; i++, written++)
                output[written] = output[written - offset];
        }

        if (written != expectedLength)
            throw new InvalidOperationException($"lz4 produced {written - history.Length} of {expectedLength - history.Length} bytes.");
        return output[history.Length..];
    }

    static uint Crc32(ReadOnlySpan<byte> bytes)
    {
        var crc = 0xFFFFFFFFu;
        foreach (var b in bytes)
        {
            crc ^= b;
            for (var k = 0; k < 8; k++)
                crc = (crc & 1) != 0 ? (crc >> 1) ^ 0xEDB88320u : crc >> 1;
        }

        return ~crc;
    }

    // ---- real pages -------------------------------------------------------------------------------------

    static void Pages(Cur c, CompressionKind kind, int level, byte[] data, string what)
    {
        // Values are slices of the buffer (zero-length ones included) so the page payload is its bytes plus lengths.
        var values = new List<byte[]>();
        var maxValue = c.Pick(1, 7, 200, 5000, 70_000);
        for (var position = 0; position < data.Length;)
        {
            var take = Math.Min(c.Int(0, maxValue + 1), data.Length - position);
            values.Add(data.AsSpan(position, take).ToArray());
            position += take;
            if (take == 0 && values.Count > 4 * data.Length + 64)
                break;
        }

        // A column with NO rows at all (as opposed to one empty value) must be writable with every codec too.
        var zeroRows = data.Length == 0 && c.Int(0, 2) == 0;
        if (zeroRows)
            values.Clear();
        else if (values.Count == 0)
            values.Add([]);
        var schema = new PlankSchema([
            ColumnDefinition.RequiredLeaf("raw", ParquetPhysicalType.ByteArray,
                new ColumnOptions(encodings: [EncodingKind.Plain]))
        ]);
        var version = c.Int(0, 2) == 0 ? ParquetDataPageVersion.V2 : ParquetDataPageVersion.V1;
        var crc = c.Int(0, 2) == 0;
        var groups = c.Int(1, 3);
        using var pool = WriterFuzzPool.Create((WriterPoolKind)c.Int(0, 7));
        byte[] file;
        using (var stream = new MemoryStream())
        {
            var writer = schema.CreateWriter(stream, new ParquetWriterOptions
            {
                Compression = kind,
                CompressionLevel = kind is CompressionKind.None or CompressionKind.Snappy ? null : level,
                DataPageVersion = version,
                WritePageCrc = crc,
                TargetDataPageSizeBytes = c.Pick(64u, 1000u, 8192u, 65_536u, 1u << 20),
                BufferChunkSizeBytes = c.Pick(64u, 4096u, 65_536u),
                InitialPageBufferBytes = c.Pick(1u, 4096u, 65_536u),
                InitialColumnBufferBytes = c.Pick(1u, 65_536u),
                BufferPool = pool
            });
            var split = Math.Max(1, values.Count / groups);
            for (var start = 0; start < Math.Max(1, values.Count); start += split)
            {
                var group = writer.StartRowGroup();
                var column = group.CreateSerializedColumn<byte[]>(schema.LeafColumns[0]);
                column.Serialize(values.Skip(start).Take(split).ToArray());
                group.Write(column);
            }

            writer.CloseFile();
            file = stream.ToArray();
        }

        // Plank round trip
        using (var reader = schema.CreateReader(new MemoryStream(file, writable: false)))
        {
            var read = new List<byte[]>();
            foreach (var rowGroup in reader.RowGroups)
                read.AddRange(Plank.Fuzzing.PlankWriterFuzzTarget.ReadAllBinaryBuffers(
                    rowGroup.Column<byte>(schema.LeafColumns[0]))!);
            if (read.Count != values.Count || read.Where((v, i) => !v.AsSpan().SequenceEqual(values[i])).Any())
                throw new InvalidOperationException($"{what}: Plank read different values back.");
        }

        // Every page payload, decoded independently
        using (var physical = new PlankPhysicalReader())
        {
            physical.Reset(new MemoryStream(file, writable: false));
            var groupCount = physical.Metadata.RowGroupCount;
            for (var g = 0; g < groupCount; g++)
            {
                var chunk = physical.Metadata.ColumnChunk(g, 0);
                var cursor = physical.OpenPages(g, 0);
                long consumed = 0;
                try
                {
                    while (cursor.MoveNext())
                    {
                        var header = cursor.CurrentHeader;
                        // The cursor hands out the payload ALREADY decompressed by Plank; the stored bytes are read
                        // from the file at the page's offset so the independent decoders see what is on disk.
                        var start = (long)chunk.ChunkOffset + consumed + header.HeaderLength;
                        var size = (int)header.CompressedPageSize;
                        if (start + size > file.Length)
                            throw new InvalidOperationException($"{what}: page runs past the end of the file.");
                        var stored = file.AsSpan((int)start, size).ToArray();
                        consumed += header.HeaderLength + size;
                        if (header.Crc is { } expected && expected != Crc32(stored))
                            throw new InvalidOperationException($"{what}: page CRC {expected:x8} != {Crc32(stored):x8}.");
                        if (crc && header.Crc is null)
                            throw new InvalidOperationException($"{what}: WritePageCrc=true but the page header has no CRC.");
                        var isV2 = header.Type == PageHeaderType.DataPageV2;
                        var levels = isV2 ? (int)(header.RepetitionLevelsByteLength + header.DefinitionLevelsByteLength) : 0;
                        var body = stored[levels..];
                        var expectedLength = (int)header.UncompressedPageSize - levels;
                        var compressedBody = kind != CompressionKind.None && (!isV2 || header.IsCompressed);
                        var plankPayload = cursor.CurrentPayload.ToArray(); // Plank's decompressed view of the page
                        if (!compressedBody)
                        {
                            if (body.Length != expectedLength)
                                throw new InvalidOperationException($"{what}: stored page is {body.Length} bytes, header says {expectedLength}.");
                            continue;
                        }

                        var independent = IndependentDecode(kind, body, expectedLength, what);
                        if (independent.Length != expectedLength)
                            throw new InvalidOperationException($"{what}: independent decode gives {independent.Length} bytes, header says {expectedLength}.");
                        var plankBody = plankPayload.Length == (int)header.UncompressedPageSize ? plankPayload[levels..] : plankPayload;
                        if (!independent.AsSpan().SequenceEqual(plankBody))
                            throw new InvalidOperationException($"{what}: page {header.Type} decoded differently by the independent decoder and by Plank.");
                        RouteEvidence.Hit($"codec.pages.{kind}.{header.Type}.page-ok");
                    }
                }
                finally
                {
                    cursor.Dispose();
                }
            }
        }

        // ParquetSharp: Arrow's own codecs read the same values
        using (var sharp = new ParquetSharp.ParquetFileReader(new MemoryStream(file, writable: false), leaveOpen: false))
        {
            var rows = new List<byte[]>();
            for (var g = 0; g < sharp.FileMetaData.NumRowGroups; g++)
            {
                using var rowGroup = sharp.RowGroup(g);
                var count = checked((int)rowGroup.MetaData.NumRows);
                using var logical = rowGroup.Column(0).LogicalReader<byte[]>();
                rows.AddRange(logical.ReadAll(count));
            }

            if (rows.Count != values.Count || rows.Where((v, i) => !v.AsSpan().SequenceEqual(values[i])).Any())
                throw new InvalidOperationException($"{what}: ParquetSharp read different values back.");
            RouteEvidence.Hit($"codec.pages.{kind}.parquetsharp-ok");
        }
    }
}
