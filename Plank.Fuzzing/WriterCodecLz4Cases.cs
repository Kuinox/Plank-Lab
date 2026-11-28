using System.Buffers.Binary;
using System.IO.Hashing;
using Plank.K4os.LZ4;
using Plank.Reading;
using Plank.Schema;

namespace Plank.Fuzzing;

/// <summary>LZ4-specific parts of the codec route: level sweeps, large repetitive buffers, and frame / Hadoop / raw inputs.</summary>
internal static partial class WriterCodecCases
{
    // Every LZ4 level the writer accepts (0 = fast, 3..12 = HC) on the SAME boundary-size buffer: the levels differ
    // in match finder, chain depth and (10-12) the optimal parser, and each must decode exactly.
    static void Lz4LevelSweep(Cur c)
    {
        var sizes = BoundarySizes.Where(static x => x <= (1 << 20)).ToArray();
        var data = DrawData(c, out var label, 1 << 20, forcedSize: c.Pick(sizes));
        foreach (var level in new[] { 0, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12 })
            Direct(c, CompressionKind.Lz4, level, data, $"Lz4/L{level} sweep {label}");
    }

    // Levels 10-12 on large, highly repetitive buffers: long chains of equal-length matches and the optimal parser.
    static void Lz4LargeRepetitive(Cur c)
    {
        var data = DrawData(c, out var label, 4 << 20,
            forcedSize: c.Pick(1 << 20, (1 << 20) + 1, 2 << 20, 3_000_000, 4 << 20),
            forcedPattern: c.Pick(3, 4, 5, 8, 9, 0));
        foreach (var level in new[] { 12, c.Pick(10, 11), c.Pick(3, 9) })
            Direct(c, CompressionKind.Lz4, level, data, $"Lz4/L{level} large {label}");
    }

    // A payload written by an EXTERNAL LZ4 implementation (python `lz4`: frames with every option, Hadoop records,
    // bare blocks, concatenations; see fuzz/tools/gen-lz4-external-seeds.py). Layout after the mode bytes:
    //   u32 original length | u32 payload length | u32 CRC-32 of (original length, SHA-256, payload) | 32 bytes SHA-256 of the original | payload
    // While the payload still matches its CRC the decoder must reproduce the original exactly; once a fuzzer mutates
    // it, the only requirement is decoded bytes or CorruptParquetException.
    static void Lz4ExternalPayload(ReadOnlySpan<byte> input)
    {
        if (input.Length < 44)
            return;
        var originalLength = BinaryPrimitives.ReadUInt32LittleEndian(input);
        var payloadLength = BinaryPrimitives.ReadUInt32LittleEndian(input[4..]);
        var payloadCrc = BinaryPrimitives.ReadUInt32LittleEndian(input[8..]);
        if (originalLength > 8u << 20 || payloadLength != (uint)(input.Length - 44))
            return;
        var hash = input.Slice(12, 32).ToArray();
        var payload = input[44..].ToArray();
        // The CRC covers the declared original length and the expected SHA-256 as well as the payload: a mutated length or
        // hash must not make the input "pristine", or a correct decoder is blamed for refusing / differing from a header
        // the fuzzer corrupted (AFL: 195 such false faults in five minutes).
        var covered = new byte[4 + hash.Length + payload.Length];
        input[..4].CopyTo(covered);
        hash.CopyTo(covered, 4);
        payload.CopyTo(covered, 4 + hash.Length);
        var pristine = Crc32(covered) == payloadCrc;
        var destination = new byte[originalLength];
        try
        {
            ParquetDecompressor.DecompressInto(payload, CompressionKind.Lz4Legacy, destination);
        }
        catch (CorruptParquetException error)
        {
            if (pristine)
                throw new InvalidOperationException(
                    $"external LZ4 payload ({payload.Length} bytes, head {Convert.ToHexString(payload.AsSpan(0, Math.Min(16, payload.Length)))}) was refused: {error.Message}", error);
            RouteEvidence.Hit("lz4-external.mutated.rejected");
            return;
        }
        catch (NotSupportedException) when (!pristine)
        {
            RouteEvidence.Hit("lz4-external.mutated.not-supported");
            return;
        }
        catch (Exception error) when (error is not InvalidOperationException)
        {
            throw new InvalidOperationException($"external LZ4 payload threw {error.GetType().Name}: {error.Message}", error);
        }

        if (!pristine)
        {
            RouteEvidence.Hit("lz4-external.mutated.decoded");
            return;
        }

        if (!System.Security.Cryptography.SHA256.HashData(destination).AsSpan().SequenceEqual(hash))
            throw new InvalidOperationException(
                $"external LZ4 payload ({payload.Length} bytes) decoded to bytes with a different SHA-256 than the original.");
        RouteEvidence.Hit("lz4-external.pristine.exact-ok");
        Corrupt(new Cur(payload.Length > 8 ? payload.AsSpan(0, 8) : payload), CompressionKind.Lz4Legacy, payload,
            (int)originalLength, "lz4-external");
    }

    // ---- LZ4 frames, Hadoop blocks and raw blocks into Plank's Lz4Legacy decoder -------------------------------

    static void Lz4DecoderInputs(Cur c)
    {
        var data = DrawData(c, out var label, 700_000);
        var variant = c.Int(0, 8);
        var what = $"lz4-decoder v{variant} {label}";
        switch (variant)
        {
            case 0 or 1 or 2: // a frame: independent / dependent blocks, checksums, content size, block sizes
            {
                var (frame, expected) = BuildFrame(c, data, variant == 0 ? null : false);
                DecodeExact(what, frame, expected);
                Corrupt(c, CompressionKind.Lz4Legacy, frame, expected.Length, what);
                break;
            }
            case 3: // skippable frames around two frames: the decoder concatenates their content
            {
                var half = data.Length / 2;
                var (first, firstOut) = BuildFrame(c, data[..half], null);
                var (second, secondOut) = BuildFrame(c, data[half..], null);
                var skippable = new byte[8 + c.Int(0, 20)];
                BinaryPrimitives.WriteUInt32LittleEndian(skippable, 0x184D2A50u + (uint)c.Int(0, 16));
                BinaryPrimitives.WriteUInt32LittleEndian(skippable.AsSpan(4), (uint)skippable.Length - 8);
                var stream = skippable.Concat(first).Concat(skippable).Concat(second).ToArray();
                var expected = firstOut.Concat(secondOut).ToArray();
                DecodeExact(what, stream, expected);
                Corrupt(c, CompressionKind.Lz4Legacy, stream, expected.Length, what);
                break;
            }
            case 4: // Hadoop: several (BE uncompressed size, BE compressed size, block) records
            {
                if (data.Length == 0)
                    return;
                var output = new List<byte>();
                var piece = c.Pick(1, 1000, 65_536, 262_144);
                for (var position = 0; position < data.Length; position += piece)
                {
                    var chunk = data.AsSpan(position, Math.Min(piece, data.Length - position));
                    var block = new byte[LZ4Codec.MaximumOutputSize(chunk.Length)];
                    var written = LZ4Codec.Encode(chunk, block, (LZ4Level)c.Pick(0, 3, 9, 12));
                    var header = new byte[8];
                    BinaryPrimitives.WriteInt32BigEndian(header, chunk.Length);
                    BinaryPrimitives.WriteInt32BigEndian(header.AsSpan(4), written);
                    output.AddRange(header);
                    output.AddRange(block.AsSpan(0, written).ToArray());
                }

                DecodeExact(what, output.ToArray(), data);
                Corrupt(c, CompressionKind.Lz4Legacy, output.ToArray(), data.Length, what);
                break;
            }
            case 5: // a bare block through the legacy path (the third fallback)
            {
                if (data.Length == 0)
                    return;
                var block = new byte[LZ4Codec.MaximumOutputSize(data.Length)];
                var written = LZ4Codec.Encode(data, block, (LZ4Level)c.Pick(0, 3, 12));
                DecodeExact(what, block.AsSpan(0, written).ToArray(), data);
                break;
            }
            case 6: // frames the decoder must refuse by name
            {
                var (frame, _) = BuildFrame(c, data.Length == 0 ? [1, 2, 3] : data, null);
                var damaged = (byte[])frame.Clone();
                var how = c.Int(0, 6);
                switch (how)
                {
                    case 0: damaged[4] = (byte)((damaged[4] & 0x3F) | 0x80); break; // version bits
                    case 1: damaged[4] |= 0x02; break; // reserved FLG bit
                    case 2: damaged[5] |= 0x01; break; // reserved BD bit
                    case 3: damaged[5] = (byte)((damaged[5] & 0x8F) | (c.Pick(0, 1, 2, 3) << 4)); break; // block size id
                    case 4: damaged[6 + ((damaged[4] & 0x08) != 0 ? 8 : 0)] ^= 0xFF; break; // header checksum
                    default: damaged = damaged[..Math.Max(4, damaged.Length - c.Int(1, 8))]; break; // truncated
                }

                try
                {
                    ParquetDecompressor.DecompressInto(damaged, CompressionKind.Lz4Legacy, new byte[Math.Max(data.Length, 3)]);
                    RouteEvidence.Hit($"lz4-decoder.refuse.v{how}.accepted");
                }
                catch (CorruptParquetException)
                {
                    RouteEvidence.Hit($"lz4-decoder.refuse.v{how}.rejected");
                }
                catch (Exception error)
                {
                    throw new InvalidOperationException(
                        $"{what}: damaged frame (variant {how}) threw {error.GetType().Name}: {error.Message}", error);
                }

                break;
            }
            default: // a frame that names an external dictionary is refused as unsupported
            {
                var descriptor = new byte[] { 0x40 | 0x20 | 0x01, 0x40, 1, 2, 3, 4 };
                var frame = new byte[4 + descriptor.Length + 1 + 4];
                BinaryPrimitives.WriteUInt32LittleEndian(frame, 0x184D2204);
                descriptor.CopyTo(frame, 4);
                frame[4 + descriptor.Length] = (byte)(XxHash32.HashToUInt32(descriptor) >> 8);
                try
                {
                    ParquetDecompressor.DecompressInto(frame, CompressionKind.Lz4Legacy, new byte[Math.Max(1, data.Length)]);
                }
                catch (NotSupportedException)
                {
                    RouteEvidence.Hit("lz4-decoder.dictionary-frame.not-supported");
                    break;
                }

                throw new InvalidOperationException($"{what}: a frame with an external dictionary was accepted.");
            }
        }
    }

    static void DecodeExact(string what, byte[] input, byte[] expected)
    {
        var buffer = new byte[expected.Length];
        try
        {
            ParquetDecompressor.DecompressInto(input, CompressionKind.Lz4Legacy, buffer);
        }
        catch (CorruptParquetException error)
        {
            throw new InvalidOperationException(
                $"{what}: a well-formed input was refused: {error.Message} (input {input.Length} bytes, head " +
                $"{Convert.ToHexString(input.AsSpan(0, Math.Min(16, input.Length)))}, expected {expected.Length} bytes)", error);
        }

        if (!buffer.AsSpan().SequenceEqual(expected))
            throw new InvalidOperationException(
                $"{what}: the Lz4Legacy decoder returned different bytes ({input.Length} input bytes).");
        RouteEvidence.Hit("lz4-decoder.exact-ok");
    }

    // An LZ4 frame around `data`, or around generated dependent blocks that reference earlier output. `expected` is
    // what any correct decoder must produce.
    static (byte[] Frame, byte[] Expected) BuildFrame(Cur c, byte[] data, bool? forceIndependent)
    {
        var independent = forceIndependent ?? c.Int(0, 2) == 0;
        var blockChecksum = c.Int(0, 2) == 0;
        var contentChecksum = c.Int(0, 2) == 0;
        var contentSize = c.Int(0, 2) == 0;
        var blockSizeId = c.Int(4, 8);
        var blockMax = blockSizeId switch { 4 => 64 << 10, 5 => 256 << 10, 6 => 1 << 20, _ => 4 << 20 };
        var useGenerated = !independent && data.Length > 0 && c.Int(0, 2) == 0;

        var output = new List<byte>();
        var blocks = new List<byte>();
        var position = 0;
        while (useGenerated ? output.Count < data.Length : position < data.Length)
        {
            var left = useGenerated ? data.Length - output.Count : data.Length - position;
            var take = Math.Max(1, Math.Min(c.Pick(blockMax, 1, 1000, 65_536, blockMax / 2 + 1), left));
            // A generated block is mostly literals, so it can be a little larger than its output: keep it under the
            // frame's block maximum.
            if (useGenerated)
                take = Math.Max(1, Math.Min(take, blockMax - blockMax / 200 - 64));
            byte[] stored;
            bool isStored;
            if (useGenerated)
            {
                var history = output.Count > 65_536 ? output.GetRange(output.Count - 65_536, 65_536) : output;
                var (block, produced) = BuildDependentBlock(c, history, take);
                stored = block;
                isStored = false;
                output.AddRange(produced);
            }
            else
            {
                var chunk = data.AsSpan(position, take);
                position += take;
                output.AddRange(chunk.ToArray());
                var encoded = new byte[LZ4Codec.MaximumOutputSize(take)];
                var written = LZ4Codec.Encode(chunk, encoded, (LZ4Level)c.Pick(0, 3, 9, 12));
                isStored = written <= 0 || written >= take || c.Int(0, 5) == 0;
                stored = isStored ? chunk.ToArray() : encoded.AsSpan(0, written).ToArray();
            }

            var header = new byte[4];
            BinaryPrimitives.WriteUInt32LittleEndian(header, (uint)stored.Length | (isStored ? 0x80000000u : 0));
            blocks.AddRange(header);
            blocks.AddRange(stored);
            if (blockChecksum)
            {
                var checksum = new byte[4];
                BinaryPrimitives.WriteUInt32LittleEndian(checksum, XxHash32.HashToUInt32(stored));
                blocks.AddRange(checksum);
            }
        }

        var expected = output.ToArray();
        var descriptor = new List<byte>
        {
            (byte)(0x40 | (independent ? 0x20 : 0) | (blockChecksum ? 0x10 : 0) | (contentSize ? 0x08 : 0)
                   | (contentChecksum ? 0x04 : 0)),
            (byte)(blockSizeId << 4)
        };
        if (contentSize)
            descriptor.AddRange(BitConverter.GetBytes((ulong)expected.Length));
        var frame = new List<byte>();
        frame.AddRange(BitConverter.GetBytes(0x184D2204u));
        frame.AddRange(descriptor);
        frame.Add((byte)(XxHash32.HashToUInt32(descriptor.ToArray()) >> 8));
        frame.AddRange(blocks);
        frame.AddRange(new byte[4]); // end mark
        if (contentChecksum)
            frame.AddRange(BitConverter.GetBytes(XxHash32.HashToUInt32(expected)));
        RouteEvidence.Hit($"lz4-decoder.frame.indep={independent}.blockcrc={blockChecksum}.contentcrc={contentChecksum}" +
                          $".size={contentSize}.generated={useGenerated}");
        return (frame.ToArray(), expected);
    }

    // A compressed block valid only together with `history` (matches reach back into it), and the output it produces.
    // The independent reference decoder and K4os' own dictionary decode both check it before a frame is built.
    static (byte[] Block, byte[] Output) BuildDependentBlock(Cur c, List<byte> history, int length)
    {
        var window = new List<byte>(history);
        var produced = new List<byte>();
        var block = new List<byte>();

        void Extended(int value)
        {
            while (value >= 255)
            {
                block.Add(255);
                value -= 255;
            }

            block.Add((byte)value);
        }

        var endedWithLiterals = false;
        var reachedIntoHistory = false;
        while (produced.Count < length)
        {
            var remaining = length - produced.Count;
            var literals = Math.Min(c.Pick(0, 1, 5, 15, 16, 40, 300), remaining);
            var matchLength = 4 + c.Pick(0, 1, 11, 15, 16, 70, 400);
            // LZ4's end-of-block rules: the last match starts at least 12 bytes before the end and the last 5 bytes are
            // literals (strict decoders reject anything else).
            var last = window.Count == 0 || remaining - literals < 12 || remaining - literals - 5 < 4;
            if (last)
                literals = remaining;
            else
                matchLength = Math.Min(matchLength, remaining - literals - 5);
            block.Add((byte)((Math.Min(literals, 15) << 4) | (last ? 0 : Math.Min(matchLength - 4, 15))));
            if (literals >= 15)
                Extended(literals - 15);
            for (var i = 0; i < literals; i++)
            {
                var b = c.Byte();
                block.Add(b);
                window.Add(b);
                produced.Add(b);
            }

            if (last)
            {
                endedWithLiterals = true;
                break;
            }

            var offset = c.Int(1, Math.Min(65_535, window.Count) + 1);
            if (offset > produced.Count)
                reachedIntoHistory = true;
            block.Add((byte)offset);
            block.Add((byte)(offset >> 8));
            if (matchLength - 4 >= 15)
                Extended(matchLength - 4 - 15);
            for (var i = 0; i < matchLength; i++)
            {
                var b = window[^offset];
                window.Add(b);
                produced.Add(b);
            }
        }

        if (!endedWithLiterals)
            block.Add(0); // every block ends with a literal-only sequence, here an empty one
        var blockBytes = block.ToArray();
        var producedBytes = produced.ToArray();
        var historyBytes = history.ToArray();
        if (!RefLz4Block(blockBytes, producedBytes.Length, historyBytes).AsSpan().SequenceEqual(producedBytes))
            throw new InvalidOperationException("The dependent-block generator and the reference LZ4 decoder disagree (harness bug).");
        var viaK4os = new byte[producedBytes.Length];
        var k4os = historyBytes.Length == 0
            ? LZ4Codec.Decode(blockBytes, viaK4os)
            : LZ4Codec.Decode(blockBytes, viaK4os, historyBytes);
        var kind = k4os == producedBytes.Length && viaK4os.AsSpan().SequenceEqual(producedBytes)
            ? "ok"
            : k4os < 0 ? "MISMATCH-negative" : k4os != producedBytes.Length ? "MISMATCH-length" : "MISMATCH-bytes";
        var bucket = historyBytes.Length == 0 ? "empty" : historyBytes.Length < 65_536 ? "short" : "64K";
        RouteEvidence.Hit($"lz4-decoder.dependent-block.k4os-dictionary-decode.{kind}.dict={bucket}.reachesDict={reachedIntoHistory}");
        return (blockBytes, producedBytes);
    }
}
