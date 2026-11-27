using System.Collections.Immutable;
using ParquetSharp;
using Plank.Reading;
using Plank.Reading.Logical;
using Plank.Schema;
using Plank.Writing;
using Plank.Writing.PageStrategy;
using PlankColumn = Plank.Schema.ColumnDefinition;
using PlankDataPageVersion = Plank.Writing.ParquetDataPageVersion;
using PlankFileVersion = Plank.Writing.ParquetFileVersion;
using PlankKeyValueMetadata = Plank.Writing.ParquetKeyValueMetadata;
using PlankReader = Plank.Reading.Logical.ParquetReader;
using PlankRowGroup = Plank.Reading.Logical.RowGroup;
using PlankRowGroupWriter = Plank.Writing.RowGroupWriter;
using PlankSchema = Plank.Schema.ParquetSchema;
using PlankWriter = Plank.Writing.ParquetWriter;

namespace Plank.Fuzzing;

public static class PlankWriterFuzzTarget
{
    const int MaxColumnCount = 5;
    const int MaxRowGroupCount = 3;
    const int MaxRowCount = 64;
    const int MaxByteArrayLength = 32;
    const int MaxFixedLength = 16;

    public static FuzzCase Decode(ReadOnlySpan<byte> data)
        => new Decoder(data).Decode();

    // A leading 0xFF routes the case to the row-oriented writer instead. That
    // pipeline can only be driven through generated code, so it needs its own
    // target rather than another axis of the column spec: see
    // PlankRowApiFuzzTarget. The marker is a whole byte value rather than a bit
    // so the existing corpus keeps decoding exactly as it did — every saved case
    // whose first byte is not 0xFF still describes the same columns.
    const byte RowApiMarker = 0xFF;

    // 0xFE routes to the partitioned dataset writer, for the same reason: it is
    // reachable only through generated code, and it owns files rather than taking
    // a stream. See PlankDatasetFuzzTarget.
    const byte DatasetMarker = 0xFE;
    static ReadOnlySpan<byte> DatasetBinaryMagic => "DBS1"u8;
    static ReadOnlySpan<byte> DatasetOperationalMagic => "DBR1"u8;

    // Drives sequential stream output through the bounded gzip output buffer, then reuses the writer.
    const byte NonSeekableStreamMarker = 0xEF;
    static ReadOnlySpan<byte> NonSeekableStreamMagic => "NSW1"u8;

    // 0xFD routes to the file merger: the one write path that does not
    // re-encode, splicing column chunks across and rewriting their offsets.
    const byte MergerMarker = 0xFD;

    // 0xFC inverts this target: Apache Arrow writes the file and Plank has to
    // read it. It lives behind the writer's marker rather than as a selector in
    // the reader target because its input is a plan for a file, not a file — see
    // PlankCrossWriterFuzzTarget.
    const byte CrossWriterMarker = 0xFC;

    // Exercises the optional all-present DOUBLE dictionary encoder, whose
    // specialized path requires both dictionary encoding and page indexes.
    const byte OptionalDoubleDictionaryMarker = 0xFB;

    // Drives the row-shaped repeated-column encoder, which flat column plans
    // cannot represent.
    const byte RepeatedRowsMarker = 0xFA;

    // Drives the custom value-converter writer route from a deterministic schema.
    const byte ValueConverterMarker = 0xF9;

    // Exercises append-to-latest sorting validation, which is not part of the
    // fresh-file writer plan decoded by Decode().
    const byte AppendSortingMarker = 0xF8;

    // Exercises forced optional integer dictionaries without page indexes.
    const byte OptionalForcedIntegerDictionaryMarker = 0xF6;

    // Exercises append-to-latest value reconstruction independently of sorting.
    const byte LatestRowGroupValuesMarker = 0xF7;
    static ReadOnlySpan<byte> LatestRowGroupValuesMagic => "LGR1"u8;

    // Reaches the fused optional PLAIN timestamp encoder with DateTime values.
    const byte OptionalPlainTimestampMarker = 0xF5;

    // Public-schema logical annotations that the ordinary descriptor does not currently select.
    const byte LogicalMetadataMarker = 0xF4;

    // Deterministic Bloom-filter value forms and repeated-row sizing/insertion.
    const byte BloomFilterMarker = 0xF3;

    // A distinct exact-magic route for nested repeated Bloom-filter recursion.
    const byte NestedBloomMarker = 0xF0;
    static ReadOnlySpan<byte> NestedBloomMagic => "NBM1"u8;
    static ReadOnlySpan<byte> NullableListBloomMagic => "NBM2"u8;

    // Exercises explicit compression-level validation boundaries and round trips.
    const byte CompressionLevelMarker = 0xF2;

    // Deliberate writer-only encoding cases beyond the general decoder's limits.
    // The following magic keeps ordinary 0xF1-prefixed inputs on the Decode path.
    const byte EncodingCoverageMarker = 0xF1;
    static ReadOnlySpan<byte> EncodingCoverageMagic => "ENCG"u8;

    // Public writer metadata probes are kept behind a four-byte discriminator so
    // ordinary schema bytes cannot accidentally select this deterministic route.
    static ReadOnlySpan<byte> WriterMetadataMagic => "WMD1"u8;

    // A small pair of fixed-width and decimal-DELTA routes. The exact magic
    // keeps ordinary inputs on the general writer-plan path.
    const byte FixedBinaryDeltaMarker = 0xEE;
    static ReadOnlySpan<byte> FixedBinaryDeltaMagic => "WFX1"u8;

    // Replays malformed and control Parquet files through the public import path.
    const byte ImportValidationMarker = 0xEC;
    static ReadOnlySpan<byte> ImportValidationMagic => "IMV1"u8;

    // The exact marker keeps this same-stream reset probe away from the general plan decoder.
    const byte SameStreamResetMarker = 0xED;
    static ReadOnlySpan<byte> SameStreamResetMagic => "SSR1"u8;

    // Temporarily records the known optional decimal plus Bloom-filter failure on an isolated route.
    const byte OptionalDecimalBloomGapMarker = 0xEB;
    static ReadOnlySpan<byte> OptionalDecimalBloomGapMagic => "ODBG"u8;

    // Strict generated Row API route for variable-width slot growth.
    const byte RowApiGrowthMarker = 0xEA;
    static ReadOnlySpan<byte> RowApiGrowthMagic => "RWG1"u8;

    const byte OptionalDoubleDictionaryCoverageMarker = 0xE9;
    static ReadOnlySpan<byte> OptionalDoubleDictionaryMagic => "ODDC"u8;

    const byte OptionalInt64DictionaryCoverageMarker = 0xD3;
    static ReadOnlySpan<byte> OptionalInt64DictionaryMagic => "OID1"u8;

    // Exact-gated optional UUID Bloom-filter coverage route.
    const byte OptionalUuidBloomGapMarker = 0xE8;
    static ReadOnlySpan<byte> OptionalUuidBloomGapMagic => "OUB1"u8;

    // Public reset to a distinct IParquetWriteSource, separate from stream reset.
    const byte DifferentWriteSourceResetMarker = 0xE7;
    static ReadOnlySpan<byte> DifferentWriteSourceResetMagic => "RDS1"u8;

    // Imports a valid external file whose column chunk has no statistics field.
    const byte ImportedMissingStatisticsMarker = 0xE6;
    static ReadOnlySpan<byte> ImportedMissingStatisticsMagic => "IMS1"u8;

    // Exercises a required INT32 dictionary with 17-bit bit-packed indexes.
    const byte RequiredInt32Dictionary17Marker = 0xE5;
    static ReadOnlySpan<byte> RequiredInt32Dictionary17Magic => "R17B"u8;

    // Direct schema-options equality sample; ordinary file plans never call Equals.
    const byte ColumnOptionsEqualityMarker = 0xE4;
    static ReadOnlySpan<byte> ColumnOptionsEqualityMagic => "COEQ"u8;

    const byte DatasetWriterOptionsGapMarker = 0xE3;
    static ReadOnlySpan<byte> DatasetWriterOptionsGapMagic => "DWOV"u8;

    const byte BufferWriterCapacityMarker = 0xE2;
    static ReadOnlySpan<byte> BufferWriterCapacityMagic => "BWOV"u8;
    static ReadOnlySpan<byte> WriterLifecycleMagic => "WLC1"u8;
    const byte WriterOptionsValidationMarker = 0xE1;
    static ReadOnlySpan<byte> WriterOptionsValidationMagic => "PWOV"u8;
    const byte BloomOptionsValidationMarker = 0xE0;
    static ReadOnlySpan<byte> BloomOptionsValidationMagic => "BOV1"u8;
    const byte BufferApiValidationMarker = 0xDF;
    // 0xDD + "EXEC": buffer-pool and execution-layer target (PlankExecutionFuzzTarget).
    const byte ExecutionMarker = 0xDD;
    static ReadOnlySpan<byte> ExecutionMagic => "EXEC"u8;
    static ReadOnlySpan<byte> BufferApiValidationMagic => "PBAP"u8;
    const byte SchemaApiValidationMarker = 0xDE;
    static ReadOnlySpan<byte> SchemaApiValidationMagic => "SAPI"u8;

    // Dedicated public-writer route for MinMaxScan's Vector128 copy-and-statistics path.
    const byte MinMaxScanCoverageMarker = 0xD8;
    static ReadOnlySpan<byte> MinMaxScanCoverageMagic => "MMS1"u8;
    const byte DecimalBinaryStatisticsMarker = 0xD9;
    static ReadOnlySpan<byte> DecimalBinaryStatisticsMagic => "DBS1"u8;
    const byte NestedDescriptorValidationMarker = 0xD7;
    static ReadOnlySpan<byte> NestedDescriptorValidationMagic => "NDV1"u8;
    const byte ParquetWriterConstructorMarker = 0xD4;
    static ReadOnlySpan<byte> ParquetWriterConstructorMagic => "PWC1"u8;
    const byte RepeatedRowsCoverageMarker = 0xD6;
    static ReadOnlySpan<byte> RepeatedRowsCoverageMagic => "RRC1"u8;
    const byte ColumnStatisticsBinaryCoverageMarker = 0xD5;
    static ReadOnlySpan<byte> ColumnStatisticsBinaryCoverageMagic => "CSB1"u8;
    const byte RepeatedAccumulatorCoverageMarker = 0xCA;
    static ReadOnlySpan<byte> RepeatedAccumulatorCoverageMagic => "RAL1"u8;
    const byte RowGroupWriteCoverageMarker = 0xC9;
    static ReadOnlySpan<byte> RowGroupWriteCoverageMagic => "RGW1"u8;

    // Typed single-column matrix with independently drawn value counts, cardinalities, widths, codecs and levels.
    // Nested list / map data with fuzzer-drawn optionality, null / empty lists, page and row-group splits.
    // Every codec Plank writes, fuzzer-chosen buffers, independent decoders (WriterCodecCases).
    const byte CodecMarker = 0xDB;
    static ReadOnlySpan<byte> CodecMagic => "WCD1"u8;

    const byte GroupShapesMarker = 0xC4;
    static ReadOnlySpan<byte> GroupShapesMagic => "WGS1"u8;

    const byte NestedShapesMarker = 0xC7;
    static ReadOnlySpan<byte> NestedShapesMagic => "WNS1"u8;

    const byte TypeMatrixMarker = 0xC8;
    static ReadOnlySpan<byte> TypeMatrixMagic => "WTM1"u8;

    // Hand-written *Cases routes build their own WriterSettings with the default pool and default
    // buffer sizes. A hash of the whole input picks the buffer pool and the initial buffer sizes for
    // those routes (the generic route chooses its own explicitly), so every route that goes through
    // WriteToStream also covers exact-size / dirty / non-retaining pools and tiny initial buffers.
    // Hash-based on purpose: it never changes what a route writes, only how the buffers behave.
    [ThreadStatic] static uint _ambientHash;

    public static void Execute(ReadOnlySpan<byte> data)
    {
        var hash = 2166136261u;
        foreach (var b in data)
            hash = (hash ^ b) * 16777619u;
        _ambientHash = hash;

        if (data.Length >= 1 + NestedSurfaceCases.Magic.Length
            && data[0] == NestedSurfaceCases.Marker
            && data.Slice(1, NestedSurfaceCases.Magic.Length).SequenceEqual(NestedSurfaceCases.Magic))
        {
            NestedSurfaceCases.Execute(data[(1 + NestedSurfaceCases.Magic.Length)..]);
            return;
        }

        if (data.Length >= 1 + OptionsSweepCases.Magic.Length
            && data[0] == OptionsSweepCases.Marker
            && data.Slice(1, OptionsSweepCases.Magic.Length).SequenceEqual(OptionsSweepCases.Magic))
        {
            OptionsSweepCases.Execute(data[(1 + OptionsSweepCases.Magic.Length)..]);
            return;
        }

        if (data.Length >= 1 + RowGroupProtocolCases.Magic.Length
            && data[0] == RowGroupProtocolCases.Marker
            && data.Slice(1, RowGroupProtocolCases.Magic.Length).SequenceEqual(RowGroupProtocolCases.Magic))
        {
            RowGroupProtocolCases.Execute(data[(1 + RowGroupProtocolCases.Magic.Length)..]);
            return;
        }

        if (data.Length >= 1 + SurfaceReflectionCases.Magic.Length
            && data[0] == SurfaceReflectionCases.Marker
            && data.Slice(1, SurfaceReflectionCases.Magic.Length).SequenceEqual(SurfaceReflectionCases.Magic))
        {
            SurfaceReflectionCases.Execute(data[(1 + SurfaceReflectionCases.Magic.Length)..]);
            return;
        }

        if (data.Length >= 1 + PhysicalReaderSurfaceCases.Magic.Length
            && data[0] == PhysicalReaderSurfaceCases.Marker
            && data.Slice(1, PhysicalReaderSurfaceCases.Magic.Length).SequenceEqual(PhysicalReaderSurfaceCases.Magic))
        {
            PhysicalReaderSurfaceCases.Execute(data[(1 + PhysicalReaderSurfaceCases.Magic.Length)..]);
            return;
        }

        if (data.Length >= 1 + PagePrunerSurfaceCases.Magic.Length
            && data[0] == PagePrunerSurfaceCases.Marker
            && data.Slice(1, PagePrunerSurfaceCases.Magic.Length).SequenceEqual(PagePrunerSurfaceCases.Magic))
        {
            PagePrunerSurfaceCases.Execute(data[(1 + PagePrunerSurfaceCases.Magic.Length)..]);
            return;
        }

        if (data.Length >= 1 + CodecMagic.Length
            && data[0] == CodecMarker
            && data.Slice(1, CodecMagic.Length).SequenceEqual(CodecMagic))
        {
            WriterCodecCases.Execute(data[(1 + CodecMagic.Length)..]);
            return;
        }

        if (data.Length >= 1 + GroupShapesMagic.Length
            && data[0] == GroupShapesMarker
            && data.Slice(1, GroupShapesMagic.Length).SequenceEqual(GroupShapesMagic))
        {
            WriterGroupCases.Execute(data[(1 + GroupShapesMagic.Length)..]);
            return;
        }

        if (data.Length >= 1 + NestedShapesMagic.Length
            && data[0] == NestedShapesMarker
            && data.Slice(1, NestedShapesMagic.Length).SequenceEqual(NestedShapesMagic))
        {
            WriterNestedCases.Execute(data[(1 + NestedShapesMagic.Length)..]);
            return;
        }

        if (data.Length >= 1 + TypeMatrixMagic.Length
            && data[0] == TypeMatrixMarker
            && data.Slice(1, TypeMatrixMagic.Length).SequenceEqual(TypeMatrixMagic))
        {
            WriterTypeMatrixCases.Execute(data[(1 + TypeMatrixMagic.Length)..]);
            return;
        }
        if (data.Length >= 1 + ExecutionMagic.Length
            && data[0] == ExecutionMarker
            && data.Slice(1, ExecutionMagic.Length).SequenceEqual(ExecutionMagic))
        {
            PlankExecutionFuzzTarget.Execute(data[(1 + ExecutionMagic.Length)..]);
            return;
        }

        if (data.Length >= 1 + RowGroupWriteCoverageMagic.Length
            && data[0] == RowGroupWriteCoverageMarker
            && data.Slice(1, RowGroupWriteCoverageMagic.Length).SequenceEqual(RowGroupWriteCoverageMagic))
        {
            RowGroupWriteCoverageCases.Execute(
                data.Length > 1 + RowGroupWriteCoverageMagic.Length
                    ? data[1 + RowGroupWriteCoverageMagic.Length]
                    : (byte)0);
            return;
        }

        if (data.Length >= 1 + RepeatedAccumulatorCoverageMagic.Length
            && data[0] == RepeatedAccumulatorCoverageMarker
            && data.Slice(1, RepeatedAccumulatorCoverageMagic.Length).SequenceEqual(RepeatedAccumulatorCoverageMagic))
        {
            RepeatedAccumulatorCoverageCase.Execute(
                data.Length > 1 + RepeatedAccumulatorCoverageMagic.Length
                    ? data[1 + RepeatedAccumulatorCoverageMagic.Length]
                    : (byte)0);
            return;
        }

        if (data.Length >= 1 + ParquetWriterConstructorMagic.Length
            && data[0] == ParquetWriterConstructorMarker
            && data.Slice(1, ParquetWriterConstructorMagic.Length).SequenceEqual(ParquetWriterConstructorMagic))
        {
            ParquetWriterConstructorCoverageCase.Execute(
                data.Length > 1 + ParquetWriterConstructorMagic.Length
                    ? data[1 + ParquetWriterConstructorMagic.Length]
                    : (byte)0);
            return;
        }

        if (data.Length >= 1 + ColumnStatisticsBinaryCoverageMagic.Length
            && data[0] == ColumnStatisticsBinaryCoverageMarker
            && data.Slice(1, ColumnStatisticsBinaryCoverageMagic.Length).SequenceEqual(ColumnStatisticsBinaryCoverageMagic))
        {
            ColumnStatisticsBinaryCoverageCase.Execute(
                data.Length > 1 + ColumnStatisticsBinaryCoverageMagic.Length
                    ? data[1 + ColumnStatisticsBinaryCoverageMagic.Length]
                    : (byte)0);
            return;
        }

        if (data.Length >= 1 + NestedDescriptorValidationMagic.Length
            && data[0] == NestedDescriptorValidationMarker
            && data.Slice(1, NestedDescriptorValidationMagic.Length).SequenceEqual(NestedDescriptorValidationMagic))
        {
            NestedDescriptorValidationCoverageCase.Execute(
                data.Length > 1 + NestedDescriptorValidationMagic.Length
                    ? data[1 + NestedDescriptorValidationMagic.Length]
                    : (byte)0);
            return;
        }

        if (data.Length >= 1 + RepeatedRowsCoverageMagic.Length
            && data[0] == RepeatedRowsCoverageMarker
            && data.Slice(1, RepeatedRowsCoverageMagic.Length).SequenceEqual(RepeatedRowsCoverageMagic))
        {
            RepeatedRowsCoverageCases.Execute(
                data.Length > 1 + RepeatedRowsCoverageMagic.Length
                    ? data[1 + RepeatedRowsCoverageMagic.Length]
                    : (byte)0);
            return;
        }

        if (data.Length >= 1 + DecimalBinaryStatisticsMagic.Length
            && data[0] == DecimalBinaryStatisticsMarker
            && data.Slice(1, DecimalBinaryStatisticsMagic.Length).SequenceEqual(DecimalBinaryStatisticsMagic))
        {
            DecimalBinaryStatisticsCoverageCase.Execute(
                data.Length > 1 + DecimalBinaryStatisticsMagic.Length
                    ? data[1 + DecimalBinaryStatisticsMagic.Length]
                    : (byte)0);
            return;
        }

        if (data.Length >= 1 + MinMaxScanCoverageMagic.Length
            && data[0] == MinMaxScanCoverageMarker
            && data.Slice(1, MinMaxScanCoverageMagic.Length).SequenceEqual(MinMaxScanCoverageMagic))
        {
            MinMaxScanCoverageWriterCase.Execute();
            return;
        }

        if (data.Length >= 1 + SchemaApiValidationMagic.Length
            && data[0] == SchemaApiValidationMarker
            && data.Slice(1, SchemaApiValidationMagic.Length).SequenceEqual(SchemaApiValidationMagic))
        {
            SchemaApiValidationCases.Execute(data.Length > 1 + SchemaApiValidationMagic.Length
                ? data[1 + SchemaApiValidationMagic.Length]
                : (byte)0);
            return;
        }

        if (data.Length >= 1 + BufferApiValidationMagic.Length
            && data[0] == BufferApiValidationMarker
            && data.Slice(1, BufferApiValidationMagic.Length).SequenceEqual(BufferApiValidationMagic))
        {
            BufferApiValidationCases.Execute(data.Length > 1 + BufferApiValidationMagic.Length
                ? data[1 + BufferApiValidationMagic.Length]
                : (byte)0);
            return;
        }

        if (data.Length >= 1 + BloomOptionsValidationMagic.Length
            && data[0] == BloomOptionsValidationMarker
            && data.Slice(1, BloomOptionsValidationMagic.Length).SequenceEqual(BloomOptionsValidationMagic))
        {
            BloomOptionsValidationCases.Execute(data.Length > 1 + BloomOptionsValidationMagic.Length
                ? data[1 + BloomOptionsValidationMagic.Length]
                : (byte)0);
            return;
        }

        if (data.Length >= 1 + WriterOptionsValidationMagic.Length
            && data[0] == WriterOptionsValidationMarker
            && data.Slice(1, WriterOptionsValidationMagic.Length).SequenceEqual(WriterOptionsValidationMagic))
        {
            WriterOptionsValidationCases.Execute(data.Length > 1 + WriterOptionsValidationMagic.Length
                ? data[1 + WriterOptionsValidationMagic.Length]
                : (byte)0);
            return;
        }

        if (data.Length >= 1 + WriterLifecycleMagic.Length
            && data[0] == BufferWriterCapacityMarker
            && data.Slice(1, WriterLifecycleMagic.Length).SequenceEqual(WriterLifecycleMagic))
        {
            WriterLifecycleCases.Execute();
            return;
        }

        if (data.Length >= 1 + BufferWriterCapacityMagic.Length
            && data[0] == BufferWriterCapacityMarker
            && data.Slice(1, BufferWriterCapacityMagic.Length).SequenceEqual(BufferWriterCapacityMagic))
        {
            BufferWriterCapacityCases.Execute(data.Length > 1 + BufferWriterCapacityMagic.Length
                ? data[1 + BufferWriterCapacityMagic.Length]
                : (byte)0);
            return;
        }

        if (data.Length >= 1 + DatasetWriterOptionsGapMagic.Length
            && data[0] == DatasetWriterOptionsGapMarker
            && data.Slice(1, DatasetWriterOptionsGapMagic.Length).SequenceEqual(DatasetWriterOptionsGapMagic))
        {
            DatasetWriterOptionsGapCases.Execute(data.Length > 1 + DatasetWriterOptionsGapMagic.Length
                ? data[1 + DatasetWriterOptionsGapMagic.Length]
                : (byte)0);
            return;
        }

        if (data.Length >= 1 + ColumnOptionsEqualityMagic.Length
            && data[0] == ColumnOptionsEqualityMarker
            && data.Slice(1, ColumnOptionsEqualityMagic.Length).SequenceEqual(ColumnOptionsEqualityMagic))
        {
            ColumnOptionsEqualityCases.Execute(data.Length > 1 + ColumnOptionsEqualityMagic.Length
                ? data[1 + ColumnOptionsEqualityMagic.Length]
                : (byte)0);
            return;
        }

        if (data.Length >= 1 + RequiredInt32Dictionary17Magic.Length
            && data[0] == RequiredInt32Dictionary17Marker
            && data.Slice(1, RequiredInt32Dictionary17Magic.Length).SequenceEqual(RequiredInt32Dictionary17Magic))
        {
            RequiredInt32Dictionary17WriterCase.Execute();
            return;
        }

        if (data.Length >= 1 + ImportedMissingStatisticsMagic.Length
            && data[0] == ImportedMissingStatisticsMarker
            && data.Slice(1, ImportedMissingStatisticsMagic.Length).SequenceEqual(ImportedMissingStatisticsMagic))
        {
            PlankMergerFuzzTarget.ExecuteImportedMissingStatistics(
                data[(1 + ImportedMissingStatisticsMagic.Length)..]);
            return;
        }

        if (data.Length >= 1 + OptionalDoubleDictionaryMagic.Length
            && data[0] == OptionalDoubleDictionaryCoverageMarker
            && data.Slice(1, OptionalDoubleDictionaryMagic.Length).SequenceEqual(OptionalDoubleDictionaryMagic))
        {
            OptionalDoubleDictionaryCoverageCases.Execute(data[(1 + OptionalDoubleDictionaryMagic.Length)..]);
            return;
        }

        if (data.Length >= 1 + OptionalInt64DictionaryMagic.Length
            && data[0] == OptionalInt64DictionaryCoverageMarker
            && data.Slice(1, OptionalInt64DictionaryMagic.Length).SequenceEqual(OptionalInt64DictionaryMagic))
        {
            OptionalInt64DictionaryCoverageCases.Execute(data[(1 + OptionalInt64DictionaryMagic.Length)..]);
            return;
        }

        if (data.Length >= 1 + OptionalUuidBloomGapMagic.Length
            && data[0] == OptionalUuidBloomGapMarker
            && data.Slice(1, OptionalUuidBloomGapMagic.Length).SequenceEqual(OptionalUuidBloomGapMagic))
        {
            OptionalUuidBloomGapWriterCases.Execute(data[(1 + OptionalUuidBloomGapMagic.Length)..]);
            return;
        }

        if (data.Length >= 1 + DifferentWriteSourceResetMagic.Length
            && data[0] == DifferentWriteSourceResetMarker
            && data.Slice(1, DifferentWriteSourceResetMagic.Length).SequenceEqual(DifferentWriteSourceResetMagic))
        {
            DifferentWriteSourceResetWriterCases.Execute(data.Length > 1 + DifferentWriteSourceResetMagic.Length
                ? data[1 + DifferentWriteSourceResetMagic.Length]
                : (byte)128);
            return;
        }

        if (data.Length >= 1 + RowApiGrowthMagic.Length
            && data[0] == RowApiGrowthMarker
            && data.Slice(1, RowApiGrowthMagic.Length).SequenceEqual(RowApiGrowthMagic))
        {
            RowApiGrowthWriterCases.Execute(data[(1 + RowApiGrowthMagic.Length)..]);
            return;
        }

        if (data.Length >= 1 + OptionalDecimalBloomGapMagic.Length
            && data[0] == OptionalDecimalBloomGapMarker
            && data.Slice(1, OptionalDecimalBloomGapMagic.Length).SequenceEqual(OptionalDecimalBloomGapMagic))
        {
            OptionalDecimalBloomGapWriterCases.Execute(data[(1 + OptionalDecimalBloomGapMagic.Length)..]);
            return;
        }

        if (data.Length >= 1 + SameStreamResetMagic.Length
            && data[0] == SameStreamResetMarker
            && data.Slice(1, SameStreamResetMagic.Length).SequenceEqual(SameStreamResetMagic))
        {
            SameStreamResetWriterCases.Execute(data.Length > 1 + SameStreamResetMagic.Length
                ? data[1 + SameStreamResetMagic.Length]
                : (byte)0);
            return;
        }

        if (data.Length >= 1 + FixedBinaryDeltaMagic.Length
            && data[0] == FixedBinaryDeltaMarker
            && data.Slice(1, FixedBinaryDeltaMagic.Length).SequenceEqual(FixedBinaryDeltaMagic))
        {
            FixedBinaryDeltaWriterCases.Execute(data[(1 + FixedBinaryDeltaMagic.Length)..]);
            return;
        }

        if (data.Length >= 1 + ImportValidationMagic.Length + 1
            && data[0] == ImportValidationMarker
            && data.Slice(1, ImportValidationMagic.Length).SequenceEqual(ImportValidationMagic))
        {
            ImportValidationCoverageCases.Execute(data[(1 + ImportValidationMagic.Length)..]);
            return;
        }

        if (data.Length >= 1 + NonSeekableStreamMagic.Length
            && data[0] == NonSeekableStreamMarker
            && data.Slice(1, NonSeekableStreamMagic.Length).SequenceEqual(NonSeekableStreamMagic))
        {
            NonSeekableStreamWriterCases.Execute(data.Length > 1 + NonSeekableStreamMagic.Length
                ? data[1 + NonSeekableStreamMagic.Length]
                : (byte)0);
            return;
        }

        if (data.Length >= 1 + DatasetOperationalMagic.Length
            && data[0] == DatasetMarker
            && data.Slice(1, DatasetOperationalMagic.Length).SequenceEqual(DatasetOperationalMagic))
        {
            PlankDatasetOperationalFuzzTarget.Execute(data[(1 + DatasetOperationalMagic.Length)..]);
            return;
        }

        if (data.Length >= 1 + NullableListBloomMagic.Length
            && data[0] == NestedBloomMarker
            && data.Slice(1, NullableListBloomMagic.Length).SequenceEqual(NullableListBloomMagic))
        {
            BloomFilterWriterCases.ExerciseNullableListBloom();
            return;
        }

        if (data.Length >= 1 + NestedBloomMagic.Length
            && data[0] == NestedBloomMarker
            && data.Slice(1, NestedBloomMagic.Length).SequenceEqual(NestedBloomMagic))
        {
            BloomFilterWriterCases.ExerciseNestedRepeatedBloom(
                data.Length > 1 + NestedBloomMagic.Length ? data[1 + NestedBloomMagic.Length] : (byte)0);
            return;
        }

        if (!data.IsEmpty && data[0] == RowApiMarker)
        {
            PlankRowApiFuzzTarget.Execute(data[1..]);
            return;
        }

        if (data.Length >= 1 + DatasetBinaryMagic.Length
            && data[0] == DatasetMarker
            && data.Slice(1, DatasetBinaryMagic.Length).SequenceEqual(DatasetBinaryMagic))
        {
            PlankDatasetBinaryFuzzTarget.Execute(data[(1 + DatasetBinaryMagic.Length)..]);
            return;
        }

        if (!data.IsEmpty && data[0] == DatasetMarker)
        {
            PlankDatasetFuzzTarget.Execute(data[1..]);
            return;
        }

        if (!data.IsEmpty && data[0] == MergerMarker)
        {
            PlankMergerFuzzTarget.Execute(data[1..]);
            return;
        }

        if (!data.IsEmpty && data[0] == CrossWriterMarker)
        {
            PlankCrossWriterFuzzTarget.Execute(data[1..]);
            return;
        }

        if (!data.IsEmpty && data[0] == OptionalDoubleDictionaryMarker)
        {
            var pageVersion = data.Length > 1 && (data[1] & 1) != 0
                ? PlankDataPageVersion.V1
                : PlankDataPageVersion.V2;
            Validate(CreateOptionalDoubleDictionaryCase(pageVersion, data[1..]));
            return;
        }

        if (!data.IsEmpty && data[0] == OptionalForcedIntegerDictionaryMarker)
        {
            var pageVersion = data.Length > 1 && (data[1] & 1) != 0
                ? PlankDataPageVersion.V1
                : PlankDataPageVersion.V2;
            Validate(CreateOptionalForcedIntegerDictionaryCase(pageVersion, data[1..]));
            return;
        }

        if (!data.IsEmpty && data[0] == OptionalPlainTimestampMarker)
        {
            var pageVersion = data.Length > 1 && (data[1] & 1) != 0
                ? PlankDataPageVersion.V1
                : PlankDataPageVersion.V2;
            ExerciseOptionalPlainTimestampCase(pageVersion, data[1..]);
            return;
        }

        if (!data.IsEmpty && data[0] == LogicalMetadataMarker)
        {
            LogicalMetadataWriterCases.Execute(data.Length > 1 ? data[1] : (byte)0);
            return;
        }

        if (!data.IsEmpty && data[0] == BloomFilterMarker)
        {
            BloomFilterWriterCases.Execute(data.Length > 1 ? data[1] : (byte)0);
            return;
        }

        if (!data.IsEmpty && data[0] == CompressionLevelMarker)
        {
            CompressionLevelWriterCases.Execute(data.Length > 1 ? data[1] : (byte)0);
            return;
        }

        if (data.Length >= 1 + EncodingCoverageMagic.Length
            && data[0] == EncodingCoverageMarker
            && data.Slice(1, EncodingCoverageMagic.Length).SequenceEqual(EncodingCoverageMagic))
        {
            EncodingCoverageWriterCases.Execute(data[(1 + EncodingCoverageMagic.Length)..]);
            return;
        }

        if (data.Length >= WriterMetadataMagic.Length
            && data[..WriterMetadataMagic.Length].SequenceEqual(WriterMetadataMagic))
        {
            WriterMetadataCases.Execute(data[WriterMetadataMagic.Length..]);
            return;
        }

        if (!data.IsEmpty && data[0] == RepeatedRowsMarker)
        {
            var pageVersion = data.Length > 1 && (data[1] & 1) != 0
                ? PlankDataPageVersion.V1
                : PlankDataPageVersion.V2;
            var controls = data.Length > 2 ? data[2..] : ReadOnlySpan<byte>.Empty;
            if (data.Length > 1 && (data[1] & 2) != 0)
            {
                switch (data[1] >> 3)
                {
                    case 1:
                        ExerciseNestedTypedRowsCase(pageVersion, controls, ParquetPhysicalType.Boolean,
                            static (row, inner, value, seed) => ((row + inner + value + seed) & 1) != 0);
                        break;
                    case 2:
                        ExerciseNestedTypedRowsCase(pageVersion, controls, ParquetPhysicalType.Int64,
                            static (row, inner, value, seed) => (long)(seed - 128) * 1024 + row * 31L + inner * 7L + value);
                        break;
                    case 3:
                        ExerciseNestedTypedRowsCase(pageVersion, controls, ParquetPhysicalType.Float,
                            static (row, inner, value, seed) => (seed - 128) / 8f + row * 1.25f + inner / 4f + value / 8f);
                        break;
                    case 4:
                        ExerciseNestedTypedRowsCase(pageVersion, controls, ParquetPhysicalType.Double,
                            static (row, inner, value, seed) => (seed - 128) / 8d + row * 1.25d + inner / 4d + value / 8d);
                        break;
                    default:
                        ExerciseNestedRowsCase(pageVersion, controls);
                        break;
                }
            }
            else if (data.Length > 1 && ((data[1] >> 3) % 6) != 0)
                ExerciseTypedRepeatedRowsCase(pageVersion, (data[1] >> 3) % 6,
                    (data[1] & 4) != 0, controls);
            else
                ExerciseRepeatedRowsCase(pageVersion, data.Length > 1 && (data[1] & 4) != 0, controls);
            return;
        }

        if (!data.IsEmpty && data[0] == ValueConverterMarker)
        {
            if (data.Length >= 5 && data[1..5].SequenceEqual("VCX1"u8))
            {
                ValueConverterMatrixWriterCases.Execute(data[5..]);
                return;
            }

            Validate(CreateValueConverterCase(data[1..]));
            return;
        }

        if (!data.IsEmpty && data[0] == AppendSortingMarker)
        {
            // oracle agent: here Plank decides whether the declared order survives the append.
            FullValueOracle.SortDeclarationsAreClaims = true;
            try { ExerciseAppendSortingCase(data[1..]); }
            finally { FullValueOracle.SortDeclarationsAreClaims = false; }
            return;
        }

        if (data.Length >= 1 + LatestRowGroupValuesMagic.Length + 1
            && data[0] == LatestRowGroupValuesMarker
            && data.Slice(1, LatestRowGroupValuesMagic.Length).SequenceEqual(LatestRowGroupValuesMagic))
        {
            LatestRowGroupValuesCoverageCases.Execute(data[(1 + LatestRowGroupValuesMagic.Length)..]);
            return;
        }


        Validate(Decode(data));
    }

    static FuzzCase CreateOptionalDoubleDictionaryCase(PlankDataPageVersion pageVersion,
        ReadOnlySpan<byte> controls)
    {
        var writePageIndexes = (Control(controls, 0, 0) & 2) == 0;
        var column = PlankColumn.Leaf("double-dictionary", ParquetPhysicalType.Double,
            new ColumnOptions(ParquetRepetition.Optional,
                encodings: SingleEncoding(EncodingKind.RleDictionary)),
            pageStrategy: writePageIndexes ? null : ForceDictionaryPageStrategy.Shared);
        var rowControl = controls.Length > 1 ? controls[1] : (byte)7;
        var paletteControl = controls.Length > 2 ? controls[2] : (byte)2;
        var stepControl = controls.Length > 3 ? controls[3] : (byte)0;
        var offsetControl = controls.Length > 4 ? controls[4] : (byte)0;
        var pageControl = controls.Length > 5 ? controls[5] : (byte)1;
        var rowCount = 128 + (rowControl & 15) * 128;
        var paletteSize = new[] { 1, 2, 3, 7, 16, 32, 64 }[paletteControl % 7];
        var step = stepControl % 7 + 1;
        var offset = offsetControl % paletteSize;
        var pageSize = new uint[] { 128, 256, 512 }[pageControl % 3];
        var values = new double?[rowCount];
        for (var i = 0; i < values.Length; i++)
            values[i] = ((i * step + offset) % paletteSize) - paletteSize / 2d;

        return new FuzzCase(
            [new ColumnSpec(column, typeof(double?))],
            [[values]],
            CompressionKind.None,
            new WriterSettings(pageVersion, WritePageCrc: true, WritePageIndexes: writePageIndexes,
                FileVersion: PlankFileVersion.V1, TargetDataPageSizeBytes: pageSize,
                BufferChunkSizeBytes: 128, WithKeyValueMetadata: false));
    }

    static FuzzCase CreateOptionalForcedIntegerDictionaryCase(PlankDataPageVersion pageVersion,
        ReadOnlySpan<byte> controls)
    {
        var useInt64 = (Control(controls, 1, 0) & 1) != 0;
        var rowCount = 128 + (Control(controls, 2, 3) & 7) * 64;
        var paletteSize = new[] { 1, 2, 3, 5, 7, 16, 32 }[Control(controls, 3, 2) % 7];
        var step = 1 + Control(controls, 4, 1) % 7;
        var offset = Control(controls, 5, 0) % paletteSize;
        var nullPeriod = 2 + Control(controls, 7, 3) % 7;
        var pageSize = new uint[] { 64, 128, 256 }[Control(controls, 6, 1) % 3];
        if (useInt64)
        {
            var values = new long?[rowCount];
            for (var i = 0; i < values.Length; i++)
                values[i] = i != 0 && (i + offset) % nullPeriod == 0
                    ? null
                    : ((i * step + offset) % paletteSize) - paletteSize / 2L;
            var column = PlankColumn.Leaf("optional-forced-i64", ParquetPhysicalType.Int64,
                new ColumnOptions(ParquetRepetition.Optional,
                    encodings: SingleEncoding(EncodingKind.RleDictionary)),
                pageStrategy: ForceDictionaryPageStrategy.Shared);
            return new FuzzCase(
                [new ColumnSpec(column, typeof(long?))], [[values]], CompressionKind.None,
                new WriterSettings(pageVersion, WritePageCrc: true, WritePageIndexes: false,
                    FileVersion: PlankFileVersion.V1, TargetDataPageSizeBytes: pageSize,
                    BufferChunkSizeBytes: 128, WithKeyValueMetadata: false));
        }
        else
        {
            var values = new int?[rowCount];
            for (var i = 0; i < values.Length; i++)
                values[i] = i != 0 && (i + offset) % nullPeriod == 0
                    ? null
                    : ((i * step + offset) % paletteSize) - paletteSize / 2;
            var column = PlankColumn.Leaf("optional-forced-i32", ParquetPhysicalType.Int32,
                new ColumnOptions(ParquetRepetition.Optional,
                    encodings: SingleEncoding(EncodingKind.RleDictionary)),
                pageStrategy: ForceDictionaryPageStrategy.Shared);
            return new FuzzCase(
                [new ColumnSpec(column, typeof(int?))], [[values]], CompressionKind.None,
                new WriterSettings(pageVersion, WritePageCrc: true, WritePageIndexes: false,
                    FileVersion: PlankFileVersion.V1, TargetDataPageSizeBytes: pageSize,
                    BufferChunkSizeBytes: 128, WithKeyValueMetadata: false));
        }
    }

    static void ExerciseOptionalPlainTimestampCase(PlankDataPageVersion pageVersion,
        ReadOnlySpan<byte> controls)
    {
        var flags = Control(controls, 0, 0);
        var unit = (flags & 2) == 0 ? Plank.Schema.TimeUnit.Millis : Plank.Schema.TimeUnit.Micros;
        var adjustedToUtc = (flags & 4) != 0;
        var writePageIndexes = (flags & 8) != 0;
        var rowCount = (flags & 16) != 0 ? 0 : 8 + Control(controls, 1, 24) % 57;
        var allNull = (flags & 32) != 0;
        var step = 1 + Control(controls, 2, 37) % 997;
        var offset = (Control(controls, 3, 128) - 128) * 10_000L;
        var nullPeriod = 2 + Control(controls, 4, 5) % 11;
        var nullOffset = Control(controls, 5, 1) % nullPeriod;
        var targetPageSize = new uint[] { 16, 32, 64 }[Control(controls, 6, 0) % 3];
        var ticksPerUnit = unit == Plank.Schema.TimeUnit.Millis ? TimeSpan.TicksPerMillisecond : 10L;
        var baseTicks = DateTime.UnixEpoch.Ticks + offset * ticksPerUnit;
        var kind = adjustedToUtc ? DateTimeKind.Utc : DateTimeKind.Unspecified;
        var values = new DateTime?[rowCount];
        for (var i = 0; i < values.Length; i++)
        {
            values[i] = allNull || i != 0 && (i + nullOffset) % nullPeriod == 0
                ? null
                : new DateTime(checked(baseTicks + (long)i * step * ticksPerUnit), kind);
        }

        var logicalType = new Plank.Schema.LogicalType.Timestamp(unit, adjustedToUtc);
        var column = PlankColumn.Leaf("optional-timestamp", ParquetPhysicalType.Int64,
            new ColumnOptions(ParquetRepetition.Optional, encodings: SingleEncoding(EncodingKind.Plain)),
            logicalType: logicalType);
        var schema = new PlankSchema([column]);
        using var stream = new MemoryStream();
        var writer = schema.CreateWriter(stream, new ParquetWriterOptions
        {
            Compression = CompressionKind.None,
            DataPageVersion = pageVersion,
            WritePageCrc = true,
            WritePageIndexes = writePageIndexes,
            TargetDataPageSizeBytes = targetPageSize,
            BufferChunkSizeBytes = 128
        });
        var rowGroup = writer.StartRowGroup();
        var serialized = rowGroup.CreateSerializedColumn<DateTime?>(schema.LeafColumns[0]);
        serialized.Serialize(values);
        rowGroup.Write(serialized);
        writer.CloseFile();

        using var source = FullValueOracle.Source(stream.ToArray());
        using var reader = schema.CreateReader(source);
        if (reader.RowGroups.Count != 1 || reader.RowGroups[0].RowCount != (ulong)rowCount)
            throw new InvalidOperationException("Optional timestamp route changed the row-group shape.");
        var actual = ReadAllBuffers(reader.RowGroups[0].Column<DateTime?>(schema.LeafColumns[0]));
        if (actual.Length != values.Length)
            throw new InvalidOperationException("Optional timestamp route changed the row count.");
        for (var i = 0; i < values.Length; i++)
        {
            if (values[i].HasValue != actual[i].HasValue ||
                (values[i] is { } expected && actual[i] is { } observed &&
                    (expected.Ticks != observed.Ticks || expected.Kind != observed.Kind)))
                throw new InvalidOperationException($"Optional timestamp route changed value/null at row {i}.");
        }
    }

    static void ExerciseRepeatedRowsCase(PlankDataPageVersion pageVersion, bool optionalElements,
        ReadOnlySpan<byte> controls)
    {
        var column = optionalElements
            ? PlankColumn.List("repeated-values",
                PlankColumn.OptionalLeaf("element", ParquetPhysicalType.Int32,
                    new ColumnOptions(encodings: SingleEncoding(EncodingKind.Plain))))
            : PlankColumn.Leaf("repeated-values", ParquetPhysicalType.Int32,
                new ColumnOptions(ParquetRepetition.Repeated, encodings: SingleEncoding(EncodingKind.Plain)));
        var schema = new PlankSchema([column]);
        var rowCount = 2 + Control(controls, 0, 2) % 7;
        var presentValueCount = 0;
        var valueBase = Control(controls, rowCount + 1, 13) - 128;
        Array rows;
        if (optionalElements)
        {
            var nullableRows = new int?[rowCount][];
            for (var rowIndex = 0; rowIndex < rowCount; rowIndex++)
            {
                var length = 1 + Control(controls, rowIndex + 1, rowIndex + 1) % 5;
                nullableRows[rowIndex] = new int?[length];
                for (var elementIndex = 0; elementIndex < length; elementIndex++)
                {
                    var isNull = elementIndex != 0
                        && (Control(controls, rowIndex + elementIndex + 2, rowIndex * 3 + elementIndex) & 1) != 0;
                    nullableRows[rowIndex][elementIndex] = isNull
                        ? null
                        : valueBase + rowIndex * 17 + elementIndex * 3;
                    if (!isNull)
                        presentValueCount++;
                }
            }
            rows = nullableRows;
        }
        else
        {
            var requiredRows = new int[rowCount][];
            for (var rowIndex = 0; rowIndex < rowCount; rowIndex++)
            {
                var length = 1 + Control(controls, rowIndex + 1, rowIndex + 1) % 5;
                requiredRows[rowIndex] = new int[length];
                for (var elementIndex = 0; elementIndex < length; elementIndex++)
                    requiredRows[rowIndex][elementIndex] = valueBase + rowIndex * 17 + elementIndex * 3;
                presentValueCount += length;
            }
            rows = requiredRows;
        }
        using var stream = new MemoryStream();
        var writer = schema.CreateWriter(stream, new ParquetWriterOptions
        {
            Compression = CompressionKind.None,
            DataPageVersion = pageVersion,
            WritePageCrc = true,
            WritePageIndexes = true,
            TargetDataPageSizeBytes = 32,
            BufferChunkSizeBytes = 64
        });
        var rowGroup = writer.StartRowGroup();
        if (optionalElements)
        {
            var serialized = rowGroup.CreateSerializedColumn<int?[]>(schema.LeafColumns[0]);
            serialized.Serialize((int?[][])rows);
            rowGroup.Write(serialized);
        }
        else
        {
            var serialized = rowGroup.CreateSerializedColumn<int[]>(schema.LeafColumns[0]);
            serialized.Serialize((int[][])rows);
            rowGroup.Write(serialized);
        }
        writer.CloseFile();

        var bytes = stream.ToArray();
        using var reader = schema.CreateReader(FullValueOracle.Source(bytes));
        var expectedValues = new List<int>(presentValueCount);
        var expectedRepetitions = new List<int>();
        var expectedDefinitions = new List<int>();
        var maxDefinitionLevel = schema.LeafColumns[0].MaxDefinitionLevel;
        if (optionalElements)
        {
            foreach (var row in (int?[][])rows)
                for (var i = 0; i < row.Length; i++)
                {
                    expectedRepetitions.Add(i == 0 ? 0 : 1);
                    if (row[i] is { } value)
                    {
                        expectedValues.Add(value);
                        expectedDefinitions.Add(maxDefinitionLevel);
                    }
                    else
                        expectedDefinitions.Add(maxDefinitionLevel - 1);
                }
        }
        else
            foreach (var row in (int[][])rows)
                for (var i = 0; i < row.Length; i++)
                {
                    expectedValues.Add(row[i]);
                    expectedRepetitions.Add(i == 0 ? 0 : 1);
                    expectedDefinitions.Add(maxDefinitionLevel);
                }
        AssertNestedRows(reader.RowGroups[0], schema.LeafColumns[0], rowCount,
            expectedValues, expectedRepetitions, expectedDefinitions, "repeated");
    }

    static void ExerciseNestedRowsCase(PlankDataPageVersion pageVersion, ReadOnlySpan<byte> controls)
    {
        var schema = new PlankSchema([
            PlankColumn.List("nested-values",
                PlankColumn.List("nested-list",
                    PlankColumn.OptionalLeaf("element", ParquetPhysicalType.Int32,
                        new ColumnOptions(encodings: SingleEncoding(EncodingKind.Plain)))))
        ]);
        var rowCount = 2 + Control(controls, 0, 1) % 7;
        var rows = new int?[rowCount][][];
        var presentValueCount = 0;
        var valueBase = Control(controls, rowCount + 1, 19) - 128;
        for (var rowIndex = 0; rowIndex < rowCount; rowIndex++)
        {
            var innerCount = rowIndex == 0
                ? 1 + Control(controls, rowIndex + 1, 1) % 4
                : Control(controls, rowIndex + 1, rowIndex) % 4;
            rows[rowIndex] = new int?[innerCount][];
            for (var innerIndex = 0; innerIndex < innerCount; innerIndex++)
            {
                var length = rowIndex == 0 && innerIndex == 0
                    ? 1 + Control(controls, rowIndex + innerIndex + 2, 1) % 4
                    : Control(controls, rowIndex + innerIndex + 2, innerIndex) % 5;
                rows[rowIndex][innerIndex] = new int?[length];
                for (var valueIndex = 0; valueIndex < length; valueIndex++)
                {
                    var isNull = !(rowIndex == 0 && innerIndex == 0 && valueIndex == 0)
                        && (Control(controls, rowIndex + innerIndex + valueIndex + 3,
                            rowIndex + innerIndex + valueIndex) & 3) == 0;
                    rows[rowIndex][innerIndex][valueIndex] = isNull
                        ? null
                        : valueBase + rowIndex * 31 + innerIndex * 7 + valueIndex;
                    if (!isNull)
                        presentValueCount++;
                }
            }
        }
        using var stream = new MemoryStream();
        var writer = schema.CreateWriter(stream, new ParquetWriterOptions
        {
            Compression = CompressionKind.None,
            DataPageVersion = pageVersion,
            WritePageCrc = true,
            WritePageIndexes = true,
            TargetDataPageSizeBytes = 32,
            BufferChunkSizeBytes = 64
        });
        var rowGroup = writer.StartRowGroup();
        var serialized = rowGroup.CreateSerializedColumn<int?[][]>(schema.LeafColumns[0]);
        serialized.Serialize(rows);
        rowGroup.Write(serialized);
        writer.CloseFile();

        using var reader = schema.CreateReader(FullValueOracle.Source(stream.ToArray()));
        var expectedValues = new List<int>(presentValueCount);
        var expectedRepetitions = new List<int>();
        var expectedDefinitions = new List<int>();
        var maxDefinitionLevel = schema.LeafColumns[0].MaxDefinitionLevel;
        for (var rowIndex = 0; rowIndex < rows.Length; rowIndex++)
        {
            var outer = rows[rowIndex];
            if (outer.Length == 0)
            {
                expectedRepetitions.Add(0);
                expectedDefinitions.Add(0);
                continue;
            }
            for (var outerIndex = 0; outerIndex < outer.Length; outerIndex++)
            {
                var outerRepetition = outerIndex == 0 ? 0 : 1;
                var inner = outer[outerIndex];
                if (inner.Length == 0)
                {
                    expectedRepetitions.Add(outerRepetition);
                    expectedDefinitions.Add(1);
                    continue;
                }
                for (var innerIndex = 0; innerIndex < inner.Length; innerIndex++)
                {
                    var value = inner[innerIndex];
                    expectedRepetitions.Add(innerIndex == 0 ? outerRepetition : 2);
                    if (value is { } present)
                    {
                        expectedValues.Add(present);
                        expectedDefinitions.Add(maxDefinitionLevel);
                    }
                    else
                        expectedDefinitions.Add(maxDefinitionLevel - 1);
                }
            }
        }
        AssertNestedRows(reader.RowGroups[0], schema.LeafColumns[0], rowCount,
            expectedValues, expectedRepetitions, expectedDefinitions, "nested");
    }

    static void ExerciseNestedTypedRowsCase<T>(PlankDataPageVersion pageVersion,
        ReadOnlySpan<byte> controls, ParquetPhysicalType physicalType,
        Func<int, int, int, int, T> createValue)
        where T : struct
    {
        var schema = new PlankSchema([
            PlankColumn.List("nested-values",
                PlankColumn.List("nested-list",
                    PlankColumn.OptionalLeaf("element", physicalType,
                        new ColumnOptions(encodings: SingleEncoding(EncodingKind.Plain)))))
        ]);
        var rowCount = 2 + Control(controls, 0, 1) % 7;
        var rows = new T?[rowCount][][];
        var expectedValues = new List<T>();
        var repetitions = new List<int>();
        var definitions = new List<int>();
        var valueSeed = Control(controls, rowCount + 1, 19);
        for (var row = 0; row < rowCount; row++)
        {
            var innerCount = row == 0
                ? 1 + Control(controls, row + 1, 1) % 4
                : Control(controls, row + 1, row) % 4;
            rows[row] = new T?[innerCount][];
            for (var inner = 0; inner < innerCount; inner++)
            {
                var length = row == 0 && inner == 0
                    ? 1 + Control(controls, row + inner + 2, 1) % 4
                    : Control(controls, row + inner + 2, inner) % 5;
                rows[row][inner] = new T?[length];
                if (length == 0)
                {
                    repetitions.Add(inner == 0 ? 0 : 1);
                    definitions.Add(1);
                    continue;
                }
                for (var value = 0; value < length; value++)
                {
                    var isNull = !(row == 0 && inner == 0 && value == 0) &&
                        (Control(controls, row + inner + value + 3, row + inner + value) & 3) == 0;
                    repetitions.Add(value == 0 ? inner == 0 ? 0 : 1 : 2);
                    if (isNull)
                    {
                        definitions.Add(schema.LeafColumns[0].MaxDefinitionLevel - 1);
                        continue;
                    }
                    rows[row][inner][value] = createValue(row, inner, value, valueSeed);
                    expectedValues.Add(rows[row][inner][value]!.Value);
                    definitions.Add(schema.LeafColumns[0].MaxDefinitionLevel);
                }
            }
            if (innerCount == 0)
            {
                repetitions.Add(0);
                definitions.Add(0);
            }
        }
        using var stream = new MemoryStream();
        var writer = schema.CreateWriter(stream, new ParquetWriterOptions
        {
            Compression = CompressionKind.None,
            DataPageVersion = pageVersion,
            WritePageCrc = true,
            WritePageIndexes = true,
            TargetDataPageSizeBytes = 32,
            BufferChunkSizeBytes = 64
        });
        var rowGroup = writer.StartRowGroup();
        var serialized = rowGroup.CreateSerializedColumn<T?[][]>(schema.LeafColumns[0]);
        serialized.Serialize(rows);
        rowGroup.Write(serialized);
        writer.CloseFile();
        using var source = FullValueOracle.Source(stream.ToArray());
        using var reader = schema.CreateReader(source);
        AssertNestedRows(reader.RowGroups[0], schema.LeafColumns[0], rowCount,
            expectedValues, repetitions, definitions, "typed nested");
    }

    static void ExerciseTypedRepeatedRowsCase(PlankDataPageVersion pageVersion, int kind,
        bool optionalElements, ReadOnlySpan<byte> controls)
    {
        switch (kind)
        {
            case 1:
                if (optionalElements)
                    ExerciseOptionalRepeatedValues(pageVersion, ParquetPhysicalType.Boolean, controls,
                        static (row, element, seed) => ((row + element + seed) & 1) != 0);
                else
                    ExerciseRequiredRepeatedValues(pageVersion, ParquetPhysicalType.Boolean, controls,
                        static (row, element, seed) => ((row + element + seed) & 1) != 0);
                break;
            case 2:
                if (optionalElements)
                    ExerciseOptionalRepeatedValues(pageVersion, ParquetPhysicalType.Int64, controls,
                        static (row, element, seed) => (long)(seed - 128) * 1024 + row * 31L + element * 7L);
                else
                    ExerciseRequiredRepeatedValues(pageVersion, ParquetPhysicalType.Int64, controls,
                        static (row, element, seed) => (long)(seed - 128) * 1024 + row * 31L + element * 7L);
                break;
            case 3:
                if (optionalElements)
                    ExerciseOptionalRepeatedValues(pageVersion, ParquetPhysicalType.Float, controls,
                        static (row, element, seed) => (seed - 128) / 8f + row * 1.25f + element / 4f);
                else
                    ExerciseRequiredRepeatedValues(pageVersion, ParquetPhysicalType.Float, controls,
                        static (row, element, seed) => (seed - 128) / 8f + row * 1.25f + element / 4f);
                break;
            case 4:
                if (optionalElements)
                    ExerciseOptionalRepeatedValues(pageVersion, ParquetPhysicalType.Double, controls,
                        static (row, element, seed) => (seed - 128) / 8d + row * 1.25d + element / 4d);
                else
                    ExerciseRequiredRepeatedValues(pageVersion, ParquetPhysicalType.Double, controls,
                        static (row, element, seed) => (seed - 128) / 8d + row * 1.25d + element / 4d);
                break;
            default:
                if (optionalElements)
                    ExerciseOptionalRepeatedBinaryRows(pageVersion, controls);
                else
                    ExerciseRequiredRepeatedBinaryRows(pageVersion, controls);
                break;
        }
    }

    static void ExerciseRequiredRepeatedValues<T>(PlankDataPageVersion pageVersion,
        ParquetPhysicalType physicalType, ReadOnlySpan<byte> controls, Func<int, int, int, T> createValue)
        where T : notnull
    {
        var rowCount = 2 + Control(controls, 0, 3) % 6;
        var valueSeed = Control(controls, 1, 37);
        var rows = new T[rowCount][];
        var expectedValues = new List<T>();
        var repetitions = new List<int>();
        var definitions = new List<int>();
        for (var row = 0; row < rowCount; row++)
        {
            var length = 1 + Control(controls, row + 2, row + 1) % 5;
            rows[row] = new T[length];
            for (var element = 0; element < length; element++)
            {
                var value = createValue(row, element, valueSeed);
                rows[row][element] = value;
                expectedValues.Add(value);
                repetitions.Add(element == 0 ? 0 : 1);
            }
        }

        var schema = new PlankSchema([
            PlankColumn.Leaf("repeated-values", physicalType,
                new ColumnOptions(ParquetRepetition.Repeated, encodings: SingleEncoding(EncodingKind.Plain)))
        ]);
        var maxDefinition = schema.LeafColumns[0].MaxDefinitionLevel;
        for (var i = 0; i < expectedValues.Count; i++)
            definitions.Add(maxDefinition);
        WriteAndAssertRepeatedRows(schema, pageVersion, rows, expectedValues, repetitions, definitions,
            "typed repeated");
    }

    static void ExerciseOptionalRepeatedValues<T>(PlankDataPageVersion pageVersion,
        ParquetPhysicalType physicalType, ReadOnlySpan<byte> controls, Func<int, int, int, T> createValue)
        where T : struct
    {
        var rowCount = 2 + Control(controls, 0, 3) % 6;
        var valueSeed = Control(controls, 1, 37);
        var rows = new T?[rowCount][];
        var expectedValues = new List<T>();
        var repetitions = new List<int>();
        var definitions = new List<int>();
        var schema = new PlankSchema([
            PlankColumn.List("repeated-values",
                PlankColumn.OptionalLeaf("element", physicalType,
                    new ColumnOptions(encodings: SingleEncoding(EncodingKind.Plain))))
        ]);
        var maxDefinition = schema.LeafColumns[0].MaxDefinitionLevel;
        for (var row = 0; row < rowCount; row++)
        {
            var length = Control(controls, row + 2, row + 1) % 5;
            rows[row] = new T?[length];
            if (length == 0)
            {
                repetitions.Add(0);
                definitions.Add(maxDefinition - 2);
                continue;
            }
            for (var element = 0; element < length; element++)
            {
                var isNull = element != 0 &&
                    (Control(controls, row + element + 3, row * 5 + element) & 1) != 0;
                repetitions.Add(element == 0 ? 0 : 1);
                if (isNull)
                {
                    definitions.Add(maxDefinition - 1);
                    continue;
                }
                var value = createValue(row, element, valueSeed);
                rows[row][element] = value;
                expectedValues.Add(value);
                definitions.Add(maxDefinition);
            }
        }
        WriteAndAssertOptionalRepeatedRows(schema, pageVersion, rows, expectedValues, repetitions,
            definitions, "optional typed repeated");
    }

    static void ExerciseRequiredRepeatedBinaryRows(PlankDataPageVersion pageVersion,
        ReadOnlySpan<byte> controls)
    {
        var rowCount = 2 + Control(controls, 0, 3) % 6;
        var valueSeed = Control(controls, 1, 37);
        var rows = new byte[rowCount][][];
        var expectedValues = new List<byte[]>();
        var repetitions = new List<int>();
        var definitions = new List<int>();
        for (var row = 0; row < rowCount; row++)
        {
            var length = 1 + Control(controls, row + 2, row + 1) % 4;
            rows[row] = new byte[length][];
            for (var element = 0; element < length; element++)
            {
                var bytes = new byte[1 + Control(controls, row + element + 4, element + 1) % 8];
                for (var i = 0; i < bytes.Length; i++)
                    bytes[i] = (byte)(valueSeed + row * 19 + element * 7 + i * 23);
                rows[row][element] = bytes;
                expectedValues.Add(bytes);
                repetitions.Add(element == 0 ? 0 : 1);
            }
        }
        var schema = new PlankSchema([
            PlankColumn.Leaf("repeated-binary", ParquetPhysicalType.ByteArray,
                new ColumnOptions(ParquetRepetition.Repeated, encodings: SingleEncoding(EncodingKind.Plain)))
        ]);
        for (var i = 0; i < expectedValues.Count; i++)
            definitions.Add(schema.LeafColumns[0].MaxDefinitionLevel);
        using var stream = new MemoryStream();
        var writer = schema.CreateWriter(stream, new ParquetWriterOptions
        {
            Compression = CompressionKind.None,
            DataPageVersion = pageVersion,
            WritePageCrc = true,
            WritePageIndexes = true,
            TargetDataPageSizeBytes = 32,
            BufferChunkSizeBytes = 64
        });
        var rowGroup = writer.StartRowGroup();
        var serialized = rowGroup.CreateSerializedColumn<byte[][]>(schema.LeafColumns[0]);
        serialized.Serialize(rows);
        rowGroup.Write(serialized);
        writer.CloseFile();
        using var source = FullValueOracle.Source(stream.ToArray());
        using var reader = schema.CreateReader(source);
        AssertNestedBinaryRows(reader.RowGroups[0], schema.LeafColumns[0], rowCount,
            expectedValues, repetitions, definitions);
    }

    static void ExerciseOptionalRepeatedBinaryRows(PlankDataPageVersion pageVersion,
        ReadOnlySpan<byte> controls)
    {
        var rowCount = 2 + Control(controls, 0, 3) % 6;
        var valueSeed = Control(controls, 1, 37);
        var rows = new byte[]?[rowCount][];
        var expectedValues = new List<byte[]>();
        var repetitions = new List<int>();
        var definitions = new List<int>();
        var schema = new PlankSchema([
            PlankColumn.List("repeated-binary",
                PlankColumn.OptionalLeaf("element", ParquetPhysicalType.ByteArray,
                    new ColumnOptions(encodings: SingleEncoding(EncodingKind.Plain))))
        ]);
        var maxDefinition = schema.LeafColumns[0].MaxDefinitionLevel;
        for (var row = 0; row < rowCount; row++)
        {
            var length = Control(controls, row + 2, row + 1) % 5;
            rows[row] = new byte[]?[length];
            if (length == 0)
            {
                repetitions.Add(0);
                definitions.Add(maxDefinition - 2);
                continue;
            }
            for (var element = 0; element < length; element++)
            {
                var isNull = element != 0 &&
                    (Control(controls, row + element + 3, row * 5 + element) & 1) != 0;
                repetitions.Add(element == 0 ? 0 : 1);
                if (isNull)
                {
                    definitions.Add(maxDefinition - 1);
                    continue;
                }
                var bytes = new byte[Control(controls, row + element + 4, element + 1) % 8];
                for (var i = 0; i < bytes.Length; i++)
                    bytes[i] = (byte)(valueSeed + row * 19 + element * 7 + i * 23);
                rows[row][element] = bytes;
                expectedValues.Add(bytes);
                definitions.Add(maxDefinition);
            }
        }
        using var stream = new MemoryStream();
        var writer = schema.CreateWriter(stream, new ParquetWriterOptions
        {
            Compression = CompressionKind.None,
            DataPageVersion = pageVersion,
            WritePageCrc = true,
            WritePageIndexes = true,
            TargetDataPageSizeBytes = 32,
            BufferChunkSizeBytes = 64
        });
        var rowGroup = writer.StartRowGroup();
        var serialized = rowGroup.CreateSerializedColumn<byte[]?[]>(schema.LeafColumns[0]);
        serialized.Serialize(rows);
        rowGroup.Write(serialized);
        writer.CloseFile();
        using var source = FullValueOracle.Source(stream.ToArray());
        using var reader = schema.CreateReader(source);
        AssertNestedBinaryRows(reader.RowGroups[0], schema.LeafColumns[0], rowCount,
            expectedValues, repetitions, definitions);
    }

    static void WriteAndAssertRepeatedRows<T>(PlankSchema schema, PlankDataPageVersion pageVersion, T[][] rows,
        List<T> expectedValues, List<int> repetitions, List<int> definitions,
        string shape, Func<T, T, bool>? valuesEqual = null)
        where T : notnull
    {
        using var stream = new MemoryStream();
        var writer = schema.CreateWriter(stream, new ParquetWriterOptions
        {
            Compression = CompressionKind.None,
            DataPageVersion = pageVersion,
            WritePageCrc = true,
            WritePageIndexes = true,
            TargetDataPageSizeBytes = 32,
            BufferChunkSizeBytes = 64
        });
        var rowGroup = writer.StartRowGroup();
        var serialized = rowGroup.CreateSerializedColumn<T[]>(schema.LeafColumns[0]);
        serialized.Serialize(rows);
        rowGroup.Write(serialized);
        writer.CloseFile();
        using var source = FullValueOracle.Source(stream.ToArray());
        using var reader = schema.CreateReader(source);
        AssertNestedRows(reader.RowGroups[0], schema.LeafColumns[0], rows.Length,
            expectedValues, repetitions, definitions, shape, valuesEqual);
    }

    static void AssertNestedBinaryRows(PlankRowGroup rowGroup, LeafColumn column, int expectedRowCount,
        List<byte[]> expectedValues, List<int> expectedRepetitionLevels, List<int> expectedDefinitionLevels)
    {
        var values = new List<byte[]>(expectedValues.Count);
        var repetitionLevels = new List<int>(expectedRepetitionLevels.Count);
        var definitionLevels = new List<int>(expectedDefinitionLevels.Count);
        var rowCount = 0;
        foreach (var buffer in rowGroup.NestedColumn<byte>(column))
        {
            rowCount += buffer.RowCount;
            var valueIndex = 0;
            for (var i = 0; i < buffer.Count; i++)
                if (buffer.DefinitionLevels[i] == buffer.MaxDefinitionLevel)
                    values.Add(buffer.Values.GetValue(valueIndex++).ToArray());
            for (var i = 0; i < buffer.Count; i++)
            {
                repetitionLevels.Add(buffer.RepetitionLevels[i]);
                definitionLevels.Add(buffer.DefinitionLevels[i]);
            }
            if (buffer.MaxRepetitionLevel != column.MaxRepetitionLevel ||
                buffer.MaxDefinitionLevel != column.MaxDefinitionLevel)
                throw new InvalidOperationException("Repeated binary reader returned unexpected maximum levels.");
        }
        if (rowCount != expectedRowCount || values.Count != expectedValues.Count ||
            values.Where((value, i) => !value.AsSpan().SequenceEqual(expectedValues[i])).Any() ||
            !repetitionLevels.SequenceEqual(expectedRepetitionLevels) ||
            !definitionLevels.SequenceEqual(expectedDefinitionLevels))
            throw new InvalidOperationException("Repeated binary round trip changed values or repetition/definition levels.");
    }

    static void WriteAndAssertOptionalRepeatedRows<T>(PlankSchema schema, PlankDataPageVersion pageVersion,
        T?[][] rows, List<T> expectedValues, List<int> repetitions, List<int> definitions, string shape)
        where T : struct
    {
        using var stream = new MemoryStream();
        var writer = schema.CreateWriter(stream, new ParquetWriterOptions
        {
            Compression = CompressionKind.None,
            DataPageVersion = pageVersion,
            WritePageCrc = true,
            WritePageIndexes = true,
            TargetDataPageSizeBytes = 32,
            BufferChunkSizeBytes = 64
        });
        var rowGroup = writer.StartRowGroup();
        var serialized = rowGroup.CreateSerializedColumn<T?[]>(schema.LeafColumns[0]);
        serialized.Serialize(rows);
        rowGroup.Write(serialized);
        writer.CloseFile();
        using var source = FullValueOracle.Source(stream.ToArray());
        using var reader = schema.CreateReader(source);
        AssertNestedRows(reader.RowGroups[0], schema.LeafColumns[0], rows.Length,
            expectedValues, repetitions, definitions, shape);
    }

    static void AssertNestedRows<T>(PlankRowGroup rowGroup, LeafColumn column, int expectedRowCount,
        List<T> expectedValues, List<int> expectedRepetitionLevels, List<int> expectedDefinitionLevels,
        string shape, Func<T, T, bool>? valuesEqual = null)
        where T : notnull
    {
        var values = new List<T>(expectedValues.Count);
        var repetitionLevels = new List<int>(expectedRepetitionLevels.Count);
        var definitionLevels = new List<int>(expectedDefinitionLevels.Count);
        var rowCount = 0;
        foreach (var buffer in rowGroup.NestedColumn<T>(column))
        {
            rowCount += buffer.RowCount;
            values.AddRange(buffer.Values.Values.ToArray());
            for (var i = 0; i < buffer.Count; i++)
            {
                repetitionLevels.Add(buffer.RepetitionLevels[i]);
                definitionLevels.Add(buffer.DefinitionLevels[i]);
            }
            if (buffer.MaxRepetitionLevel != column.MaxRepetitionLevel ||
                buffer.MaxDefinitionLevel != column.MaxDefinitionLevel)
                throw new InvalidOperationException($"{shape} nested reader returned unexpected maximum levels.");
        }

        var valuesMatch = values.Count == expectedValues.Count;
        if (valuesMatch)
            for (var i = 0; i < values.Count; i++)
                if (valuesEqual is null
                    ? !EqualityComparer<T>.Default.Equals(values[i], expectedValues[i])
                    : !valuesEqual(values[i], expectedValues[i]))
                {
                    valuesMatch = false;
                    break;
                }
        if (rowCount != expectedRowCount || !valuesMatch ||
            !repetitionLevels.SequenceEqual(expectedRepetitionLevels) ||
            !definitionLevels.SequenceEqual(expectedDefinitionLevels))
            throw new InvalidOperationException(
                $"{shape} nested round trip mismatch: rows {rowCount}/{expectedRowCount}, " +
                $"values {values.Count}/{expectedValues.Count}, rep {repetitionLevels.Count}/" +
                $"{expectedRepetitionLevels.Count}, def {definitionLevels.Count}/{expectedDefinitionLevels.Count}.");
    }

    static int Control(ReadOnlySpan<byte> controls, int index, int fallback)
        => controls.IsEmpty ? fallback : controls[index % controls.Length];

    static FuzzCase CreateValueConverterCase(ReadOnlySpan<byte> controls)
    {
        var rowCount = 4 + Control(controls, 0, 6) % 13;
        var dataPageVersion = (Control(controls, 1, 0) & 1) == 0
            ? PlankDataPageVersion.V2
            : PlankDataPageVersion.V1;
        var valueBase = (Control(controls, 2, 137) - 128) * 16;
        var step = 1 + Control(controls, 3, 2) % 7;
        var nullMask = Control(controls, 4, 0x2A);

        var intValues = new IntBox[rowCount];
        var longValues = new LongBox?[rowCount];
        var doubleValues = new DoubleBox?[rowCount];
        for (var i = 0; i < rowCount; i++)
        {
            intValues[i] = new(valueBase + i * step);
            longValues[i] = i == 0 || (nullMask & (1 << (i & 7))) == 0
                ? new LongBox((long)valueBase * 1024 + i * step * 3L)
                : null;
            doubleValues[i] = i == 0 || (nullMask & (1 << ((i + 3) & 7))) == 0
                ? new DoubleBox(valueBase / 8d + i * step / 4d)
                : null;
        }

        var columns = new[]
        {
            new ColumnSpec(PlankColumn.RequiredLeaf("box-int32", ParquetPhysicalType.Int32,
                new ColumnOptions(encodings: SingleEncoding(EncodingKind.Plain)), converter: new IntBoxConverter()),
                typeof(IntBox)),
            new ColumnSpec(PlankColumn.OptionalLeaf("box-int64", ParquetPhysicalType.Int64,
                new ColumnOptions(encodings: SingleEncoding(EncodingKind.Plain)), converter: new LongBoxConverter()),
                typeof(LongBox?)),
            new ColumnSpec(PlankColumn.OptionalLeaf("box-double", ParquetPhysicalType.Double,
                new ColumnOptions(encodings: SingleEncoding(EncodingKind.Plain)), converter: new DoubleBoxConverter()),
                typeof(DoubleBox?))
        };
        var pageSize = new uint[] { 16, 64, 256 }[Control(controls, 5, 1) % 3];
        return new FuzzCase(columns, [[intValues, longValues, doubleValues]], CompressionKind.None,
            new WriterSettings(dataPageVersion, WritePageCrc: true, WritePageIndexes: true,
                FileVersion: PlankFileVersion.V1, TargetDataPageSizeBytes: pageSize,
                BufferChunkSizeBytes: 64, WithKeyValueMetadata: false));
    }

    static void ExerciseAppendSortingCase(ReadOnlySpan<byte> controls)
    {
        // Keep the original six selector values stable while giving the
        // comparator's less common CLR representations deterministic routes.
        var kind = Control(controls, 0, 0) % 36;
        var descending = (Control(controls, 1, 0) & 1) != 0;
        var nullsFirst = (Control(controls, 1, 0) & 2) != 0;
        var breakOrder = (Control(controls, 1, 0) & 4) != 0;
        var rowCount = 3 + Control(controls, 2, 2) % 4;
        var step = 1 + Control(controls, 3, 2) % 7;
        var start = (Control(controls, 4, 128) - 128) * 8;
        var sorting = new ParquetSortingColumn(0, descending, nullsFirst);

        switch (kind)
        {
            case 20:
            case 21:
            {
                var retained = new byte[rowCount][];
                var incoming = new byte[rowCount][];
                for (var i = 0; i < rowCount; i++)
                {
                    retained[i] = [(byte)(128 + (descending ? -i : i) * step), 0x41];
                    incoming[i] = [(byte)(128 + (descending ? -(rowCount + i) : rowCount + i) * step), 0x41];
                }
                var schema = new PlankSchema([
                    PlankColumn.RequiredLeaf("key", ParquetPhysicalType.ByteArray,
                        new ColumnOptions(encodings: SingleEncoding(EncodingKind.Plain)))
                ]);
                if (kind == 20)
                    ExerciseAppendSorting(schema, sorting, retained, incoming,
                        static (group, column) => ReadAllBinaryBuffers(group.Column<byte>(column))!,
                        static (expected, actual) => ByteArraysEqual(expected, actual), expectedSorted: true);
                else
                {
                    var retainedMemory = retained.Select(static value => (ReadOnlyMemory<byte>)value).ToArray();
                    var incomingMemory = incoming.Select(static value => (ReadOnlyMemory<byte>)value).ToArray();
                    ExerciseAppendSorting(schema, sorting, retainedMemory, incomingMemory,
                        static (group, column) => ReadBinaryMemoryBuffers(group.Column<byte>(column), 2),
                        static (expected, actual) => BinaryMemoriesEqual(expected, actual), expectedSorted: true);
                }
                break;
            }
            case 22:
                ExerciseAppendSortingTwoColumns(rowCount, step, start, descending);
                break;
            case 23:
                ExerciseAppendWithoutSorting(rowCount, step, start);
                break;
            case 24:
            {
                var retained = new double[rowCount];
                var incoming = new double[rowCount];
                for (var i = 0; i < rowCount; i++)
                    retained[i] = (descending ? rowCount - 1 - i : i - (rowCount - 1)) * step;
                incoming[0] = retained[^1];
                for (var i = 1; i < rowCount; i++)
                    incoming[i] = (descending ? -1 : 1) * i * step;
                var schema = new PlankSchema([
                    PlankColumn.RequiredLeaf("key", ParquetPhysicalType.Double,
                        new ColumnOptions(encodings: SingleEncoding(EncodingKind.Plain)))
                ]);
                ExerciseAppendSorting(schema, sorting, retained, incoming,
                    static (group, column) => ReadAllBuffers(group.Column<double>(column)),
                    static (expected, actual) => expected.SequenceEqual(actual), expectedSorted: true);
                break;
            }
            case 25:
            {
                var retained = new byte[rowCount][];
                var incoming = new byte[rowCount][];
                var first = 100 + start;
                for (var i = 0; i < rowCount; i++)
                    retained[i] = IntervalBytes(first + i * step);
                for (var i = 0; i < rowCount; i++)
                    incoming[i] = IntervalBytes(first + (rowCount + i) * step);
                var schema = new PlankSchema([
                    PlankColumn.RequiredLeaf("key", ParquetPhysicalType.FixedLenByteArray,
                        new ColumnOptions(typeLength: 12, encodings: SingleEncoding(EncodingKind.Plain)),
                        new Plank.Schema.LogicalType.Interval())
                ]);
                ExerciseAppendSorting(schema, sorting, retained, incoming,
                    static (group, column) => ReadAllBinaryBuffers(group.Column<byte>(column))!,
                    static (expected, actual) => ByteArraysEqual(expected, actual), expectedSorted: false);
                break;
            }
            case 26:
            {
                // Exercise the signed CLR carrier with an unsigned INT32 annotation.
                // Values cross the sign bit while their Parquet unsigned order decreases.
                descending = true;
                sorting = new ParquetSortingColumn(0, descending, nullsFirst);
                var retained = new int[rowCount];
                var incoming = new int[rowCount];
                for (var i = 0; i < rowCount; i++)
                    retained[i] = UnsignedInt32DescendingValue(i);
                for (var i = 0; i < rowCount; i++)
                    incoming[i] = UnsignedInt32DescendingValue(rowCount + i);
                var schema = new PlankSchema([
                    PlankColumn.RequiredLeaf("key", ParquetPhysicalType.Int32,
                        new ColumnOptions(encodings: SingleEncoding(EncodingKind.Plain)),
                        new Plank.Schema.LogicalType.Int(32, isSigned: false))
                ]);
                ExerciseAppendSorting(schema, sorting, retained, incoming,
                    static (group, column) => ReadAllBuffers(group.Column<uint>(column))!
                        .Select(static value => unchecked((int)value)).ToArray(),
                    static (expected, actual) => expected.SequenceEqual(actual), expectedSorted: true);
                break;
            }
            case 27:
            {
                // Exercise the unsigned CLR carrier with a signed INT32 annotation.
                descending = false;
                sorting = new ParquetSortingColumn(0, descending, nullsFirst);
                var retained = new uint[rowCount];
                var incoming = new uint[rowCount];
                for (var i = 0; i < rowCount; i++)
                    retained[i] = SignedInt32AscendingBits(i);
                for (var i = 0; i < rowCount; i++)
                    incoming[i] = SignedInt32AscendingBits(rowCount + i);
                var schema = new PlankSchema([
                    PlankColumn.RequiredLeaf("key", ParquetPhysicalType.Int32,
                        new ColumnOptions(encodings: SingleEncoding(EncodingKind.Plain)),
                        new Plank.Schema.LogicalType.Int(32, isSigned: true))
                ]);
                ExerciseAppendSorting(schema, sorting, retained, incoming,
                    static (group, column) => ReadAllBuffers(group.Column<int>(column))!
                        .Select(static value => unchecked((uint)value)).ToArray(),
                    static (expected, actual) => expected.SequenceEqual(actual), expectedSorted: true);
                break;
            }
            case 28:
            {
                // Exercise the signed CLR carrier with an unsigned INT64 annotation.
                descending = true;
                sorting = new ParquetSortingColumn(0, descending, nullsFirst);
                var retained = new long[rowCount];
                var incoming = new long[rowCount];
                for (var i = 0; i < rowCount; i++)
                    retained[i] = UnsignedInt64DescendingValue(i);
                for (var i = 0; i < rowCount; i++)
                    incoming[i] = UnsignedInt64DescendingValue(rowCount + i);
                var schema = new PlankSchema([
                    PlankColumn.RequiredLeaf("key", ParquetPhysicalType.Int64,
                        new ColumnOptions(encodings: SingleEncoding(EncodingKind.Plain)),
                        new Plank.Schema.LogicalType.Int(64, isSigned: false))
                ]);
                ExerciseAppendSorting(schema, sorting, retained, incoming,
                    static (group, column) => ReadAllBuffers(group.Column<ulong>(column))!
                        .Select(static value => unchecked((long)value)).ToArray(),
                    static (expected, actual) => expected.SequenceEqual(actual), expectedSorted: true);
                break;
            }
            case 29:
            {
                // Exercise the unsigned CLR carrier with a signed INT64 annotation.
                descending = false;
                sorting = new ParquetSortingColumn(0, descending, nullsFirst);
                var retained = new ulong[rowCount];
                var incoming = new ulong[rowCount];
                for (var i = 0; i < rowCount; i++)
                    retained[i] = SignedInt64AscendingBits(i);
                for (var i = 0; i < rowCount; i++)
                    incoming[i] = SignedInt64AscendingBits(rowCount + i);
                var schema = new PlankSchema([
                    PlankColumn.RequiredLeaf("key", ParquetPhysicalType.Int64,
                        new ColumnOptions(encodings: SingleEncoding(EncodingKind.Plain)),
                        new Plank.Schema.LogicalType.Int(64, isSigned: true))
                ]);
                ExerciseAppendSorting(schema, sorting, retained, incoming,
                    static (group, column) => ReadAllBuffers(group.Column<long>(column))!
                        .Select(static value => unchecked((ulong)value)).ToArray(),
                    static (expected, actual) => expected.SequenceEqual(actual), expectedSorted: true);
                break;
            }
            case 0:
            {
                var retained = new int[rowCount];
                var incoming = new int[rowCount];
                for (var i = 0; i < rowCount; i++)
                    retained[i] = start + (descending ? -1 : 1) * i * step;
                for (var i = 0; i < rowCount; i++)
                    incoming[i] = retained[^1] + (descending ? -1 : 1) * (i + 1) * step;
                if (breakOrder)
                    incoming[0] = retained[^1] + (descending ? 1 : -1) * step;
                var schema = new PlankSchema([
                    PlankColumn.RequiredLeaf("key", ParquetPhysicalType.Int32,
                        new ColumnOptions(encodings: SingleEncoding(EncodingKind.Plain)))
                ]);
                ExerciseAppendSorting(schema, sorting, retained, incoming,
                    static (group, column) => ReadAllBuffers(group.Column<int>(column)),
                    static (expected, actual) => expected.SequenceEqual(actual), !breakOrder);
                break;
            }
            case 1:
            {
                // Null placement is independent of ascending/descending order.
                var retained = new long?[rowCount];
                var incoming = new long?[rowCount];
                if (nullsFirst)
                {
                    retained[0] = null;
                    retained[1] = null;
                    for (var i = 2; i < rowCount; i++)
                        retained[i] = start + (descending ? -1 : 1) * (i - 2) * step;
                    for (var i = 0; i < rowCount; i++)
                        incoming[i] = retained[^1]!.Value + (descending ? -1 : 1) * (i + 1) * step;
                    if (breakOrder)
                        incoming[0] = retained[^1]!.Value + (descending ? 1 : -1) * step;
                }
                else
                {
                    for (var i = 0; i < rowCount - 1; i++)
                        retained[i] = start + (descending ? -1 : 1) * i * step;
                    retained[^1] = null;
                    Array.Fill(incoming, null);
                    if (breakOrder)
                        incoming[0] = start;
                }
                var schema = new PlankSchema([
                    PlankColumn.OptionalLeaf("key", ParquetPhysicalType.Int64,
                        new ColumnOptions(encodings: SingleEncoding(EncodingKind.Plain)))
                ]);
                ExerciseAppendSorting(schema, sorting, retained, incoming,
                    static (group, column) => ReadAllBuffers(group.Column<long?>(column)),
                    static (expected, actual) => expected.SequenceEqual(actual), !breakOrder);
                break;
            }
            case 2:
            {
                var retained = new byte[rowCount][];
                var incoming = new byte[rowCount][];
                var binaryStart = 80 + Control(controls, 5, 30) % 80;
                for (var i = 0; i < rowCount; i++)
                {
                    retained[i] = [0x42, (byte)(binaryStart + (descending ? -1 : 1) * i * step), 0];
                    incoming[i] = [0x42, (byte)(binaryStart + (descending ? -1 : 1) * (rowCount + i) * step), 0];
                }
                if (breakOrder)
                    incoming[0] = [0x42, (byte)(binaryStart + (descending ? 1 : -1) * step), 0];
                var schema = new PlankSchema([
                    PlankColumn.RequiredLeaf("key", ParquetPhysicalType.ByteArray,
                        new ColumnOptions(encodings: SingleEncoding(EncodingKind.Plain)))
                ]);
                ExerciseAppendSorting(schema, sorting, retained, incoming,
                    static (group, column) => ReadAllBinaryBuffers(group.Column<byte>(column))!,
                    static (expected, actual) => ByteArraysEqual(expected, actual), !breakOrder);
                break;
            }
            case 3:
            {
                var retained = new double[rowCount];
                var incoming = new double[rowCount];
                var scale = 1 + step / 4d;
                // Fill retained completely first: incoming is derived from retained[^1].
                for (var i = 0; i < rowCount; i++)
                    retained[i] = start / 8d + (descending ? -1 : 1) * i * scale;
                for (var i = 0; i < rowCount; i++)
                    incoming[i] = retained[^1] + (descending ? -1 : 1) * (i + 1) * scale;
                var ambiguous = (Control(controls, 1, 0) & 8) != 0;
                if (ambiguous)
                {
                    if ((Control(controls, 5, 0) & 1) == 0)
                        incoming[0] = double.NaN;
                    else
                    {
                        for (var i = 0; i < rowCount; i++)
                            retained[i] = i - rowCount + 1;
                        incoming[0] = -0d;
                        for (var i = 1; i < rowCount; i++)
                            incoming[i] = i;
                    }
                }
                else if (breakOrder)
                    incoming[0] = retained[^1] + (descending ? 1 : -1) * scale;
                var schema = new PlankSchema([
                    PlankColumn.RequiredLeaf("key", ParquetPhysicalType.Double,
                        new ColumnOptions(encodings: SingleEncoding(EncodingKind.Plain)))
                ]);
                ExerciseAppendSorting(schema, sorting, retained, incoming,
                    static (group, column) => ReadAllBuffers(group.Column<double>(column)),
                    static (expected, actual) => expected.SequenceEqual(actual), !breakOrder && !ambiguous);
                break;
            }
            case 4:
            {
                var retained = new float[rowCount];
                var incoming = new float[rowCount];
                var scale = 1 + step / 4f;
                // Fill retained completely first: incoming is derived from retained[^1].
                for (var i = 0; i < rowCount; i++)
                    retained[i] = start / 8f + (descending ? -1 : 1) * i * scale;
                for (var i = 0; i < rowCount; i++)
                    incoming[i] = retained[^1] + (descending ? -1 : 1) * (i + 1) * scale;
                var ambiguous = (Control(controls, 1, 0) & 8) != 0;
                if (ambiguous)
                {
                    if ((Control(controls, 5, 0) & 1) == 0)
                        incoming[0] = float.NaN;
                    else
                    {
                        for (var i = 0; i < rowCount; i++)
                            retained[i] = i - rowCount + 1;
                        incoming[0] = -0f;
                        for (var i = 1; i < rowCount; i++)
                            incoming[i] = i;
                    }
                }
                else if (breakOrder)
                    incoming[0] = retained[^1] + (descending ? 1 : -1) * scale;
                var schema = new PlankSchema([
                    PlankColumn.RequiredLeaf("key", ParquetPhysicalType.Float,
                        new ColumnOptions(encodings: SingleEncoding(EncodingKind.Plain)))
                ]);
                ExerciseAppendSorting(schema, sorting, retained, incoming,
                    static (group, column) => ReadAllBuffers(group.Column<float>(column)),
                    static (expected, actual) => expected.SequenceEqual(actual), !breakOrder && !ambiguous);
                break;
            }
            case 6:
            {
                var retained = new uint[rowCount];
                var incoming = new uint[rowCount];
                var first = (uint)(4096 + start);
                for (var i = 0; i < rowCount; i++)
                    retained[i] = first + (uint)(i * step * (descending ? -1 : 1));
                for (var i = 0; i < rowCount; i++)
                    incoming[i] = retained[^1] + (uint)((i + 1) * step * (descending ? -1 : 1));
                if (breakOrder)
                    incoming[0] = retained[^1] + (uint)(step * (descending ? 1 : -1));
                var schema = new PlankSchema([
                    PlankColumn.RequiredLeaf("key", ParquetPhysicalType.Int32,
                        new ColumnOptions(encodings: SingleEncoding(EncodingKind.Plain)),
                        new Plank.Schema.LogicalType.Int(32, isSigned: false))
                ]);
                ExerciseAppendSorting(schema, sorting, retained, incoming,
                    static (group, column) => ReadAllBuffers(group.Column<uint>(column)),
                    static (expected, actual) => expected.SequenceEqual(actual), !breakOrder);
                break;
            }
            case 7:
            {
                var retained = new ulong[rowCount];
                var incoming = new ulong[rowCount];
                var first = (ulong)(4096 + start);
                for (var i = 0; i < rowCount; i++)
                    retained[i] = first + (ulong)(i * step * (descending ? -1 : 1));
                for (var i = 0; i < rowCount; i++)
                    incoming[i] = retained[^1] + (ulong)((i + 1) * step * (descending ? -1 : 1));
                if (breakOrder)
                    incoming[0] = retained[^1] + (ulong)(step * (descending ? 1 : -1));
                var schema = new PlankSchema([
                    PlankColumn.RequiredLeaf("key", ParquetPhysicalType.Int64,
                        new ColumnOptions(encodings: SingleEncoding(EncodingKind.Plain)),
                        new Plank.Schema.LogicalType.Int(64, isSigned: false))
                ]);
                ExerciseAppendSorting(schema, sorting, retained, incoming,
                    static (group, column) => ReadAllBuffers(group.Column<ulong>(column)),
                    static (expected, actual) => expected.SequenceEqual(actual), !breakOrder);
                break;
            }
            case 8:
            {
                var retained = new DateOnly[rowCount];
                var incoming = new DateOnly[rowCount];
                var first = 20_000 + start;
                for (var i = 0; i < rowCount; i++)
                    retained[i] = DateOnly.FromDayNumber(first + i * step * (descending ? -1 : 1));
                for (var i = 0; i < rowCount; i++)
                    incoming[i] = retained[^1].AddDays((i + 1) * step * (descending ? -1 : 1));
                if (breakOrder)
                    incoming[0] = retained[^1].AddDays(step * (descending ? 1 : -1));
                var schema = new PlankSchema([
                    PlankColumn.RequiredLeaf("key", ParquetPhysicalType.Int32,
                        new ColumnOptions(encodings: SingleEncoding(EncodingKind.Plain)), new Plank.Schema.LogicalType.Date())
                ]);
                ExerciseAppendSorting(schema, sorting, retained, incoming,
                    static (group, column) => ReadAllBuffers(group.Column<DateOnly>(column)),
                    static (expected, actual) => expected.SequenceEqual(actual), !breakOrder);
                break;
            }
            case 9:
            {
                var retained = new TimeOnly[rowCount];
                var incoming = new TimeOnly[rowCount];
                var first = TimeOnly.FromTimeSpan(TimeSpan.FromHours(12));
                for (var i = 0; i < rowCount; i++)
                    retained[i] = first.Add(TimeSpan.FromTicks(i * step * 10L * (descending ? -1 : 1)));
                for (var i = 0; i < rowCount; i++)
                    incoming[i] = retained[^1].Add(TimeSpan.FromTicks((i + 1) * step * 10L * (descending ? -1 : 1)));
                if (breakOrder)
                    incoming[0] = retained[^1].Add(TimeSpan.FromTicks(step * 10L * (descending ? 1 : -1)));
                var schema = new PlankSchema([
                    PlankColumn.RequiredLeaf("key", ParquetPhysicalType.Int64,
                        new ColumnOptions(encodings: SingleEncoding(EncodingKind.Plain)),
                        new Plank.Schema.LogicalType.Time(Plank.Schema.TimeUnit.Micros, IsAdjustedToUtc: false))
                ]);
                ExerciseAppendSorting(schema, sorting, retained, incoming,
                    static (group, column) => ReadAllBuffers(group.Column<TimeOnly>(column)),
                    static (expected, actual) => expected.SequenceEqual(actual), !breakOrder);
                break;
            }
            case 10:
            {
                var retained = new DateTime[rowCount];
                var incoming = new DateTime[rowCount];
                var first = new DateTime(2020, 1, 1);
                for (var i = 0; i < rowCount; i++)
                    retained[i] = first.AddTicks(i * step * 10L * (descending ? -1 : 1));
                for (var i = 0; i < rowCount; i++)
                    incoming[i] = retained[^1].AddTicks((i + 1) * step * 10L * (descending ? -1 : 1));
                if (breakOrder)
                    incoming[0] = retained[^1].AddTicks(step * 10L * (descending ? 1 : -1));
                var schema = new PlankSchema([
                    PlankColumn.RequiredLeaf("key", ParquetPhysicalType.Int64,
                        new ColumnOptions(encodings: SingleEncoding(EncodingKind.Plain)),
                        new Plank.Schema.LogicalType.Timestamp(Plank.Schema.TimeUnit.Micros, IsAdjustedToUtc: false))
                ]);
                ExerciseAppendSorting(schema, sorting, retained, incoming,
                    static (group, column) => ReadAllBuffers(group.Column<DateTime>(column)),
                    static (expected, actual) => expected.SequenceEqual(actual), !breakOrder);
                break;
            }
            case 11:
            {
                var retained = new DateTimeOffset[rowCount];
                var incoming = new DateTimeOffset[rowCount];
                var first = new DateTimeOffset(2020, 1, 1, 0, 0, 0, TimeSpan.Zero);
                for (var i = 0; i < rowCount; i++)
                    retained[i] = first.AddTicks(i * step * 10L * (descending ? -1 : 1));
                for (var i = 0; i < rowCount; i++)
                    incoming[i] = retained[^1].AddTicks((i + 1) * step * 10L * (descending ? -1 : 1));
                if (breakOrder)
                    incoming[0] = retained[^1].AddTicks(step * 10L * (descending ? 1 : -1));
                var schema = new PlankSchema([
                    PlankColumn.RequiredLeaf("key", ParquetPhysicalType.Int64,
                        new ColumnOptions(encodings: SingleEncoding(EncodingKind.Plain)),
                        new Plank.Schema.LogicalType.Timestamp(Plank.Schema.TimeUnit.Micros, IsAdjustedToUtc: true))
                ]);
                ExerciseAppendSorting(schema, sorting, retained, incoming,
                    static (group, column) => ReadAllBuffers(group.Column<DateTimeOffset>(column)),
                    static (expected, actual) => expected.SequenceEqual(actual), !breakOrder);
                break;
            }
            case 12:
            {
                var retained = new string[rowCount];
                var incoming = new string[rowCount];
                var first = 10_000 + start;
                for (var i = 0; i < rowCount; i++)
                    retained[i] = $"k{first + i * step * (descending ? -1 : 1):D6}";
                for (var i = 0; i < rowCount; i++)
                    incoming[i] = $"k{first + (rowCount + i) * step * (descending ? -1 : 1):D6}";
                if (breakOrder)
                    incoming[0] = $"k{first + (rowCount - 1) * step * (descending ? -1 : 1) + step * (descending ? 1 : -1):D6}";
                var schema = new PlankSchema([
                    PlankColumn.RequiredLeaf("key", ParquetPhysicalType.ByteArray,
                        new ColumnOptions(encodings: SingleEncoding(EncodingKind.Plain)))
                ]);
                ExerciseAppendSorting(schema, sorting, retained, incoming,
                    static (group, column) => ReadAllBinaryBuffers(group.Column<byte>(column))!
                        .Select(static value => System.Text.Encoding.UTF8.GetString(value)).ToArray(),
                    static (expected, actual) => expected.SequenceEqual(actual), !breakOrder);
                break;
            }
            case 13:
            {
                var retained = new Guid[rowCount];
                var incoming = new Guid[rowCount];
                var first = 10_000 + start;
                for (var i = 0; i < rowCount; i++)
                    retained[i] = GuidFromSortableInt(first + i * step * (descending ? -1 : 1));
                for (var i = 0; i < rowCount; i++)
                    incoming[i] = GuidFromSortableInt(first + (rowCount + i) * step * (descending ? -1 : 1));
                if (breakOrder)
                    incoming[0] = GuidFromSortableInt(
                        first + (rowCount - 1) * step * (descending ? -1 : 1) + step * (descending ? 1 : -1));
                var schema = new PlankSchema([
                    PlankColumn.RequiredLeaf("key", ParquetPhysicalType.FixedLenByteArray,
                        new ColumnOptions(typeLength: 16, encodings: SingleEncoding(EncodingKind.Plain)),
                        new Plank.Schema.LogicalType.Uuid())
                ]);
                ExerciseAppendSorting(schema, sorting, retained, incoming,
                    static (group, column) => ReadAllBinaryBuffers(group.Column<byte>(column))!
                        .Select(static value => new Guid(value, bigEndian: true)).ToArray(),
                    static (expected, actual) => expected.SequenceEqual(actual), !breakOrder);
                break;
            }
            case 14:
            {
                var retained = new byte[rowCount];
                var incoming = new byte[rowCount];
                var first = descending ? (byte)240 : (byte)8;
                for (var i = 0; i < rowCount; i++)
                    retained[i] = (byte)(first + i * step * (descending ? -1 : 1));
                for (var i = 0; i < rowCount; i++)
                    incoming[i] = (byte)(retained[^1] + (i + 1) * step * (descending ? -1 : 1));
                if (breakOrder)
                    incoming[0] = (byte)(retained[^1] + step * (descending ? 1 : -1));
                var schema = new PlankSchema([
                    PlankColumn.RequiredLeaf("key", ParquetPhysicalType.Int32,
                        new ColumnOptions(encodings: SingleEncoding(EncodingKind.Plain)))
                ]);
                ExerciseAppendSorting(schema, sorting, retained, incoming,
                    static (group, column) => ReadAllBuffers(group.Column<byte>(column)),
                    static (expected, actual) => expected.SequenceEqual(actual), !breakOrder);
                break;
            }
            case 15:
            {
                var retained = new ushort[rowCount];
                var incoming = new ushort[rowCount];
                var first = descending ? (ushort)5000 : (ushort)100;
                for (var i = 0; i < rowCount; i++)
                    retained[i] = (ushort)(first + i * step * (descending ? -1 : 1));
                for (var i = 0; i < rowCount; i++)
                    incoming[i] = (ushort)(retained[^1] + (i + 1) * step * (descending ? -1 : 1));
                if (breakOrder)
                    incoming[0] = (ushort)(retained[^1] + step * (descending ? 1 : -1));
                var schema = new PlankSchema([
                    PlankColumn.RequiredLeaf("key", ParquetPhysicalType.Int32,
                        new ColumnOptions(encodings: SingleEncoding(EncodingKind.Plain)))
                ]);
                ExerciseAppendSorting(schema, sorting, retained, incoming,
                    static (group, column) => ReadAllBuffers(group.Column<ushort>(column)),
                    static (expected, actual) => expected.SequenceEqual(actual), !breakOrder);
                break;
            }
            case 16:
            case 17:
            {
                var unit = kind == 16 ? Plank.Schema.TimeUnit.Millis : Plank.Schema.TimeUnit.Nanos;
                var ticksPerStep = kind == 16 ? TimeSpan.TicksPerMillisecond : 1;
                var retained = new TimeOnly[rowCount];
                var incoming = new TimeOnly[rowCount];
                var first = TimeOnly.FromTimeSpan(TimeSpan.FromHours(descending ? 20 : 2));
                for (var i = 0; i < rowCount; i++)
                    retained[i] = first.Add(TimeSpan.FromTicks(i * step * ticksPerStep * (descending ? -1 : 1)));
                for (var i = 0; i < rowCount; i++)
                    incoming[i] = retained[^1].Add(TimeSpan.FromTicks((i + 1) * step * ticksPerStep * (descending ? -1 : 1)));
                if (breakOrder)
                    incoming[0] = retained[^1].Add(TimeSpan.FromTicks(step * ticksPerStep * (descending ? 1 : -1)));
                var physical = kind == 16 ? ParquetPhysicalType.Int32 : ParquetPhysicalType.Int64;
                var schema = new PlankSchema([
                    PlankColumn.RequiredLeaf("key", physical,
                        new ColumnOptions(encodings: SingleEncoding(EncodingKind.Plain)),
                        new Plank.Schema.LogicalType.Time(unit, IsAdjustedToUtc: false))
                ]);
                ExerciseAppendSorting(schema, sorting, retained, incoming,
                    static (group, column) => ReadAllBuffers(group.Column<TimeOnly>(column)),
                    static (expected, actual) => expected.SequenceEqual(actual), !breakOrder);
                break;
            }
            case 18:
            {
                var retained = new byte[rowCount][];
                var incoming = new byte[rowCount][];
                var first = descending ? 1_000 : -1_000;
                for (var i = 0; i < rowCount; i++)
                    retained[i] = DecimalBytes(first + i * step * (descending ? -1 : 1));
                for (var i = 0; i < rowCount; i++)
                    incoming[i] = DecimalBytes(first + (rowCount + i) * step * (descending ? -1 : 1));
                if (breakOrder)
                    incoming[0] = DecimalBytes(first + (rowCount - 1) * step * (descending ? -1 : 1) +
                        step * (descending ? 1 : -1));
                var schema = new PlankSchema([
                    PlankColumn.RequiredLeaf("key", ParquetPhysicalType.FixedLenByteArray,
                        new ColumnOptions(typeLength: 16, encodings: SingleEncoding(EncodingKind.Plain)),
                        new Plank.Schema.LogicalType.Decimal(28, 0))
                ]);
                ExerciseAppendSorting(schema, sorting, retained, incoming,
                    static (group, column) => ReadAllBinaryBuffers(group.Column<byte>(column))!,
                    static (expected, actual) => ByteArraysEqual(expected, actual), !breakOrder);
                break;
            }
            case 19:
            {
                var retained = new byte[rowCount][];
                var incoming = new byte[rowCount][];
                var first = descending ? 100 : -100;
                for (var i = 0; i < rowCount; i++)
                    retained[i] = Float16Bytes(first + i * step * (descending ? -1 : 1));
                for (var i = 0; i < rowCount; i++)
                    incoming[i] = Float16Bytes(first + (rowCount + i) * step * (descending ? -1 : 1));
                if (breakOrder)
                    incoming[0] = Float16Bytes(first + (rowCount - 1) * step * (descending ? -1 : 1) +
                        step * (descending ? 1 : -1));
                var schema = new PlankSchema([
                    PlankColumn.RequiredLeaf("key", ParquetPhysicalType.FixedLenByteArray,
                        new ColumnOptions(typeLength: 2, encodings: SingleEncoding(EncodingKind.Plain)),
                        new Plank.Schema.LogicalType.Float16())
                ]);
                ExerciseAppendSorting(schema, sorting, retained, incoming,
                    static (group, column) => ReadAllBinaryBuffers(group.Column<byte>(column))!,
                    static (expected, actual) => ByteArraysEqual(expected, actual), !breakOrder);
                break;
            }
            case 30:
            {
                var retained = new decimal[rowCount];
                var incoming = new decimal[rowCount];
                for (var i = 0; i < rowCount; i++)
                    retained[i] = start + (descending ? -1 : 1) * i * step;
                for (var i = 0; i < rowCount; i++)
                    incoming[i] = retained[^1] + (descending ? -1 : 1) * (i + 1) * step;
                if (breakOrder)
                    incoming[0] = retained[^1] + (descending ? 1 : -1) * step;
                var schema = new PlankSchema([
                    PlankColumn.RequiredLeaf("key", ParquetPhysicalType.FixedLenByteArray,
                        new ColumnOptions(typeLength: 16, encodings: SingleEncoding(EncodingKind.Plain)),
                        new Plank.Schema.LogicalType.Decimal(28, 0))
                ]);
                ExerciseAppendSorting(schema, sorting, retained, incoming,
                    static (group, column) => ReadAllBuffers(group.Column<decimal>(column)),
                    static (expected, actual) => expected.SequenceEqual(actual), !breakOrder);
                break;
            }
            case 31:
            {
                var retained = new IntBox[rowCount];
                var incoming = new IntBox[rowCount];
                for (var i = 0; i < rowCount; i++)
                    retained[i] = new(start + (descending ? -1 : 1) * i * step);
                for (var i = 0; i < rowCount; i++)
                    incoming[i] = new(retained[^1].Value + (descending ? -1 : 1) * (i + 1) * step);
                var schema = new PlankSchema([
                    PlankColumn.RequiredLeaf("key", ParquetPhysicalType.Int32,
                        new ColumnOptions(encodings: SingleEncoding(EncodingKind.Plain)),
                        converter: new IntBoxConverter())
                ]);
                var converterPreempted = false;
                try
                {
                    ExerciseAppendSorting(schema, sorting, retained, incoming,
                        static (group, column) => ReadAllBuffers(group.Column<IntBox>(column)),
                        static (expected, actual) => expected.SequenceEqual(actual), expectedSorted: false);
                }
                catch (InvalidOperationException exception) when (exception.Message ==
                    "Column 'key' uses a converter for 'Plank.Fuzzing.IntBox' and cannot be read as 'System.Int32'.")
                {
                    converterPreempted = true;
                }
                if (!converterPreempted)
                    throw new InvalidOperationException("The converter append route no longer preempts sorting comparison.");
                break;
            }
            case 32:
            {
                var retained = new byte[rowCount][];
                var incoming = new byte[rowCount][];
                for (var i = 0; i < rowCount; i++)
                    retained[i] = Int96AppendBytes(start + i * step);
                for (var i = 0; i < rowCount; i++)
                    incoming[i] = Int96AppendBytes(start + (rowCount + i) * step);
                var schema = new PlankSchema([
                    PlankColumn.RequiredLeaf("key", ParquetPhysicalType.Int96,
                        new ColumnOptions(encodings: SingleEncoding(EncodingKind.Plain)))
                ]);
                ExerciseAppendSorting(schema, sorting, retained, incoming,
                    static (group, column) => ReadAllBinaryBuffers(group.Column<byte>(column))!,
                    static (expected, actual) => ByteArraysEqual(expected, actual), expectedSorted: false);
                break;
            }
            case 33:
            {
                var retained = new byte[]?[rowCount];
                var incoming = new byte[]?[rowCount];
                var schema = new PlankSchema([
                    PlankColumn.OptionalLeaf("key", ParquetPhysicalType.ByteArray,
                        new ColumnOptions(encodings: SingleEncoding(EncodingKind.Plain)),
                        new Plank.Schema.LogicalType.Unknown())
                ]);
                ExerciseAppendSorting(schema, sorting, retained, incoming,
                    static (group, column) => ReadAllBinaryBuffers(group.Column<byte>(column)),
                    static (expected, actual) => expected.SequenceEqual(actual), expectedSorted: false);
                break;
            }
            case 34:
            case 35:
            {
                var retained = new byte[rowCount][];
                var incoming = new byte[rowCount][];
                for (var i = 0; i < rowCount; i++)
                    retained[i] = [(byte)(20 + i * step), 0x41];
                for (var i = 0; i < rowCount; i++)
                    incoming[i] = [(byte)(20 + (rowCount + i) * step), 0x41];
                var logicalType = kind == 34
                    ? (Plank.Schema.LogicalType)new Plank.Schema.LogicalType.Geometry()
                    : new Plank.Schema.LogicalType.Geography();
                var schema = new PlankSchema([
                    PlankColumn.RequiredLeaf("key", ParquetPhysicalType.ByteArray,
                        new ColumnOptions(encodings: SingleEncoding(EncodingKind.Plain)), logicalType)
                ]);
                ExerciseAppendSorting(schema, sorting, retained, incoming,
                    static (group, column) => ReadAllBinaryBuffers(group.Column<byte>(column))!,
                    static (expected, actual) => ByteArraysEqual(expected, actual), expectedSorted: false);
                break;
            }
            default:
            {
                var retained = new bool[rowCount];
                var incoming = new bool[rowCount];
                for (var i = 0; i < rowCount; i++)
                {
                    retained[i] = descending ? (i & 1) == 0 : (i & 1) != 0;
                    incoming[i] = descending ? (i & 1) != 0 : (i & 1) == 0;
                }
                // bool has only two ordered values, so construct a fully ordered
                // boundary for the selected direction and optionally invert it.
                Array.Fill(retained, descending);
                Array.Fill(incoming, descending);
                if (breakOrder)
                {
                    Array.Fill(retained, !descending);
                    Array.Fill(incoming, descending);
                }
                var schema = new PlankSchema([
                    PlankColumn.RequiredLeaf("key", ParquetPhysicalType.Boolean,
                        new ColumnOptions(encodings: SingleEncoding(EncodingKind.Plain)))
                ]);
                ExerciseAppendSorting(schema, sorting, retained, incoming,
                    static (group, column) => ReadAllBuffers(group.Column<bool>(column)),
                    static (expected, actual) => expected.SequenceEqual(actual), !breakOrder);
                break;
            }
        }
    }

    static int UnsignedInt32DescendingValue(int index) => index switch
    {
        0 => -1,
        1 => int.MinValue,
        _ => int.MaxValue - (index - 2)
    };

    static uint SignedInt32AscendingBits(int index) => unchecked((uint)(int.MinValue + index));

    static long UnsignedInt64DescendingValue(int index) => index switch
    {
        0 => -1,
        1 => long.MinValue,
        _ => long.MaxValue - (index - 2)
    };

    static ulong SignedInt64AscendingBits(int index) => unchecked((ulong)(long.MinValue + index));

    static Guid GuidFromSortableInt(int value)
    {
        Span<byte> bytes = stackalloc byte[16];
        System.Buffers.Binary.BinaryPrimitives.WriteInt32BigEndian(bytes, value);
        return new Guid(bytes, bigEndian: true);
    }

    static byte[] DecimalBytes(int value)
    {
        var encoded = new System.Numerics.BigInteger(value).ToByteArray(isUnsigned: false, isBigEndian: true);
        var result = new byte[16];
        if (value < 0)
            Array.Fill(result, (byte)0xFF);
        encoded.CopyTo(result.AsSpan(result.Length - encoded.Length));
        return result;
    }

    static byte[] Float16Bytes(int value)
    {
        var result = new byte[sizeof(ushort)];
        System.Buffers.Binary.BinaryPrimitives.WriteUInt16LittleEndian(result,
            BitConverter.HalfToUInt16Bits((Half)value));
        return result;
    }

    static byte[] IntervalBytes(int value)
    {
        var bytes = new byte[12];
        System.Buffers.Binary.BinaryPrimitives.WriteUInt32LittleEndian(bytes, (uint)value);
        System.Buffers.Binary.BinaryPrimitives.WriteUInt32LittleEndian(bytes.AsSpan(4), 1);
        System.Buffers.Binary.BinaryPrimitives.WriteUInt32LittleEndian(bytes.AsSpan(8), 2);
        return bytes;
    }

    static byte[] Int96AppendBytes(int value)
    {
        var bytes = new byte[12];
        System.Buffers.Binary.BinaryPrimitives.WriteInt32LittleEndian(bytes, value);
        System.Buffers.Binary.BinaryPrimitives.WriteInt32LittleEndian(bytes.AsSpan(4), 1);
        System.Buffers.Binary.BinaryPrimitives.WriteInt32LittleEndian(bytes.AsSpan(8), 2);
        return bytes;
    }

    static void ExerciseAppendSortingTwoColumns(int rowCount, int step, int start, bool descending)
    {
        var schema = new PlankSchema([
            PlankColumn.RequiredLeaf("key", ParquetPhysicalType.Int32,
                new ColumnOptions(encodings: SingleEncoding(EncodingKind.Plain))),
            PlankColumn.RequiredLeaf("payload", ParquetPhysicalType.Int32,
                new ColumnOptions(encodings: SingleEncoding(EncodingKind.Plain)))
        ]);
        var direction = descending ? -1 : 1;
        var retainedKey = Enumerable.Range(0, rowCount).Select(i => start + direction * i * step).ToArray();
        var incomingKey = Enumerable.Range(rowCount, rowCount).Select(i => start + direction * i * step).ToArray();
        var retainedPayload = Enumerable.Range(0, rowCount).Select(i => 10_000 + i).ToArray();
        var incomingPayload = Enumerable.Range(0, rowCount).Select(i => 20_000 + i).ToArray();
        var options = new ParquetWriterOptions { SortingColumns = [new ParquetSortingColumn(0, descending)] };

        using var initial = new MemoryStream();
        var writer = schema.CreateWriter(initial, options);
        var key = writer.CreateSerializedColumn<int>(schema.LeafColumns[0]);
        key.Serialize(retainedKey);
        var payload = writer.CreateSerializedColumn<int>(schema.LeafColumns[1]);
        payload.Serialize(retainedPayload);
        var initialGroup = writer.StartRowGroup();
        initialGroup.Write(key);
        initialGroup.Write(payload);
        writer.CloseFile();

        using var appendStream = new MemoryStream();
        appendStream.Write(initial.ToArray());
        appendStream.Position = 0;
        var appender = schema.CreateAppender(appendStream, new ParquetAppendOptions
        {
            AppendToLatestRowGroup = true,
            WriterOptions = options
        });
        key = appender.CreateSerializedColumn<int>(schema.LeafColumns[0]);
        key.Serialize(incomingKey);
        payload = appender.CreateSerializedColumn<int>(schema.LeafColumns[1]);
        payload.Serialize(incomingPayload);
        var appendGroup = appender.StartRowGroup();
        appendGroup.Write(key);
        appendGroup.Write(payload);
        appender.CloseFile();

        using var reader = schema.CreateReader(FullValueOracle.Source(appendStream.ToArray()));
        var group = reader.RowGroups[0];
        if (reader.RowGroups.Count != 1 || group.RowCount != (ulong)(rowCount * 2) ||
            !ReadAllBuffers(group.Column<int>(schema.LeafColumns[0])).SequenceEqual(retainedKey.Concat(incomingKey)) ||
            !ReadAllBuffers(group.Column<int>(schema.LeafColumns[1])).SequenceEqual(retainedPayload.Concat(incomingPayload)))
            throw new InvalidOperationException("Two-column append sorting route changed the appended values.");
        var sorting = reader.PhysicalReader.Metadata.RowGroupSortingColumns(0);
        if (sorting.Length != 1 || sorting[0].ColumnOrdinal != 0 || sorting[0].Descending != descending)
            throw new InvalidOperationException("Two-column append sorting route lost the ordinal-zero sort key.");
    }

    static void ExerciseAppendWithoutSorting(int rowCount, int step, int start)
    {
        var schema = new PlankSchema([
            PlankColumn.RequiredLeaf("key", ParquetPhysicalType.Int32,
                new ColumnOptions(encodings: SingleEncoding(EncodingKind.Plain)))
        ]);
        var retained = Enumerable.Range(0, rowCount).Select(i => start + i * step).ToArray();
        var incoming = Enumerable.Range(rowCount, rowCount).Select(i => start + i * step).ToArray();
        var options = new ParquetWriterOptions { SortingColumns = [] };
        using var initial = new MemoryStream();
        var writer = schema.CreateWriter(initial, options);
        var column = writer.CreateSerializedColumn<int>(schema.LeafColumns[0]);
        column.Serialize(retained);
        writer.StartRowGroup().Write(column);
        writer.CloseFile();
        using var appendStream = new MemoryStream();
        appendStream.Write(initial.ToArray());
        appendStream.Position = 0;
        var appender = schema.CreateAppender(appendStream, new ParquetAppendOptions
        {
            AppendToLatestRowGroup = true,
            WriterOptions = options
        });
        column = appender.CreateSerializedColumn<int>(schema.LeafColumns[0]);
        column.Serialize(incoming);
        appender.StartRowGroup().Write(column);
        appender.CloseFile();
        using var reader = schema.CreateReader(FullValueOracle.Source(appendStream.ToArray()));
        if (reader.RowGroups.Count != 1 ||
            !ReadAllBuffers(reader.RowGroups[0].Column<int>(schema.LeafColumns[0]))
                .SequenceEqual(retained.Concat(incoming)) ||
            reader.PhysicalReader.Metadata.RowGroupSortingColumns(0).Length != 0)
            throw new InvalidOperationException("Unsorted append route changed values or wrote sorting metadata.");
    }

    static ReadOnlyMemory<byte>[] ReadBinaryMemoryBuffers(RowGroupColumn<byte> column, int width)
    {
        var values = ReadAllBuffers(column);
        if (values.Length % width != 0)
            throw new InvalidOperationException("Binary memory append readback had an unexpected byte count.");
        var result = new ReadOnlyMemory<byte>[values.Length / width];
        for (var i = 0; i < result.Length; i++)
            result[i] = values.AsMemory(i * width, width);
        return result;
    }

    static bool BinaryMemoriesEqual(ReadOnlyMemory<byte>[] expected, ReadOnlyMemory<byte>[] actual)
    {
        if (expected.Length != actual.Length)
            return false;
        for (var i = 0; i < expected.Length; i++)
            if (!expected[i].Span.SequenceEqual(actual[i].Span))
                return false;
        return true;
    }

    static void ExerciseAppendSorting<T>(PlankSchema schema, ParquetSortingColumn sorting,
        T[] retained, T[] incoming, Func<PlankRowGroup, LeafColumn, T[]> read,
        Func<T[], T[], bool> equal, bool expectedSorted)
    {
        var options = new ParquetWriterOptions
        {
            SortingColumns = [sorting],
            WritePageCrc = true,
            WritePageIndexes = true,
            TargetDataPageSizeBytes = 64,
            BufferChunkSizeBytes = 128
        };
        using var initial = new MemoryStream();
        var writer = schema.CreateWriter(initial, options);
        var initialColumn = writer.CreateSerializedColumn<T>(schema.LeafColumns[0]);
        initialColumn.Serialize(retained);
        writer.StartRowGroup().Write(initialColumn);
        writer.CloseFile();
        using (var initialSource = FullValueOracle.Source(initial.ToArray()))
        using (var initialReader = schema.CreateReader(initialSource))
        {
            var initialSorting = initialReader.PhysicalReader.Metadata.RowGroupSortingColumns(0);
            if (initialSorting.Length != 1 || initialSorting[0].ColumnOrdinal != sorting.ColumnOrdinal ||
                initialSorting[0].Descending != sorting.Descending || initialSorting[0].NullsFirst != sorting.NullsFirst)
                throw new InvalidOperationException("Append sorting route did not write the requested initial sorting metadata.");
        }

        var appendStream = new MemoryStream();
        appendStream.Write(initial.ToArray());
        appendStream.Position = 0;
        var appender = schema.CreateAppender(appendStream, new ParquetAppendOptions
        {
            AppendToLatestRowGroup = true,
            WriterOptions = options
        });
        var appendedColumn = appender.CreateSerializedColumn<T>(schema.LeafColumns[0]);
        appendedColumn.Serialize(incoming);
        appender.StartRowGroup().Write(appendedColumn);
        appender.CloseFile();

        var expected = new T[retained.Length + incoming.Length];
        retained.CopyTo(expected, 0);
        incoming.CopyTo(expected, retained.Length);
        using var reader = schema.CreateReader(FullValueOracle.Source(appendStream.ToArray()));
        if (reader.RowGroups.Count != 1 || reader.RowGroups[0].RowCount != (ulong)expected.Length)
            throw new InvalidOperationException("Append sorting route changed the row-group shape.");
        var actual = read(reader.RowGroups[0], schema.LeafColumns[0]);
        if (!equal(expected, actual))
            throw new InvalidOperationException("Append sorting route changed values or row order.");

        var sortColumns = reader.PhysicalReader.Metadata.RowGroupSortingColumns(0);
        if ((sortColumns.Length == 1) != expectedSorted ||
            (expectedSorted && (sortColumns[0].ColumnOrdinal != sorting.ColumnOrdinal ||
                sortColumns[0].Descending != sorting.Descending || sortColumns[0].NullsFirst != sorting.NullsFirst)))
            throw new InvalidOperationException(
                $"Append sorting route wrote {sortColumns.Length} sorting columns; expected " +
                $"{(expectedSorted ? 1 : 0)} (requested desc={sorting.Descending}, nullsFirst={sorting.NullsFirst}).");
    }

    static bool ByteArraysEqual(byte[]?[] expected, byte[]?[] actual)
    {
        if (expected.Length != actual.Length)
            return false;
        for (var i = 0; i < expected.Length; i++)
            if (expected[i] is null || actual[i] is null ||
                !expected[i].AsSpan().SequenceEqual(actual[i]))
                return false;
        return true;
    }

    public static void Validate(FuzzCase fuzzCase)
    {
        ArgumentNullException.ThrowIfNull(fuzzCase);
        if (Environment.GetEnvironmentVariable("PLANK_FUZZ_DESCRIBE") == "1")
            Console.Error.WriteLine("CASE " + fuzzCase.Describe());
        using var ms = new MemoryStream();
        WriteToStream(fuzzCase, ms);

        // CloseFile() closes the stream it was writing to, so the written bytes
        // have to be taken from the MemoryStream rather than rewinding it.
        // (ToArray still works on a closed MemoryStream.)
        var bytes = ms.ToArray();
        FullValueOracle.VerifyWritten(bytes); // oracle agent: metadata vs Arrow-decoded values
        AssertPlankCanRead(new MemoryStream(bytes, writable: false), fuzzCase);
        AssertParquetSharpCanRead(new MemoryStream(bytes, writable: false), fuzzCase);
    }

    static void WriteToStream(FuzzCase fuzzCase, Stream stream)
    {
        var settings = fuzzCase.Settings;
        var defaults = ParquetWriterOptions.Default;
        if (!settings.Explicit && _ambientHash % 3 != 0)
        {
            var h = _ambientHash / 3;
            settings = settings with
            {
                Pool = (WriterPoolKind)(h % 7),
                InitialPageBufferBytes = new uint?[] { null, 1, 7, 64, 4096 }[(h >> 3) % 5],
                InitialColumnBufferBytes = new uint?[] { null, 1, 100, 65536 }[(h >> 6) % 4],
                InitialPageCapacity = new uint?[] { null, 1, 2, 17 }[(h >> 8) % 4],
                WorkerCount = new int?[] { null, 1, 2 }[(h >> 10) % 3],
            };
        }
        using var pool = WriterFuzzPool.Create(settings.Pool);
        var writer = fuzzCase.Schema.CreateWriter(stream, new ParquetWriterOptions
        {
            BufferPool = pool,
            InitialPageBufferBytes = settings.InitialPageBufferBytes ?? defaults.InitialPageBufferBytes,
            InitialColumnBufferBytes = settings.InitialColumnBufferBytes ?? defaults.InitialColumnBufferBytes,
            InitialPageCapacity = settings.InitialPageCapacity ?? defaults.InitialPageCapacity,
            CreatedBy = settings.CreatedBy,
            Execution = settings.WorkerCount is { } workers
                ? new ParquetExecutionOptions { WorkerCount = workers }
                : new ParquetExecutionOptions(),
            SortingColumns = settings.Sorting is { Length: > 0 } sorting ? [.. sorting] : [],
            Compression = fuzzCase.Compression,
            DataPageVersion = settings.DataPageVersion,
            WritePageCrc = settings.WritePageCrc,
            WritePageIndexes = settings.WritePageIndexes,
            FileVersion = settings.FileVersion,
            CompressionLevel = settings.CompressionLevel,
            TargetDataPageSizeBytes = settings.TargetDataPageSizeBytes,
            BufferChunkSizeBytes = settings.BufferChunkSizeBytes,
            KeyValueMetadata = settings.WithKeyValueMetadata
                ? [new PlankKeyValueMetadata("fuzz", "1"), new PlankKeyValueMetadata("empty", "")]
                : []
        });
        var serializedColumns = new object[fuzzCase.Columns.Count];
        for (var columnIndex = 0; columnIndex < serializedColumns.Length; columnIndex++)
            serializedColumns[columnIndex] = CreateSerializedColumn(writer, fuzzCase.Schema.LeafColumns[columnIndex],
                fuzzCase.Columns[columnIndex]);

        for (var rowGroupIndex = 0; rowGroupIndex < fuzzCase.RowGroups.Count; rowGroupIndex++)
        {
            var rowGroup = writer.StartRowGroup();
            for (var columnIndex = 0; columnIndex < fuzzCase.Columns.Count; columnIndex++)
            {
                SerializeColumn(serializedColumns[columnIndex], fuzzCase.RowGroups[rowGroupIndex][columnIndex]);
                WriteColumn(rowGroup, serializedColumns[columnIndex]);
            }
        }

        writer.CloseFile();
    }

    static object CreateSerializedColumn(PlankWriter writer, LeafColumn column, ColumnSpec spec)
        => spec.ClrType == typeof(bool) ? writer.CreateSerializedColumn<bool>(column)
        : spec.ClrType == typeof(bool?) ? writer.CreateSerializedColumn<bool?>(column)
        : spec.ClrType == typeof(int) ? writer.CreateSerializedColumn<int>(column)
        : spec.ClrType == typeof(int?) ? writer.CreateSerializedColumn<int?>(column)
        : spec.ClrType == typeof(long) ? writer.CreateSerializedColumn<long>(column)
        : spec.ClrType == typeof(long?) ? writer.CreateSerializedColumn<long?>(column)
        : spec.ClrType == typeof(double) ? writer.CreateSerializedColumn<double>(column)
        : spec.ClrType == typeof(double?) ? writer.CreateSerializedColumn<double?>(column)
        : spec.ClrType == typeof(float) ? writer.CreateSerializedColumn<float>(column)
        : spec.ClrType == typeof(float?) ? writer.CreateSerializedColumn<float?>(column)
        : spec.ClrType == typeof(IntBox) ? writer.CreateSerializedColumn<IntBox>(column)
        : spec.ClrType == typeof(LongBox?) ? writer.CreateSerializedColumn<LongBox?>(column)
        : spec.ClrType == typeof(DoubleBox?) ? writer.CreateSerializedColumn<DoubleBox?>(column)
        : writer.CreateSerializedColumn<byte[]>(column);

    static void SerializeColumn(object serializedColumn, Array values)
    {
        switch (serializedColumn)
        {
            case SerializedColumn<bool> typed:
                typed.Serialize((bool[])values);
                return;
            case SerializedColumn<bool?> typed:
                typed.Serialize((bool?[])values);
                return;
            case SerializedColumn<int> typed:
                typed.Serialize((int[])values);
                return;
            case SerializedColumn<int?> typed:
                typed.Serialize((int?[])values);
                return;
            case SerializedColumn<long> typed:
                typed.Serialize((long[])values);
                return;
            case SerializedColumn<long?> typed:
                typed.Serialize((long?[])values);
                return;
            case SerializedColumn<double> typed:
                typed.Serialize((double[])values);
                return;
            case SerializedColumn<double?> typed:
                typed.Serialize((double?[])values);
                return;
            case SerializedColumn<float> typed:
                typed.Serialize((float[])values);
                return;
            case SerializedColumn<float?> typed:
                typed.Serialize((float?[])values);
                return;
            case SerializedColumn<IntBox> typed:
                typed.Serialize((IntBox[])values);
                return;
            case SerializedColumn<LongBox?> typed:
                typed.Serialize((LongBox?[])values);
                return;
            case SerializedColumn<DoubleBox?> typed:
                typed.Serialize((DoubleBox?[])values);
                return;
            case SerializedColumn<byte[]> typed:
                typed.Serialize((byte[][])values);
                return;
            default:
                throw new InvalidOperationException($"Unsupported serialized column type '{serializedColumn.GetType()}'.");
        }
    }

    static void WriteColumn(PlankRowGroupWriter rowGroup, object serializedColumn)
    {
        switch (serializedColumn)
        {
            case SerializedColumn<bool> typed:
                rowGroup.Write(typed);
                return;
            case SerializedColumn<bool?> typed:
                rowGroup.Write(typed);
                return;
            case SerializedColumn<int> typed:
                rowGroup.Write(typed);
                return;
            case SerializedColumn<int?> typed:
                rowGroup.Write(typed);
                return;
            case SerializedColumn<long> typed:
                rowGroup.Write(typed);
                return;
            case SerializedColumn<long?> typed:
                rowGroup.Write(typed);
                return;
            case SerializedColumn<double> typed:
                rowGroup.Write(typed);
                return;
            case SerializedColumn<double?> typed:
                rowGroup.Write(typed);
                return;
            case SerializedColumn<float> typed:
                rowGroup.Write(typed);
                return;
            case SerializedColumn<float?> typed:
                rowGroup.Write(typed);
                return;
            case SerializedColumn<IntBox> typed:
                rowGroup.Write(typed);
                return;
            case SerializedColumn<LongBox?> typed:
                rowGroup.Write(typed);
                return;
            case SerializedColumn<DoubleBox?> typed:
                rowGroup.Write(typed);
                return;
            case SerializedColumn<byte[]> typed:
                rowGroup.Write(typed);
                return;
            default:
                throw new InvalidOperationException($"Unsupported serialized column type '{serializedColumn.GetType()}'.");
        }
    }

    static void AssertPlankCanRead(Stream stream, FuzzCase fuzzCase)
    {
        using var reader = fuzzCase.Schema.CreateReader(stream);
        var rowGroupIndex = 0;
        foreach (var rowGroup in reader.RowGroups)
        {
            for (var columnIndex = 0; columnIndex < fuzzCase.Columns.Count; columnIndex++)
            {
                var actual = ReadPlankColumn(rowGroup, fuzzCase.Schema.LeafColumns[columnIndex],
                    fuzzCase.Columns[columnIndex]);
                AssertArraysEqual("Plank", fuzzCase, rowGroupIndex, columnIndex,
                    fuzzCase.RowGroups[rowGroupIndex][columnIndex], actual);
            }
            rowGroupIndex++;
        }

        if (rowGroupIndex != fuzzCase.RowGroups.Count)
            throw new InvalidOperationException(
                $"Plank row-group count mismatch. Expected {fuzzCase.RowGroups.Count}, got {rowGroupIndex}.");
    }

    static Array ReadPlankColumn(PlankRowGroup rowGroup, LeafColumn column, ColumnSpec spec)
        => spec.ClrType == typeof(bool) ? ReadAllBuffers(rowGroup.Column<bool>(column))
        : spec.ClrType == typeof(bool?) ? ReadAllBuffers(rowGroup.Column<bool?>(column))
        : spec.ClrType == typeof(int) ? ReadAllBuffers(rowGroup.Column<int>(column))
        : spec.ClrType == typeof(int?) ? ReadAllBuffers(rowGroup.Column<int?>(column))
        : spec.ClrType == typeof(long) ? ReadAllBuffers(rowGroup.Column<long>(column))
        : spec.ClrType == typeof(long?) ? ReadAllBuffers(rowGroup.Column<long?>(column))
        : spec.ClrType == typeof(double) ? ReadAllBuffers(rowGroup.Column<double>(column))
        : spec.ClrType == typeof(double?) ? ReadAllBuffers(rowGroup.Column<double?>(column))
        : spec.ClrType == typeof(IntBox) ? ReadAllBuffers(rowGroup.Column<IntBox>(column))
        : spec.ClrType == typeof(LongBox?) ? ReadAllBuffers(rowGroup.Column<LongBox?>(column))
        : spec.ClrType == typeof(DoubleBox?) ? ReadAllBuffers(rowGroup.Column<DoubleBox?>(column))
        : spec.ClrType == typeof(float) ? ReadAllBuffers(rowGroup.Column<float>(column))
        : spec.ClrType == typeof(float?) ? ReadAllBuffers(rowGroup.Column<float?>(column))
        : ReadAllBinaryBuffers(rowGroup.Column<byte>(column));

    static void AssertParquetSharpCanRead(Stream stream, FuzzCase fuzzCase)
    {
        using var reader = new ParquetFileReader(stream, leaveOpen: true);
        var rowGroupCount = checked((int)reader.FileMetaData.NumRowGroups);
        if (rowGroupCount != fuzzCase.RowGroups.Count)
            throw new InvalidOperationException(
                $"ParquetSharp row-group count mismatch. Expected {fuzzCase.RowGroups.Count}, got {rowGroupCount}.");

        AssertFileMetadata(reader, fuzzCase);

        for (var rowGroupIndex = 0; rowGroupIndex < rowGroupCount; rowGroupIndex++)
        {
            using var rowGroup = reader.RowGroup(rowGroupIndex);
            AssertRowGroupMetadata(rowGroup, fuzzCase, rowGroupIndex);
            var expectedRowCount = fuzzCase.RowGroups[rowGroupIndex][0].Length;
            var rowCount = checked((int)rowGroup.MetaData.NumRows);
            if (rowCount != expectedRowCount)
                throw new InvalidOperationException(
                    $"ParquetSharp row-group {rowGroupIndex} row count mismatch. Expected {expectedRowCount}, got {rowCount}.");

            for (var columnIndex = 0; columnIndex < fuzzCase.Columns.Count; columnIndex++)
            {
                if (!CanParquetSharpRead(fuzzCase.Columns[columnIndex]))
                    continue;
                var actual = ReadParquetSharpColumn(rowGroup, fuzzCase.Columns[columnIndex], rowCount, columnIndex);
                AssertArraysEqual("ParquetSharp", fuzzCase, rowGroupIndex, columnIndex,
                    fuzzCase.RowGroups[rowGroupIndex][columnIndex], actual);
            }
        }
    }

    // The value round trip never looked at the footer: created_by, key/value metadata, the codec of
    // every column chunk (file-wide or per-column override), declared sorting columns and the
    // per-chunk value counts were written and never compared with what was asked for.
    static void AssertFileMetadata(ParquetFileReader reader, FuzzCase fuzzCase)
    {
        var metadata = reader.FileMetaData;
        long expectedRows = 0;
        foreach (var group in fuzzCase.RowGroups)
            expectedRows += group[0].Length;
        if (metadata.NumRows != expectedRows)
            throw new InvalidOperationException(
                $"Footer num_rows mismatch. Expected {expectedRows}, got {metadata.NumRows}. {fuzzCase.Describe()}");
        if (metadata.NumColumns != fuzzCase.Columns.Count)
            throw new InvalidOperationException(
                $"Footer column count mismatch. Expected {fuzzCase.Columns.Count}, got {metadata.NumColumns}.");
        // ParquetSharp reads created_by as a C string, so an embedded NUL ends it early: compare the prefix.
        var expectedCreatedBy = fuzzCase.Settings.CreatedBy is { } createdBy
            ? createdBy[..(createdBy.IndexOf('\0') is var nul and >= 0 ? nul : createdBy.Length)]
            : null;
        if (!string.IsNullOrEmpty(expectedCreatedBy) && metadata.CreatedBy != expectedCreatedBy)
            throw new InvalidOperationException(
                $"Footer created_by mismatch. Expected '{expectedCreatedBy}', got '{metadata.CreatedBy}'.");
        if (fuzzCase.Settings.WithKeyValueMetadata)
        {
            var kv = metadata.KeyValueMetadata;
            if (kv is null || !kv.TryGetValue("fuzz", out var fuzzValue) || fuzzValue != "1"
                || !kv.TryGetValue("empty", out var emptyValue) || emptyValue != "")
                throw new InvalidOperationException("Footer key/value metadata lost or altered an entry.");
        }
    }

    static void AssertRowGroupMetadata(ParquetSharp.RowGroupReader rowGroup, FuzzCase fuzzCase, int rowGroupIndex)
    {
        var meta = rowGroup.MetaData;
        for (var c = 0; c < fuzzCase.Columns.Count; c++)
        {
            using var chunk = meta.GetColumnChunkMetaData(c);
            var options = fuzzCase.Columns[c].Column.Options!;
            var expected = options.Compression ?? fuzzCase.Compression;
            var actual = chunk.Compression;
            var ok = expected switch
            {
                CompressionKind.None => actual == ParquetSharp.Compression.Uncompressed,
                CompressionKind.Snappy => actual == ParquetSharp.Compression.Snappy,
                CompressionKind.Gzip => actual == ParquetSharp.Compression.Gzip,
                CompressionKind.Zstd => actual == ParquetSharp.Compression.Zstd,
                CompressionKind.Brotli => actual == ParquetSharp.Compression.Brotli,
                CompressionKind.Lz4 => actual is ParquetSharp.Compression.Lz4 or ParquetSharp.Compression.Lz4Hadoop,
                _ => true
            };
            if (!ok)
                throw new InvalidOperationException(
                    $"Row group {rowGroupIndex} column {c} codec mismatch: expected {expected}, footer says {actual}.");
            if (chunk.NumValues != fuzzCase.RowGroups[rowGroupIndex][c].Length)
                throw new InvalidOperationException(
                    $"Row group {rowGroupIndex} column {c} num_values {chunk.NumValues} != {fuzzCase.RowGroups[rowGroupIndex][c].Length}.");
        }

        var expectedSorting = fuzzCase.Settings.Sorting ?? [];
        var sorting = meta.SortingColumns();
        if ((sorting?.Length ?? 0) != expectedSorting.Length)
            throw new InvalidOperationException(
                $"Row group {rowGroupIndex} sorting column count {(sorting?.Length ?? 0)} != {expectedSorting.Length}.");
        for (var i = 0; i < expectedSorting.Length; i++)
            if (sorting![i].ColumnIndex != expectedSorting[i].ColumnOrdinal
                || sorting[i].IsDescending != expectedSorting[i].Descending
                || sorting[i].NullsFirst != expectedSorting[i].NullsFirst)
                throw new InvalidOperationException($"Row group {rowGroupIndex} sorting column {i} differs.");
    }

    // ParquetSharp is the second opinion on everything this target writes, so a
    // column it cannot represent has to be named rather than quietly mismatched.
    //
    // An unannotated FIXED_LEN_BYTE_ARRAY is the one case: its default
    // LogicalTypeFactory maps a descriptor to CLR types by logical type, and for
    // FLBA with no annotation it throws "unsupported logical type None with
    // physical type FixedLenByteArray". LogicalReaderOverride does not help — it
    // renames the element type but goes through the same mapping — and a custom
    // factory would additionally need a FixedLenByteArray-to-byte[] read
    // converter, which ParquetSharp does not ship. A hand-rolled oracle there
    // would be more likely to be wrong than to catch anything.
    //
    // These columns keep Plank's own round-trip check, which still compares every
    // value written against every value read. They lose only the
    // cross-implementation comparison.
    // ParquetSharp's Arrow has no ALP decoder ("Unknown encoding type."), and an
    // unhandled exception here killed the persistent fork server on the first
    // seed that drew ALP for a float or double column: the writer fleet aborted
    // at start-up ("Unable to request new process from fork server") on every
    // run after ALP became a writer choice. Plank's own read-back still checks
    // those columns.
    static bool CanParquetSharpRead(ColumnSpec spec)
    {
        if (spec.Encoding == EncodingKind.Alp)
            return false;

        // ParquetSharp 24.0.0's LogicalTypeFactory throws
        // "unsupported logical type {Enum|Float16|Geometry|Geography|Interval|Unknown} with physical type {ByteArray|FixedLenByteArray}"
        // for these exact schema annotations. Plank still round-trips every value above; keep the independent
        // reader for Bson, Float16, and every other annotation it can map.
        var logical = spec.Column.LogicalType;
        var physical = spec.Column.PhysicalType;
        if (logical is Plank.Schema.LogicalType.Enum or Plank.Schema.LogicalType.Geometry
                or Plank.Schema.LogicalType.Geography or Plank.Schema.LogicalType.Unknown)
            return physical == ParquetPhysicalType.FixedLenByteArray
                ? logical is not Plank.Schema.LogicalType.Unknown
                : physical != ParquetPhysicalType.ByteArray;
        if (logical is Plank.Schema.LogicalType.Interval)
            return physical != ParquetPhysicalType.FixedLenByteArray;
        if (logical is Plank.Schema.LogicalType.Float16)
            return physical != ParquetPhysicalType.FixedLenByteArray;

        return physical != ParquetPhysicalType.FixedLenByteArray || logical is not null;
    }

    static Array ReadParquetSharpColumn(ParquetSharp.RowGroupReader rowGroup, ColumnSpec spec, int rowCount,
        int columnIndex)
    {
        if (spec.ClrType == typeof(bool))
        {
            using var valueReader = rowGroup.Column(columnIndex).LogicalReader<bool>();
            return valueReader.ReadAll(rowCount);
        }

        if (spec.ClrType == typeof(bool?))
        {
            using var nullableReader = rowGroup.Column(columnIndex).LogicalReader<bool?>();
            return nullableReader.ReadAll(rowCount);
        }

        if (spec.ClrType == typeof(int))
        {
            using var valueReader = rowGroup.Column(columnIndex).LogicalReader<int>();
            return valueReader.ReadAll(rowCount);
        }

        if (spec.ClrType == typeof(int?))
        {
            using var nullableReader = rowGroup.Column(columnIndex).LogicalReader<int?>();
            return nullableReader.ReadAll(rowCount);
        }

        if (spec.ClrType == typeof(long))
        {
            using var valueReader = rowGroup.Column(columnIndex).LogicalReader<long>();
            return valueReader.ReadAll(rowCount);
        }

        if (spec.ClrType == typeof(long?))
        {
            using var nullableReader = rowGroup.Column(columnIndex).LogicalReader<long?>();
            return nullableReader.ReadAll(rowCount);
        }

        if (spec.ClrType == typeof(double))
        {
            using var valueReader = rowGroup.Column(columnIndex).LogicalReader<double>();
            return valueReader.ReadAll(rowCount);
        }

        if (spec.ClrType == typeof(double?))
        {
            using var nullableReader = rowGroup.Column(columnIndex).LogicalReader<double?>();
            return nullableReader.ReadAll(rowCount);
        }

        if (spec.ClrType == typeof(float))
        {
            using var valueReader = rowGroup.Column(columnIndex).LogicalReader<float>();
            return valueReader.ReadAll(rowCount);
        }

        if (spec.ClrType == typeof(float?))
        {
            using var nullableReader = rowGroup.Column(columnIndex).LogicalReader<float?>();
            return nullableReader.ReadAll(rowCount);
        }

        if (spec.ClrType == typeof(IntBox))
        {
            using var valueReader = rowGroup.Column(columnIndex).LogicalReader<int>();
            return Array.ConvertAll(valueReader.ReadAll(rowCount), static value => new IntBox(value));
        }

        if (spec.ClrType == typeof(LongBox?))
        {
            using var nullableReader = rowGroup.Column(columnIndex).LogicalReader<long?>();
            return Array.ConvertAll(nullableReader.ReadAll(rowCount), static value =>
                value is { } physical ? new LongBox(physical) : (LongBox?)null);
        }

        if (spec.ClrType == typeof(DoubleBox?))
        {
            using var nullableReader = rowGroup.Column(columnIndex).LogicalReader<double?>();
            return Array.ConvertAll(nullableReader.ReadAll(rowCount), static value =>
                value is { } physical ? new DoubleBox(physical) : (DoubleBox?)null);
        }

        using var bytesReader = rowGroup.Column(columnIndex).LogicalReader<byte[]>();
        return bytesReader.ReadAll(rowCount);
    }

    internal static T[] ReadAllBuffers<T>(RowGroupColumn<T> buffers)
    {
        var values = new List<T>();
        foreach (var buffer in buffers)
            foreach (var value in buffer.Values)
                values.Add(value);
        return values.ToArray();
    }

    // Variable-length byte[] columns are read as RowGroupColumn<byte>, one
    // span per row, rather than as RowGroupColumn<byte[]>.
    // A null must come back as null, not as an empty array: an optional column can
    // legitimately hold both, and collapsing them would make the round-trip check
    // blind to a writer that confused the two.
    internal static byte[]?[] ReadAllBinaryBuffers(RowGroupColumn<byte> buffers)
    {
        var values = new List<byte[]?>();
        foreach (var buffer in buffers)
            for (var i = 0; i < buffer.Count; i++)
                values.Add(buffer.IsNull(i) ? null : buffer.GetValue(i).ToArray());
        return values.ToArray();
    }

    static void AssertArraysEqual(string readerName, FuzzCase fuzzCase, int rowGroupIndex, int columnIndex,
        Array expected, Array actual)
    {
        var spec = fuzzCase.Columns[columnIndex];
        if (expected.Length != actual.Length)
            throw new InvalidOperationException(
                $"{readerName} row-group {rowGroupIndex} column {columnIndex} '{spec.Column.Name}' ({spec.Describe()}) length mismatch. Expected {expected.Length}, got {actual.Length}.");

        if (spec.ClrType == typeof(byte[]))
        {
            AssertByteArraysEqual(readerName, spec, rowGroupIndex, columnIndex, (byte[]?[])expected, (byte[]?[])actual);
            return;
        }

        for (var rowIndex = 0; rowIndex < expected.Length; rowIndex++)
            if (!Equals(actual.GetValue(rowIndex), expected.GetValue(rowIndex)))
                throw new InvalidOperationException(
                    $"{readerName} row-group {rowGroupIndex} column {columnIndex} '{spec.Column.Name}' ({spec.Describe()}) value mismatch at row {rowIndex}. Expected '{expected.GetValue(rowIndex)}', got '{actual.GetValue(rowIndex)}'.");
    }

    static void AssertByteArraysEqual(string readerName, ColumnSpec spec, int rowGroupIndex, int columnIndex,
        byte[]?[] expected, byte[]?[] actual)
    {
        for (var rowIndex = 0; rowIndex < expected.Length; rowIndex++)
            if (expected[rowIndex] is null != actual[rowIndex] is null ||
                (expected[rowIndex] is not null && !actual[rowIndex].SequenceEqual(expected[rowIndex])))
                throw new InvalidOperationException(
                    $"{readerName} row-group {rowGroupIndex} column {columnIndex} '{spec.Column.Name}' ({spec.Describe()}) byte[] mismatch at row {rowIndex}.");
    }

    static ImmutableArray<EncodingKind> SingleEncoding(EncodingKind encoding)
        => ImmutableArray.Create(encoding);

    public sealed class FuzzCase
    {
        internal FuzzCase(ColumnSpec[] columns, Array[][] rowGroups, CompressionKind compression,
            WriterSettings settings)
        {
            Columns = columns;
            RowGroups = rowGroups;
            Compression = compression;
            Settings = settings;
            Schema = new PlankSchema(columns.Select(static c => c.Column).ToImmutableArray());
        }

        public IReadOnlyList<ColumnSpec> Columns { get; }

        public IReadOnlyList<IReadOnlyList<Array>> RowGroups { get; }

        public PlankSchema Schema { get; }

        public CompressionKind Compression { get; }

        public WriterSettings Settings { get; }

        public string Describe()
            => $"Columns=[{string.Join(", ", Columns.Select(static c => $"{c.Column.Name}:{c.Describe()}"))}], "
               + $"RowGroups={RowGroups.Count}, Compression={Compression}, {Settings.Describe()}";
    }

    /// <summary>The writer options a case asks for, beyond the codec.</summary>
    /// <remarks>
    /// Every one of these was pinned to its default, and each default skips code.
    /// The page size matters most: it defaults to 1 MiB while a case writes at
    /// most 64 rows, so every column the target ever produced fit in a single
    /// page. Page splitting, per-page statistics, the page index and the
    /// multi-page read path were therefore unreachable no matter how long it ran.
    /// </remarks>
    public readonly record struct WriterSettings(
        PlankDataPageVersion DataPageVersion,
        bool WritePageCrc,
        bool WritePageIndexes,
        PlankFileVersion FileVersion,
        uint TargetDataPageSizeBytes,
        uint BufferChunkSizeBytes,
        bool WithKeyValueMetadata,
        int? CompressionLevel = null)
    {
        internal uint? InitialPageBufferBytes { get; init; }
        internal uint? InitialColumnBufferBytes { get; init; }
        internal uint? InitialPageCapacity { get; init; }
        internal string? CreatedBy { get; init; }
        internal int? WorkerCount { get; init; }
        internal WriterPoolKind Pool { get; init; }
        internal ParquetSortingColumn[]? Sorting { get; init; }
        internal bool Explicit { get; init; }

        public string Describe()
            => $"{DataPageVersion}/{FileVersion}/page={TargetDataPageSizeBytes}B/chunk={BufferChunkSizeBytes}B"
               + $"{(WritePageCrc ? "/crc" : "")}{(WritePageIndexes ? "/pageindex" : "")}"
               + $"{(WithKeyValueMetadata ? "/kv" : "")}" + (CompressionLevel is { } level ? $"/level={level}" : "")
               + $"/initPage={InitialPageBufferBytes}/initCol={InitialColumnBufferBytes}/pageCap={InitialPageCapacity}"
               + $"/workers={WorkerCount}/pool={Pool}/sort={Sorting?.Length ?? 0}";
    }

    public readonly record struct ColumnSpec(PlankColumn Column, Type ClrType)
    {
        public EncodingKind Encoding
            => Column.Options!.Encodings[0];

        public bool Optional
            => Column.Options!.Repetition == ParquetRepetition.Optional;

        public string Describe()
            => $"{Column.PhysicalType}/{Encoding}{(Optional ? "/optional" : "")}" +
               $"{(Column.Options!.BloomFilter is null ? "" : "/bloom")}";
    }

    sealed class Decoder
    {
        readonly ByteCursor _cursor;

        public Decoder(ReadOnlySpan<byte> data)
            => _cursor = new ByteCursor(data);

        public FuzzCase Decode()
        {
            var compression = PickCompression();
            var settings = PickWriterSettings();
            var columns = CreateColumns();
            var rowGroups = CreateRowGroups(columns);
            // Everything below draws AFTER the original decode so seeds saved before these
            // options existed still describe the same columns and values.
            settings = PickExtraSettings(settings, compression, columns);
            columns = PickColumnOverrides(columns, compression);
            rowGroups = ScaleRowGroups(rowGroups, columns);
            // One-byte pages/chunks are a legitimate boundary but cost one allocation per value:
            // keep them for small groups only so large groups do not become a pure resource test.
            // A page per value also rents the (320 KiB default) initial page buffer per page.
            if (settings.TargetDataPageSizeBytes < 64 && (settings.InitialPageBufferBytes ?? uint.MaxValue) > 4096)
                settings = settings with { InitialPageBufferBytes = 4096 };
            if (rowGroups.Max(static g => g[0].Length) > 256)
                settings = settings with
                {
                    TargetDataPageSizeBytes = Math.Max(settings.TargetDataPageSizeBytes, 256),
                    BufferChunkSizeBytes = Math.Max(settings.BufferChunkSizeBytes, 64)
                };
            return new FuzzCase(columns, rowGroups, compression, settings);
        }

        // The base decode caps a case at 3 groups x 64 rows and pins every buffer option to a
        // default derived from nothing, so growth of the page/column buffers, the page-capacity
        // table, row-group rollover and multi-page columns with the realistic 4 KiB page target
        // were reachable only by luck. These are independent fuzzer-chosen values, including 1,
        // tiny, power-of-two edges and the defaults.
        WriterSettings PickExtraSettings(WriterSettings settings, CompressionKind compression,
            ColumnSpec[] columns)
        {
            uint Pick(uint?[] choices)
                => choices[_cursor.NextInt(0, choices.Length)] ?? uint.MaxValue;

            var initialPage = Pick([null, 1, 2, 7, 64, 100, 4096, 65536]);
            var initialColumn = Pick([null, 1, 3, 16, 100, 1000, 65536, 1u << 20]);
            var initialPageCapacity = Pick([null, 0, 1, 2, 3, 4, 17]);
            var chunk = Pick([null, 1, 3, 8, 17, 63, 65, 4097]);
            var targetPage = Pick([null, 1, 8, 100, 513, 1000, 8192, 65535]);
            var createdBy = _cursor.NextInt(0, 5) switch
            {
                0 => null,
                1 => "",
                2 => "fuzz writer",
                3 => new string('x', 300),
                _ => "créé par ✓ \u0000 plank"
            };
            var workers = _cursor.NextInt(0, 6) switch { 0 => 1, 1 => 2, 2 => 3, 3 => 8, _ => 0 };
            var pool = (WriterPoolKind)_cursor.NextInt(0, 7);
            var sortingCount = _cursor.NextInt(0, 4) == 0 ? _cursor.NextInt(1, columns.Length + 1) : 0;
            // Ordinals must be distinct (duplicates are invalid input), so draw a partial shuffle.
            var ordinals = Enumerable.Range(0, columns.Length).ToArray();
            var sorting = new ParquetSortingColumn[sortingCount];
            for (var i = 0; i < sorting.Length; i++)
            {
                var j = _cursor.NextInt(i, ordinals.Length);
                (ordinals[i], ordinals[j]) = (ordinals[j], ordinals[i]);
                sorting[i] = new ParquetSortingColumn(ordinals[i], _cursor.NextInt(0, 2) == 0,
                    _cursor.NextInt(0, 2) == 0);
            }
            return settings with
            {
                InitialPageBufferBytes = initialPage == uint.MaxValue ? null : initialPage,
                InitialColumnBufferBytes = initialColumn == uint.MaxValue ? null : initialColumn,
                InitialPageCapacity = initialPageCapacity == uint.MaxValue ? null : initialPageCapacity,
                BufferChunkSizeBytes = chunk == uint.MaxValue ? settings.BufferChunkSizeBytes : chunk,
                TargetDataPageSizeBytes = targetPage == uint.MaxValue ? settings.TargetDataPageSizeBytes : targetPage,
                CreatedBy = createdBy,
                WorkerCount = workers == 0 ? null : workers,
                Pool = pool,
                Sorting = sorting,
                Explicit = true,
                CompressionLevel = PickLevel(compression),
            };
        }

        int? PickLevel(CompressionKind compression)
        {
            if (_cursor.NextInt(0, 2) == 0)
                return null;
            return compression switch
            {
                CompressionKind.Gzip => _cursor.NextInt(0, 10),
                CompressionKind.Zstd => _cursor.NextInt(0, 6) switch
                {
                    0 => ZstdSharp.Compressor.MinCompressionLevel,
                    1 => ZstdSharp.Compressor.MaxCompressionLevel,
                    2 => -1,
                    3 => 0,
                    4 => 3,
                    _ => 19
                },
                CompressionKind.Lz4 => _cursor.NextInt(0, 11) is var l and > 0 ? l + 2 : 0,
                CompressionKind.Brotli => _cursor.NextInt(0, 12),
                _ => null
            };
        }

        // Per-column compression/level overrides and bloom-filter tuning were never set: the
        // column options always inherited the file codec and used the default bloom filter.
        ColumnSpec[] PickColumnOverrides(ColumnSpec[] columns, CompressionKind fileCompression)
        {
            var result = new ColumnSpec[columns.Length];
            for (var i = 0; i < columns.Length; i++)
            {
                var spec = columns[i];
                var old = spec.Column.Options!;
                CompressionKind? columnCompression = null;
                int? columnLevel = null;
                if (_cursor.NextInt(0, 4) == 0)
                {
                    columnCompression = _cursor.NextInt(0, 6) switch
                    {
                        0 => CompressionKind.None,
                        1 => CompressionKind.Snappy,
                        2 => CompressionKind.Gzip,
                        3 => CompressionKind.Zstd,
                        4 => CompressionKind.Lz4,
                        _ => CompressionKind.Brotli
                    };
                    columnLevel = PickLevel(columnCompression.Value);
                }
                var bloom = old.BloomFilter;
                if (bloom is not null && _cursor.NextInt(0, 2) == 0)
                    bloom = new ParquetBloomFilterOptions
                    {
                        FalsePositiveProbability = _cursor.NextInt(0, 5) switch
                        {
                            0 => 0.5, 1 => 0.1, 2 => 0.001, 3 => 1e-9, _ => 0.01
                        },
                        ExpectedDistinctValueCount = _cursor.NextInt(0, 3) switch
                        {
                            0 => null, 1 => 1u, _ => (uint)_cursor.NextInt(1, 100_000)
                        },
                        MaximumBytes = 32u << _cursor.NextInt(0, 14)
                    };
                if (columnCompression is null && ReferenceEquals(bloom, old.BloomFilter))
                {
                    result[i] = spec;
                    continue;
                }
                var options = new ColumnOptions(old.Repetition, old.Encodings, old.TypeLength,
                    columnCompression, columnLevel, bloom);
                result[i] = spec with
                {
                    Column = Plank.Schema.ColumnDefinition.Leaf(spec.Column.Name, spec.Column.PhysicalType!.Value, options)
                };
            }
            return result;
        }

        // Tiles each row group's values to reach counts the 64-row cap never produces (several
        // 4 KiB pages, dictionary overflow, index width changes) and repeats whole groups.
        // Tiling preserves each column's value distribution and null pattern, so the decoded
        // expectations stay trivially correct. Delta columns keep working because deltas simply
        // jump back at tile seams, which is itself a useful negative-delta pattern.
        Array[][] ScaleRowGroups(Array[][] rowGroups, ColumnSpec[] columns)
        {
            var tile = _cursor.NextInt(0, 8) switch
            {
                0 or 1 or 2 or 3 => 1,
                4 => 2,
                5 => 5,
                6 => 17,
                _ => 70
            };
            var extraGroups = _cursor.NextInt(0, 4) switch { 0 => _cursor.NextInt(1, 6), _ => 0 };
            if (tile == 1 && extraGroups == 0)
                return rowGroups;

            var scaled = new List<Array[]>();
            foreach (var group in rowGroups)
            {
                var copy = new Array[group.Length];
                for (var c = 0; c < group.Length; c++)
                    copy[c] = Tile(group[c], tile);
                scaled.Add(copy);
            }
            for (var i = 0; i < extraGroups; i++)
                scaled.Add(scaled[_cursor.NextInt(0, scaled.Count)]);
            return scaled.ToArray();
        }

        static Array Tile(Array source, int tile)
        {
            if (tile == 1)
                return source;
            var result = Array.CreateInstance(source.GetType().GetElementType()!, source.Length * tile);
            for (var i = 0; i < tile; i++)
                Array.Copy(source, 0, result, i * source.Length, source.Length);
            return result;
        }

        // Compression used to be pinned to None, which left every codec — and
        // the round-trip through it — outside anything this target could
        // generate. Lz4Legacy is excluded: the writer cannot produce it.
        CompressionKind PickCompression()
            => _cursor.NextInt(0, 6) switch
            {
                0 => CompressionKind.None,
                1 => CompressionKind.Snappy,
                2 => CompressionKind.Gzip,
                3 => CompressionKind.Zstd,
                4 => CompressionKind.Lz4,
                _ => CompressionKind.Brotli
            };

        WriterSettings PickWriterSettings()
            => new(
                // V1 pages carry their levels inside the payload; V2 keeps them in
                // the header. Only V2 was ever written.
                DataPageVersion: _cursor.NextInt(0, 2) == 0
                    ? PlankDataPageVersion.V2
                    : PlankDataPageVersion.V1,
                WritePageCrc: _cursor.NextInt(0, 3) == 0,
                // Defaults to on, so the "no page index" footer shape was never
                // written and the reader never had to cope with its absence.
                WritePageIndexes: _cursor.NextInt(0, 4) != 0,
                FileVersion: _cursor.NextInt(0, 4) == 0
                    ? PlankFileVersion.V2
                    : PlankFileVersion.V1,
                // Small enough to force several pages out of a 64-row column, which
                // is the only way to reach page splitting and per-page statistics.
                // The large value keeps the single-page shape in rotation.
                TargetDataPageSizeBytes: _cursor.NextInt(0, 4) switch
                {
                    0 => 64,
                    1 => 256,
                    2 => 4096,
                    _ => 1024 * 1024
                },
                // Drives the buffer growth and segment-spanning paths in
                // BufferWriter, which a single large chunk never exercises.
                BufferChunkSizeBytes: _cursor.NextInt(0, 3) switch
                {
                    0 => 64,
                    1 => 1024,
                    _ => 64 * 1024
                },
                WithKeyValueMetadata: _cursor.NextInt(0, 4) == 0);

        ColumnSpec[] CreateColumns()
        {
            var count = _cursor.NextInt(1, MaxColumnCount + 1);
            var columns = new ColumnSpec[count];
            for (var columnIndex = 0; columnIndex < columns.Length; columnIndex++)
                columns[columnIndex] = CreateColumn(columnIndex);
            return columns;
        }

        // Five of the eight physical types were writable and three were not, so
        // the encoders and statistics for FLOAT and FIXED_LEN_BYTE_ARRAY were
        // never written by anything: PlainEncoding.WriteFloatValues 0/15,
        // WriteFixedLengthByteArrayValues 0/41, and every float path in
        // ColumnStatistics — the vectorized min/max included — flat at zero.
        ColumnSpec CreateColumn(int columnIndex)
            => _cursor.NextInt(0, 7) switch
            {
                0 => CreateBooleanColumn(columnIndex),
                1 => CreateInt32Column(columnIndex),
                2 => CreateInt64Column(columnIndex),
                3 => CreateDoubleColumn(columnIndex),
                4 => CreateFloatColumn(columnIndex),
                5 => CreateFixedLenByteArrayColumn(columnIndex),
                _ => CreateByteArrayColumn(columnIndex)
            };

        // Optional columns are where definition levels, the nullable encode
        // paths and the statistics null counts live; the target generated none,
        // so ColumnStatistics and much of SerializedColumn were never written.
        bool NextOptional()
            => _cursor.NextInt(0, 2) == 0;

        // A bloom filter is a separate structure with its own footer offsets.
        // BloomFilterBuilder sat at 1.4% because nothing asked for one.
        ParquetBloomFilterOptions? NextBloomFilter(ParquetPhysicalType physicalType)
            => physicalType != ParquetPhysicalType.Boolean && _cursor.NextInt(0, 4) == 0
                ? ParquetBloomFilterOptions.Default
                : null;

        ColumnOptions Options(ParquetPhysicalType physicalType, EncodingKind encoding, bool optional)
            => new(optional ? ParquetRepetition.Optional : ParquetRepetition.Required,
                encodings: SingleEncoding(encoding), bloomFilter: NextBloomFilter(physicalType));

        ColumnSpec CreateBooleanColumn(int columnIndex)
        {
            var optional = NextOptional();
            return new ColumnSpec(Plank.Schema.ColumnDefinition.Leaf($"c{columnIndex}_bool",
                ParquetPhysicalType.Boolean, Options(ParquetPhysicalType.Boolean, EncodingKind.Plain, optional)),
                optional ? typeof(bool?) : typeof(bool));
        }

        ColumnSpec CreateInt32Column(int columnIndex)
        {
            var encoding = PickEncoding([
                EncodingKind.Plain,
                EncodingKind.DeltaBinaryPacked,
                EncodingKind.PlainDictionary,
                EncodingKind.RleDictionary
            ]);
            var optional = NextOptional();
            return new ColumnSpec(Plank.Schema.ColumnDefinition.Leaf($"c{columnIndex}_i32", ParquetPhysicalType.Int32,
                Options(ParquetPhysicalType.Int32, encoding, optional)), optional ? typeof(int?) : typeof(int));
        }

        ColumnSpec CreateInt64Column(int columnIndex)
        {
            var encoding = PickEncoding([
                EncodingKind.Plain,
                EncodingKind.DeltaBinaryPacked,
                EncodingKind.PlainDictionary,
                EncodingKind.RleDictionary
            ]);
            var optional = NextOptional();
            return new ColumnSpec(Plank.Schema.ColumnDefinition.Leaf($"c{columnIndex}_i64", ParquetPhysicalType.Int64,
                Options(ParquetPhysicalType.Int64, encoding, optional)), optional ? typeof(long?) : typeof(long));
        }

        ColumnSpec CreateDoubleColumn(int columnIndex)
        {
            var encoding = PickEncoding([
                EncodingKind.Plain,
                EncodingKind.ByteStreamSplit,
                EncodingKind.Alp
            ]);
            var optional = NextOptional();
            return new ColumnSpec(Plank.Schema.ColumnDefinition.Leaf($"c{columnIndex}_dbl", ParquetPhysicalType.Double,
                Options(ParquetPhysicalType.Double, encoding, optional)), optional ? typeof(double?) : typeof(double));
        }

        ColumnSpec CreateFloatColumn(int columnIndex)
        {
            var encoding = PickEncoding([
                EncodingKind.Plain,
                EncodingKind.ByteStreamSplit,
                EncodingKind.Alp
            ]);
            var optional = NextOptional();
            return new ColumnSpec(Plank.Schema.ColumnDefinition.Leaf($"c{columnIndex}_flt", ParquetPhysicalType.Float,
                Options(ParquetPhysicalType.Float, encoding, optional)), optional ? typeof(float?) : typeof(float));
        }

        // A fixed-length column is still byte[] on both sides, so it shares every
        // dispatch with the variable-length one; the width is what differs, and it
        // is fuzzed because the encoder's stride arithmetic depends on it. Widths
        // stay small: the point is the bookkeeping, not the payload.
        ColumnSpec CreateFixedLenByteArrayColumn(int columnIndex)
        {
            var encoding = PickEncoding([
                EncodingKind.Plain,
                EncodingKind.PlainDictionary,
                EncodingKind.RleDictionary
            ]);
            var optional = NextOptional();
            var length = (uint)_cursor.NextInt(1, MaxFixedLength + 1);
            var options = new ColumnOptions(
                optional ? ParquetRepetition.Optional : ParquetRepetition.Required,
                encodings: SingleEncoding(encoding),
                typeLength: length,
                bloomFilter: NextBloomFilter(ParquetPhysicalType.FixedLenByteArray));
            return new ColumnSpec(
                Plank.Schema.ColumnDefinition.Leaf($"c{columnIndex}_flba",
                    ParquetPhysicalType.FixedLenByteArray, options),
                typeof(byte[]));
        }

        ColumnSpec CreateByteArrayColumn(int columnIndex)
        {
            // The dictionary encodings were missing here while the int32, int64
            // and double columns all had them. A byte[] dictionary is a
            // different implementation from a fixed-width one — it hashes the
            // bytes with wyhash and compares them for equality, rather than
            // hashing a value type — so leaving them out left WyHashing (0/88)
            // and ByteArrayComparer (0/22) both entirely unwritten, and with
            // nothing writing them nothing read them back either.
            var encoding = PickEncoding([
                EncodingKind.Plain,
                EncodingKind.DeltaLengthByteArray,
                EncodingKind.DeltaByteArray,
                EncodingKind.PlainDictionary,
                EncodingKind.RleDictionary
            ]);
            var optional = NextOptional();
            return new ColumnSpec(Plank.Schema.ColumnDefinition.Leaf($"c{columnIndex}_bin", ParquetPhysicalType.ByteArray,
                Options(ParquetPhysicalType.ByteArray, encoding, optional)), typeof(byte[]));
        }

        EncodingKind PickEncoding(ReadOnlySpan<EncodingKind> encodings)
            => encodings[_cursor.NextInt(0, encodings.Length)];

        Array[][] CreateRowGroups(ColumnSpec[] columns)
        {
            var rowGroupCount = _cursor.NextInt(1, MaxRowGroupCount + 1);
            var rowGroups = new Array[rowGroupCount][];
            for (var rowGroupIndex = 0; rowGroupIndex < rowGroups.Length; rowGroupIndex++)
            {
                var rowCount = _cursor.NextInt(1, MaxRowCount + 1);
                var rowGroup = new Array[columns.Length];
                for (var columnIndex = 0; columnIndex < columns.Length; columnIndex++)
                    rowGroup[columnIndex] = CreateValues(columns[columnIndex], rowCount);
                rowGroups[rowGroupIndex] = rowGroup;
            }
            return rowGroups;
        }

        Array CreateValues(ColumnSpec spec, int rowCount)
            => spec.ClrType == typeof(bool) ? CreateBooleanValues(rowCount)
            : spec.ClrType == typeof(bool?) ? Nullable(CreateBooleanValues(rowCount))
            : spec.ClrType == typeof(int) ? CreateInt32Values(spec.Encoding, rowCount)
            : spec.ClrType == typeof(int?) ? Nullable(CreateInt32Values(spec.Encoding, rowCount))
            : spec.ClrType == typeof(long) ? CreateInt64Values(spec.Encoding, rowCount)
            : spec.ClrType == typeof(long?) ? Nullable(CreateInt64Values(spec.Encoding, rowCount))
            : spec.ClrType == typeof(double) ? CreateDoubleValues(spec.Encoding, rowCount)
            : spec.ClrType == typeof(double?) ? Nullable(CreateDoubleValues(spec.Encoding, rowCount))
            : spec.ClrType == typeof(float) ? CreateFloatValues(spec.Encoding, rowCount)
            : spec.ClrType == typeof(float?) ? Nullable(CreateFloatValues(spec.Encoding, rowCount))
            // Both byte[] columns land here; only the fixed-width one constrains
            // the length, and writing the wrong length is a caller error rather
            // than something the writer should have to survive.
            : spec.Column.PhysicalType == ParquetPhysicalType.FixedLenByteArray
                ? CreateFixedLengthValues(checked((int)spec.Column.Options!.TypeLength), rowCount, spec.Optional)
                : CreateByteArrayValues(spec.Encoding, rowCount, spec.Optional);

        // Punch holes in an already-generated column. Doing it here rather than
        // in each generator keeps the value distributions identical between the
        // required and optional cases, so the only difference under test is the
        // definition levels.
        TValue?[] Nullable<TValue>(TValue[] values) where TValue : struct
        {
            var result = new TValue?[values.Length];
            for (var i = 0; i < values.Length; i++)
                result[i] = _cursor.NextInt(0, 4) == 0 ? null : values[i];
            return result;
        }

        bool[] CreateBooleanValues(int rowCount)
        {
            var values = new bool[rowCount];
            for (var i = 0; i < values.Length; i++)
                values[i] = _cursor.NextInt(0, 2) == 0;
            return values;
        }

        int[] CreateInt32Values(EncodingKind encoding, int rowCount)
        {
            var values = new int[rowCount];
            var accumulator = _cursor.NextInt(-100_000, 100_001);
            var dictionary = CreateInt32Dictionary();
            for (var i = 0; i < values.Length; i++)
                values[i] = encoding switch
                {
                    EncodingKind.DeltaBinaryPacked => accumulator += _cursor.NextInt(-2, 11),
                    EncodingKind.PlainDictionary or EncodingKind.RleDictionary =>
                        dictionary[_cursor.NextInt(0, dictionary.Length)],
                    _ => _cursor.NextInt(-1_000_000, 1_000_001)
                };
            return values;
        }

        long[] CreateInt64Values(EncodingKind encoding, int rowCount)
        {
            var values = new long[rowCount];
            var accumulator = _cursor.NextInt64(-1_000_000L, 1_000_001L);
            var dictionary = CreateInt64Dictionary();
            for (var i = 0; i < values.Length; i++)
                values[i] = encoding switch
                {
                    EncodingKind.DeltaBinaryPacked => accumulator += _cursor.NextInt(-4, 8193),
                    EncodingKind.PlainDictionary or EncodingKind.RleDictionary =>
                        dictionary[_cursor.NextInt(0, dictionary.Length)],
                    _ => _cursor.NextInt64(-10_000_000_000L, 10_000_000_001L)
                };
            return values;
        }

        double[] CreateDoubleValues(EncodingKind encoding, int rowCount)
        {
            var values = new double[rowCount];
            for (var i = 0; i < values.Length; i++)
                values[i] = _cursor.NextInt(0, 8) == 0
                    ? SpecialDouble()
                    : encoding == EncodingKind.Alp
                        ? _cursor.NextInt(-1_000_000, 1_000_001) / 100d
                        : (_cursor.NextInt(-1_000_000, 1_000_001) / 128d) + _cursor.NextDouble();
            return values;
        }

        float[] CreateFloatValues(EncodingKind encoding, int rowCount)
        {
            var values = new float[rowCount];
            for (var i = 0; i < values.Length; i++)
                values[i] = _cursor.NextInt(0, 8) == 0
                    ? (float)SpecialDouble()
                    : encoding == EncodingKind.Alp
                        ? _cursor.NextInt(-1_000_000, 1_000_001) / 100f
                        : (_cursor.NextInt(-1_000_000, 1_000_001) / 128f) + (float)_cursor.NextDouble();
            return values;
        }

        // Statistics track a minimum and a maximum, and these are the values that
        // make that ordering awkward: NaN is unordered against everything, the
        // infinities bound it, and negative zero compares equal to zero while
        // encoding differently. Every float and double value the target wrote was
        // an ordinary finite number, so the NaN and signed-zero branches in
        // ColumnStatistics — including the vectorized min/max — never ran.
        double SpecialDouble()
            => _cursor.NextInt(0, 6) switch
            {
                0 => double.NaN,
                1 => double.PositiveInfinity,
                2 => double.NegativeInfinity,
                3 => -0d,
                4 => double.Epsilon,
                _ => 0d
            };

        byte[]?[] CreateFixedLengthValues(int length, int rowCount, bool optional)
        {
            var values = new byte[]?[rowCount];
            // A dictionary over fixed-width values needs repeats for the same
            // reason the variable-width one does.
            var dictionary = new byte[_cursor.NextInt(1, 6)][];
            for (var i = 0; i < dictionary.Length; i++)
                dictionary[i] = CreateRandomBytes(length);
            for (var i = 0; i < values.Length; i++)
                values[i] = optional && _cursor.NextInt(0, 4) == 0
                    ? null
                    : dictionary[_cursor.NextInt(0, dictionary.Length)];
            return values;
        }

        byte[][] CreateByteArrayValues(EncodingKind encoding, int rowCount, bool optional)
        {
            var values = new byte[rowCount][];
            var prefix = CreateRandomBytes(_cursor.NextInt(0, 7));

            // A dictionary only forms if values repeat. All-distinct values make
            // one pointless and the writer correctly falls back to plain, which
            // is what asking for a dictionary encoding over random bytes gets
            // you — the encoding would be requested and never exercised. So the
            // dictionary cases draw from a small pool, and the pool size is
            // fuzzed too: it decides the index bit width, and a pool of one
            // collapses the whole column to a single entry.
            var dictionary = encoding is EncodingKind.PlainDictionary or EncodingKind.RleDictionary
                ? CreateByteArrayDictionary(_cursor.NextInt(1, 9))
                : null;

            for (var i = 0; i < values.Length; i++)
                values[i] = optional && _cursor.NextInt(0, 4) == 0 ? null! : encoding switch
                {
                    EncodingKind.DeltaByteArray => CreateBytesWithPrefix(prefix),
                    EncodingKind.DeltaLengthByteArray => CreateRandomBytes(_cursor.NextInt(0, MaxByteArrayLength + 1)),
                    EncodingKind.PlainDictionary or EncodingKind.RleDictionary =>
                        dictionary![_cursor.NextInt(0, dictionary.Length)],
                    _ => CreateRandomBytes(_cursor.NextInt(0, MaxByteArrayLength + 1))
                };
            return values;
        }

        // Entries share prefixes and include an empty one, because the hash and
        // the equality comparison are what a byte[] dictionary does differently
        // from a fixed-width one, and near-identical keys are what tests them.
        byte[][] CreateByteArrayDictionary(int count)
        {
            var entries = new byte[count][];
            var shared = CreateRandomBytes(_cursor.NextInt(0, 5));
            for (var i = 0; i < entries.Length; i++)
                entries[i] = i == 0 ? [] : CreateBytesWithPrefix(shared);
            return entries;
        }

        int[] CreateInt32Dictionary()
        {
            var values = new int[_cursor.NextInt(1, 9)];
            for (var i = 0; i < values.Length; i++)
                values[i] = _cursor.NextInt(-4096, 4097);
            return values;
        }

        long[] CreateInt64Dictionary()
        {
            var values = new long[_cursor.NextInt(1, 9)];
            for (var i = 0; i < values.Length; i++)
                values[i] = _cursor.NextInt64(-1_000_000L, 1_000_001L);
            return values;
        }

        byte[] CreateBytesWithPrefix(byte[] prefix)
        {
            var suffix = CreateRandomBytes(_cursor.NextInt(0, MaxByteArrayLength + 1 - prefix.Length));
            var value = new byte[prefix.Length + suffix.Length];
            prefix.CopyTo(value, 0);
            suffix.CopyTo(value, prefix.Length);
            return value;
        }

        byte[] CreateRandomBytes(int length)
        {
            var value = new byte[length];
            _cursor.NextBytes(value);
            return value;
        }
    }

    sealed class ByteCursor
    {
        readonly byte[] _data;
        int _offset;

        public ByteCursor(ReadOnlySpan<byte> data)
            => _data = data.ToArray();

        public int NextInt(int minInclusive, int maxExclusive)
        {
            if (minInclusive >= maxExclusive)
                throw new ArgumentOutOfRangeException(nameof(maxExclusive),
                    "maxExclusive must be greater than minInclusive.");

            var range = (uint)(maxExclusive - minInclusive);
            return minInclusive + (int)(NextUInt32() % range);
        }

        public long NextInt64(long minInclusive, long maxExclusive)
        {
            if (minInclusive >= maxExclusive)
                throw new ArgumentOutOfRangeException(nameof(maxExclusive),
                    "maxExclusive must be greater than minInclusive.");

            var range = (ulong)(maxExclusive - minInclusive);
            return minInclusive + (long)(NextUInt64() % range);
        }

        public double NextDouble()
            => NextUInt64() / ((double)ulong.MaxValue + 1d);

        public void NextBytes(Span<byte> buffer)
        {
            for (var i = 0; i < buffer.Length; i++)
                buffer[i] = NextByte();
        }

        byte NextByte()
            => _data.Length == 0 ? (byte)0 : _data[_offset++ % _data.Length];

        uint NextUInt32()
        {
            uint value = NextByte();
            value |= (uint)NextByte() << 8;
            value |= (uint)NextByte() << 16;
            value |= (uint)NextByte() << 24;
            return value;
        }

        ulong NextUInt64()
            => ((ulong)NextUInt32() << 32) | NextUInt32();
    }

}
