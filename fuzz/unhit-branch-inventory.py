#!/usr/bin/env python3
"""Export unhit library branch outcomes from a complete four-tier snapshot.

Usage: python3 fuzz/unhit-branch-inventory.py 20261111ae > fuzz/unhit-20261111ae.tsv
       python3 fuzz/unhit-branch-inventory.py TAG --unlabeled > fresh.tsv
The table is an audit queue, not a claim that its rows are dead code.
Use --unlabeled for a new build; source lines and IL offsets can shift, so old
classification labels must be reconciled before reuse.
"""

import csv
import glob
import json
import sys


def status(source, method, line, offset, path, ordinal):
    # Keep these deliberately narrow. A zero-hit tuple is not dead by default.
    if (source, line, offset, path, ordinal) in {
        ("Writing/Encoding/ByteStreamSplitEncoding.cs", 142, 327, 1, 13),
        ("Writing/Encoding/DeltaBinaryPackedEncoding.cs", 997, 3, 1, 1),
    }:
        return "reachable_alternate_numeric_encoding_sample"
    if (source == "Writing/Encoding/DeltaBinaryPackedEncoding.cs"
            and "WritePackedUnsignedValues" in method):
        # Only the decoder unit tests call this internal writer helper.
        # No production Plank source references it.
        return "no_production_caller_candidate"
    if source == "Writing/MinMaxScan.cs" and (line, offset, path, ordinal) in {
        (104, 7, 0, 0), (106, 39, 0, 2),
    }:
        # PlainEncoding's two sole call sites return for zero values and pass
        # a destination span sliced to the exact required byte count.
        return "preempted_plain_page_statistics_callers"
    if source == "Writing/MinMaxScan.cs" and "CopyAndComputeVector128Bulk" in method:
        # Sole production calls are the ARM PLAIN page writers, chosen by
        # Encoding only when AdvSimd.Arm64.IsSupported; this helper is the
        # little-endian arm inside those writers.
        return "arm64_little_endian_plain_writer_guard"
    if source == "Writing/MinMaxScan.cs" and "ComputeVector128Bulk" in method:
        # The ARM PLAIN page writers call this only on big-endian hosts.
        return "arm64_big_endian_plain_writer_guard"
    if source == "Writing/AppendSortingOrder.cs" and (
            line, offset, path, ordinal) in {
        (97, 1000, 1, 83), (98, 1039, 0, 84),
        (99, 1078, 1, 87), (100, 1117, 0, 88),
    }:
        return "reachable_append_signedness_controls"
    if source == "Writing/BloomFilterBuilder.cs" and "InsertObject" in method:
        # Supported required/optional/repeated physical leaves use typed
        # InsertValues paths after serialization validates and normalizes
        # their shapes. InsertObject is reached by the unsupported fallback
        # (e.g. Decimal), which takes the already-covered default throw.
        return "preempted_typed_bloom_value_dispatch"
    if source == "Reading/Logical/RowGroup.cs" and line == 229 and (
            "ValidatePhysicalType" in method):
        # The only supported CLR types resolving to ByteArray are byte[] and
        # string; both throw in the earlier binary-type guard at line 200.
        # The return for byte[] with FixedLen/Int96 can never be reached.
        return "dead_candidate_preceding_binary_type_reject"
    if (source, line, offset, path, ordinal) == (
            "Reading/Logical/RowGroup.cs", 225, 734, 0, 42):
        return "reachable_rowgroup_unsupported_clr_sample"
    if source == "Writing/ColumnStatistics.cs" and (
            line, offset, path, ordinal) in {
        (1403, 7, 0, 0), (1404, 16, 0, 2),
        (1404, 16, 1, 3), (1405, 34, 0, 4),
        (1410, 84, 0, 6), (1411, 87, 0, 8),
        (1411, 87, 1, 9), (1416, 135, 0, 10),
        (1417, 138, 0, 12), (1417, 138, 1, 13),
    }:
        return "reachable_decimal_binary_byte_payload_sample"
    if source == "RowApi/RowApiNestedColumnDescriptor.cs" and "::.ctor(" in method:
        return "reachable_nested_descriptor_validation_sample"
    if (source, line, offset, path, ordinal) in {
        ("Writing/Encoding/Encoding.cs", 1085, 15, 1, 1),
        ("Writing/Encoding/Encoding.cs", 1085, 29, 1, 3),
        ("Writing/Encoding/Encoding.cs", 1250, 1141, 0, 72),
    }:
        return "reachable_optional_double_dictionary_focused_sample"
    if source == "Writing/Encoding/Encoding.cs" and (
            line, offset, path, ordinal) in {
        (1085, 38, 1, 5), (1085, 70, 1, 11), (1085, 84, 1, 13),
    }:
        return "preempted_optional_double_dictionary_caller"
    if (source, line, offset, path, ordinal) == (
            "Writing/Encoding/Encoding.cs", 1085, 99, 1, 15):
        return "preempted_default_strategy_page_size_result"
    if source == "Writing/Encoding/Encoding.cs" and (
            line, offset, path, ordinal) in {
        (1085, 106, 1, 17), (1085, 113, 1, 19), (1085, 127, 0, 22),
    }:
        return "optional_double_dictionary_host_layout_gate"
    if source == "Writing/Encoding/Encoding.cs" and (
            line, offset, path, ordinal) in {
        (1246, 1107, 0, 66), (1250, 1137, 1, 71), (1250, 1145, 0, 74),
    }:
        return "preempted_optional_double_dictionary_progress_invariant"
    if source == "Writing/Encoding/Encoding.cs" and (
            line, offset, path, ordinal) in {
        (3821, 52, 0, 2), (3855, 296, 0, 11),
        (3865, 397, 1, 23), (3865, 427, 1, 25),
        (3881, 516, 1, 29), (3881, 546, 1, 31),
        (3897, 635, 1, 35), (3897, 665, 1, 37),
        (3913, 754, 1, 41), (3913, 784, 1, 43),
        (3929, 873, 1, 47), (3929, 903, 1, 49),
        (3940, 958, 1, 51), (3952, 1044, 1, 55),
    }:
        return "reachable_repeated_rows_focused_sample"
    if source == "Writing/ParquetWriter.cs" and (
            line, offset, path, ordinal) in {
        (97, 115, 1, 3), (98, 165, 1, 5),
        (101, 314, 1, 9), (106, 423, 0, 12),
        (108, 452, 0, 14),
    }:
        # ParquetSchema's constructor always populates Columns, LeafPaths,
        # and LeafProjectionInfos with matching nondefault arrays.
        return "preempted_schema_projection_constructor_invariant"
    if source == "Writing/ParquetWriter.cs" and (
            line, offset, path, ordinal) in {
        (98, 186, 1, 7), (101, 335, 1, 11),
        (121, 699, 1, 17), (148, 857, 0, 22),
    }:
        return "reachable_parquet_writer_constructor_controls"
    if source == "Writing/Encoding/Encoding.cs" and (
            "BuildOptionalDictionaryIndexes" in method):
        return "reachable_optional_memory_dictionary_index_sample"
    if source == "Writing/Encoding/DeltaByteArrayEncoding.cs" and (
            "WritePayloads" in method):
        return "reachable_delta_bytearray_memory_payload_sample"
    if source == "Writing/ColumnStatistics.cs" and any(
            name in method for name in (
                "::CreateByteArray(", "::CreateOptionalByteArray(",
                "::CreateNullableMemory(")) and "Plank.ParquetBuffer&" not in method:
        # Public binary serialization uses the reusable-buffer wrappers;
        # their generic fallback runs only for types other than these three.
        return "no_public_unpooled_binary_statistics_route"
    if source == "Writing/ColumnStatistics.cs" and (
            line, offset, path, ordinal) in {
        (776, 7, 0, 0),
        (849, 87, 0, 4), (851, 112, 1, 7),
        (941, 136, 0, 8), (941, 136, 1, 9),
        (943, 49, 0, 0), (943, 49, 1, 1),
        (950, 79, 0, 2), (950, 79, 1, 3),
        (958, 101, 0, 4), (958, 101, 1, 5),
        (960, 116, 0, 6), (960, 116, 1, 7),
        (964, 139, 1, 11),
    }:
        return "reachable_pooled_binary_statistics_sample"
    if source == "Writing/ColumnStatistics.cs" and (
            line, offset, path, ordinal) in {
        (779, 26, 0, 2), (783, 78, 0, 4),
    }:
        return "preempted_required_binary_null_encoding"
    if (source, line, offset, path, ordinal) == (
            "Writing/ColumnStatistics.cs", 964, 139, 0, 10):
        return "preempted_optional_memory_all_null_shortcut"
    if source == "Writing/ColumnStatistics.cs" and (
            "TryGetNullableFloatMinMax" in method or
            "TryGetNullableDoubleMinMax" in method):
        # Public nullable float/double writes with present values take the
        # DataV2 page-statistics path. Their all-null fallback reaches only
        # the opposite null-loop branch before this method returns.
        return "preempted_nullable_float_page_statistics"
    if source == "Writing/ColumnStatistics.cs" and (
            "RepeatedAccumulator::AddInt32Leaf" in method or
            "RepeatedAccumulator::AddInt64Leaf" in method):
        # Repeated INT32/INT64 writer dispatch admits only int?/long? leaves;
        # other boxed conversion arms cannot arrive through that caller.
        return "preempted_repeated_leaf_type_dispatch"
    if source == "Writing/Encoding/Encoding.cs" and "TryEncodeOptionalInt64Dictionary" in method:
        if (line, offset, path, ordinal) == (1292, 15, 1, 1):
            return "reachable_empty_optional_int64_dictionary_sample"
        if (line, offset, path, ordinal) in {
            (1292, 29, 1, 3), (1292, 38, 1, 5),
            (1292, 48, 1, 7), (1292, 57, 1, 9),
            (1292, 70, 1, 11), (1292, 84, 1, 13),
            (1292, 99, 0, 14),
        }:
            return "preempted_optional_int64_dictionary_caller"
        if (line, offset, path, ordinal) in {
            (1511, 1247, 0, 80), (1515, 1277, 1, 85),
            (1515, 1281, 0, 86),
        }:
            return "preempted_optional_int64_dictionary_progress_invariant"
    if source == "Writing/RowGroupWriter.cs" and "::Write(" in method and (
            line, offset, path, ordinal) in {
        (47, 34, 0, 0), (51, 55, 0, 2), (55, 85, 0, 4),
        (59, 110, 0, 6), (69, 350, 0, 10),
    }:
        return "reachable_row_group_validation_sample"
    if source == "Writing/RowGroupWriter.cs" and "::Write(" in method:
        if (line, offset, path, ordinal) == (99, 691, 1, 23):
            return "preempted_public_unknown_page_kind"
        if (line, offset, path, ordinal) in {
            (139, 913, 0, 32), (161, 1154, 0, 40),
        }:
            return "preempted_public_missing_statistics"
        if (line, offset, path, ordinal) == (151, 1046, 1, 39):
            return "preempted_public_dictionary_without_data_page"
    if source == "Writing/AppendSortingOrder.cs" and "::CompareNonNull(" in method:
        if (line, offset, path, ordinal) in {
            (90, 523, 0, 46), (90, 541, 0, 48), (90, 541, 1, 49),
        }:
            return "preempted_append_decimal_materialization"
        if (line, offset, path, ordinal) in {
            (105, 1246, 1, 91), (107, 1315, 1, 93), (110, 1394, 1, 95),
        }:
            return "preempted_append_logical_type_guard"
        if (line, offset, path, ordinal) in {
            (90, 58, 1, 5), (90, 101, 1, 9), (90, 127, 0, 10),
            (90, 145, 0, 12), (90, 145, 1, 13), (90, 171, 0, 14),
            (90, 189, 0, 16), (90, 189, 1, 17), (90, 233, 1, 21),
            (90, 277, 1, 25), (90, 321, 1, 29), (90, 365, 1, 33),
            (90, 409, 1, 37), (90, 453, 1, 41), (90, 497, 1, 45),
            (90, 585, 1, 53), (90, 629, 1, 57), (90, 673, 1, 61),
            (90, 717, 1, 65), (90, 760, 0, 68), (90, 794, 0, 72),
            (90, 829, 1, 77), (90, 855, 1, 79), (90, 876, 1, 81),
        }:
            return "preempted_public_append_carrier_type"
    if source == "Writing/AppendSortingOrder.cs" and "::Compare(" in method:
        if (line, offset, path, ordinal) in {
            (75, 22, 1, 3), (75, 45, 1, 7),
            (75, 61, 1, 11), (75, 69, 0, 12),
        }:
            return "reachable_append_logical_comparator_sample"
        if (line, offset, path, ordinal) == (75, 6, 1, 1):
            return "preempted_append_converter_materialization"
        if (line, offset, path, ordinal) == (75, 53, 1, 9):
            return "preempted_append_variant_group_only"
    if source == "Writing/MutationSchemaValidator.cs" and (
            "::ValidateNode(" in method or "::ValidateNodeHeader(" in method):
        if (line, offset, path, ordinal) in {
            (29, 22, 0, 2), (44, 214, 1, 17),
            (47, 272, 0, 20), (47, 272, 1, 21),
            (54, 293, 0, 22), (60, 409, 0, 26),
            (60, 413, 0, 28), (60, 413, 1, 29),
            (73, 87, 1, 3), (73, 98, 0, 4),
            (76, 131, 1, 9), (76, 178, 0, 10),
            (78, 193, 1, 13), (80, 208, 0, 14),
            (82, 268, 0, 16),
        }:
            return "reachable_mutation_schema_public_sample"
        if (line, offset, path, ordinal) in {
            (37, 131, 0, 8), (40, 177, 0, 12),
            (40, 190, 0, 14), (76, 120, 1, 7),
        }:
            return "preempted_mutation_reader_projection"
        if (line, offset, path, ordinal) == (70, 10, 0, 0):
            return "preempted_mutation_validated_node_count"
        if (line, offset, path, ordinal) == (57, 371, 0, 24):
            return "hard_reach_legacy_annotated_wrapper"
    if source == "Reading/Logical/Internal/ColumnChunkReader.cs" and (
            "::TryDecodeConvertedRequiredByPhysicalType(" in method or
            "::TryDecodeNullableValuesByPhysicalType(" in method):
        # Public fallback exists, but batching handles ordinary compatible
        # projections first. Existing Decimal/IntBox controls enter only
        # already-hit arms; targeted non-int probes have not hit these misses.
        return "hard_reach_native_decode_type_dispatch"
    if source == "Reading/Logical/Internal/ColumnChunkReader.cs" and (
            "::TryDecodeNullableValues(" in method):
        if (line, offset, path, ordinal) == (1647, 82, 0, 6):
            return "preempted_nullable_decode_outer_type_gate"
        if (line, offset, path, ordinal) in {
            (1645, 9, 0, 0), (1645, 32, 0, 2),
            (1664, 189, 1, 11), (1664, 194, 0, 12),
            (1664, 206, 0, 14), (1666, 215, 0, 16),
            (1666, 215, 1, 17), (1678, 269, 0, 20),
            (1689, 410, 0, 26),
        }:
            return "hard_reach_nullable_decode_after_batching"
    if source == "Reading/Logical/Internal/ColumnChunkReader.cs" and (
            "::TryDecodeByteStreamSplitIntoNative(" in method):
        if (line, offset, path, ordinal) == (2831, 691, 0, 28):
            return "reachable_nested_bss_datetimeoffset_sample"
        if (line, offset, path, ordinal) in {
            (2785, 24, 0, 0), (2785, 24, 3, 3), (2785, 24, 6, 6),
            (2839, 791, 0, 30), (2842, 808, 0, 32),
            (2842, 808, 1, 33), (2847, 951, 0, 36),
            (2847, 951, 1, 37), (2849, 907, 0, 34),
            (2849, 907, 1, 35), (2855, 980, 1, 39),
            (2858, 1030, 1, 41), (2888, 1490, 1, 55),
            (2898, 1632, 1, 59), (2908, 1774, 1, 63),
            (2913, 1818, 1, 65),
        }:
            return "preempted_bss_public_decode_constraints"
    if source == "Reading/Logical/Internal/ColumnChunkReader.cs" and (
            "::TryDecodeByteStreamSplitSliceIntoNative(" in method):
        if (line, offset, path, ordinal) in {
            (3607, 809, 0, 32), (3610, 822, 1, 35),
            (3614, 950, 0, 38), (3614, 950, 1, 39),
            (3616, 906, 0, 36), (3616, 906, 1, 37),
        }:
            return "reachable_bss_slice_guid_sample"
        if (line, offset, path, ordinal) == (3610, 822, 0, 34):
            return "preempted_bss_slice_guid_length_validation"
        if (line, offset, path, ordinal) in {
            (3653, 1323, 1, 51), (3662, 1459, 1, 55),
            (3672, 1600, 1, 59),
        }:
            return "preempted_bss_slice_decimal_type_dispatch"
    if source == "Reading/Logical/Internal/ColumnChunkReader.cs" and (
            "::DecodeFixedWidthBatch(" in method):
        if (line, offset, path, ordinal) == (862, 497, 0, 46):
            return "big_endian_host_only"
        if (line, offset, path, ordinal) in {
            (805, 593, 1, 29), (828, 100, 1, 11),
            (837, 221, 0, 22), (850, 332, 0, 30),
            (850, 341, 0, 32), (850, 368, 0, 34),
            (850, 395, 0, 36),
        }:
            return "preempted_fixed_width_batch_caller_dispatch"
    if source == "Reading/Logical/Internal/ColumnChunkReader.cs" and (
            "::TryDecodeDeltaByteArrayIntoNative(" in method):
        # Public fixed-width Guid/decimal DELTA_BYTE_ARRAY pages are claimed
        # by encoded batching; malformed pages fail there without fallback.
        return "preempted_delta_byte_array_native_fallback"
    if source == "Reading/Logical/Internal/ColumnChunkReader.cs" and (
            "::TryStartFixedWidthPageBatches(" in method) and (
            line, offset, path, ordinal) in {
        (366, 87, 1, 5), (369, 299, 1, 39),
        (383, 459, 0, 52), (383, 472, 0, 56),
        (448, 1197, 0, 88), (452, 1223, 1, 95),
        (474, 1289, 1, 103),
    }:
        return "preempted_fixed_width_starter_public_gates"
    if source == "Reading/Logical/ColumnBuffer.cs" and "::.ctor(" in method and (
            line, offset, path, ordinal) in {
        (36, 33, 0, 0), (40, 61, 1, 3), (40, 71, 0, 4),
        (50, 1, 1, 1), (50, 28, 0, 2),
        (59, 90, 1, 7), (59, 101, 0, 8),
        (67, 165, 1, 17), (67, 174, 0, 18),
        (88, 25, 1, 1), (88, 34, 0, 2),
        (96, 94, 1, 5), (96, 103, 0, 6),
        (111, 16, 0, 0), (114, 80, 1, 3), (114, 90, 0, 4),
    }:
        return "preempted_column_buffer_caller_invariants"
    if source == "Reading/Logical/Internal/DeltaBinaryPackedDecoder.cs" and (
            "Avx2UnpackControls::Create(" in method):
        # This host selects BMI2/PDEP rather than the AVX2 unpack kernels;
        # the controls table initializes only for the latter.
        return "host_preempted_avx2_delta_unpack_controls"
    if source == "Reading/Logical/Internal/ColumnChunkReader.EncodedBatching.cs" and (
            "::GetEncodedDecoderKind(" in method):
        # Method and related positive arms are publicly reached; fixed-width
        # batching and parser/selector gates precede these exact misses.
        # Mutated valid page headers have not reached them yet.
        return "hard_reach_encoded_decoder_selector"
    if source == "Reading/Logical/Internal/ColumnChunkReader.EncodedBatching.cs" and (
            "::DecodeNullableInt32DictionaryRleBatch(" in method):
        if (line, offset, path, ordinal) in {
            (1007, 622, 0, 24), (1007, 622, 1, 25),
            (1007, 632, 0, 26), (1007, 632, 1, 27),
        }:
            return "arm_adv_simd_guard"
        if (line, offset, path, ordinal) in {
            (979, 234, 1, 3), (979, 252, 0, 4),
        }:
            return "hard_reach_nullable_dictionary_rle_malformed_payload"
        if (line, offset, path, ordinal) in {
            (993, 434, 1, 9), (1007, 609, 1, 21),
            (1007, 616, 0, 22),
        }:
            return "hard_reach_nullable_dictionary_simd_layout"
    if source == "Reading/Logical/Internal/ColumnChunkReader.EncodedBatching.cs" and (
            "::DecodeFixedDeltaByteArrayBatch(" in method):
        if (line, offset, path, ordinal) in {
            (1946, 134, 0, 4), (1946, 142, 0, 6),
            (1946, 142, 1, 7), (1949, 175, 0, 8),
            (1959, 319, 0, 10), (1964, 417, 0, 12),
            (1983, 831, 1, 23),
        }:
            return "reachable_fixed_delta_byte_array_batched_sample"
        if (line, offset, path, ordinal) == (1942, 52, 0, 2):
            return "preempted_fixed_delta_byte_array_clr_type_gate"
    if source == "Writing/ColumnStatistics.cs" and (
            "RepeatedAccumulator::ToUnixTimeForStatistics(" in method):
        # Public repeated INT64 serialization admits long/long? leaves only;
        # DateTime/DateTimeOffset never reach this statistics accumulator.
        return "preempted_repeated_timestamp_leaf_dispatch"
    if source == "Writing/ColumnStatistics.cs" and "::CreateMemory(" in method:
        if (line, offset, path, ordinal) == (885, 7, 0, 0):
            return "reachable_empty_pooled_memory_statistics_sample"
        if (line, offset, path, ordinal) in {
            (865, 7, 0, 0), (865, 7, 1, 1),
            (870, 88, 0, 6), (870, 88, 1, 7),
            (873, 59, 0, 2), (873, 59, 1, 3),
            (875, 72, 0, 4), (875, 72, 1, 5),
        }:
            return "no_public_unpooled_memory_statistics_route"
    if source == "Writing/ColumnStatistics.cs" and "::CreateNullableInt32(" in method:
        # Present nullable INT32 values take SerializeOptionalConverted and
        # page statistics; only all-null arrays reach this fallback helper.
        return "preempted_nullable_int32_present_page_statistics"
    if source == "Writing/ColumnStatistics.cs" and "::CreateNullableInt64(" in method:
        # Present nullable INT64 values take the specialized PLAIN/DELTA or
        # converted page-statistics paths before this all-null fallback.
        return "preempted_nullable_int64_present_page_statistics"
    if source == "Writing/ColumnStatistics.cs" and "::CompareZeroToDecimal(" in method and (
            line, offset, path, ordinal) in {
        (1424, 15, 0, 0), (1424, 15, 1, 1),
        (1426, 48, 0, 4), (1426, 48, 1, 5),
        (1427, 32, 0, 2), (1427, 32, 1, 3),
    }:
        return "reachable_decimal_zero_compare_sample"
    if source == "RowApi/RowValueSizeEstimator.cs" and "::Estimate(" in method:
        if (line, offset, path, ordinal) == (55, 216, 0, 10):
            return "reachable_nullable_byte_array_row_size_sample"
        if (line, offset, path, ordinal) in {
            (50, 115, 0, 4), (52, 160, 0, 6),
            (63, 337, 0, 18), (64, 347, 0, 20),
            (64, 347, 1, 21), (73, 7, 0, 0),
            (73, 7, 1, 1),
        }:
            return "preempted_row_size_unsupported_clr_type"
    if source == "Writing/Encoding/ByteArrayRow.cs" and "::CountPresent(" in method:
        if (line, offset, path, ordinal) == (113, 52, 1, 3):
            return "preempted_count_present_byte_array_generic_route"
        if (line, offset, path, ordinal) in {
            (108, 11, 1, 1), (112, 118, 0, 6),
            (112, 118, 1, 7), (113, 52, 0, 2),
            (113, 100, 0, 4), (113, 100, 1, 5),
        }:
            return "reachable_count_present_memory_sample"
    if source == "Writing/Encoding/Encoding.cs" and "::EncodeOptionalFlatByteArrays(" in method:
        if (line, offset, path, ordinal) in {
            (3349, 929, 1, 53), (3359, 1040, 0, 56),
            (3359, 1040, 1, 57), (3363, 1061, 0, 58),
            (3363, 1061, 1, 59),
        }:
            return "reachable_optional_binary_target_pages_sample"
        if (line, offset, path, ordinal) in {
            (3225, 70, 0, 4), (3296, 524, 0, 20),
        }:
            return "preempted_optional_binary_dictionary_buffer_invariant"
        if (line, offset, path, ordinal) in {
            (3267, 356, 1, 15), (3311, 695, 1, 31),
            (3320, 733, 0, 32), (3320, 733, 1, 33),
            (3320, 737, 0, 34), (3320, 737, 1, 35),
        }:
            return "preempted_optional_binary_row_carrier"
    if source == "Writing/Encoding/Encoding.cs" and (
            "::GetOrAddSmallDoubleDictionaryIndex(" in method):
        if (line, offset, path, ordinal) == (2906, 3, 0, 0):
            return "preempted_small_double_dictionary_caller_guard"
        if (line, offset, path, ordinal) in {
            (2906, 3, 1, 1), (2915, 72, 0, 2),
            (2915, 72, 1, 3), (2915, 84, 0, 4),
            (2915, 84, 1, 5), (2918, 96, 0, 6),
            (2918, 96, 1, 7), (2920, 119, 0, 8),
            (2920, 119, 1, 9),
        }:
            return "reachable_small_double_dictionary_sample"
    if source == "Writing/Encoding/Encoding.cs" and "::EncodeOptionalPlainInt64(" in method:
        if (line, offset, path, ordinal) in {
            (1860, 46, 1, 1), (1860, 55, 0, 2),
            (1864, 92, 1, 5), (1864, 101, 0, 6),
            (1875, 220, 0, 16),
        }:
            return "reachable_optional_plain_int64_validation_sample"
        if (line, offset, path, ordinal) in {
            (1867, 136, 1, 9), (1867, 149, 1, 11),
            (1867, 162, 1, 13), (1867, 177, 0, 14),
        }:
            return "preempted_optional_plain_int64_caller_options"
    if source == "Writing/Encoding/Encoding.cs" and "::EncodeOptional(" in method:
        if (line, offset, path, ordinal) == (2515, 143, 0, 6):
            return "reachable_empty_optional_reference_sample"
        if (line, offset, path, ordinal) in {
            (944, 46, 0, 0), (947, 83, 1, 3),
            (947, 92, 0, 4), (958, 181, 0, 10),
            (2506, 46, 0, 0), (2509, 83, 1, 3),
            (2509, 92, 0, 4), (2518, 171, 0, 8),
        }:
            return "preempted_encode_optional_public_dispatch"
    if source == "Writing/Encoding/Encoding.cs" and (
            "::EncodeOptionalInt64DeltaBinaryPacked(" in method):
        if (line, offset, path, ordinal) in {
            (2263, 46, 1, 1), (2263, 55, 0, 2),
            (2266, 92, 1, 5), (2266, 101, 0, 6),
        }:
            return "reachable_optional_delta_int64_validation_sample"
        if (line, offset, path, ordinal) in {
            (2269, 141, 1, 9), (2269, 154, 1, 11),
            (2269, 163, 0, 12), (2276, 206, 0, 14),
            (2345, 590, 0, 32),
        }:
            return "preempted_optional_delta_int64_caller_contract"
    if source == "Writing/Encoding/Encoding.cs" and (
            "::MeasureMemoryPageRowsAndWriteDefinitionLevels(" in method):
        if (line, offset, path, ordinal) == (3603, 374, 1, 27):
            return "preempted_nonempty_memory_page_run_invariant"
        if (line, offset, path, ordinal) in {
            (3545, 106, 1, 5), (3557, 183, 1, 11),
            (3563, 222, 1, 13), (3610, 426, 1, 31),
            (3618, 499, 0, 32), (3618, 499, 1, 33),
            (3621, 552, 0, 34), (3621, 552, 1, 35),
        }:
            return "reachable_memory_page_decision_sample"
    if source == "Writing/Encoding/Encoding.cs" and (
            "::TryEncodeOptionalPlainDateTime(" in method):
        if (line, offset, path, ordinal) in {
            (1548, 21, 1, 3), (1548, 40, 1, 7),
        }:
            return "preempted_optional_datetime_schema_guard"
        if (line, offset, path, ordinal) in {
            (1548, 12, 1, 1), (1548, 31, 1, 5),
            (1548, 48, 1, 9), (1548, 62, 1, 11),
            (1548, 76, 1, 13), (1548, 92, 0, 14),
        }:
            return "reachable_optional_datetime_predicate_sample"
    if source == "Writing/Encoding/Encoding.cs" and (
            "::EncodeOptionalForcedInt32Dictionary(" in method):
        if (line, offset, path, ordinal) in {
            (337, 46, 0, 0), (339, 83, 1, 3),
            (339, 92, 0, 4),
        }:
            return "reachable_forced_optional_int32_dictionary_validation_sample"
        if (line, offset, path, ordinal) in {
            (342, 132, 0, 6), (347, 175, 0, 8),
            (423, 622, 0, 26), (435, 764, 0, 30),
        }:
            return "preempted_forced_optional_int32_caller_guard"
    if source == "Writing/Encoding/Encoding.cs" and (
            "::EncodeOptionalForcedInt64Dictionary(" in method):
        if (line, offset, path, ordinal) in {
            (2144, 46, 0, 0), (2146, 83, 1, 3),
            (2146, 92, 0, 4),
        }:
            return "reachable_forced_optional_int64_validation_sample"
        if (line, offset, path, ordinal) in {
            (2149, 132, 0, 6), (2154, 175, 0, 8),
            (2230, 624, 0, 26), (2242, 766, 0, 30),
        }:
            return "preempted_forced_optional_int64_caller_guard"
    if source == "Writing/Encoding/Encoding.cs" and (
            "::BuildForcedRequiredByteArrayDictionaryIndexes(" in method):
        if (line, offset, path, ordinal) == (2763, 282, 1, 25):
            return "preempted_required_binary_unsorted_map_dispatch"
        if (line, offset, path, ordinal) in {
            (2723, 18, 0, 0), (2731, 59, 1, 3),
            (2731, 64, 1, 5), (2737, 88, 1, 7),
            (2737, 91, 1, 9), (2741, 135, 0, 12),
        }:
            return "reachable_required_binary_dictionary_sort_sample"
    if source == "Writing/Encoding/Encoding.cs" and (
            "::BuildForcedRequiredByteArrayDictionaryIndexesMap(" in method) and (
            line, offset, path, ordinal) in {
        (2792, 17, 0, 0), (2806, 106, 0, 8),
        (2814, 185, 0, 14),
    }:
        return "reachable_required_binary_dictionary_map_null_sample"
    if source == "Writing/Encoding/Encoding.cs" and "::TryCompareForSort(" in method:
        if (line, offset, path, ordinal) in {
            (4377, 382, 0, 14), (4398, 609, 1, 23),
        }:
            return "reachable_dictionary_float_decimal_sort_sample"
        if (line, offset, path, ordinal) in {
            (4342, 25, 0, 0), (4352, 127, 0, 4),
            (4357, 178, 0, 6), (4362, 229, 0, 8),
            (4372, 331, 0, 12),
        }:
            return "preempted_dictionary_sort_public_carrier_conversion"
    if source == "Writing/SerializedColumn.cs" and "::SerializeOptionalCore(" in method:
        if (line, offset, path, ordinal) in {
            (1197, 17, 0, 0), (1397, 2408, 0, 114),
            (1414, 2632, 1, 119), (1423, 17, 0, 0),
            (1445, 317, 0, 8),
        }:
            return "reachable_serialized_optional_sample"
        if (line, offset, path, ordinal) in {
            (1281, 1047, 0, 58), (1301, 1297, 0, 70),
            (1322, 1565, 0, 84), (1343, 1822, 0, 96),
            (1362, 2062, 0, 106), (1437, 155, 0, 4),
        }:
            return "preempted_optional_serialization_helper_contract"
    if source == "Writing/Encoding/DeltaBinaryPackedEncoding.cs" and (
            "::WriteInt32Values(" in method) and (
            line, offset, path, ordinal) in {
        (422, 128, 0, 4), (425, 183, 0, 6), (425, 183, 1, 7),
        (431, 223, 0, 8), (434, 279, 0, 10), (434, 279, 1, 11),
        (440, 319, 0, 12), (443, 375, 0, 14), (443, 375, 1, 15),
        (449, 415, 1, 17),
    }:
        return "preempted_delta_int32_generic_caller_conversion"
    if source == "Writing/Encoding/DeltaByteArrayEncoding.cs" and (
            "::WritePrecomputedRequiredByteArrayPage(" in method) and (
            line, offset, path, ordinal) in {
        (83, 14, 0, 0), (86, 46, 0, 2), (89, 66, 0, 4),
        (102, 14, 0, 0), (102, 14, 1, 1),
        (105, 46, 0, 2), (105, 46, 1, 3),
        (108, 66, 0, 4), (108, 66, 1, 5),
    }:
        return "preempted_delta_byte_array_precomputed_lengths"
    if source == "Writing/Encoding/ByteStreamSplitEncoding.cs" and (
            "::WriteFixedLengthByteArrayValues(" in method):
        if (line, offset, path, ordinal) in {
            (152, 466, 0, 16), (163, 623, 0, 20),
            (165, 660, 0, 22),
        }:
            return "reachable_fixed_bss_carrier_validation_sample"
        if (line, offset, path, ordinal) in {
            (113, 40, 0, 2), (119, 150, 0, 4),
            (138, 308, 0, 10), (158, 601, 0, 18),
        }:
            return "preempted_fixed_bss_empty_or_guid_width"
    if source == "Writing/Encoding/ByteStreamSplitEncoding.cs" and (
            "::WriteInt32Lanes(" in method) and (
            line, offset, path, ordinal) in {
        (199, 76, 0, 2), (209, 159, 0, 4),
        (214, 278, 0, 6), (214, 278, 1, 7),
        (225, 345, 0, 8), (232, 391, 1, 11),
    }:
        return "preempted_bss_int32_narrow_carrier_conversion"
    if source == "Writing/Encoding/PlainEncoding.cs" and "::WriteInt32Values(" in method:
        if (line, offset, path, ordinal) == (151, 589, 1, 27):
            return "reachable_plain_int32_unsupported_carrier_sample"
        if (line, offset, path, ordinal) in {
            (115, 185, 0, 8), (118, 206, 0, 10),
            (127, 317, 0, 14), (130, 338, 0, 16),
            (139, 449, 0, 20), (142, 470, 0, 22),
        }:
            return "preempted_plain_int32_narrow_carrier_conversion"
    if source == "Writing/LatestRowGroupValues.cs" and "::Read(" in method:
        if (line, offset, path, ordinal) in {
            (29, 58, 0, 2), (36, 161, 1, 14),
            (39, 187, 1, 16), (45, 236, 1, 20),
            (48, 259, 1, 22),
        }:
            return "reachable_latest_row_group_read_sample"
        if (line, offset, path, ordinal) == (22, 13, 0, 0):
            return "hard_reach_latest_group_over_int32_rows"
        if (line, offset, path, ordinal) == (34, 118, 0, 4):
            return "preempted_latest_group_unknown_physical_type"
    if source == "Writing/ParquetWriter.cs" and "::ValidateImportChunk(" in method:
        if (line, offset, path, ordinal) in {
            (643, 55, 1, 1), (643, 65, 0, 2),
            (645, 85, 0, 4), (645, 101, 0, 6),
            (645, 111, 0, 8),
        }:
            return "reachable_import_chunk_footer_mutation_sample"
        if (line, offset, path, ordinal) == (645, 101, 1, 7):
            return "preempted_import_chunk_offset_minimum"
        if (line, offset, path, ordinal) == (654, 215, 0, 16):
            return "preempted_import_signed_thrift_index_length"
    if source == "Writing/ParquetWriter.cs" and (
            "::GetLatestRowGroupReplacementOffset(" in method) and (
            line, offset, path, ordinal) in {
        (556, 115, 1, 3), (556, 124, 1, 5),
        (556, 143, 1, 7), (556, 152, 1, 9),
        (556, 171, 1, 11), (556, 189, 1, 15),
        (556, 208, 0, 16),
    }:
        return "reachable_latest_group_external_layout_sample"
    if (source, line, offset, path, ordinal) in {
        ("Writing/ColumnStatistics.cs", 835, 40, 1, 1),
        ("Writing/ColumnStatistics.cs", 841, 50, 0, 2),
        ("Writing/ColumnStatistics.cs", 841, 50, 1, 3),
        ("Writing/ColumnStatistics.cs", 849, 87, 1, 5),
        ("Writing/ColumnStatistics.cs", 851, 112, 0, 6),
        ("Writing/ColumnStatistics.cs", 855, 140, 1, 11),
        ("Writing/Encoding/Encoding.cs", 3255, 226, 1, 11),
        ("Writing/Encoding/Encoding.cs", 3291, 486, 0, 16),
        ("Writing/Encoding/Encoding.cs", 3635, 17, 0, 0),
        ("Writing/Encoding/PlainEncoding.cs", 1092, 9, 1, 1),
        ("Writing/Encoding/PlainEncoding.cs", 1094, 37, 1, 7),
        ("Writing/Encoding/PlainEncoding.cs", 1126, 340, 0, 20),
        ("Writing/Encoding/PlainEncoding.cs", 1129, 389, 1, 25),
        ("Writing/Encoding/PlainEncoding.cs", 1130, 363, 0, 22),
        ("Writing/Encoding/PlainEncoding.cs", 1130, 363, 1, 23),
    }:
        return "reachable_optional_binary_page_strategy_sample"
    if (source, line, offset, path, ordinal) in {
        ("Writing/ColumnStatistics.cs", 376, 73, 0, 4),
        ("Writing/ColumnStatistics.cs", 378, 81, 1, 7),
        ("Writing/ColumnStatistics.cs", 407, 73, 0, 4),
        ("Writing/ColumnStatistics.cs", 409, 81, 1, 7),
        ("Writing/ColumnStatistics.cs", 438, 75, 0, 4),
        ("Writing/ColumnStatistics.cs", 440, 83, 1, 7),
    }:
        return "reachable_nullable_unsigned_statistics_extremes_sample"
    if (source, line, offset, path, ordinal) in {
        ("Writing/Encoding/ByteStreamSplitEncoding.cs", 192, 25, 1, 1),
        ("Writing/Encoding/ByteStreamSplitEncoding.cs", 199, 76, 1, 3),
        ("Writing/Encoding/ByteStreamSplitEncoding.cs", 209, 159, 1, 5),
        ("Writing/Encoding/ByteStreamSplitEncoding.cs", 225, 345, 1, 9),
        ("Writing/Encoding/ByteStreamSplitEncoding.cs", 232, 391, 0, 10),
        ("Writing/Encoding/ByteStreamSplitEncoding.cs", 236, 569, 0, 14),
        ("Writing/Encoding/ByteStreamSplitEncoding.cs", 236, 569, 1, 15),
        ("Writing/Encoding/ByteStreamSplitEncoding.cs", 240, 524, 0, 12),
        ("Writing/Encoding/ByteStreamSplitEncoding.cs", 240, 524, 1, 13),
        ("Writing/Encoding/ByteStreamSplitEncoding.cs", 257, 25, 1, 1),
        ("Writing/Encoding/ByteStreamSplitEncoding.cs", 264, 76, 1, 3),
        ("Writing/Encoding/ByteStreamSplitEncoding.cs", 271, 122, 0, 4),
        ("Writing/Encoding/ByteStreamSplitEncoding.cs", 275, 289, 0, 8),
        ("Writing/Encoding/ByteStreamSplitEncoding.cs", 275, 289, 1, 9),
        ("Writing/Encoding/ByteStreamSplitEncoding.cs", 279, 248, 0, 6),
        ("Writing/Encoding/ByteStreamSplitEncoding.cs", 279, 248, 1, 7),
        ("Writing/Encoding/DeltaBinaryPackedEncoding.cs", 421, 58, 1, 3),
        ("Writing/Encoding/DeltaBinaryPackedEncoding.cs", 465, 25, 1, 1),
        ("Writing/Encoding/DeltaBinaryPackedEncoding.cs", 472, 58, 1, 3),
        ("Writing/Encoding/DeltaBinaryPackedEncoding.cs", 473, 128, 1, 5),
        ("Writing/Encoding/DeltaBinaryPackedEncoding.cs", 482, 223, 0, 8),
        ("Writing/Encoding/DeltaBinaryPackedEncoding.cs", 485, 289, 0, 10),
        ("Writing/Encoding/DeltaBinaryPackedEncoding.cs", 485, 289, 1, 11),
    }:
        return "reachable_alternate_numeric_encoding_sample"
    if (source, line, offset, path, ordinal) in {
        ("Writing/Encoding/Encoding.cs", 3554, 152, 1, 7),
        ("Writing/Encoding/PlainEncoding.cs", 1035, 28, 1, 3),
        ("Writing/Encoding/PlainEncoding.cs", 1114, 155, 0, 16),
    }:
        return "reachable_optional_fixed_memory_probe"
    if (source, line, offset, path, ordinal) == (
        "Reading/Logical/Internal/ColumnChunkReader.cs", 216, 857, 0, 42
    ):
        # The only production caller first calls TryDecodeDictionaryPageIntoNative,
        # which throws when a dictionary-encoded data page has no dictionary.
        return "preempted_nested_dictionary_precheck"
    if (source, line, offset, path, ordinal) == (
        "Dataset/DatasetWriterBase.cs", 324, 81, 0, 2
    ):
        # Each used key owns at least one parked row. Before AddPendingKey,
        # parkedRowCount < pendingRowCapacity == pendingKeys.Length; the full
        # case promotes a partition first or throws before this call.
        return "preempted_pending_key_capacity_invariant"
    if source == "Dataset/DatasetWriterBase.cs" and (
        line, offset, path, ordinal
    ) in {
        (197, 180, 0, 12), (201, 197, 1, 15), (379, 7, 1, 1),
    }:
        return "reachable_dataset_promotion_open_retry_sample"
    if source == "Writing/RowWriterBase.cs" and (
        line, offset, path, ordinal
    ) in {(646, 7, 0, 0), (647, 29, 0, 2)}:
        # Rollover's sole caller requires _rolloverPending. Only the rolling
        # constructor can set it, and it assigns both readonly members.
        return "preempted_rolling_constructor_invariant"
    if (source, line, offset, path, ordinal) in {
        ("RowApi/PipelineRowWriterBase.cs", 118, 12, 0, 0),
        ("RowApi/RowBufferSlot.cs", 75, 20, 1, 3),
        ("Writing/RowWriterBase.cs", 71, 203, 0, 4),
    }:
        return "reachable_row_api_pipeline_control_sample"
    if source == "Reading/Logical/Internal/ColumnChunkReader.cs" and (
        line, offset, path, ordinal
    ) in {
        (918, 22, 1, 1), (918, 34, 0, 2),
    }:
        return "preempted_nullable_int32_plain_batch_payload_validation"
    if source == "Reading/Logical/Internal/ColumnChunkReader.cs" and (
        line, offset, path, ordinal
    ) in {
        (924, 166, 0, 4), (926, 241, 0, 6), (926, 241, 1, 7),
    }:
        return "big_endian_host_only"
    if (source, line, offset, path, ordinal) == (
        "Writing/Encoding/Encoding.cs", 1032, 193, 0, 24
    ):
        # IL_00c1 falls through only when AdvSimd.IsSupported is true; AVX2
        # already branches around this check on x86.
        return "arm_adv_simd_guard"
    if source == "Writing/Encoding/PlainEncoding.cs" and (
        line, offset, path, ordinal
    ) in {
        (1079, 75, 0, 2), (1079, 86, 0, 4), (1079, 86, 1, 5),
        (1079, 90, 0, 6), (1079, 90, 1, 7), (1079, 101, 0, 8),
    }:
        # The preceding byte[] type check returns, so the repeated byte[]
        # check at line 1079 cannot fall through to its fixed-length call.
        return "dead_candidate_preceding_return"
    if source == "Writing/Encoding/PlainEncoding.cs" and any(
        name in method for name in (
            "::CanUseInt32Vector128(", "::CanUseInt64Vector128(",
            "::WriteInt32PageWithVector128Statistics(",
            "::WriteInt64PageWithVector128Statistics(",
            "::ExtractOptionalDoubleValuesAdvSimd(",
        )
    ):
        # The only production callers are behind AdvSimd/AdvSimd.Arm64 gates.
        return "arm_adv_simd_guard"
    if source == "Writing/Encoding/PlainEncoding.cs" and (
        line, offset, path, ordinal
    ) in {
        (106, 67, 1, 5), (109, 150, 1, 7),
        (118, 206, 1, 11), (121, 282, 0, 12), (121, 282, 1, 13),
        (130, 338, 1, 17), (133, 414, 0, 18), (133, 414, 1, 19),
        (142, 470, 1, 23), (145, 554, 0, 24), (145, 554, 1, 25),
        (276, 67, 1, 5), (279, 150, 1, 7),
        (288, 206, 1, 11), (291, 290, 0, 12), (291, 290, 1, 13),
    }:
        return "big_endian_host_only"
    if source == "Writing/Encoding/PlainEncoding.cs" and (
        line, offset, path, ordinal
    ) in {
        (367, 45, 1, 3), (373, 129, 0, 4), (373, 129, 1, 5),
        (451, 45, 1, 3), (457, 129, 0, 4), (457, 129, 1, 5),
        (474, 58, 1, 3), (477, 147, 1, 5),
        (505, 117, 1, 9), (508, 206, 1, 11),
    }:
        return "big_endian_host_only"
    if source == "Writing/Encoding/PlainEncoding.cs" and (
        line, offset, path, ordinal
    ) in {
        (417, 413, 0, 14), (417, 413, 1, 15), (427, 456, 1, 17),
    }:
        return "arm_adv_simd_guard"
    if source == "Writing/Encoding/PlainEncoding.cs" and (
        line, offset, path, ordinal
    ) in {
        (68, 13, 0, 0), (386, 11, 0, 0),
        (445, 11, 0, 0), (522, 11, 0, 0),
    }:
        # Every public page writer call gets a nonempty slice from a positive
        # rowsPerPage loop; optional INT64 also checks presentCount > 0.
        return "preempted_nonempty_page_slice"
    if source == "Reading/Logical/Internal/ColumnChunkReader.EncodedBatching.cs" and (
        line, offset, path, ordinal
    ) in {
        (1674, 7, 1, 1),
        (1678, 281, 0, 8), (1678, 281, 1, 9),
        (1680, 42, 0, 2), (1680, 42, 1, 3),
        (1684, 90, 0, 4), (1684, 90, 1, 5),
        (1688, 185, 0, 6), (1688, 185, 1, 7),
    }:
        return "preempted_byte_array_plain_batch_length_parser"
    if (source, line, offset, path, ordinal) == (
        "Reading/Logical/Internal/ColumnChunkReader.cs", 380, 354, 0, 46
    ):
        return "preempted_by_row_group_metadata_validation"
    if source == "Reading/Logical/Internal/ColumnChunkReader.cs" and (
        line, offset, path, ordinal
    ) in {
        (4231, 58, 0, 0), (4231, 58, 1, 1),
        (4233, 244, 0, 2), (4233, 244, 1, 3),
        (4249, 451, 0, 4), (4249, 451, 1, 5),
        (4285, 17, 0, 0), (4285, 17, 1, 1),
        (4287, 42, 0, 2), (4287, 42, 1, 3),
        (4290, 79, 0, 4), (4290, 79, 1, 5),
    }:
        return "preempted_wide_int64_scalar_cpu_model"
    if source == "Writing/Encoding/Encoding.cs" and (
        line, offset, path, ordinal
    ) in {
        (141, 47, 1, 1),   # SerializedColumn only calls this for Required columns.
        (145, 98, 0, 4),   # The caller requires DictionaryMode.Forced.
        (154, 171, 0, 8),   # Nonempty + Forced makes TryWriteDictionaryPage succeed.
    }:
        return "preempted_required_timestamp_dictionary_guard"
    if source == "Writing/Encoding/Encoding.cs" and (
        line, offset, path, ordinal
    ) in {
        (141, 56, 0, 2),   # An invalid INT32+Timestamp definition reaches this public error guard.
        (150, 141, 0, 6),  # Empty DateTime input returns before allocating a dictionary page.
        (163, 235, 1, 11), # A single unique value selects bit width zero.
    }:
        return "reachable_required_timestamp_dictionary_boundary_sample"
    if source == "Writing/Encoding/Encoding.cs" and (
        line, offset, path, ordinal
    ) == (811, 23, 1, 5):
        return "reachable_fixedwidth_page_target_sample"
    if (source, line, offset, path, ordinal) in {
        ("Reading/Logical/Internal/ColumnChunkReader.cs", 1786, 5, 1, 1),
        ("Reading/Logical/Internal/ColumnChunkReader.cs", 3129, 5, 1, 1),
        ("Reading/Logical/Internal/ColumnChunkReader.cs", 3141, 5, 1, 1),
        ("Reading/Logical/Internal/ColumnChunkReader.cs", 3153, 5, 1, 1),
        ("Reading/Logical/Internal/ColumnChunkReader.cs", 3165, 5, 1, 1),
        ("Reading/Logical/Internal/ColumnChunkReader.cs", 3177, 5, 1, 1),
        ("Reading/Logical/Internal/ColumnChunkReader.cs", 3192, 5, 1, 1),
        ("Writing/Encoding/DeltaBinaryPackedEncoding.cs", 638, 204, 0, 0),
        ("Writing/Encoding/DeltaBinaryPackedEncoding.cs", 671, 210, 0, 0),
        ("Writing/Encoding/DeltaBinaryPackedEncoding.cs", 700, 226, 0, 0),
        ("Writing/Encoding/DeltaBinaryPackedEncoding.cs", 727, 64, 0, 7),
        ("Writing/Encoding/DeltaBinaryPackedEncoding.cs", 736, 102, 0, 9),
        ("Writing/Encoding/DeltaBinaryPackedEncoding.cs", 822, 116, 0, 0),
        ("Writing/Encoding/DeltaBinaryPackedEncoding.cs", 862, 118, 0, 0),
        ("Writing/Encoding/DeltaBinaryPackedEncoding.cs", 1032, 161, 0, 12),
        ("Writing/Encoding/DeltaBinaryPackedEncoding.cs", 1066, 218, 0, 0),
        ("Writing/Encoding/Encoding.cs", 2067, 178, 1, 15),
        ("Writing/Encoding/PlainEncoding.cs", 106, 67, 1, 5),
        ("Writing/Encoding/PlainEncoding.cs", 276, 67, 1, 5),
        ("Writing/Encoding/PlainEncoding.cs", 324, 176, 1, 5),
        ("Writing/Encoding/PlainEncoding.cs", 347, 176, 1, 5),
        ("Writing/Encoding/PlainEncoding.cs", 367, 45, 1, 3),
        ("Writing/Encoding/PlainEncoding.cs", 451, 45, 1, 3),
        ("Writing/Encoding/PlainEncoding.cs", 474, 58, 1, 3),
        ("Writing/Encoding/PlainEncoding.cs", 505, 117, 1, 9),
        ("Reading/Logical/Internal/DeltaBinaryPackedDecoder.cs", 1032, 38, 0, 2),
        ("Writing/Encoding/DeltaBinaryPackedEncoding.cs", 514, 107, 0, 6),
        ("Writing/Encoding/DeltaBinaryPackedEncoding.cs", 1019, 92, 0, 6),
    }:
        return "big_endian_host_only"
    if source == "Writing/Encoding/RleBitPackingHybridEncoding.cs":
        if (line, offset, path, ordinal) in {
            (420, 149, 1, 13), (420, 154, 1, 15),
            (432, 198, 0, 16), (437, 327, 1, 23),
            (439, 241, 0, 18), (439, 241, 1, 19),
            (443, 315, 1, 21), (443, 315, 0, 20),
            (437, 327, 0, 22), (451, 332, 1, 25),
        }:
            return "reachable_17bit_dictionary_sample"
        # These are defensive/internal entry points or states excluded by the
        # valid writer call graph. Keep the coordinates exact: neighboring
        # outcomes in this file remain ordinary audit candidates.
        if method.endswith("::ValidateValues(System.ReadOnlySpan`1<System.Int32>,System.Int32)"):
            return "no_public_writer_callsite_validation"
        if (line, offset, path, ordinal) in {
            (64, 7, 0, 0),       # empty bool spans are omitted before page encoding
            (123, 3, 0, 0),      # dictionary widths are in [0, 32]
            (134, 3, 0, 0),      # dictionary widths are in [0, 32]
            (391, 7, 0, 0),      # WriteUnchecked calls only with a nonempty slice
            (432, 198, 1, 17),
            (451, 332, 0, 24),   # groups are padded to eight values
            (575, 7, 0, 0),      # bool literal collector also emits nonempty slices
        }:
            return "public_writer_invariant_excludes_outcome"
    if source == "Writing/BloomFilterBuilder.cs" and (
        line, offset, path, ordinal
    ) in {(19, 46, 1, 5), (54, 32, 1, 3)}:
        return "reachable_bloom_estimate_sample"
    if source == "Writing/BloomFilterBuilder.cs" and (
        line, offset, path, ordinal
    ) in {(105, 1, 0, 0), (147, 1, 0, 0)}:
        return "reachable_optional_null_list_bloom_sample"
    if source == "Writing/AppendSortingOrder.cs" and (
        line, offset, path, ordinal
    ) == (23, 29, 0, 2):
        return "preempted_append_nonempty_latest"
    if source == "Writing/BufferWriter.cs" and (
        line, offset, path, ordinal
    ) in {(21, 67, 0, 4), (24, 145, 0, 6)}:
        return "reachable_buffer_capacity_sample"
    if source == "Writing/BufferWriter.cs" and (
        line, offset, path, ordinal
    ) in {(15, 12, 0, 0), (18, 37, 0, 2)}:
        return "preempted_buffer_factory_nonzero"
    if source == "Writing/BufferWriter.cs" and (
        line, offset, path, ordinal
    ) == (98, 6, 0, 0):
        return "preempted_buffer_reset_lifecycle"
    if source == "Writing/BufferWriter.cs" and (
        line, offset, path, ordinal
    ) in {
        (111, 2, 0, 0), (111, 11, 1, 3), (114, 90, 0, 4),
        (114, 99, 0, 6), (114, 99, 1, 7),
        (120, 192, 0, 12), (120, 192, 1, 13),
        (126, 167, 0, 8), (126, 167, 1, 9),
        (126, 170, 0, 10), (126, 170, 1, 11),
        (132, 195, 0, 14), (132, 195, 1, 15),
    }:
        return "reachable_merger_rollback_sample"
    if source == "Writing/BufferWriter.cs" and (
        line, offset, path, ordinal
    ) in {(111, 2, 1, 1), (111, 11, 0, 2), (114, 90, 1, 5)}:
        return "preempted_merger_rollback_invariant"
    if source == "Writing/BufferWriter.cs" and (
        line, offset, path, ordinal
    ) in {
        (281, 6, 1, 1), (281, 14, 0, 2), (285, 53, 0, 4),
        (296, 6, 0, 0), (301, 38, 1, 5), (312, 13, 0, 0),
    }:
        return "preempted_buffer_segment_lifecycle"
    if source == "Writing/BufferWriter.cs" and (
        line, offset, path, ordinal
    ) in {
        (66, 6, 1, 1), (86, 80, 0, 10), (146, 17, 1, 1),
        (161, 13, 0, 0), (163, 37, 1, 3), (181, 8, 1, 1),
        (66, 14, 0, 2), (163, 45, 0, 4), (207, 6, 1, 1),
    }:
        return "preempted_buffer_initialized_content_invariant"
    if source == "Writing/ColumnStatistics.cs" and (
        line, offset, path, ordinal
    ) in {(646, 12, 0, 0), (646, 12, 1, 1)}:
        return "internal_no_public_nullable_decimal_route"
    if source == "Writing/ColumnStatistics.cs" and (
        line, offset, path, ordinal
    ) == (659, 12, 0, 0):
        return "reachable_optional_decimal_empty_statistics_seed"
    if source == "Writing/ColumnStatistics.cs" and (
        line, offset, path, ordinal
    ) in {
        (236, 220, 0, 10), (238, 260, 0, 12),
        (247, 25, 0, 0), (247, 25, 1, 1),
    }:
        return "internal_optional_statistics_fallback_no_public_route"
    if source == "Writing/Encoding/ReusableDictionaryState.cs" and (
        line, offset, path, ordinal
    ) in {(220, 25, 0, 0), (264, 25, 0, 0)}:
        return "reachable_readonly_memory_dictionary_sample"
    if source == "Writing/Encoding/DeltaLengthByteArrayEncoding.cs" and (
        line, offset, path, ordinal
    ) in {
        (14, 31, 1, 1), (20, 79, 0, 2), (77, 25, 0, 0),
        (99, 42, 0, 2), (99, 42, 1, 3), (100, 21, 0, 0),
        (100, 21, 1, 1), (110, 182, 0, 6), (110, 182, 1, 7),
        (112, 122, 0, 4), (112, 122, 1, 5), (119, 198, 0, 8),
        (119, 198, 1, 9), (124, 327, 0, 12), (124, 327, 1, 13),
        (126, 246, 0, 10), (126, 246, 1, 11), (214, 125, 0, 2),
        (214, 125, 1, 3), (216, 76, 0, 0), (216, 76, 1, 1),
        (223, 140, 0, 4), (223, 140, 1, 5), (228, 241, 0, 8),
        (228, 241, 1, 9), (230, 178, 0, 6), (230, 178, 1, 7),
    }:
        return "reachable_delta_length_byte_array_shapes_sample"
    if source == "Writing/Encoding/DeltaLengthByteArrayEncoding.cs" and (
        line, offset, path, ordinal
    ) in {(20, 79, 1, 3), (85, 72, 1, 3)}:
        return "preempted_delta_length_public_value_shape"
    if source == "Writing/Encoding/DeltaLengthByteArrayEncoding.cs" and (
        line, offset, path, ordinal
    ) == (246, 7, 0, 0):
        return "preempted_delta_length_physical_compatibility"
    if source == "Writing/SerializedColumn.cs" and (
        line, offset, path, ordinal
    ) == (682, 173, 0, 14):
        return "reachable_required_datetime_plain_sample"
    if source == "Writing/SerializedColumn.cs" and (
        line, offset, path, ordinal
    ) in {
        (708, 23, 1, 3),  # Adjusted-to-UTC timestamp kind expectation.
        (710, 52, 0, 4),  # First DateTime has the wrong kind.
        (718, 177, 0, 6), # Later DateTime has the wrong kind.
    }:
        return "reachable_required_datetime_kind_boundary_sample"
    if source == "Writing/SerializedColumn.cs" and (
        line, offset, path, ordinal
    ) in {
        (696, 294, 0, 18),  # Empty required timestamp dictionary skips single-page stats.
        (705, 7, 0, 0),      # Empty span returns empty column statistics.
        (1790, 77, 0, 2),    # Empty dictionary has no V2 data pages to visit.
        (1800, 87, 1, 5),    # Zero covered rows equal the empty input length.
    }:
        return "reachable_empty_required_datetime_statistics_sample"
    if (source, line, offset, path, ordinal) in {
        ("Writing/Encoding/Encoding.cs", 4307, 63, 0, 2),
        ("Writing/Encoding/Encoding.cs", 4392, 547, 1, 21),
        ("Writing/Encoding/Encoding.cs", 4398, 609, 0, 22),
        ("Writing/Encoding/PlainEncoding.cs", 771, 253, 1, 9),
        ("Writing/Encoding/PlainEncoding.cs", 778, 300, 0, 10),
        ("Writing/Encoding/PlainEncoding.cs", 1031, 4, 0, 0),
        ("Writing/Encoding/PlainEncoding.cs", 1034, 54, 1, 5),
        ("Writing/Encoding/PlainEncoding.cs", 1035, 28, 0, 2),
    }:
        return "reachable_readonly_memory_dictionary_sample"
    if source == "Writing/Encoding/ByteStreamSplitEncoding.cs" and (
        line, offset, path, ordinal
    ) in {
        (111, 32, 0, 0), (113, 40, 1, 3), (119, 150, 1, 5),
        (124, 240, 0, 6), (124, 240, 1, 7), (134, 276, 0, 8),
        (138, 308, 1, 11), (142, 327, 0, 12), (143, 430, 0, 14),
        (143, 430, 1, 15), (485, 38, 0, 0), (485, 38, 1, 1),
    }:
        return "reachable_fixed_bss_sample"
    if source == "Dataset/DatasetWriterOptions.cs" and (
        line, offset, path, ordinal
    ) == (27, 65, 0, 0):
        return "reachable_dataset_options_sample"
    if source == "Dataset/DatasetWriterBase.cs" and (
        line, offset, path, ordinal
    ) in ((76, 81, 0, 2), (105, 376, 0, 8), (109, 447, 0, 14), (165, 12, 0, 0)):
        return "reachable_dataset_options_sample"
    if source == "Dataset/DatasetWriterBase.cs" and (
        line, offset, path, ordinal
    ) == (172, 56, 0, 2):
        return "reachable_dataset_empty_path_sample"
    if source == "Dataset/DatasetWriterBase.cs" and (
        line, offset, path, ordinal
    ) in {
        (218, 251, 0, 18),  # ParkRow fails for a new pending key; catch releases the empty key.
        (218, 251, 1, 19),  # ParkRow fails for an existing pending key; catch preserves its rows.
        (371, 19, 0, 0),    # The catch cleanup reaches a used key with no parked rows.
        (371, 27, 1, 3),    # Existing parked rows keep their pending key alive after a failed copy.
    }:
        return "reachable_dataset_parked_copy_failure_sample"
    if source == "Dataset/DatasetWriterBase.cs" and (
        line, offset, path, ordinal
    ) in {(236, 6, 0, 0), (802, 25, 0, 2)}:
        return "reachable_dataset_disposed_guard_sample"
    if source == "Dataset/DatasetWriterBase.cs" and (
        line, offset, path, ordinal
    ) in {(147, 6, 0, 0), (800, 6, 0, 0)}:
        return "generated_dataset_lifecycle_preempts_guard"
    if source == "Dataset/DatasetWriterBase.cs" and (
        line, offset, path, ordinal
    ) in ((61, 11, 0, 0), (73, 54, 0, 0)):
        return "internal_guard_generated_constraint"
    if source == "Dataset/DatasetWriterBase.cs" and (
        line, offset, path, ordinal
    ) == (106, 405, 0, 12):
        return "internal_guard_generated_constraint"
    if source == "Writing/Thrift/ParquetMetadataThriftWriter.cs" and (
        line, offset, path, ordinal
    ) == (762, 8, 0, 0):
        return "reachable_invalid_timeunit_sample"
    if source == "Writing/Encoding/DeltaBinaryPackedEncoding.cs" and (
        line, offset, path, ordinal
    ) == (764, 31, 0, 0):
        return "preempted_narrow_width_guard"
    if source == "AlpEncodingPrimitives.cs" and (line, offset, path, ordinal) in (
        (39, 76, 1, 7), (56, 82, 1, 7)
    ):
        return "reachable_writer_sample"
    if source == "Writing/ParquetWriter.cs" and (line, offset, path, ordinal) in (
        (695, 268, 0, 2), (698, 293, 0, 4)
    ):
        return "reachable_import_bloom_sample"
    if source == "Writing/ParquetWriter.cs" and (line, offset, path, ordinal) in {
        (281, 12, 0, 0), (319, 6, 0, 0), (330, 12, 0, 0),
        (342, 12, 0, 0), (348, 6, 0, 0),
    }:
        return "reachable_writer_lifecycle_sample"
    if source == "Writing/Thrift/ParquetMetadataThriftWriter.cs" and (
        line, offset, path, ordinal
    ) == (841, 192, 0, 2):
        return "reachable_import_bloom_sample"
    if source == "Schema/ColumnOptions.cs" and ("::Equals(" in method or "::GetHashCode(" in method):
        return "reachable_api_sample"
    if source == "Writing/ParquetWriterOptions.cs" and (
        line, offset, path, ordinal
    ) in {
        (56, 6, 1, 1),
        (65, 49, 0, 0), (68, 84, 0, 2), (71, 119, 0, 4),
        (74, 154, 0, 6), (77, 194, 0, 8), (80, 278, 0, 10),
        (83, 313, 0, 12), (86, 348, 0, 14), (89, 391, 0, 16),
        (92, 420, 0, 18), (95, 460, 0, 20), (104, 562, 0, 22),
    }:
        return "reachable_writer_options_sample"
    if source == "BloomFilters/SplitBlockBloomFilter.cs" and (
        line, offset, path, ordinal
    ) in {(66, 9, 1, 1), (66, 21, 0, 2)}:
        return "preempted_bloom_bitset_size_validation"
    if source == "Schema/ParquetBloomFilterOptions.cs" and (
        line, offset, path, ordinal
    ) in {
        (32, 16, 1, 1), (32, 35, 1, 3), (32, 47, 0, 4),
        (32, 58, 0, 6), (35, 116, 0, 8), (38, 157, 1, 11),
        (38, 166, 0, 12), (38, 175, 1, 15), (38, 188, 0, 16),
        (52, 98, 1, 3), (52, 102, 0, 4),
    }:
        return "reachable_bloom_options_sample"
    if source == "Schema/ParquetBloomFilterOptions.cs" and (
        line, offset, path, ordinal
    ) in {(57, 134, 1, 7), (57, 140, 1, 9)}:
        return "preempted_validated_bloom_power2_bound"
    if source == "Writing/TimestampConversion.cs" and (
        line, offset, path, ordinal
    ) in {(141, 17, 1, 1), (252, 5, 0, 2)}:
        return "internal_local_expected_kind_no_public_writer_route"
    if source == "ParquetBuffer.cs" and (
        line, offset, path, ordinal
    ) in {
        (42, 11, 0, 0), (45, 79, 0, 2),
        (62, 13, 0, 0), (64, 46, 0, 2),
        (92, 1, 0, 0), (94, 16, 0, 2),
        (96, 36, 1, 5), (96, 40, 0, 6),
        (98, 55, 1, 9), (98, 61, 0, 10),
        (156, 8, 1, 1), (156, 27, 0, 2),
    }:
        return "reachable_buffer_api_sample"
    if source == "DefaultParquetBufferPool.cs" and (
        line, offset, path, ordinal
    ) in {
        (52, 27, 0, 0), (55, 54, 0, 2),
        (94, 40, 0, 2), (162, 68, 0, 6),
        (169, 32, 0, 0), (169, 32, 1, 1),
        (181, 12, 0, 0), (181, 12, 1, 1),
        (196, 47, 0, 4), (304, 49, 1, 1),
    }:
        return "reachable_buffer_api_sample"
    if source == "Schema/ColumnDefinition.cs" and (
        line, offset, path, ordinal
    ) in {
        (135, 57, 1, 1), (207, 17, 0, 0),
        (259, 773, 0, 36), (261, 828, 0, 40),
        (293, 16, 0, 0), (319, 256, 1, 17),
    }:
        return "reachable_schema_api_sample"
    if source == "Schema/ParquetSchema.cs" and (
        line, offset, path, ordinal
    ) in {
        (13, 14, 1, 1), (14, 48, 0, 2),
        (16, 57, 0, 4), (16, 57, 1, 5),
        (92, 4, 0, 0), (98, 4, 0, 0),
        (105, 5, 0, 0), (110, 4, 0, 0),
        (117, 5, 0, 0), (195, 63, 0, 2),
        (199, 104, 0, 7), (204, 138, 0, 13),
        (243, 595, 0, 27), (263, 743, 1, 32),
        (263, 748, 0, 33), (263, 760, 0, 35),
    }:
        return "reachable_schema_api_sample"
    if source == "Schema/ColumnDefinition.cs" and (
        line, offset, path, ordinal
    ) in {
        (180, 11, 0, 2), (189, 157, 0, 6),
        (193, 252, 0, 8), (197, 435, 0, 14),
        (261, 814, 1, 39), (348, 59, 1, 3),
    }:
        return "reachable_schema_api_sample"
    if source == "Schema/ParquetTypeMap.cs" and (
        line, offset, path, ordinal
    ) in {(46, 18, 1, 3), (86, 341, 1, 33)}:
        return "reachable_schema_api_sample"
    if source == "Schema/ColumnDefinition.cs" and (
        line, offset, path, ordinal
    ) == (183, 51, 0, 4):
        return "internal_nullable_converter_physical_type_uninstantiable"
    if source == "Schema/ParquetSchema.cs" and (
        line, offset, path, ordinal
    ) == (36, 7, 1, 1):
        return "internal_schema_builder_nondefault"
    if source in ("Compression/ZlibLibraryResolver.cs", "Compression/ZlibNative.cs"):
        return "platform_or_loader_environment"
    if source == "Reading/Logical/Internal/DeltaBinaryPackedDecoder.cs" and (
        "::ReadNarrowInt32Core(" in method and line in (1044, 1054)
    ):
        return "internal_decoder_api_no_reader_route"
    generated_name = method.split("::")[-1].split("(")[0]
    if (source == "obj/Release/net10.0/Plank.InternalGen/Plank.InternalGen.DeltaBinaryPackedIntegerGenerator/DeltaBinaryPackedDecoder.FastInteger.g.cs"
        and any(generated_name.startswith(prefix) for prefix in (
            "DecodeInt32MiniBlockFastW", "DecodeNullableInt32MiniBlockFastW",
            "DecodeInt64MiniBlockFastW"))
        and generated_name.rsplit("W", 1)[-1].isdigit()
        and path == 0 and ordinal % 2 == 0
        and offset in (47, 49, 50, 83, 117, 151)):
        # Each generated word load checks BitConverter.IsLittleEndian. Path 0
        # falls through to ReverseEndianness; the separate group-loop branch
        # uses another source line and IL offset.
        return "big_endian_host_only"
    if source == "obj/Release/net10.0/Plank.InternalGen/Plank.InternalGen.DeltaBinaryPackedIntegerGenerator/DeltaBinaryPackedDecoder.FastInteger.g.cs" and (
        (line, offset, path, ordinal, method.split("::")[-1].split("(")[0])
        in {
            (15, 3, 0, 0, "DecodeInt32MiniBlockFast"),
            (1176, 3, 0, 0, "DecodeNullableInt32MiniBlockFast"),
            (2337, 3, 0, 0, "DecodeInt64MiniBlockFast"),
        }
    ):
        return "internal_guard_generated_constraint"
    if source == "Reading/Logical/Internal/PageMetadataReader.cs" and (
        line, offset, path, ordinal
    ) == (403, 26, 0, 0):
        return "fuzzer_input_cap_precludes_large_gap"
    if source == "Reading/Logical/Internal/ColumnChunkReader.DictionaryPortable.cs" and (
        "::DecodeNullableInt32DictionaryNineBitPortable(" in method
    ):
        return "arm_adv_simd_guard"
    if (source, line, offset, path, ordinal) in {
        ("Reading/Logical/Internal/ColumnChunkReader.cs", 29, 42, 0, 2),
        ("Reading/Logical/Internal/ColumnChunkReader.cs", 29, 50, 0, 4),
        ("Reading/Logical/Internal/ColumnChunkReader.cs", 29, 50, 1, 5),
        ("Reading/Logical/Internal/ColumnChunkReader.cs", 29, 58, 1, 7),
        ("Reading/Logical/Internal/ColumnChunkReader.cs", 34, 101, 0, 8),
        ("Reading/Logical/Internal/ColumnChunkReader.cs", 34, 101, 1, 9),
    }:
        return "preempted_cpu_not_intel_family6_model158"
    if source == "Reading/Logical/Internal/ColumnChunkReader.cs":
        if "::TryDecodeBinaryDataPage(" in method and line > 1953:
            return "dead_candidate_dispatch_bypass"
        if "::ReadUnsignedVarInt(" in method and line == 4417:
            return "preempted_diagnostic"
    if source == "Writing/Encoding/PlainEncoding.cs" and "::WriteOptionalFixedLengthPayloads(" in method:
        return "dead_candidate_preceding_return"
    if source == "RowApi/RowReaderCore.cs" and (
        line, offset, path, ordinal
    ) in {
        (637, 12, 1, 1),
        (639, 22, 0, 2), (639, 22, 1, 3),
        (639, 36, 0, 4), (639, 36, 1, 5),
    }:
        return "preempted_rowapi_materialized_type_by_physical_validation"
    if source == "Writing/Encoding/PlainEncoding.cs" and (
        (
            "::WriteByteValuesAsUInt32(" in method
            and (line, offset, path, ordinal) in {
                (172, 36, 0, 0), (172, 36, 1, 1),
                (176, 197, 0, 2), (176, 197, 1, 3),
                (188, 238, 0, 4), (188, 238, 1, 5),
                (192, 250, 0, 6), (192, 250, 1, 7),
                (196, 386, 0, 8), (196, 386, 1, 9),
                (209, 412, 0, 10), (209, 412, 1, 11),
            }
        )
        or (
            "::WriteUInt16ValuesAsUInt32(" in method
            and (line, offset, path, ordinal) in {
                (220, 36, 0, 0), (220, 36, 1, 1),
                (224, 197, 0, 2), (224, 197, 1, 3),
                (236, 238, 0, 4), (236, 238, 1, 5),
                (240, 250, 0, 6), (240, 250, 1, 7),
                (243, 316, 0, 8), (243, 316, 1, 9),
                (250, 325, 0, 10), (250, 325, 1, 11),
                (250, 334, 0, 12), (250, 334, 1, 13),
                (253, 400, 0, 14), (253, 400, 1, 15),
                (261, 426, 0, 16), (261, 426, 1, 17),
            }
        )
    ):
        return "preempted_public_int32_byte_ushort_coercion"
    if source == "Writing/PageIndex.cs" and line in (7, 8, 9, 90):
        return "internal_guard_preempted"
    if source == "Writing/Thrift/ParquetMetadataThriftWriter.cs" and (
        line, offset, path, ordinal
    ) == (872, 6, 0, 0):
        return "preempted_default_page_statistics"
    return "unreviewed"


def main(tag, unlabeled=False):
    hits = {}
    methods = {}
    for target in ("reader", "writer"):
        files = glob.glob(f"fuzz/coverage/history/{target}-{tag}-*..json")
        if len(files) != 4:
            raise SystemExit(f"expected four {target} reports for {tag}, found {len(files)}")
        for filename in files:
            with open(filename, encoding="utf-8") as stream:
                modules = json.load(stream)
            for source, classes in modules["Plank.dll"].items():
                relative = source.split("/library/Plank/Plank/", 1)[-1]
                for class_name, class_methods in classes.items():
                    for method_name, method in class_methods.items():
                        for branch in method.get("Branches", []):
                            key = (
                                relative,
                                branch["Line"],
                                branch["Offset"],
                                branch["Path"],
                                branch["Ordinal"],
                            )
                            hits[key] = max(hits.get(key, 0), branch["Hits"])
                            methods[key] = (class_name, method_name)

    writer = csv.writer(sys.stdout, delimiter="\t", lineterminator="\n")
    writer.writerow(("source", "line", "offset", "path", "ordinal", "class", "method", "status"))
    for key, count in sorted(hits.items()):
        if count == 0:
            label = "unreviewed" if unlabeled else status(key[0], methods[key][1], *key[1:])
            writer.writerow((*key, *methods[key], label))
    print(f"{sum(count == 0 for count in hits.values())} unhit / {len(hits)} total", file=sys.stderr)


if __name__ == "__main__":
    if len(sys.argv) not in (2, 3) or (len(sys.argv) == 3 and sys.argv[2] != "--unlabeled"):
        raise SystemExit(__doc__)
    main(sys.argv[1], unlabeled=len(sys.argv) == 3)
