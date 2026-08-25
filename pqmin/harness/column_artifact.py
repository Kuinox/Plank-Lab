"""Build a scored Parquet file from a researcher-owned physical column.

The current research surface is a deliberately tiny binary bundle written by C:
page boundaries, standard Parquet value encoding, and compressed page payloads.
The trusted gate owns page headers, exact statistics indexes, schema, and footer.
Legacy one-column Parquet carriers remain readable so archived tests and candidates
can still be inspected, but new workers never receive the Plank repository.
"""

from __future__ import annotations

import os
import struct
from pathlib import Path
from typing import Any, BinaryIO

try:
    from .compact_thrift import CompactThriftError, read_struct, read_struct_with_spans
except ImportError:  # Direct import from gate.py.
    from compact_thrift import CompactThriftError, read_struct, read_struct_with_spans


MAGIC = b"PAR1"
BUNDLE_MAGIC = b"PQCOL01\x00"
BUNDLE_HEADER = struct.Struct("<8sIIIIIQ")
BUNDLE_PAGE = struct.Struct("<QqqQQ")
CANONICAL_ROOT_NAME = b"schema"
CANONICAL_COLUMN_NAME = b"TradeTimestamp"

# Parquet enum values.  Keeping this list intentionally small ensures that the
# wrapper never has to infer dictionary or level streams from researcher output.
SUPPORTED_ENCODINGS = {0, 5, 9}  # PLAIN, DELTA_BINARY_PACKED, BYTE_STREAM_SPLIT
SUPPORTED_CODECS = {0, 1, 2, 4, 5, 6, 7}  # standard Parquet codec enum values
SUPPORTED_PAGE_VERSIONS = {1, 2}


class ColumnArtifactError(ValueError):
    """The staging carrier cannot be wrapped by the fixed envelope."""


def _zigzag(value: int) -> int:
    return value << 1 if value >= 0 else ((-value) << 1) - 1


def _compact_type(kind: str, value: Any = None) -> int:
    return {
        "bool": 1 if value else 2,
        "i32": 5,
        "i64": 6,
        "binary": 8,
        "list": 9,
        "struct": 12,
    }[kind]


def _compact_value(kind: str, value: Any) -> bytes:
    if kind == "bool":
        # Boolean struct fields carry their value in the field type.  Boolean
        # list elements use one compact-type byte as the value.
        return bytes((1 if value else 2,))
    if kind in {"i32", "i64"}:
        return _uvarint(_zigzag(int(value)))
    if kind == "binary":
        encoded = bytes(value)
        return _uvarint(len(encoded)) + encoded
    if kind == "struct":
        return _compact_struct(value)
    if kind == "list":
        element_kind, values = value
        values = list(values)
        element_type = _compact_type(element_kind)
        header = (
            bytes(((len(values) << 4) | element_type,))
            if len(values) < 15
            else bytes((0xF0 | element_type,)) + _uvarint(len(values))
        )
        return header + b"".join(_compact_value(element_kind, item) for item in values)
    raise ValueError(f"unsupported Compact Protocol kind {kind!r}")


def _compact_struct(fields: list[tuple[int, str, Any]]) -> bytes:
    result = bytearray()
    previous = 0
    for field_id, kind, value in fields:
        compact_type = _compact_type(kind, value)
        delta = field_id - previous
        if 0 < delta <= 15:
            result.append((delta << 4) | compact_type)
        else:
            result.append(compact_type)
            result.extend(_uvarint(_zigzag(field_id)))
        if kind != "bool":
            result.extend(_compact_value(kind, value))
        previous = field_id
    result.append(0)
    return bytes(result)


def _int64_bytes(value: int) -> bytes:
    return struct.pack("<q", value)


def _statistics(minimum: int, maximum: int) -> list[tuple[int, str, Any]]:
    # Legacy min/max are shorter than writing both legacy and modern fields and
    # are required to be interpreted according to the physical INT64 order.
    return [
        (1, "binary", _int64_bytes(maximum)),
        (2, "binary", _int64_bytes(minimum)),
        (3, "i64", 0),
    ]


def _page_header(
    *,
    page_version: int,
    encoding: int,
    row_count: int,
    uncompressed_size: int,
    compressed_size: int,
    minimum: int,
    maximum: int,
) -> bytes:
    if not 0 < row_count <= 0x7FFFFFFF:
        raise ColumnArtifactError("each bundle page must contain 1..2^31-1 rows")
    if not 0 <= uncompressed_size <= 0x7FFFFFFF:
        raise ColumnArtifactError("each uncompressed page payload must fit a Parquet i32")
    if not 0 <= compressed_size <= 0x7FFFFFFF:
        raise ColumnArtifactError("each compressed page payload must fit a Parquet i32")
    stats = _statistics(minimum, maximum)
    if page_version == 1:
        nested = [
            (1, "i32", row_count),
            (2, "i32", encoding),
            (3, "i32", 3),  # RLE definition-level encoding (zero bytes for required data)
            (4, "i32", 3),  # RLE repetition-level encoding (zero bytes for flat data)
            (5, "struct", stats),
        ]
        page_type, nested_field = 0, 5
    else:
        nested = [
            (1, "i32", row_count),
            (2, "i32", 0),
            (3, "i32", row_count),
            (4, "i32", encoding),
            (5, "i32", 0),
            (6, "i32", 0),
            (7, "bool", True),
            (8, "struct", stats),
        ]
        page_type, nested_field = 3, 8
    return _compact_struct([
        (1, "i32", page_type),
        (2, "i32", uncompressed_size),
        (3, "i32", compressed_size),
        (nested_field, "struct", nested),
    ])


def _column_index(pages: list[dict[str, int]]) -> bytes:
    return _compact_struct([
        (1, "list", ("bool", [False] * len(pages))),
        (2, "list", ("binary", [_int64_bytes(page["minimum"]) for page in pages])),
        (3, "list", ("binary", [_int64_bytes(page["maximum"]) for page in pages])),
        (4, "i32", 0),  # UNORDERED; always correct even when pages cross series boundaries
        (5, "list", ("i64", [0] * len(pages))),
    ])


def _offset_index(pages: list[dict[str, int]]) -> bytes:
    return _compact_struct([
        (1, "list", ("struct", [[
            (1, "i64", page["file_offset"]),
            (2, "i32", page["stored_size"]),
            (3, "i64", page["first_row"]),
        ] for page in pages])),
    ])


def _footer(
    *,
    encoding: int,
    codec: int,
    total_rows: int,
    total_uncompressed_size: int,
    total_compressed_size: int,
    data_offset: int,
    column_index_offset: int,
    column_index_length: int,
    offset_index_offset: int,
    offset_index_length: int,
    minimum: int,
    maximum: int,
) -> bytes:
    timestamp = [(1, "bool", True), (2, "struct", [(2, "struct", [])])]
    schema = [
        [(4, "binary", CANONICAL_ROOT_NAME), (5, "i32", 1)],
        [
            (1, "i32", 2),
            (3, "i32", 0),
            (4, "binary", CANONICAL_COLUMN_NAME),
            (6, "i32", 10),
            (10, "struct", [(8, "struct", timestamp)]),
        ],
    ]
    metadata = [
        (1, "i32", 2),
        (2, "list", ("i32", [encoding])),
        (3, "list", ("binary", [CANONICAL_COLUMN_NAME])),
        (4, "i32", codec),
        (5, "i64", total_rows),
        (6, "i64", total_uncompressed_size),
        (7, "i64", total_compressed_size),
        (9, "i64", data_offset),
        (12, "struct", _statistics(minimum, maximum)),
    ]
    chunk = [
        (2, "i64", 0),
        (3, "struct", metadata),
        (4, "i64", offset_index_offset),
        (5, "i32", offset_index_length),
        (6, "i64", column_index_offset),
        (7, "i32", column_index_length),
    ]
    row_group = [
        (1, "list", ("struct", [chunk])),
        (2, "i64", total_uncompressed_size),
        (3, "i64", total_rows),
    ]
    return _compact_struct([
        (1, "i32", 1),
        (2, "list", ("struct", schema)),
        (3, "i64", total_rows),
        (4, "list", ("struct", [row_group])),
    ])


def _read_bundle(path: Path) -> tuple[dict[str, int], list[dict[str, int]]]:
    size = path.stat().st_size
    if size < BUNDLE_HEADER.size + BUNDLE_PAGE.size:
        raise ColumnArtifactError("PQCOL bundle is too short")
    pages: list[dict[str, int]] = []
    with path.open("rb") as stream:
        raw = stream.read(BUNDLE_HEADER.size)
        magic, version, encoding, codec, page_version, page_count, total_rows = BUNDLE_HEADER.unpack(raw)
        if magic != BUNDLE_MAGIC or version != 1:
            raise ColumnArtifactError("PQCOL bundle has an unsupported magic or version")
        if encoding not in SUPPORTED_ENCODINGS:
            raise ColumnArtifactError(f"unsupported Parquet value encoding {encoding}")
        if codec not in SUPPORTED_CODECS:
            raise ColumnArtifactError(f"unsupported Parquet compression codec {codec}")
        if page_version not in SUPPORTED_PAGE_VERSIONS:
            raise ColumnArtifactError(f"unsupported Parquet data-page version {page_version}")
        if not 0 < page_count <= 1_000_000:
            raise ColumnArtifactError("PQCOL page count is unreasonable")
        first_row = 0
        for page_number in range(page_count):
            record = stream.read(BUNDLE_PAGE.size)
            if len(record) != BUNDLE_PAGE.size:
                raise ColumnArtifactError(f"PQCOL page {page_number} header is truncated")
            row_count, minimum, maximum, uncompressed_size, compressed_size = BUNDLE_PAGE.unpack(record)
            if not row_count or minimum > maximum:
                raise ColumnArtifactError(f"PQCOL page {page_number} has invalid rows or statistics")
            payload_offset = stream.tell()
            if payload_offset + compressed_size > size:
                raise ColumnArtifactError(f"PQCOL page {page_number} payload is truncated")
            pages.append({
                "row_count": row_count,
                "minimum": minimum,
                "maximum": maximum,
                "uncompressed_size": uncompressed_size,
                "compressed_size": compressed_size,
                "payload_offset": payload_offset,
                "first_row": first_row,
            })
            first_row += row_count
            stream.seek(compressed_size, os.SEEK_CUR)
        if stream.tell() != size:
            raise ColumnArtifactError("PQCOL bundle contains trailing bytes")
    if first_row != total_rows:
        raise ColumnArtifactError(
            f"PQCOL page rows sum to {first_row:,}, header declares {total_rows:,}"
        )
    return {
        "encoding": encoding,
        "codec": codec,
        "page_version": page_version,
        "total_rows": total_rows,
    }, pages


def _assemble_bundle(bundle: Path, destination: Path) -> Path:
    config, pages = _read_bundle(bundle)
    cursor = len(MAGIC)
    for page in pages:
        header = _page_header(
            page_version=config["page_version"],
            encoding=config["encoding"],
            row_count=page["row_count"],
            uncompressed_size=page["uncompressed_size"],
            compressed_size=page["compressed_size"],
            minimum=page["minimum"],
            maximum=page["maximum"],
        )
        page["header"] = header
        page["file_offset"] = cursor
        page["stored_size"] = len(header) + page["compressed_size"]
        cursor += page["stored_size"]

    column_index = _column_index(pages)
    column_index_offset = cursor
    cursor += len(column_index)
    offset_index = _offset_index(pages)
    offset_index_offset = cursor
    cursor += len(offset_index)
    total_uncompressed = sum(len(page["header"]) + page["uncompressed_size"] for page in pages)
    total_compressed = sum(page["stored_size"] for page in pages)
    footer = _footer(
        encoding=config["encoding"],
        codec=config["codec"],
        total_rows=config["total_rows"],
        total_uncompressed_size=total_uncompressed,
        total_compressed_size=total_compressed,
        data_offset=len(MAGIC),
        column_index_offset=column_index_offset,
        column_index_length=len(column_index),
        offset_index_offset=offset_index_offset,
        offset_index_length=len(offset_index),
        minimum=min(page["minimum"] for page in pages),
        maximum=max(page["maximum"] for page in pages),
    )
    destination.parent.mkdir(parents=True, exist_ok=True)
    temporary = destination.with_name(f".{destination.name}.{os.getpid()}.tmp")
    try:
        with bundle.open("rb") as source, temporary.open("wb") as output:
            output.write(MAGIC)
            for page in pages:
                output.write(page["header"])
                source.seek(page["payload_offset"])
                _copy_exact(source, output, page["compressed_size"])
            output.write(column_index)
            output.write(offset_index)
            output.write(footer)
            output.write(struct.pack("<I", len(footer)))
            output.write(MAGIC)
            output.flush()
            os.fsync(output.fileno())
        os.replace(temporary, destination)
    finally:
        temporary.unlink(missing_ok=True)
    return destination


def _uvarint(value: int) -> bytes:
    if value < 0:
        raise ValueError("varints cannot be negative")
    result = bytearray()
    while value >= 0x80:
        result.append((value & 0x7F) | 0x80)
        value >>= 7
    result.append(value)
    return bytes(result)


def _read_footer(path: Path) -> tuple[int, bytes, dict[int, Any], list[tuple[int, int, int]]]:
    size = path.stat().st_size
    if size < 12:
        raise ColumnArtifactError("column carrier is too short")
    with path.open("rb") as stream:
        if stream.read(4) != MAGIC:
            raise ColumnArtifactError("column carrier does not start with PAR1")
        stream.seek(size - 8)
        trailer = stream.read(8)
        if trailer[4:] != MAGIC:
            raise ColumnArtifactError("column carrier does not end with PAR1")
        footer_length = struct.unpack("<I", trailer[:4])[0]
        footer_offset = size - 8 - footer_length
        if footer_offset < 4:
            raise ColumnArtifactError("column carrier has an invalid footer length")
        stream.seek(footer_offset)
        encoded = stream.read(footer_length)
    try:
        footer, spans, _ = read_struct_with_spans(encoded)
    except CompactThriftError as exc:
        raise ColumnArtifactError(f"column carrier footer is invalid: {exc}") from exc
    return footer_offset, encoded, footer, spans


def _canonicalize_footer(
    encoded: bytes, footer: dict[int, Any], spans: list[tuple[int, int, int]],
) -> bytes:
    # Optional file-level metadata is deliberately outside the research surface.
    # Requiring this exact field set prevents created_by/key-value/footer tricks.
    if not {1, 2, 3, 4}.issubset(footer):
        raise ColumnArtifactError(
            "column carrier must contain version, schema, row count, and row groups"
        )
    if any(field_id >= 8 for field_id in footer):
        raise ColumnArtifactError("encrypted or signed column carriers are not supported")
    ordered_fields = [field_id for field_id, _, _ in spans]
    if ordered_fields[:4] != [1, 2, 3, 4]:
        raise ColumnArtifactError("column carrier core footer fields are not in canonical order")
    # Discard optional key/value metadata, created_by, and column-order fields.
    # They follow field 4 in a canonical carrier and belong to the fixed wrapper.
    core_footer_end = spans[3][2]
    encoded = encoded[:core_footer_end] + b"\x00"
    if footer.get(1) != 1:
        raise ColumnArtifactError("column carrier must use Parquet file metadata version 1")
    schema = footer.get(2)
    if not isinstance(schema, list) or len(schema) != 2:
        raise ColumnArtifactError("column carrier must have one flat column")
    root, leaf = schema
    if not isinstance(root, dict) or set(root) != {4, 5} or root.get(5) != 1:
        raise ColumnArtifactError("column carrier root schema shape is not canonical")
    root_name = root.get(4)
    if not isinstance(root_name, bytes):
        raise ColumnArtifactError("column carrier root schema name is not binary")
    expected_leaf = {
        1: 2,  # INT64
        3: 0,  # REQUIRED
        4: CANONICAL_COLUMN_NAME,
        6: 10,  # legacy TIMESTAMP_MICROS annotation retained for compatibility
        10: {8: {1: True, 2: {2: {}}}},  # timestamp[us, adjustedToUTC]
    }
    if leaf != expected_leaf:
        raise ColumnArtifactError(
            "column carrier leaf must be required TradeTimestamp timestamp[us, tz=UTC]"
        )
    row_groups = footer.get(4)
    if not isinstance(row_groups, list) or not row_groups:
        raise ColumnArtifactError("column carrier must contain at least one row group")

    # Plank's Compact Protocol writer emits the root name as field 4 using a
    # delta header.  Replace that field only; all column-owned offsets remain
    # valid because the footer follows every referenced region.
    marker = b"\x48" + _uvarint(len(root_name)) + root_name
    offset = encoded.find(marker)
    if offset < 0:
        raise ColumnArtifactError("cannot locate the root schema name in the carrier footer")
    replacement = b"\x48" + _uvarint(len(CANONICAL_ROOT_NAME)) + CANONICAL_ROOT_NAME
    canonical = encoded[:offset] + replacement + encoded[offset + len(marker):]
    try:
        rewritten, _ = read_struct(canonical)
    except CompactThriftError as exc:
        raise ColumnArtifactError(f"assembled footer is invalid: {exc}") from exc
    if rewritten.get(2, [{}])[0].get(4) != CANONICAL_ROOT_NAME:
        raise ColumnArtifactError("assembled footer did not receive the canonical root name")
    return canonical


def _copy_exact(source: BinaryIO, destination: BinaryIO, count: int) -> None:
    remaining = count
    while remaining:
        block = source.read(min(16 * 1024 * 1024, remaining))
        if not block:
            raise ColumnArtifactError("column carrier ended before its footer")
        destination.write(block)
        remaining -= len(block)


def assemble_column_carrier(carrier: Path, destination: Path) -> Path:
    """Wrap a PQCOL bundle (or archived Parquet carrier) in the fixed envelope."""

    carrier = carrier.resolve()
    destination = destination.resolve()
    if carrier == destination:
        raise ColumnArtifactError("carrier and assembled output must be different files")
    with carrier.open("rb") as stream:
        prefix = stream.read(len(BUNDLE_MAGIC))
    if prefix == BUNDLE_MAGIC:
        return _assemble_bundle(carrier, destination)
    footer_offset, encoded, footer, spans = _read_footer(carrier)
    canonical = _canonicalize_footer(encoded, footer, spans)
    destination.parent.mkdir(parents=True, exist_ok=True)
    temporary = destination.with_name(f".{destination.name}.{os.getpid()}.tmp")
    try:
        with carrier.open("rb") as source, temporary.open("wb") as output:
            _copy_exact(source, output, footer_offset)
            output.write(canonical)
            output.write(struct.pack("<I", len(canonical)))
            output.write(MAGIC)
            output.flush()
            os.fsync(output.fileno())
        os.replace(temporary, destination)
    finally:
        temporary.unlink(missing_ok=True)
    return destination
