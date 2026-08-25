# /// script
# requires-python = ">=3.11"
# dependencies = [
#   "duckdb>=1.3,<2",
#   "pyarrow>=20,<26",
# ]
# ///
"""Mechanical correctness gate for pqmin Parquet candidates.

The command prints exactly one JSON result to stdout and exits successfully
only when every structural and data check passes.  It intentionally validates
with PyArrow, DuckDB, and a tiny independent Compact Thrift decoder.
"""

import argparse
import hashlib
import json
import os
import struct
import sys
from collections.abc import Iterable
from dataclasses import dataclass
from pathlib import Path
from typing import Any, BinaryIO

try:
    from .compact_thrift import CompactThriftError, read_struct
except ImportError:
    try:  # Dynamically loaded by the gate from the repository root.
        from pqmin.harness.compact_thrift import CompactThriftError, read_struct
    except ImportError:  # Direct execution: ``uv run pqmin/harness/validate.py``.
        from compact_thrift import CompactThriftError, read_struct


COLUMN_NAME = "TradeTimestamp"
HASH_ALGORITHM = "sha256-int64-le"
PAGE_HEADER_PROBE = 64 * 1024


class ValidationFailure(ValueError):
    """A candidate or reference violated a validation invariant."""


@dataclass(frozen=True)
class ExpectedReference:
    row_count: int
    digest: str


@dataclass(frozen=True)
class EncodedStatistics:
    minimum: int
    maximum: int
    null_count: int
    minimum_exact: bool | None
    maximum_exact: bool | None


@dataclass(frozen=True)
class DataPage:
    offset: int
    compressed_size: int
    value_count: int
    first_row_index: int
    statistics: EncodedStatistics


@dataclass(frozen=True)
class Chunk:
    row_group: int
    row_count: int
    statistics: EncodedStatistics
    pages: tuple[DataPage, ...]


def _field(value: dict[int, Any], field_id: int, context: str) -> Any:
    try:
        return value[field_id]
    except KeyError as error:
        raise ValidationFailure(f"{context} is missing required field {field_id}") from error


def _integer(value: Any, context: str, *, minimum: int = 0) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < minimum:
        raise ValidationFailure(f"{context} must be an integer >= {minimum}")
    return value


def _load_reference(path: Path) -> ExpectedReference:
    try:
        raw = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        raise ValidationFailure(f"cannot read reference JSON {path}: {error}") from error
    if not isinstance(raw, dict):
        raise ValidationFailure("reference JSON must be an object")

    row_count = _integer(raw.get("rows", raw.get("row_count")), "reference row count", minimum=1)
    hash_entry = raw.get(
        "sha256_i64_le", raw.get("timestamp_hash", raw.get("raw_timestamp_hash"))
    )
    algorithm = raw.get("hash_algorithm")
    if isinstance(hash_entry, dict):
        algorithm = hash_entry.get("algorithm", algorithm)
        digest = hash_entry.get("value", hash_entry.get("digest"))
    else:
        digest = hash_entry
    normalized_algorithm = str(algorithm or HASH_ALGORITHM).lower().replace("_", "-")
    if normalized_algorithm in ("sha256", "sha-256", "sha256-int64-le"):
        normalized_algorithm = HASH_ALGORITHM
    if normalized_algorithm != HASH_ALGORITHM:
        raise ValidationFailure(
            f"unsupported reference hash algorithm {algorithm!r}; expected {HASH_ALGORITHM}"
        )
    if not isinstance(digest, str) or len(digest) != 64:
        raise ValidationFailure("reference timestamp hash must be a 64-character SHA-256 hex digest")
    try:
        bytes.fromhex(digest)
    except ValueError as error:
        raise ValidationFailure("reference timestamp hash is not hexadecimal") from error

    schema = raw.get("schema")
    if schema is not None:
        expected_schema = {
            "name": COLUMN_NAME,
            "unit": "us",
            "timezone": "UTC",
            "nullable": False,
        }
        if schema != expected_schema:
            raise ValidationFailure(
                f"reference schema must be exactly {expected_schema!r}, got {schema!r}"
            )
    if "column" in raw and raw["column"] != COLUMN_NAME:
        raise ValidationFailure(f"reference column must be {COLUMN_NAME!r}")
    if "logical_type" in raw and raw["logical_type"] != "timestamp[us, tz=UTC]":
        raise ValidationFailure("reference logical_type must be timestamp[us, tz=UTC]")
    if "nullable" in raw and raw["nullable"] is not False:
        raise ValidationFailure("reference column must be non-nullable")
    if "nulls" in raw and raw["nulls"] != 0:
        raise ValidationFailure("reference must contain zero nulls")
    return ExpectedReference(row_count=row_count, digest=digest.lower())


def _read_at(handle: BinaryIO, offset: int, length: int, context: str) -> bytes:
    if offset < 0 or length < 0:
        raise ValidationFailure(f"invalid {context} range ({offset}, {length})")
    handle.seek(offset)
    data = handle.read(length)
    if len(data) != length:
        raise ValidationFailure(f"truncated {context}: expected {length} bytes, found {len(data)}")
    return data


def _decode_int64(value: Any, context: str) -> int:
    if not isinstance(value, bytes) or len(value) != 8:
        length = len(value) if isinstance(value, bytes) else "non-binary"
        raise ValidationFailure(f"{context} must contain one little-endian INT64, got {length}")
    return struct.unpack("<q", value)[0]


def _statistics(fields: Any, context: str) -> EncodedStatistics:
    if not isinstance(fields, dict):
        raise ValidationFailure(f"{context} statistics must be a struct")
    if 5 in fields or 6 in fields:
        maximum = _decode_int64(_field(fields, 5, context), f"{context} maximum")
        minimum = _decode_int64(_field(fields, 6, context), f"{context} minimum")
    else:
        maximum = _decode_int64(_field(fields, 1, context), f"{context} legacy maximum")
        minimum = _decode_int64(_field(fields, 2, context), f"{context} legacy minimum")
    null_count = _integer(_field(fields, 3, context), f"{context} null_count")
    minimum_exact = fields.get(8)
    maximum_exact = fields.get(7)
    if minimum_exact is not None and not isinstance(minimum_exact, bool):
        raise ValidationFailure(f"{context} minimum exactness flag is not boolean")
    if maximum_exact is not None and not isinstance(maximum_exact, bool):
        raise ValidationFailure(f"{context} maximum exactness flag is not boolean")
    if minimum > maximum:
        raise ValidationFailure(f"{context} minimum exceeds maximum")
    if minimum_exact is False or maximum_exact is False:
        raise ValidationFailure(f"{context} declares inexact minimum or maximum")
    return EncodedStatistics(minimum, maximum, null_count, minimum_exact, maximum_exact)


def _parse_page_header(handle: BinaryIO, offset: int, chunk_end: int) -> tuple[dict[int, Any], int]:
    probe_length = min(PAGE_HEADER_PROBE, chunk_end - offset)
    if probe_length <= 0:
        raise ValidationFailure("empty page header range")
    probe = _read_at(handle, offset, probe_length, f"page header at {offset}")
    try:
        return read_struct(probe, require_eof=False)
    except CompactThriftError as error:
        raise ValidationFailure(f"invalid page header at byte {offset}: {error}") from error


def _parse_index(handle: BinaryIO, offset: Any, length: Any, file_size: int, context: str) -> dict[int, Any]:
    checked_offset = _integer(offset, f"{context} offset", minimum=4)
    checked_length = _integer(length, f"{context} length", minimum=1)
    if checked_offset + checked_length > file_size - 8:
        raise ValidationFailure(f"{context} lies outside the Parquet body")
    encoded = _read_at(handle, checked_offset, checked_length, context)
    try:
        value, _ = read_struct(encoded)
    except CompactThriftError as error:
        raise ValidationFailure(f"invalid {context}: {error}") from error
    return value


def _column_index_statistics(index: dict[int, Any], context: str) -> tuple[EncodedStatistics, ...]:
    null_pages = _field(index, 1, context)
    minima = _field(index, 2, context)
    maxima = _field(index, 3, context)
    null_counts = _field(index, 5, context)
    if not all(isinstance(values, list) for values in (null_pages, minima, maxima, null_counts)):
        raise ValidationFailure(f"{context} fields 1, 2, 3, and 5 must be lists")
    count = len(null_pages)
    if count == 0 or any(len(values) != count for values in (minima, maxima, null_counts)):
        raise ValidationFailure(f"{context} lists must have the same nonzero length")
    result: list[EncodedStatistics] = []
    for page_index in range(count):
        if null_pages[page_index] is not False:
            raise ValidationFailure(f"{context} page {page_index} must not be a null page")
        null_count = _integer(null_counts[page_index], f"{context} page {page_index} null_count")
        result.append(
            EncodedStatistics(
                _decode_int64(minima[page_index], f"{context} page {page_index} minimum"),
                _decode_int64(maxima[page_index], f"{context} page {page_index} maximum"),
                null_count,
                True,
                True,
            )
        )
    return tuple(result)


def _offset_index_locations(index: dict[int, Any], context: str) -> tuple[tuple[int, int, int], ...]:
    locations = _field(index, 1, context)
    if not isinstance(locations, list) or not locations:
        raise ValidationFailure(f"{context} page_locations must be a nonempty list")
    result: list[tuple[int, int, int]] = []
    for page_index, location in enumerate(locations):
        if not isinstance(location, dict):
            raise ValidationFailure(f"{context} page location {page_index} must be a struct")
        result.append(
            (
                _integer(_field(location, 1, context), f"{context} page {page_index} offset", minimum=4),
                _integer(
                    _field(location, 2, context),
                    f"{context} page {page_index} compressed size",
                    minimum=1,
                ),
                _integer(
                    _field(location, 3, context),
                    f"{context} page {page_index} first row",
                ),
            )
        )
    return tuple(result)


def _inspect_structure(path: Path, parquet_file: Any) -> tuple[Chunk, ...]:
    file_size = path.stat().st_size
    if file_size < 12:
        raise ValidationFailure("candidate is too short to be a Parquet file")
    with path.open("rb") as handle:
        if _read_at(handle, 0, 4, "leading magic") != b"PAR1":
            raise ValidationFailure("candidate does not start with PAR1")
        trailer = _read_at(handle, file_size - 8, 8, "Parquet trailer")
        if trailer[4:] != b"PAR1":
            raise ValidationFailure("candidate does not end with PAR1")
        footer_length = struct.unpack("<I", trailer[:4])[0]
        footer_offset = file_size - 8 - footer_length
        if footer_offset < 4:
            raise ValidationFailure("invalid Parquet footer length")
        try:
            footer, _ = read_struct(_read_at(handle, footer_offset, footer_length, "footer"))
        except CompactThriftError as error:
            raise ValidationFailure(f"invalid Parquet footer: {error}") from error

        footer_rows = _integer(_field(footer, 3, "footer"), "footer row count")
        row_groups = _field(footer, 4, "footer")
        if not isinstance(row_groups, list) or not row_groups:
            raise ValidationFailure("footer must contain at least one row group")
        if footer_rows != parquet_file.metadata.num_rows:
            raise ValidationFailure("PyArrow and footer disagree about row count")
        if len(row_groups) != parquet_file.metadata.num_row_groups:
            raise ValidationFailure("PyArrow and footer disagree about row-group count")

        chunks: list[Chunk] = []
        for row_group_index, row_group in enumerate(row_groups):
            context = f"row group {row_group_index}"
            if not isinstance(row_group, dict):
                raise ValidationFailure(f"{context} must be a struct")
            row_count = _integer(_field(row_group, 3, context), f"{context} row count", minimum=1)
            columns = _field(row_group, 1, context)
            if not isinstance(columns, list) or len(columns) != 1:
                raise ValidationFailure(f"{context} must contain exactly one column chunk")
            column = columns[0]
            if not isinstance(column, dict):
                raise ValidationFailure(f"{context} column chunk must be a struct")
            metadata = _field(column, 3, f"{context} column chunk")
            if not isinstance(metadata, dict):
                raise ValidationFailure(f"{context} column metadata must be a struct")
            if _integer(_field(metadata, 1, context), f"{context} physical type") != 2:
                raise ValidationFailure(f"{context} physical type must be INT64")
            if _integer(_field(metadata, 5, context), f"{context} value count") != row_count:
                raise ValidationFailure(f"{context} value count does not equal row count")
            row_group_statistics = _statistics(_field(metadata, 12, context), context)
            if row_group_statistics.null_count != 0:
                raise ValidationFailure(f"{context} row-group null_count must be zero")

            arrow_chunk = parquet_file.metadata.row_group(row_group_index).column(0)
            if not arrow_chunk.has_column_index or not arrow_chunk.has_offset_index:
                raise ValidationFailure(f"{context} must have both ColumnIndex and OffsetIndex")
            column_index = _parse_index(
                handle,
                _field(column, 6, f"{context} column chunk"),
                _field(column, 7, f"{context} column chunk"),
                file_size,
                f"{context} ColumnIndex",
            )
            offset_index = _parse_index(
                handle,
                _field(column, 4, f"{context} column chunk"),
                _field(column, 5, f"{context} column chunk"),
                file_size,
                f"{context} OffsetIndex",
            )
            indexed_statistics = _column_index_statistics(column_index, f"{context} ColumnIndex")
            locations = _offset_index_locations(offset_index, f"{context} OffsetIndex")
            if len(indexed_statistics) != len(locations):
                raise ValidationFailure(f"{context} ColumnIndex and OffsetIndex page counts differ")

            total_compressed_size = _integer(
                _field(metadata, 7, context), f"{context} total compressed size", minimum=1
            )
            data_offset = _integer(_field(metadata, 9, context), f"{context} data page offset", minimum=4)
            dictionary_offset = metadata.get(11)
            chunk_start = (
                _integer(dictionary_offset, f"{context} dictionary page offset", minimum=4)
                if dictionary_offset is not None
                else data_offset
            )
            chunk_end = chunk_start + total_compressed_size
            if chunk_end > footer_offset:
                raise ValidationFailure(f"{context} compressed chunk overlaps the footer")

            parsed_pages: list[tuple[int, int, int, EncodedStatistics]] = []
            cursor = chunk_start
            while cursor < chunk_end:
                header, header_length = _parse_page_header(handle, cursor, chunk_end)
                page_type = _integer(_field(header, 1, f"page at {cursor}"), f"page type at {cursor}")
                payload_size = _integer(
                    _field(header, 3, f"page at {cursor}"), f"compressed page size at {cursor}"
                )
                stored_size = header_length + payload_size
                if stored_size <= 0 or cursor + stored_size > chunk_end:
                    raise ValidationFailure(f"page at {cursor} exceeds its column chunk")
                if page_type in (0, 3):
                    nested_field = 5 if page_type == 0 else 8
                    page_header = _field(header, nested_field, f"data page at {cursor}")
                    if not isinstance(page_header, dict):
                        raise ValidationFailure(f"data page at {cursor} has no data-page header")
                    value_count = _integer(
                        _field(page_header, 1, f"data page at {cursor}"),
                        f"data page value count at {cursor}",
                        minimum=1,
                    )
                    if page_type == 3:
                        page_row_count = _integer(
                            _field(page_header, 3, f"data page at {cursor}"),
                            f"data page row count at {cursor}",
                            minimum=1,
                        )
                        if page_row_count != value_count:
                            raise ValidationFailure(
                                f"required data page at {cursor} has different row and value counts"
                            )
                    statistics_field = 5 if page_type == 0 else 8
                    if statistics_field not in page_header:
                        raise ValidationFailure(
                            f"data page at {cursor} must carry statistics in its page header"
                        )
                    page_statistics = _statistics(
                        page_header[statistics_field], f"data page at {cursor}"
                    )
                    if page_statistics.null_count != 0:
                        raise ValidationFailure(f"data page at {cursor} null_count must be zero")
                    parsed_pages.append((cursor, stored_size, value_count, page_statistics))
                elif page_type not in (1, 2):
                    raise ValidationFailure(f"page at {cursor} has unknown Parquet page type {page_type}")
                cursor += stored_size
            if cursor != chunk_end:
                raise ValidationFailure(f"{context} page stream does not end at chunk boundary")
            if len(parsed_pages) != len(locations):
                raise ValidationFailure(f"{context} page stream and page indexes have different counts")

            pages: list[DataPage] = []
            expected_first_row = 0
            for page_index, ((offset, size, value_count, header_stats), index_stats, location) in enumerate(
                zip(parsed_pages, indexed_statistics, locations, strict=True)
            ):
                location_offset, location_size, first_row = location
                if (location_offset, location_size) != (offset, size):
                    raise ValidationFailure(f"{context} OffsetIndex page {page_index} does not match page stream")
                if first_row != expected_first_row:
                    raise ValidationFailure(
                        f"{context} OffsetIndex page {page_index} first_row_index is {first_row}, "
                        f"expected {expected_first_row}"
                    )
                if (
                    header_stats.minimum,
                    header_stats.maximum,
                    header_stats.null_count,
                ) != (
                    index_stats.minimum,
                    index_stats.maximum,
                    index_stats.null_count,
                ):
                    raise ValidationFailure(
                        f"{context} data-page header and ColumnIndex statistics differ at page {page_index}"
                    )
                pages.append(DataPage(offset, size, value_count, first_row, header_stats))
                expected_first_row += value_count
            if expected_first_row != row_count:
                raise ValidationFailure(f"{context} data-page counts do not sum to row-group count")
            chunks.append(Chunk(row_group_index, row_count, row_group_statistics, tuple(pages)))
        return tuple(chunks)


def _validate_arrow_schema(parquet_file: Any, pa: Any) -> None:
    schema = parquet_file.schema_arrow
    if len(schema) != 1:
        raise ValidationFailure(f"schema must contain exactly one field, found {len(schema)}")
    field = schema.field(0)
    if field.name != COLUMN_NAME:
        raise ValidationFailure(f"column must be named {COLUMN_NAME}, found {field.name!r}")
    if field.nullable:
        raise ValidationFailure(f"{COLUMN_NAME} must be required (non-nullable)")
    if not pa.types.is_timestamp(field.type):
        raise ValidationFailure(f"{COLUMN_NAME} must be a timestamp, found {field.type}")
    if field.type.unit != "us" or field.type.tz != "UTC":
        raise ValidationFailure(f"{COLUMN_NAME} must be timestamp[us, tz=UTC], found {field.type}")


def _update_hash(hasher: Any, int64_array: Any) -> None:
    if sys.byteorder != "little":
        for value in int64_array.to_pylist():
            hasher.update(struct.pack("<q", value))
        return
    buffer = int64_array.buffers()[1]
    if buffer is None:
        raise ValidationFailure("decoded timestamp array has no values buffer")
    start = int64_array.offset * 8
    hasher.update(memoryview(buffer)[start : start + len(int64_array) * 8])


def _scan_pyarrow(parquet_file: Any, chunks: Iterable[Chunk], pa: Any, pc: Any) -> tuple[int, str]:
    hasher = hashlib.sha256()
    total_rows = 0
    for chunk in chunks:
        page_index = 0
        page_rows = 0
        page_minimum: int | None = None
        page_maximum: int | None = None
        row_group_minimum: int | None = None
        row_group_maximum: int | None = None
        row_group_rows = 0
        for batch in parquet_file.iter_batches(
            batch_size=1_048_576,
            row_groups=[chunk.row_group],
            columns=[COLUMN_NAME],
            use_threads=False,
        ):
            values = batch.column(0)
            if values.null_count:
                raise ValidationFailure(f"PyArrow found nulls in row group {chunk.row_group}")
            raw_values = pc.cast(values, pa.int64(), safe=True)
            _update_hash(hasher, raw_values)
            total_rows += len(raw_values)
            row_group_rows += len(raw_values)
            consumed = 0
            while consumed < len(raw_values):
                if page_index >= len(chunk.pages):
                    raise ValidationFailure(f"row group {chunk.row_group} decoded beyond its page index")
                expected_page = chunk.pages[page_index]
                take = min(len(raw_values) - consumed, expected_page.value_count - page_rows)
                fragment = raw_values.slice(consumed, take)
                fragment_minimum = pc.min(fragment).as_py()
                fragment_maximum = pc.max(fragment).as_py()
                page_minimum = fragment_minimum if page_minimum is None else min(page_minimum, fragment_minimum)
                page_maximum = fragment_maximum if page_maximum is None else max(page_maximum, fragment_maximum)
                row_group_minimum = (
                    fragment_minimum if row_group_minimum is None else min(row_group_minimum, fragment_minimum)
                )
                row_group_maximum = (
                    fragment_maximum if row_group_maximum is None else max(row_group_maximum, fragment_maximum)
                )
                page_rows += take
                consumed += take
                if page_rows == expected_page.value_count:
                    if (page_minimum, page_maximum) != (
                        expected_page.statistics.minimum,
                        expected_page.statistics.maximum,
                    ):
                        raise ValidationFailure(
                            f"row group {chunk.row_group} page {page_index} statistics do not match decoded values"
                        )
                    page_index += 1
                    page_rows = 0
                    page_minimum = None
                    page_maximum = None
        if row_group_rows != chunk.row_count or page_index != len(chunk.pages) or page_rows:
            raise ValidationFailure(f"PyArrow row count/page boundaries disagree in row group {chunk.row_group}")
        if (row_group_minimum, row_group_maximum) != (
            chunk.statistics.minimum,
            chunk.statistics.maximum,
        ):
            raise ValidationFailure(f"row group {chunk.row_group} statistics do not match decoded values")
    return total_rows, hasher.hexdigest()


def _scan_duckdb(path: Path, pa: Any, pc: Any) -> tuple[int, str]:
    try:
        import duckdb
    except ImportError as error:
        raise ValidationFailure("DuckDB is required for complete independent validation") from error
    connection = duckdb.connect(database=":memory:")
    try:
        connection.execute("SET threads = 1")
        connection.execute("SET preserve_insertion_order = true")
        reader = connection.execute(
            f'SELECT "{COLUMN_NAME}" FROM read_parquet(?)', [os.fspath(path)]
        ).to_arrow_reader(1_048_576)
        hasher = hashlib.sha256()
        row_count = 0
        for batch in reader:
            if batch.num_columns != 1 or batch.schema.field(0).name != COLUMN_NAME:
                raise ValidationFailure("DuckDB returned an unexpected schema")
            values = batch.column(0)
            if values.null_count:
                raise ValidationFailure("DuckDB found null timestamp values")
            raw_values = pc.cast(values, pa.int64(), safe=True)
            _update_hash(hasher, raw_values)
            row_count += len(raw_values)
        return row_count, hasher.hexdigest()
    except ValidationFailure:
        raise
    except Exception as error:
        raise ValidationFailure(f"DuckDB could not completely read the candidate: {error}") from error
    finally:
        connection.close()


def validate(candidate: Path | str, reference_path: Path | str) -> dict[str, Any]:
    """Validate *candidate* and return a stable, JSON-serializable result."""

    candidate = Path(candidate).expanduser().resolve()
    reference_path = Path(reference_path).expanduser().resolve()
    result: dict[str, Any] = {
        "ok": False,
        "candidate_path": os.fspath(candidate),
        "size_bytes": None,
        "checks": [],
        "errors": [],
        "metrics": {},
    }

    def passed(name: str, details: dict[str, Any] | None = None) -> None:
        check: dict[str, Any] = {"name": name, "ok": True}
        if details:
            check["details"] = details
        result["checks"].append(check)

    try:
        if not candidate.is_file():
            raise ValidationFailure(f"candidate does not exist or is not a file: {candidate}")
        result["size_bytes"] = candidate.stat().st_size
        passed("candidate_file", {"size_bytes": result["size_bytes"]})

        reference = _load_reference(reference_path)
        passed(
            "reference",
            {"row_count": reference.row_count, "hash_algorithm": HASH_ALGORITHM},
        )

        try:
            import pyarrow as pa
            import pyarrow.compute as pc
            import pyarrow.parquet as pq
        except ImportError as error:
            raise ValidationFailure("PyArrow is required for validation") from error
        try:
            parquet_file = pq.ParquetFile(candidate)
        except Exception as error:
            raise ValidationFailure(f"PyArrow could not open the candidate: {error}") from error
        _validate_arrow_schema(parquet_file, pa)
        if parquet_file.metadata.num_rows != reference.row_count:
            raise ValidationFailure(
                f"row count is {parquet_file.metadata.num_rows}, expected {reference.row_count}"
            )
        passed("schema_and_count", {"row_count": parquet_file.metadata.num_rows})

        chunks = _inspect_structure(candidate, parquet_file)
        data_page_count = sum(len(chunk.pages) for chunk in chunks)
        passed(
            "parquet_structure",
            {"row_groups": len(chunks), "data_pages": data_page_count},
        )

        arrow_rows, arrow_hash = _scan_pyarrow(parquet_file, chunks, pa, pc)
        if arrow_rows != reference.row_count or arrow_hash != reference.digest:
            raise ValidationFailure(
                f"PyArrow decoded ({arrow_rows}, {arrow_hash}), expected "
                f"({reference.row_count}, {reference.digest})"
            )
        passed("pyarrow_complete_equality", {"hash": arrow_hash})

        duckdb_rows, duckdb_hash = _scan_duckdb(candidate, pa, pc)
        if duckdb_rows != reference.row_count or duckdb_hash != reference.digest:
            raise ValidationFailure(
                f"DuckDB decoded ({duckdb_rows}, {duckdb_hash}), expected "
                f"({reference.row_count}, {reference.digest})"
            )
        passed("duckdb_complete_equality", {"hash": duckdb_hash})

        result["metrics"] = {
            "row_count": reference.row_count,
            "pyarrow_hash": arrow_hash,
            "duckdb_hash": duckdb_hash,
            "row_groups": len(chunks),
            "data_pages": data_page_count,
        }
        result["ok"] = True
    except (ValidationFailure, OSError, OverflowError, struct.error) as error:
        result["errors"].append(str(error))
        result["checks"].append({"name": "validation", "ok": False, "details": {"error": str(error)}})
    except Exception as error:  # noqa: BLE001 - preserve the JSON/nonzero command contract.
        result["errors"].append(f"unexpected validator error: {type(error).__name__}: {error}")
        result["checks"].append(
            {
                "name": "validation",
                "ok": False,
                "details": {"error": result["errors"][-1]},
            }
        )
    return result


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("candidate", type=Path, help="candidate Parquet artifact")
    parser.add_argument(
        "--reference",
        type=Path,
        default=Path(__file__).resolve().parents[1] / "reference.json",
        help="truth record (default: pqmin/reference.json)",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    arguments = _parser().parse_args(argv)
    result = validate(arguments.candidate, arguments.reference)
    print(json.dumps(result, sort_keys=True, separators=(",", ":")))
    return 0 if result["ok"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
