from __future__ import annotations

import hashlib
import json
import subprocess
import sys
from pathlib import Path

import pyarrow as pa
import pyarrow.compute as pc
import pyarrow.parquet as pq

from pqmin.harness.compact_thrift import CompactThriftError, read_struct
from pqmin.harness.validate import (
    Chunk,
    DataPage,
    EncodedStatistics,
    _column_index_statistics,
    _load_reference,
    _offset_index_locations,
    _scan_duckdb,
    _scan_pyarrow,
    validate,
)


def _uvarint(value: int) -> bytes:
    encoded = bytearray()
    while value >= 0x80:
        encoded.append((value & 0x7F) | 0x80)
        value >>= 7
    encoded.append(value)
    return bytes(encoded)


def _zigzag(value: int) -> bytes:
    return _uvarint((value << 1) ^ (value >> 63))


def _reference(path: Path, values: list[int]) -> Path:
    digest = hashlib.sha256(
        b"".join(value.to_bytes(8, "little", signed=True) for value in values)
    ).hexdigest()
    path.write_text(
        json.dumps(
            {
                "row_count": len(values),
                "timestamp_hash": {
                    "algorithm": "sha256-int64-le",
                    "value": digest,
                },
                "schema": {
                    "name": "TradeTimestamp",
                    "unit": "us",
                    "timezone": "UTC",
                    "nullable": False,
                },
            }
        ),
        encoding="utf-8",
    )
    return path


def _parquet(path: Path, values: list[int], *, indexes: bool, required: bool = True) -> Path:
    timestamp_type = pa.timestamp("us", tz="UTC")
    array = pa.array(values, type=timestamp_type)
    schema = pa.schema([pa.field("TradeTimestamp", timestamp_type, nullable=not required)])
    table = pa.Table.from_arrays([array], schema=schema)
    pq.write_table(
        table,
        path,
        compression="zstd",
        use_dictionary=False,
        write_statistics=True,
        write_page_index=indexes,
        data_page_size=256,
        data_page_version="2.0",
        row_group_size=max(1, len(values) // 2),
    )
    return path


def test_compact_thrift_reader_decodes_fields_and_rejects_trailing_bytes() -> None:
    # struct { 1: i32=-7, 2: binary="ok", 3: bool=true }
    encoded = b"\x15" + _zigzag(-7) + b"\x18\x02ok\x11\x00"
    value, length = read_struct(encoded)
    assert value == {1: -7, 2: b"ok", 3: True}
    assert length == len(encoded)
    try:
        read_struct(encoded + b"x")
    except CompactThriftError as error:
        assert "trailing" in str(error)
    else:
        raise AssertionError("trailing Compact Protocol bytes were accepted")


def test_reference_contract_accepts_only_exact_schema_and_hash(tmp_path: Path) -> None:
    reference_path = _reference(tmp_path / "reference.json", [1, 2, 3])
    reference = _load_reference(reference_path)
    assert reference.row_count == 3
    assert reference.digest == hashlib.sha256(
        (1).to_bytes(8, "little", signed=True)
        + (2).to_bytes(8, "little", signed=True)
        + (3).to_bytes(8, "little", signed=True)
    ).hexdigest()

    raw = json.loads(reference_path.read_text(encoding="utf-8"))
    raw["schema"]["nullable"] = True
    reference_path.write_text(json.dumps(raw), encoding="utf-8")
    try:
        _load_reference(reference_path)
    except ValueError as error:
        assert "schema must be exactly" in str(error)
    else:
        raise AssertionError("a nullable truth schema was accepted")


def test_index_decoders_require_complete_nonnull_page_entries() -> None:
    minimum = (10).to_bytes(8, "little", signed=True)
    maximum = (20).to_bytes(8, "little", signed=True)
    statistics = _column_index_statistics(
        {1: [False], 2: [minimum], 3: [maximum], 4: 0, 5: [0]}, "index"
    )
    assert statistics == (EncodedStatistics(10, 20, 0, True, True),)
    locations = _offset_index_locations(
        {1: [{1: 100, 2: 42, 3: 0}]}, "offset index"
    )
    assert locations == ((100, 42, 0),)

    try:
        _column_index_statistics(
            {1: [True], 2: [minimum], 3: [maximum], 4: 0, 5: [1]}, "index"
        )
    except ValueError as error:
        assert "must not be a null page" in str(error)
    else:
        raise AssertionError("a null page was accepted for a required column")


def test_independent_readers_hash_every_value_and_check_page_statistics(tmp_path: Path) -> None:
    values = [-50, -10, 7, 9, 100, 2, 4, 6]
    candidate = _parquet(tmp_path / "candidate.parquet", values, indexes=False)
    parquet_file = pq.ParquetFile(candidate)
    chunks = (
        Chunk(
            0,
            4,
            EncodedStatistics(-50, 9, 0, True, True),
            (
                DataPage(4, 1, 2, 0, EncodedStatistics(-50, -10, 0, True, True)),
                DataPage(5, 1, 2, 2, EncodedStatistics(7, 9, 0, True, True)),
            ),
        ),
        Chunk(
            1,
            4,
            EncodedStatistics(2, 100, 0, True, True),
            (
                DataPage(6, 1, 3, 0, EncodedStatistics(2, 100, 0, True, True)),
                DataPage(7, 1, 1, 3, EncodedStatistics(6, 6, 0, True, True)),
            ),
        ),
    )
    expected_hash = hashlib.sha256(
        b"".join(value.to_bytes(8, "little", signed=True) for value in values)
    ).hexdigest()
    assert _scan_pyarrow(parquet_file, chunks, pa, pc) == (len(values), expected_hash)
    assert _scan_duckdb(candidate, pa, pc) == (len(values), expected_hash)

    bad_chunks = list(chunks)
    bad_chunks[0] = Chunk(
        0,
        4,
        chunks[0].statistics,
        (
            DataPage(4, 1, 2, 0, EncodedStatistics(-49, -10, 0, True, True)),
            chunks[0].pages[1],
        ),
    )
    try:
        _scan_pyarrow(parquet_file, bad_chunks, pa, pc)
    except ValueError as error:
        assert "statistics do not match decoded values" in str(error)
    else:
        raise AssertionError("incorrect page statistics were accepted")


def test_validator_rejects_missing_indexes_and_missing_page_header_statistics(tmp_path: Path) -> None:
    values = list(range(2_000))
    reference = _reference(tmp_path / "reference.json", values)

    without_indexes = _parquet(tmp_path / "without-indexes.parquet", values, indexes=False)
    result = validate(without_indexes, reference)
    assert result["ok"] is False
    assert "both ColumnIndex and OffsetIndex" in result["errors"][0]

    # PyArrow follows the modern page-index recommendation and omits duplicate
    # page-header statistics.  pqmin requires both representations so that the
    # validator can check their correspondence independently.
    without_header_stats = _parquet(tmp_path / "without-header-stats.parquet", values, indexes=True)
    result = validate(without_header_stats, reference)
    assert result["ok"] is False
    assert "must carry statistics in its page header" in result["errors"][0]


def test_validator_rejects_nullable_schema_before_scanning_data(tmp_path: Path) -> None:
    values = [1, 2, 3, 4]
    reference = _reference(tmp_path / "reference.json", values)
    candidate = _parquet(
        tmp_path / "nullable.parquet", values, indexes=False, required=False
    )
    result = validate(candidate, reference)
    assert result["ok"] is False
    assert "must be required (non-nullable)" in result["errors"][0]


def test_cli_always_emits_json_and_returns_nonzero_on_failure(tmp_path: Path) -> None:
    script = Path(__file__).parents[1] / "harness" / "validate.py"
    completed = subprocess.run(
        [
            sys.executable,
            str(script),
            str(tmp_path / "missing.parquet"),
            "--reference",
            str(tmp_path / "missing-reference.json"),
        ],
        check=False,
        capture_output=True,
        text=True,
    )
    assert completed.returncode != 0
    assert completed.stderr == ""
    assert json.loads(completed.stdout)["ok"] is False
