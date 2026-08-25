from __future__ import annotations

import struct
from pathlib import Path

from pqmin.harness.column_artifact import (
    BUNDLE_HEADER,
    BUNDLE_MAGIC,
    BUNDLE_PAGE,
    assemble_column_carrier,
)
from pqmin.harness.compact_thrift import read_struct


# The current canonical 160-byte footer. Tests use only its structural bytes,
# not the 508 MB data payload that normally precedes it.
FOOTER = bytes.fromhex(
    "1502192c4806736368656d6115020015042500180e547261646554696d657374616d70"
    "25144c8c111c2c00000000001680e9c9d601191c191c26001c150419150a19180e5472"
    "61646554696d657374616d70150c1680e9c9d60116fab1e7e90416ca90b5e40326083c"
    "18080322e626ba580600180880cfeefad157060016000000169091b5e403151c16d290"
    "b5e403153e0016fab1e7e9041680e9c9d6010000"
)


def _carrier(path: Path, root_name: bytes) -> None:
    footer = FOOTER.replace(b"\x48\x06schema", b"\x48" + bytes([len(root_name)]) + root_name, 1)
    path.write_bytes(b"PAR1" + footer + struct.pack("<I", len(footer)) + b"PAR1")


def _root_name(path: Path) -> bytes:
    data = path.read_bytes()
    footer_length = struct.unpack("<I", data[-8:-4])[0]
    footer, _ = read_struct(data[-8-footer_length:-8])
    return footer[2][0][4]


def test_gate_replaces_researcher_root_name_with_canonical_envelope(tmp_path: Path) -> None:
    carrier = tmp_path / "candidate.column"
    final = tmp_path / "candidate.parquet"
    _carrier(carrier, b"xy")

    assemble_column_carrier(carrier, final)

    assert _root_name(carrier) == b"xy"
    assert _root_name(final) == b"schema"
    assert final.stat().st_size == carrier.stat().st_size + 4


def test_canonical_carrier_is_byte_stable(tmp_path: Path) -> None:
    carrier = tmp_path / "candidate.column"
    final = tmp_path / "candidate.parquet"
    _carrier(carrier, b"schema")

    assemble_column_carrier(carrier, final)

    assert final.read_bytes() == carrier.read_bytes()


def test_gate_discards_optional_file_level_metadata(tmp_path: Path) -> None:
    carrier = tmp_path / "candidate.column"
    final = tmp_path / "candidate.parquet"
    # created_by is top-level field 6, following core field 4.
    footer = FOOTER[:-1] + b"\x28\x03abc\x00"
    carrier.write_bytes(b"PAR1" + footer + struct.pack("<I", len(footer)) + b"PAR1")

    assemble_column_carrier(carrier, final)

    assert final.stat().st_size == carrier.stat().st_size - 5
    assert _root_name(final) == b"schema"


def test_gate_wraps_plain_pqcol_bundle_with_page_indexes(tmp_path: Path) -> None:
    bundle = tmp_path / "candidate.column"
    final = tmp_path / "candidate.parquet"
    values = (3, -2, 9)
    payload = struct.pack("<3q", *values)
    bundle.write_bytes(
        BUNDLE_HEADER.pack(BUNDLE_MAGIC, 1, 0, 0, 1, 1, len(values))
        + BUNDLE_PAGE.pack(len(values), min(values), max(values), len(payload), len(payload))
        + payload
    )

    assemble_column_carrier(bundle, final)

    encoded = final.read_bytes()
    footer_length = struct.unpack("<I", encoded[-8:-4])[0]
    footer, _ = read_struct(encoded[-8-footer_length:-8])
    column = footer[4][0][1][0]
    metadata = column[3]
    assert footer[3] == len(values)
    assert metadata[2] == [0]  # PLAIN
    assert metadata[4] == 0  # UNCOMPRESSED
    assert column[4] > column[6]  # OffsetIndex follows ColumnIndex.
    assert encoded.startswith(b"PAR1") and encoded.endswith(b"PAR1")
