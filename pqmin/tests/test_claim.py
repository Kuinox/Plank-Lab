from pathlib import Path

from pqmin.claim import (
    _same_subject_area,
    claim_for_run,
    claim_subject,
    finish_run,
    read_board,
    reset_active,
)


def test_claim_is_atomic_and_rejects_active_collision(tmp_path: Path) -> None:
    accepted, _ = claim_subject(
        tmp_path, slot=1, run_id=101, key="codec-grid", subject="Coarse codec parameter grid"
    )
    assert accepted
    accepted, message = claim_subject(
        tmp_path, slot=2, run_id=102, key="codec-grid", subject="A differently worded subject"
    )
    assert not accepted
    assert "collision" in message
    assert claim_for_run(tmp_path, 101)["subject"] == "Coarse codec parameter grid"


def test_finished_claim_leaves_active_board_and_is_archived(tmp_path: Path) -> None:
    assert claim_subject(
        tmp_path, slot=3, run_id=303, key="writer-audit", subject="Audit emitted writer bytes"
    )[0]
    finish_run(tmp_path, 303, "completed")
    board = read_board(tmp_path)
    assert board["active"] == []
    assert board["recent"][-1]["run_id"] == 303
    assert board["recent"][-1]["status"] == "completed"


def test_reset_archives_stale_active_claims(tmp_path: Path) -> None:
    assert claim_subject(
        tmp_path, slot=4, run_id=404, key="layout-test", subject="Distinct layout experiment"
    )[0]
    reset_active(tmp_path)
    board = read_board(tmp_path)
    assert board["active"] == []
    assert board["recent"][-1]["status"] == "interrupted"


def test_new_generation_clears_old_subject_context(tmp_path: Path) -> None:
    assert claim_subject(
        tmp_path, slot=4, run_id=405, key="old-layout", subject="Old envelope layout experiment"
    )[0]
    reset_active(tmp_path, generation=3)
    board = read_board(tmp_path)
    assert board["generation"] == 3
    assert board["active"] == []
    assert board["recent"] == []


def test_semantic_subject_collision_normalizes_common_aliases() -> None:
    assert _same_subject_area(
        "zstd-long-distance-matching",
        "Enable Zstandard long-distance matching for the current stream",
        "zstdlongdistance",
        "Zstandard long distance parameters for one page",
    )
    assert _same_subject_area(
        "plain_zstd",
        "Plain int64 encoding with Zstandard",
        "plain-zstd",
        "Plain encoding and high-window Zstandard",
    )
    assert _same_subject_area(
        "brotli11",
        "Brotli compression level 11",
        "brotli_codec",
        "Brotli compression for the timestamp stream",
    )
    assert _same_subject_area(
        "delta-block-4096",
        "DeltaBinaryPacked 4096-value blocks",
        "delta_block_4096",
        "Delta block size 4096 values",
    )
    assert _same_subject_area(
        "footer-sortingcolumns",
        "Declare the row group sorted and test sorting-column footer metadata",
        "sorting_column",
        "Declare the row-group sorting column while retaining the data layout",
    )
    assert _same_subject_area(
        "zstd-level-1",
        "Zstandard preset level 1 with advanced matcher parameters",
        "zstd-preset-level",
        "Zstandard preset level sweep with fixed advanced matcher parameters",
    )
    assert _same_subject_area(
        "plain-delta-compare",
        "PLAIN encoding for the required int64 stream",
        "plain_timestamp",
        "PLAIN encoding for the timestamp stream",
    )
    assert _same_subject_area(
        "delta_block_4096",
        "DeltaBinaryPacked 4096-value block geometry",
        "block_geometry_256",
        "Block geometry 256",
    )
    assert _same_subject_area(
        "zstd_strategy4",
        "Zstandard strategy 4",
        "zstd_s2",
        "Zstandard strategy 2",
    )
    assert _same_subject_area(
        "gzip0",
        "Gzip level 0",
        "gzip-level-9",
        "Gzip compression level 9",
    )
    assert _same_subject_area(
        "page-target-16m",
        "16 MiB target data page size",
        "p2m_boundary",
        "Two MiB page boundary experiment",
    )
    assert _same_subject_area(
        "adaptive-pages",
        "Data-dependent page boundaries aligned to disruptive negative deltas",
        "delta_transition_pages",
        "Page reset boundaries at large timestamp-series transitions",
    )
    assert _same_subject_area(
        "page-size-sweep",
        "Fixed page row count sweep",
        "fixed-page-segmentation",
        "Fixed multi-page segmentation at regular row intervals",
    )


def test_distinct_zstd_parameters_do_not_collide() -> None:
    assert not _same_subject_area(
        "zstd-windowlog-30",
        "Zstandard windowLog 30",
        "zstd-strategy-4",
        "Zstandard strategy 4",
    )
