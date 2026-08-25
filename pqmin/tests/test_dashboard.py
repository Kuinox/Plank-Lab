from __future__ import annotations

import json
from pathlib import Path

import pqmin.dashboard as dashboard


def test_progress_includes_live_tokens_and_reports_historical_gap(
    tmp_path: Path, monkeypatch,
) -> None:
    monkeypatch.setattr(dashboard, "ROOT", tmp_path)
    (tmp_path / "status.json").write_text(json.dumps({
        "status": "researching",
        "cohort": 3,
        "slots": [
            {"slot": 1, "state": "running", "tokens_used": 100},
            {"slot": 2, "state": "running", "tokens_used": 200},
        ],
        "gate": {"status": "idle", "queue": []},
    }))
    (tmp_path / "current.json").write_text(json.dumps({
        "baseline": {"bytes": 1_000},
        "best": {"bytes": 900, "candidate_id": "slot-2"},
    }))
    (tmp_path / "progress.jsonl").write_text(
        json.dumps({"cohort": 0, "cumulative_tokens": 0, "best_bytes": 1_000}) + "\n"
        + json.dumps({"cohort": 1, "cumulative_tokens": 500, "best_bytes": 900}) + "\n"
    )

    progress = dashboard.DashboardState().snapshot()["progress"]

    assert progress["tracked_tokens"] == 800
    assert progress["complete"] is False
    assert progress["missing_cohorts"] == [2]
    assert progress["checkpoint_count"] == 3
    assert progress["points"][-1] == {
        "tokens": 800,
        "size_bytes": 900,
        "cohort": 3,
        "candidate_id": "slot-2",
        "kind": "live",
        "timestamp": progress["points"][-1]["timestamp"],
        "live": True,
            "token_gap": False,
            "run_id": None,
            "experiment": None,
            "drop_bytes": 0,
        }


def test_progress_chart_collapses_flat_worker_checkpoints(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setattr(dashboard, "ROOT", tmp_path)
    (tmp_path / "status.json").write_text(json.dumps({
        "status": "researching", "cohort": 4, "slots": [], "gate": {"status": "idle"},
    }))
    (tmp_path / "current.json").write_text(json.dumps({
        "baseline": {"bytes": 1_000}, "best": {"bytes": 900},
    }))
    records = [
        {"cohort": 0, "cumulative_tokens": 0, "best_bytes": 1_000},
        {"cohort": 1, "cumulative_tokens": 100, "best_bytes": 900, "kind": "promotion"},
        {"cohort": 2, "cumulative_tokens": 200, "best_bytes": 900, "kind": "worker"},
        {"cohort": 3, "cumulative_tokens": 300, "best_bytes": 900, "kind": "worker"},
        {"cohort": 4, "cumulative_tokens": 400, "best_bytes": 900, "kind": "worker"},
    ]
    (tmp_path / "progress.jsonl").write_text(
        "\n".join(json.dumps(record) for record in records) + "\n"
    )

    progress = dashboard.DashboardState().snapshot()["progress"]

    assert progress["checkpoint_count"] == 5
    assert [point["tokens"] for point in progress["points"]] == [0, 100, 400]


def test_progress_exposes_every_sized_attempt_not_only_frontier(
    tmp_path: Path, monkeypatch,
) -> None:
    monkeypatch.setattr(dashboard, "ROOT", tmp_path)
    (tmp_path / "status.json").write_text(json.dumps({
        "status": "researching", "cohort": 2, "slots": [], "gate": {"status": "idle"},
    }))
    (tmp_path / "current.json").write_text(json.dumps({
        "baseline": {"bytes": 1_000}, "best": {"bytes": 800},
    }))
    (tmp_path / "progress.jsonl").write_text(
        json.dumps({"run_id": 101, "cumulative_tokens": 100, "best_bytes": 900}) + "\n"
        + json.dumps({"run_id": 102, "cumulative_tokens": 200, "best_bytes": 800}) + "\n"
    )
    attempts = [
        {
            "candidate_id": "run-00000101", "submitted_bytes": 950,
            "phase": "reproduction_size", "hypothesis": "Tune delta reset",
            "tested_scope": "One reset at the largest negative delta",
            "observation": "Smaller but not promoted", "elapsed_seconds": 3.5,
        },
        {"candidate_id": "run-00000102", "submitted_bytes": 1_200, "phase": "reproduction"},
    ]
    (tmp_path / "trials.jsonl").write_text(
        "\n".join(json.dumps(record) for record in attempts) + "\n"
    )

    progress = dashboard.DashboardState().snapshot()["progress"]

    assert progress["attempt_count"] == 2
    assert [(point["tokens"], point["size_bytes"]) for point in progress["attempts"]] == [
        (100, 950),
        (200, 1_200),
    ]
    assert progress["attempts"][0]["experiment"] == {
        "candidate_id": "run-00000101",
        "run_id": None,
        "slot": "—",
        "hypothesis": "Tune delta reset",
        "tested_scope": "One reset at the largest negative delta",
        "observation": "Smaller but not promoted",
        "phase": "reproduction_size",
        "accepted": False,
        "elapsed_seconds": 3.5,
        "timestamp": None,
    }


def test_frontier_point_exposes_the_promotion_experiment(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setattr(dashboard, "ROOT", tmp_path)
    (tmp_path / "status.json").write_text(json.dumps({
        "status": "stopped", "cohort": 1, "slots": [], "gate": {"status": "idle"},
    }))
    (tmp_path / "current.json").write_text(json.dumps({
        "baseline": {"bytes": 1_000}, "best": {"bytes": 850},
    }))
    (tmp_path / "progress.jsonl").write_text(
        json.dumps({"cumulative_tokens": 0, "best_bytes": 1_000}) + "\n"
        + json.dumps({
            "run_id": 77, "cumulative_tokens": 400, "best_bytes": 850,
            "candidate_id": "run-00000077", "kind": "promotion",
        }) + "\n"
    )
    (tmp_path / "trials.jsonl").write_text(json.dumps({
        "run_id": 77,
        "candidate_id": "run-00000077",
        "hypothesis": "Split at the largest negative delta",
        "tested_scope": "Two independently compressed pages around row 500",
        "observation": "Promoted reproduced artifact at 850 bytes",
        "reproduced_bytes": 850,
        "elapsed_seconds": 2.25,
        "phase": "promotion",
        "accepted": True,
    }) + "\n")

    points = dashboard.DashboardState().snapshot()["progress"]["points"]

    assert points[-1]["drop_bytes"] == 150
    assert points[-1]["experiment"]["hypothesis"] == "Split at the largest negative delta"
    assert points[-1]["experiment"]["tested_scope"] == (
        "Two independently compressed pages around row 500"
    )
