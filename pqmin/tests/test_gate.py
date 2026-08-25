from __future__ import annotations

import json
from pathlib import Path

from pqmin.harness.gate import CandidateGate, GateConfig, Reproduction, validate_candidate


def setup_gate(tmp_path: Path, submitted: int, reproduced: int):
    pq = tmp_path / "pq"
    workspace = pq / "work" / "slot-1"
    repo = workspace / "repo"
    repo.mkdir(parents=True)
    artifact = repo / "submission" / "candidate.column"
    artifact.parent.mkdir()
    artifact.write_bytes(b"s" * submitted)
    manifest = repo / "submission.json"
    manifest.write_text(json.dumps({
        "kind": "candidate",
        "hypothesis": "compressed output can win despite a larger encoded stream",
        "tested_scope": "synthetic exact gate case",
        "artifact": "submission/candidate.column",
        "reproduce_argv": ["writer"],
        "output_path": "submission/candidate.column",
        "metrics": {"encoded_bytes": 120},
    }))
    current = pq / "current.json"
    current.write_text(json.dumps({"best": {"bytes": 100}, "baseline": {"cap_seconds": 4}}))
    best = pq / "best" / "best.parquet"
    best.parent.mkdir()
    best.write_bytes(b"b" * 100)
    reference = pq / "reference.json"
    reference.write_text("{}")
    validator = pq / "validate.py"
    validator.write_text("")
    trials = pq / "trials.jsonl"
    config = GateConfig(pq, tmp_path / "input.parquet", None, reference, validator, current,
                        trials, best, pq / "best" / "reproducer", 4.0)
    calls = []

    def runner(loaded, _config):
        calls.append(loaded.candidate_id)
        gate_workspace = pq / "gate-work"
        gate_repo = gate_workspace / "repo"
        gate_repo.mkdir(parents=True)
        output = gate_repo / "candidate.parquet"
        output.write_bytes(b"r" * reproduced)
        return Reproduction(output, gate_workspace, 1.0)

    gate = CandidateGate(config, runner=runner, validator=lambda _path, _reference: {"ok": True})
    return gate, manifest, calls, current, best, trials


def test_final_compressed_size_can_win_despite_encoded_regression(tmp_path: Path):
    gate, manifest, calls, current, best, trials = setup_gate(tmp_path, submitted=80, reproduced=80)
    result = gate.evaluate([manifest])
    assert result[0].accepted is True
    assert result[0].phase == "promotion"
    assert calls == ["slot-1"]
    assert best.stat().st_size == 80
    assert json.loads(current.read_text())["best"]["bytes"] == 80
    assert json.loads(trials.read_text())["metrics"]["encoded_bytes"] == 120


def test_carrier_size_does_not_prefilter_smaller_assembled_artifact(tmp_path: Path):
    gate, manifest, calls, _current, best, _trials = setup_gate(tmp_path, submitted=101, reproduced=70)
    result = gate.evaluate([manifest])
    assert result[0].phase == "promotion"
    assert calls == ["slot-1"]
    assert best.stat().st_size == 70


def test_dynamic_validator_can_import_sibling_module(tmp_path: Path):
    validator_dir = tmp_path / "harness"
    validator_dir.mkdir()
    (validator_dir / "validator_dependency.py").write_text("VALUE = 42\n")
    validator = validator_dir / "validate.py"
    validator.write_text(
        "from validator_dependency import VALUE\n\n"
        "def validate(candidate, reference):\n"
        "    return {'ok': True, 'value': VALUE}\n"
    )

    assert validate_candidate(tmp_path / "candidate", tmp_path / "reference", validator) == {
        "ok": True,
        "value": 42,
    }
