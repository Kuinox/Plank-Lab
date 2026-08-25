from __future__ import annotations

import json
from pathlib import Path

from pqmin.orchestrator import _agent_command, _parse_cpu_list, _session_tokens


def test_session_tokens_sums_exact_recorded_usage(tmp_path: Path) -> None:
    session = tmp_path / "session"
    session.mkdir()
    records = [
        {"message": {"usage": {"totalTokens": 125}}},
        {"message": {"usage": {"totalTokens": 375}}},
        {"message": {"usage": {"totalTokens": -1}}},
        {"message": {"usage": {"totalTokens": "ignored"}}},
        {"message": {"content": []}},
    ]
    (session / "research.jsonl").write_text(
        "\n".join(json.dumps(record) for record in records) + "\n{incomplete",
        encoding="utf-8",
    )

    assert _session_tokens(tmp_path) == 500


def test_agent_command_pins_slot_and_uses_disk_backed_tmp(tmp_path: Path) -> None:
    slot = tmp_path / "slot"
    prompt = slot / "prompt.md"
    prompt.parent.mkdir()
    prompt.write_text("research")
    command = _agent_command(
        slot,
        prompt,
        {"input": "/input.parquet", "raw_values": "/values", "model": "model", "thinking": "high"},
        1,
        2,
        7,
    )

    assert command[:4] == ["taskset", "--cpu-list", "7", "bwrap"]
    tmp_index = command.index("--bind", command.index("bwrap"))
    assert command[tmp_index + 1:tmp_index + 3] == [str(slot / "tmp"), "/tmp"]
    assert "/coordination" in command
    assert "/opt/pqmin_claim.py" in command
    assert "/input/values.i64le" in command
    assert "/input/source.parquet" not in command
    assert "DOTNET_CLI_HOME" not in command
    assert "NUGET_PACKAGES" not in command


def test_parse_cpu_list_supports_smt_sibling_syntax() -> None:
    assert _parse_cpu_list("0,12\n") == {0, 12}
    assert _parse_cpu_list("0-3,8,10-11") == {0, 1, 2, 3, 8, 10, 11}
