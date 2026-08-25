#!/usr/bin/env python3
from __future__ import annotations

import json
import shutil
import subprocess
import sys
import time
from pathlib import Path

from harness.common import (
    CURRENT,
    NOTEBOOK,
    PQ,
    ROOT,
    atomic_json,
    now_iso,
    sha256_file,
)
from harness.truth import build_reference

CONFIG = json.loads((PQ / "config.json").read_text())
INPUT = Path(CONFIG["input"])
RAW = Path(CONFIG["raw_values"])
BASELINE = PQ / "best" / "best.parquet"
BASELINE_PROJECT = PQ / "kit" / "BaselineWriter" / "BaselineWriter.csproj"


def run(argv: list[str], *, timeout: int = 600, capture: bool = False) -> subprocess.CompletedProcess[str]:
    print("+", " ".join(argv), flush=True)
    return subprocess.run(argv, cwd=ROOT, check=True, text=True,
                          capture_output=capture, timeout=timeout)


def verify_pin() -> None:
    result = run(["taskset", "-c", "0", "python3", "-c",
                  "import os; print(len(os.sched_getaffinity(0)))"], capture=True)
    if result.stdout.strip() != "1":
        raise RuntimeError(f"single-core pin failed: {result.stdout!r}")


def build_seed() -> None:
    seed = PQ / "seed"
    if seed.exists():
        shutil.rmtree(seed)
    seed.mkdir(parents=True)

    library = ROOT / "library" / "Plank"
    if not (library / "Plank" / "Plank.csproj").is_file():
        raise RuntimeError("initialize the library/Plank submodule before bootstrapping pqmin")
    shutil.copytree(
        library,
        seed / "library" / "Plank",
        dirs_exist_ok=True,
        ignore=shutil.ignore_patterns(".git", "bin", "obj", "__pycache__"),
    )

    research = seed / "research"
    shutil.copytree(
        PQ / "kit",
        research,
        dirs_exist_ok=True,
        ignore=shutil.ignore_patterns("bin", "obj", "__pycache__"),
    )
    workspace_project = research / "BaselineWriter" / "BaselineWriter.csproj"
    workspace_project.write_text(
        workspace_project.read_text().replace(
            "../../../library/Plank/Plank/Plank.csproj",
            "../../library/Plank/Plank/Plank.csproj",
        )
    )
    for name in ("MISSION.md", "submission.schema.json", "reference.json", "current.json", "NOTEBOOK.md"):
        source = PQ / name
        if source.exists():
            shutil.copy2(source, research / name)


def timed_baseline() -> float:
    verify_pin()
    run(["dotnet", "build", str(BASELINE_PROJECT), "-c", "Release"], timeout=600)
    command = ["dotnet", "run", "--project", str(BASELINE_PROJECT), "-c", "Release",
               "--no-build", "--", str(RAW), str(BASELINE)]
    started = time.monotonic()
    run(["taskset", "-c", "0", *command], timeout=600)
    return time.monotonic() - started


def main() -> int:
    if not INPUT.is_file():
        raise FileNotFoundError(INPUT)
    for directory in (PQ / "best", PQ / "work", PQ / "logs", PQ / "web"):
        directory.mkdir(parents=True, exist_ok=True)

    print("Building exact truth and derived raw cache", flush=True)
    reference = build_reference(INPUT, RAW, CONFIG["column"])
    if reference["rows"] != CONFIG["rows"] or reference["nulls"] != 0:
        raise RuntimeError(f"unexpected source truth: {reference}")
    atomic_json(PQ / "reference.json", reference)

    print("Writing fresh ordinary-Plank baseline", flush=True)
    elapsed = timed_baseline()
    cap = elapsed * 4.0
    current = {
        "generation": 1,
        "cohort": 0,
        "updated_at": now_iso(),
        "baseline": {
            "artifact": str(BASELINE),
            "bytes": BASELINE.stat().st_size,
            "elapsed_seconds": round(elapsed, 3),
            "cap_seconds": round(cap, 3),
            "command": ["dotnet", "run", "--project", "research/BaselineWriter/BaselineWriter.csproj",
                        "-c", "Release", "--no-build", "--", "/input/values.i64le",
                        "submission/candidate.parquet"]
        },
        "best": {
            "artifact": str(BASELINE),
            "bytes": BASELINE.stat().st_size,
            "sha256": sha256_file(BASELINE),
            "reproducer": str(PQ / "seed")
        }
    }
    atomic_json(CURRENT, current)
    NOTEBOOK.write_text(
        "# Neutral notebook\n\n"
        f"Current validated best: {BASELINE.stat().st_size:,} bytes.\n\n"
        "No trials have been recorded in this new run. Observations below are exact scopes, not prohibitions.\n"
    )
    build_seed()

    validator = PQ / "harness" / "validate.py"
    if validator.exists():
        run([sys.executable, str(validator), str(BASELINE)], timeout=1200)
    print(json.dumps(current, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
