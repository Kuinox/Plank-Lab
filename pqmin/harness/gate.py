#!/usr/bin/env python3
"""Deterministic, artifact-first candidate gate for the pqmin research loop."""

from __future__ import annotations

import argparse
import fcntl
import hashlib
import importlib.util
import json
import os
import shutil
import signal
import subprocess
import sys
import tempfile
import time
import uuid
from collections.abc import Callable, Iterable, Mapping, Sequence
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

try:
    from .column_artifact import ColumnArtifactError, assemble_column_carrier
except ImportError:  # Direct execution from pqmin/run.sh.
    from column_artifact import ColumnArtifactError, assemble_column_carrier


class ManifestError(ValueError):
    """A candidate manifest is incomplete or unsafe to execute."""


@dataclass(frozen=True)
class CandidateManifest:
    path: Path
    workspace: Path
    candidate_id: str
    kind: str
    hypothesis: str
    tested_scope: str
    artifact: Path | None
    prepare_argv: tuple[str, ...]
    reproduce_argv: tuple[str, ...]
    expected_output: Path | None
    cwd: Path
    metrics: Mapping[str, Any]
    notes: str


@dataclass(frozen=True)
class Reproduction:
    output: Path
    workspace: Path
    elapsed_seconds: float


@dataclass
class GateObservation:
    candidate_id: str
    hypothesis: str
    tested_scope: str
    submitted_bytes: int | None
    reproduced_bytes: int | None
    elapsed_seconds: float | None
    accepted: bool
    phase: str
    observation: str
    metrics: Mapping[str, Any]
    timestamp: str


@dataclass(frozen=True)
class GateConfig:
    pqmin: Path
    source_input: Path
    raw_values: Path | None
    reference: Path
    validator: Path
    current: Path
    trials: Path
    best_artifact: Path
    best_reproducer: Path
    runtime_cap_seconds: float
    cpu: int = 0
    prepare_timeout_seconds: float = 600.0


Runner = Callable[[CandidateManifest, GateConfig], Reproduction]
Validator = Callable[[Path, Path], Mapping[str, Any]]


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _inside(base: Path, relative: str, field: str) -> Path:
    if not isinstance(relative, str) or not relative.strip():
        raise ManifestError(f"{field} must be a non-empty relative path")
    candidate = Path(relative)
    if candidate.is_absolute():
        raise ManifestError(f"{field} must be relative to the researcher workspace")
    resolved = (base / candidate).resolve()
    try:
        resolved.relative_to(base.resolve())
    except ValueError as exc:
        raise ManifestError(f"{field} escapes the researcher workspace") from exc
    return resolved


def _argv(value: Any, field: str, *, required: bool) -> tuple[str, ...]:
    if value is None and not required:
        return ()
    if not isinstance(value, list) or (required and not value):
        raise ManifestError(f"{field} must be a non-empty JSON string array")
    if any(not isinstance(part, str) or not part for part in value):
        raise ManifestError(f"{field} must contain only non-empty strings")
    return tuple(value)


def load_manifest(path: Path) -> CandidateManifest:
    path = path.resolve()
    try:
        raw = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ManifestError(f"cannot read manifest: {exc}") from exc
    if not isinstance(raw, dict):
        raise ManifestError("manifest root must be a JSON object")
    repo = path.parent.resolve()
    workspace = repo.parent.resolve()
    if repo.name != "repo":
        raise ManifestError("manifest must be written at the repository root as submission.json")
    allowed = {
        "kind", "hypothesis", "tested_scope", "artifact", "prepare_argv",
        "reproduce_argv", "output_path", "metrics", "notes",
    }
    unexpected = sorted(set(raw) - allowed)
    if unexpected:
        raise ManifestError("unexpected manifest fields: " + ", ".join(unexpected))
    kind = raw.get("kind")
    if kind not in {"candidate", "observation"}:
        raise ManifestError("kind must be candidate or observation")
    for field in ("hypothesis", "tested_scope"):
        if not isinstance(raw.get(field), str) or not raw[field].strip():
            raise ManifestError(f"{field} must be a non-empty string")
    metrics = raw.get("metrics", {})
    if not isinstance(metrics, dict):
        raise ManifestError("metrics must be a JSON object")

    notes = raw.get("notes", "")
    if not isinstance(notes, str):
        raise ManifestError("notes must be a string")
    if kind == "candidate":
        artifact = _inside(repo, raw.get("artifact", ""), "artifact")
        expected_output = _inside(repo, raw.get("output_path", ""), "output_path")
        if artifact.relative_to(repo) != Path("submission/candidate.column"):
            raise ManifestError("artifact must be submission/candidate.column")
        if expected_output.relative_to(repo) != Path("submission/candidate.column"):
            raise ManifestError("output_path must be submission/candidate.column")
        prepare_argv = _argv(raw.get("prepare_argv"), "prepare_argv", required=False)
        reproduce_argv = _argv(raw.get("reproduce_argv"), "reproduce_argv", required=True)
        if (repo / ".pqmin-c-only").is_file():
            if not prepare_argv or Path(prepare_argv[0]).name not in {"make", "cc", "gcc", "clang"}:
                raise ManifestError(
                    "C-only candidates must compile with make, cc, gcc, or clang in prepare_argv"
                )
            if not reproduce_argv[0].startswith("./"):
                raise ManifestError("C-only reproduce_argv must directly run a workspace executable")
            if not any(repo.glob("**/*.c")):
                raise ManifestError("C-only candidate workspace contains no C source")
    else:
        if any(field in raw for field in ("artifact", "prepare_argv", "reproduce_argv", "output_path")):
            raise ManifestError("observation manifests cannot contain candidate execution fields")
        artifact = None
        expected_output = None
        prepare_argv = ()
        reproduce_argv = ()

    return CandidateManifest(
        path=path,
        workspace=workspace,
        candidate_id=workspace.name,
        kind=kind,
        hypothesis=raw["hypothesis"].strip(),
        tested_scope=raw["tested_scope"].strip(),
        artifact=artifact,
        prepare_argv=prepare_argv,
        reproduce_argv=reproduce_argv,
        expected_output=expected_output,
        cwd=repo,
        metrics=metrics,
        notes=notes,
    )


def _system_mounts() -> list[str]:
    args: list[str] = []
    for directory in ("/usr", "/bin", "/sbin", "/lib", "/lib64", "/etc"):
        if Path(directory).exists():
            args.extend(("--ro-bind", directory, directory))
    return args


def sandbox_command(
    *,
    workspace: Path,
    source_input: Path,
    raw_values: Path | None,
    argv: Sequence[str],
    cwd: str = "/workspace/repo",
) -> list[str]:
    """Build a bwrap command that cannot see the host project or discarded history."""
    (workspace / "home").mkdir(parents=True, exist_ok=True)
    args = [
        "bwrap",
        "--unshare-all",
        "--share-net",
        "--die-with-parent",
        "--new-session",
        *_system_mounts(),
        "--dev",
        "/dev",
        "--proc",
        "/proc",
        "--tmpfs",
        "/tmp",
        "--dir",
        "/workspace",
        "--bind",
        str(workspace),
        "/workspace",
        "--dir",
        "/input",
    ]
    if raw_values is not None and raw_values.exists():
        args.extend(("--ro-bind", str(raw_values), "/input/values.i64le"))
    args.extend(
        (
            "--setenv",
            "HOME",
            "/workspace/home",
            "--setenv",
            "PATH",
            "/usr/local/bin:/usr/bin:/bin",
            "--setenv",
            "CC",
            "cc",
            "--setenv",
            "OMP_NUM_THREADS",
            "1",
            "--setenv",
            "OPENBLAS_NUM_THREADS",
            "1",
            "--setenv",
            "MKL_NUM_THREADS",
            "1",
            "--setenv",
            "RAYON_NUM_THREADS",
            "1",
            "--chdir",
            cwd,
            "--",
            *argv,
        )
    )
    return args


def _run_process(argv: Sequence[str], timeout: float) -> tuple[float, subprocess.CompletedProcess[str]]:
    started = time.monotonic()
    process = subprocess.Popen(
        list(argv),
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        start_new_session=True,
    )
    try:
        stdout, stderr = process.communicate(timeout=timeout)
    except subprocess.TimeoutExpired:
        os.killpg(process.pid, signal.SIGKILL)
        process.communicate()
        raise
    elapsed = time.monotonic() - started
    return elapsed, subprocess.CompletedProcess(argv, process.returncode, stdout, stderr)


def reproduce_candidate(manifest: CandidateManifest, config: GateConfig) -> Reproduction:
    if manifest.expected_output is None:
        raise RuntimeError("observation manifests cannot be reproduced")
    gate_work = config.pqmin / "work" / "gate"
    gate_work.mkdir(parents=True, exist_ok=True)
    temporary = Path(tempfile.mkdtemp(prefix=f"{manifest.candidate_id}-", dir=gate_work))
    reproduced_repo = temporary / "repo"
    shutil.copytree(manifest.workspace / "repo", reproduced_repo, symlinks=True)
    relative_cwd = manifest.cwd.relative_to(manifest.workspace / "repo")
    sandbox_cwd = str(Path("/workspace/repo") / relative_cwd)

    if manifest.prepare_argv:
        prepare = sandbox_command(
            workspace=temporary,
            source_input=config.source_input,
            raw_values=config.raw_values,
            argv=manifest.prepare_argv,
            cwd=sandbox_cwd,
        )
        _, completed = _run_process(prepare, config.prepare_timeout_seconds)
        if completed.returncode:
            shutil.rmtree(temporary, ignore_errors=True)
            detail = (completed.stderr or completed.stdout)[-1000:]
            raise RuntimeError(f"prepare command exited {completed.returncode}: {detail}")

    output_relative = manifest.expected_output.relative_to(manifest.workspace / "repo")
    reproduced_output = reproduced_repo / output_relative
    if reproduced_output.exists():
        reproduced_output.unlink()
    timed = sandbox_command(
        workspace=temporary,
        source_input=config.source_input,
        raw_values=config.raw_values,
        argv=manifest.reproduce_argv,
        cwd=sandbox_cwd,
    )
    pinned = ["taskset", "--cpu-list", str(config.cpu), *timed]
    try:
        elapsed, completed = _run_process(pinned, config.runtime_cap_seconds)
    except subprocess.TimeoutExpired as exc:
        shutil.rmtree(temporary, ignore_errors=True)
        raise TimeoutError(f"writer exceeded {config.runtime_cap_seconds:.6f}s") from exc
    if completed.returncode:
        shutil.rmtree(temporary, ignore_errors=True)
        detail = (completed.stderr or completed.stdout)[-1000:]
        raise RuntimeError(f"writer exited {completed.returncode}: {detail}")
    if elapsed > config.runtime_cap_seconds:
        shutil.rmtree(temporary, ignore_errors=True)
        raise TimeoutError(
            f"writer took {elapsed:.6f}s; cap is {config.runtime_cap_seconds:.6f}s"
        )
    if not reproduced_output.is_file():
        shutil.rmtree(temporary, ignore_errors=True)
        raise RuntimeError("writer did not create expected_output")
    assembled = temporary / "assembled" / "candidate.parquet"
    try:
        assemble_column_carrier(reproduced_output, assembled)
    except ColumnArtifactError:
        shutil.rmtree(temporary, ignore_errors=True)
        raise
    return Reproduction(assembled, temporary, elapsed)


def validate_candidate(candidate: Path, reference: Path, validator_path: Path) -> Mapping[str, Any]:
    validator_directory = str(validator_path.resolve().parent)
    spec = importlib.util.spec_from_file_location("pqmin_validate", validator_path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"cannot import validator {validator_path}")
    module = importlib.util.module_from_spec(spec)
    # Loading a module by file path does not make sibling modules importable.
    # The validator intentionally supports direct execution and therefore uses
    # ``from compact_thrift import ...`` as its final fallback.
    sys.path.insert(0, validator_directory)
    try:
        spec.loader.exec_module(module)
    finally:
        try:
            sys.path.remove(validator_directory)
        except ValueError:
            pass
    result = module.validate(candidate, reference)
    if not isinstance(result, dict):
        raise TypeError("validator returned a non-object result")
    return result


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _write_json_atomic(path: Path, value: Mapping[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(f".{path.name}.{uuid.uuid4().hex}.tmp")
    with temporary.open("w", encoding="utf-8") as stream:
        json.dump(value, stream, indent=2, sort_keys=True)
        stream.write("\n")
        stream.flush()
        os.fsync(stream.fileno())
    os.replace(temporary, path)


def _clean_copy(source: Path, destination: Path, excluded_artifact: Path) -> None:
    excluded = excluded_artifact.resolve()

    def ignore(directory: str, names: list[str]) -> set[str]:
        ignored = {
            name
            for name in names
            if name in {"bin", "obj", ".git", ".cache", "__pycache__", "submission"}
        }
        base = Path(directory)
        for name in names:
            try:
                if (base / name).resolve() == excluded:
                    ignored.add(name)
            except OSError:
                pass
        return ignored

    shutil.copytree(source, destination, symlinks=True, ignore=ignore)


def _replace_directory(staging: Path, destination: Path) -> None:
    backup = destination.with_name(f".{destination.name}.{uuid.uuid4().hex}.old")
    if destination.exists() or destination.is_symlink():
        os.replace(destination, backup)
    try:
        os.replace(staging, destination)
    except BaseException:
        if backup.exists() or backup.is_symlink():
            os.replace(backup, destination)
        raise
    if backup.is_dir() and not backup.is_symlink():
        shutil.rmtree(backup)
    elif backup.exists() or backup.is_symlink():
        backup.unlink()


def _strip_compiled_outputs(root: Path) -> None:
    """Keep promoted C reproducers source-only so prepare_argv really compiles."""
    for path in root.rglob("*"):
        if not path.is_file() or path.is_symlink():
            continue
        try:
            with path.open("rb") as stream:
                is_elf = stream.read(4) == b"\x7fELF"
        except OSError:
            continue
        if is_elf:
            path.unlink()


def promote(
    reproduction: Reproduction,
    manifest: CandidateManifest,
    config: GateConfig,
    current: Mapping[str, Any],
) -> dict[str, Any]:
    lock_path = config.pqmin / "promotion.lock"
    lock_path.touch(exist_ok=True)
    with lock_path.open("r") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX)
        try:
            config.best_artifact.parent.mkdir(parents=True, exist_ok=True)
            artifact_staging = config.best_artifact.with_name(
                f".{config.best_artifact.name}.{uuid.uuid4().hex}.tmp"
            )
            shutil.copyfile(reproduction.output, artifact_staging)
            with artifact_staging.open("rb") as stream:
                os.fsync(stream.fileno())

            source_staging = config.best_reproducer.with_name(
                f".{config.best_reproducer.name}.{uuid.uuid4().hex}.tmp"
            )
            _clean_copy(reproduction.workspace / "repo", source_staging, reproduction.output)
            if (source_staging / ".pqmin-c-only").is_file():
                _strip_compiled_outputs(source_staging)
            # Preserve a ready output location without retaining multi-gigabyte
            # experimental artifacts from the winning workspace.
            (source_staging / "submission").mkdir(exist_ok=True)

            os.replace(artifact_staging, config.best_artifact)
            _replace_directory(source_staging, config.best_reproducer)
            size = config.best_artifact.stat().st_size
            updated = dict(current)
            updated["best"] = {
                "artifact": str(config.best_artifact),
                "bytes": size,
                "sha256": _sha256(config.best_artifact),
                "reproducer": str(config.best_reproducer),
                "candidate_id": manifest.candidate_id,
            }
            updated["updated_at"] = utc_now()
            _write_json_atomic(config.current, updated)
            return updated
        finally:
            fcntl.flock(lock, fcntl.LOCK_UN)


def append_trial(path: Path, observation: GateObservation) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a", encoding="utf-8") as stream:
        fcntl.flock(stream, fcntl.LOCK_EX)
        stream.write(json.dumps(asdict(observation), sort_keys=True) + "\n")
        stream.flush()
        os.fsync(stream.fileno())
        fcntl.flock(stream, fcntl.LOCK_UN)


class CandidateGate:
    def __init__(
        self,
        config: GateConfig,
        *,
        runner: Runner | None = None,
        validator: Validator | None = None,
    ) -> None:
        self.config = config
        self.runner = runner or reproduce_candidate
        self.validator = validator or (
            lambda artifact, reference: validate_candidate(artifact, reference, config.validator)
        )

    def _record(
        self,
        manifest: CandidateManifest,
        *,
        submitted_bytes: int | None,
        reproduced_bytes: int | None = None,
        elapsed_seconds: float | None = None,
        accepted: bool,
        phase: str,
        observation: str,
    ) -> GateObservation:
        result = GateObservation(
            candidate_id=manifest.candidate_id,
            hypothesis=manifest.hypothesis,
            tested_scope=manifest.tested_scope,
            submitted_bytes=submitted_bytes,
            reproduced_bytes=reproduced_bytes,
            elapsed_seconds=elapsed_seconds,
            accepted=accepted,
            phase=phase,
            observation=observation,
            metrics=manifest.metrics,
            timestamp=utc_now(),
        )
        append_trial(self.config.trials, result)
        return result

    def evaluate(self, manifest_paths: Iterable[Path]) -> list[GateObservation]:
        current = json.loads(self.config.current.read_text(encoding="utf-8"))
        incumbent_bytes = int(current["best"]["bytes"])
        loaded: list[tuple[int, CandidateManifest]] = []
        observations: list[GateObservation] = []
        for path in manifest_paths:
            try:
                manifest = load_manifest(path)
                if manifest.kind == "observation":
                    observations.append(
                        self._record(
                            manifest,
                            submitted_bytes=None,
                            accepted=False,
                            phase="research_observation",
                            observation=manifest.notes or "scoped observation submitted without an artifact",
                        )
                    )
                    continue
                assert manifest.artifact is not None
                submitted_bytes = manifest.artifact.stat().st_size
                loaded.append((submitted_bytes, manifest))
            except (ManifestError, OSError) as exc:
                # Invalid manifests cannot safely supply free-form fields to the trial log.
                synthetic = CandidateManifest(
                    path=Path(path),
                    workspace=Path(path).parent,
                    candidate_id=Path(path).parent.name,
                    kind="observation",
                    hypothesis="manifest could not be loaded",
                    tested_scope=str(Path(path)),
                    artifact=Path(path),
                    prepare_argv=(),
                    reproduce_argv=("invalid",),
                    expected_output=Path(path),
                    cwd=Path(path).parent,
                    metrics={},
                    notes="",
                )
                observations.append(
                    self._record(
                        synthetic,
                        submitted_bytes=None,
                        accepted=False,
                        phase="manifest",
                        observation=str(exc),
                    )
                )

        for submitted_bytes, manifest in sorted(loaded, key=lambda item: (item[0], item[1].candidate_id)):
            reproduction: Reproduction | None = None
            try:
                reproduction = self.runner(manifest, self.config)
                reproduced_bytes = reproduction.output.stat().st_size
                if reproduced_bytes >= incumbent_bytes:
                    observations.append(
                        self._record(
                            manifest,
                            submitted_bytes=submitted_bytes,
                            reproduced_bytes=reproduced_bytes,
                            elapsed_seconds=reproduction.elapsed_seconds,
                            accepted=False,
                            phase="reproduction_size",
                            observation=f"reproduced artifact is {reproduced_bytes} bytes; current best is {incumbent_bytes} bytes",
                        )
                    )
                    continue

                validation = self.validator(reproduction.output, self.config.reference)
                if not validation.get("ok", False):
                    errors = validation.get("errors", [])
                    observations.append(
                        self._record(
                            manifest,
                            submitted_bytes=submitted_bytes,
                            reproduced_bytes=reproduced_bytes,
                            elapsed_seconds=reproduction.elapsed_seconds,
                            accepted=False,
                            phase="validation",
                            observation="validator checks did not pass: " + "; ".join(map(str, errors)),
                        )
                    )
                    continue

                current = promote(reproduction, manifest, self.config, current)
                incumbent_bytes = int(current["best"]["bytes"])
                observations.append(
                    self._record(
                        manifest,
                        submitted_bytes=submitted_bytes,
                        reproduced_bytes=reproduced_bytes,
                        elapsed_seconds=reproduction.elapsed_seconds,
                        accepted=True,
                        phase="promotion",
                        observation=f"promoted reproduced artifact at {reproduced_bytes} bytes",
                    )
                )
            except (
                ColumnArtifactError,
                OSError,
                RuntimeError,
                TypeError,
                TimeoutError,
                subprocess.SubprocessError,
            ) as exc:
                observations.append(
                    self._record(
                        manifest,
                        submitted_bytes=submitted_bytes,
                        accepted=False,
                        phase="reproduction",
                        observation=str(exc),
                    )
                )
            finally:
                if reproduction is not None:
                    shutil.rmtree(reproduction.workspace, ignore_errors=True)
        return observations


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("manifests", nargs="+", type=Path)
    parser.add_argument("--pqmin", type=Path, required=True)
    parser.add_argument("--input", type=Path, required=True)
    parser.add_argument("--raw-values", type=Path)
    parser.add_argument("--reference", type=Path, required=True)
    parser.add_argument("--validator", type=Path, required=True)
    parser.add_argument("--current", type=Path, required=True)
    parser.add_argument("--trials", type=Path, required=True)
    parser.add_argument("--best-artifact", type=Path, required=True)
    parser.add_argument("--best-reproducer", type=Path, required=True)
    parser.add_argument("--runtime-cap-seconds", type=float, required=True)
    parser.add_argument("--cpu", type=int, default=0)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    config = GateConfig(
        pqmin=args.pqmin.resolve(),
        source_input=args.input.resolve(),
        raw_values=args.raw_values.resolve() if args.raw_values else None,
        reference=args.reference.resolve(),
        validator=args.validator.resolve(),
        current=args.current.resolve(),
        trials=args.trials.resolve(),
        best_artifact=args.best_artifact.resolve(),
        best_reproducer=args.best_reproducer.resolve(),
        runtime_cap_seconds=args.runtime_cap_seconds,
        cpu=args.cpu,
    )
    observations = CandidateGate(config).evaluate(args.manifests)
    print(json.dumps([asdict(item) for item in observations], indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
