#!/usr/bin/env python3
"""Continuous CPU-pinned, artifact-first Parquet research loop."""
from __future__ import annotations

import argparse
import fcntl
import json
import os
import shutil
import signal
import subprocess
import sys
import time
from collections import deque
from dataclasses import dataclass
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any

try:
    from .claim import claim_for_run, finish_run, reset_active
    from .harness.common import (
        CURRENT,
        NOTEBOOK,
        PQ,
        PROGRESS,
        REFERENCE,
        STATUS,
        TRIALS,
        append_trial,
        append_progress,
        atomic_json,
        now_iso,
        read_json,
    )
except ImportError:  # Direct execution from pqmin/run.sh.
    from claim import claim_for_run, finish_run, reset_active
    from harness.common import (
        CURRENT,
        NOTEBOOK,
        PQ,
        PROGRESS,
        REFERENCE,
        STATUS,
        TRIALS,
        append_trial,
        append_progress,
        atomic_json,
        now_iso,
        read_json,
    )

ROOT = PQ.parent
CONFIG_PATH = PQ / "config.json"
COORDINATION = PQ / "coordination"
STOP = PQ / "STOP"
LOCK = PQ / "orchestrator.lock"
PID = PQ / "orchestrator.pid"
def _clean_copy(source: Path, destination: Path) -> None:
    def ignore(_directory: str, names: list[str]) -> set[str]:
        return {
            name
            for name in names
            if name in {"bin", "obj", ".git", ".cache", "__pycache__", "submission", "submission.json"}
        }

    lock_path = PQ / "promotion.lock"
    lock_path.touch(exist_ok=True)
    with lock_path.open("r") as lock:
        fcntl.flock(lock, fcntl.LOCK_SH)
        try:
            shutil.copytree(source, destination, symlinks=True, ignore=ignore)
        finally:
            fcntl.flock(lock, fcntl.LOCK_UN)


def _iso(value: datetime) -> str:
    return value.astimezone().isoformat(timespec="seconds")


def _parse_cpu_list(value: str) -> set[int]:
    cpus: set[int] = set()
    for field in value.strip().split(","):
        if not field:
            continue
        if "-" in field:
            first, last = field.split("-", 1)
            cpus.update(range(int(first), int(last) + 1))
        else:
            cpus.add(int(field))
    return cpus


def _cpu_siblings(cpu: int) -> set[int]:
    path = Path(f"/sys/devices/system/cpu/cpu{cpu}/topology/thread_siblings_list")
    try:
        siblings = _parse_cpu_list(path.read_text(encoding="ascii"))
    except (OSError, UnicodeError, ValueError):
        siblings = {cpu}
    return siblings or {cpu}


def _system_mounts() -> list[str]:
    result: list[str] = []
    for path in ("/usr", "/bin", "/sbin", "/lib", "/lib64", "/etc"):
        if Path(path).exists():
            result.extend(("--ro-bind", path, path))
    return result


def _agent_command(
    slot: Path,
    prompt: Path,
    config: dict[str, Any],
    cohort: int,
    slot_id: int,
    cpu: int,
) -> list[str]:
    home = slot / "home"
    agent_home = home / ".pi" / "agent"
    agent_home.mkdir(parents=True, exist_ok=True)
    (slot / "session").mkdir(parents=True, exist_ok=True)
    slot_tmp = slot / "tmp"
    slot_tmp.mkdir(parents=True, exist_ok=True)
    slot_tmp.chmod(0o1777)
    node_modules = Path.home() / ".local" / "lib" / "node_modules"
    pi_agent = Path.home() / ".pi" / "agent"
    cli = "/opt/node_modules/@earendil-works/pi-coding-agent/dist/cli.js"
    for name in ("settings.json", "models.json", "models-store.json"):
        source = pi_agent / name
        if source.is_file():
            shutil.copy2(source, agent_home / name)
    auth_target = agent_home / "auth.json"
    auth_target.touch(exist_ok=True)
    command = [
        "taskset", "--cpu-list", str(cpu),
        "bwrap", "--unshare-all", "--share-net", "--die-with-parent", "--new-session",
        *_system_mounts(),
        "--dev", "/dev", "--proc", "/proc", "--bind", str(slot_tmp), "/tmp",
        "--dir", "/coordination", "--bind", str(COORDINATION), "/coordination",
        "--dir", "/workspace", "--bind", str(slot), "/workspace",
        "--dir", "/input", "--ro-bind", str(config["raw_values"]), "/input/values.i64le",
        "--dir", "/opt", "--ro-bind", str(node_modules), "/opt/node_modules",
        "--ro-bind", str(PQ / "claim.py"), "/opt/pqmin_claim.py",
        "--ro-bind", str(pi_agent / "auth.json"), "/workspace/home/.pi/agent/auth.json",
    ]
    command.extend((
        "--setenv", "HOME", "/workspace/home",
        "--setenv", "PATH", "/usr/local/bin:/usr/bin:/bin",
        "--setenv", "CC", "cc",
        "--chdir", "/workspace/repo",
        "--", "node", cli,
        "--approve", "--model", str(config["model"]), "--thinking", str(config["thinking"]),
        "--tools", "read,bash,edit,write,grep,find,ls",
        "--session-dir", "/workspace/session",
        "--name", f"minimal-parquet-c{cohort:04d}-s{slot_id}",
        "-p", f"@{Path('/workspace') / prompt.name}",
    ))
    return command


def _write_worker_prompt(
    path: Path,
    cohort: int,
    slot_id: int,
    run_id: int,
) -> None:
    path.write_text(
        "# Independent timeboxed research assignment\n\n"
        "Read `research/MISSION.md`, `research/COLUMN_FORMAT.md`, `research/current.json`, "
        "`research/reference.json`, `research/NOTEBOOK.md`, and the live shared "
        "`/coordination/RESULTS.md` first. Follow them exactly. Re-read `/coordination/RESULTS.md` "
        "before changing subjects because other workers update it while you run.\n\n"
        f"Cohort: {cohort}\nSlot: {slot_id}\nRun: {run_id}\n\n"
        "Choose your own research subject after looking at what the other workers are doing. Before doing any "
        "experiment, run `python3 /opt/pqmin_claim.py list`, choose a materially different subject, then reserve it "
        f"atomically with `python3 /opt/pqmin_claim.py claim --slot {slot_id} --run {run_id} --key KEY --subject SUBJECT`. "
        "KEY is a concise lowercase canonical name. If the claim collides, list the board again and choose another "
        "subject. Do not begin experimental work until your claim succeeds. If you abandon the subject, release it "
        f"with `python3 /opt/pqmin_claim.py release --run {run_id}` and claim a new one first.\n\n"
        "This is a C-only physical-column laboratory. There is no Plank or .NET source and you must keep the "
        "reproducer in C. Optimize page boundaries, delta encoding, encoded byte patterns, compression transforms, "
        "and codec parameters in `candidate.c`. The trusted gate turns the PQCOL bundle into the scored Parquet "
        "file. Schema, footer, page-header, and metadata tweaks are outside the research surface. Do not reject an idea merely "
        "because its pre-compression encoding grows. Proxy measurements may prioritize work, but only the final "
        "gate-assembled compressed file decides the score.\n\n"
        "Do not choose a subject already active on the board, and do not spend a full-data run reproducing the "
        "unchanged current winner: it is already validated. A "
        "different shell spelling or executable invocation is not a new experiment. Before an expensive full-data "
        "run, state the exact variable, mechanism, or implementation change that makes it materially different "
        "from both the winner and the exact scopes in NOTEBOOK.md. Use the 15-minute box as three phases: inspect "
        "and choose; run cheap discriminating measurements; then reserve enough time for one complete candidate "
        "and its manifest.\n\n"
        "Your local wall-clock time is distorted by simultaneous work on the sibling hardware thread. Never "
        "downgrade a smaller complete artifact to an observation merely because its local write exceeded the "
        "runtime cap. Submit the candidate and let the gate's isolated physical core make the authoritative "
        "runtime decision.\n\n"
        "Before ending, write `/workspace/repo/submission.json`. For a candidate, the bundle path is "
        "`/workspace/repo/submission/candidate.column`; use only argument arrays, never a shell command string. "
        "Use `prepare_argv` to compile C (normally `make`) and make `reproduce_argv` run only the compiled program. "
        "For an observation, describe only the exact tested scope and measurements. Never use refuted/exhausted "
        "language. Do not inspect paths outside this sandbox.\n"
    )


def _refresh_research_context(repo: Path) -> None:
    research = repo / "research"
    research.mkdir(parents=True, exist_ok=True)
    for name in ("MISSION.md", "COLUMN_FORMAT.md", "NOTEBOOK.md", "submission.schema.json"):
        shutil.copy2(PQ / name, research / name)
    current = read_json(CURRENT, {})
    baseline = current.get("baseline", {}) if isinstance(current.get("baseline"), dict) else {}
    best = current.get("best", {}) if isinstance(current.get("best"), dict) else {}
    atomic_json(research / "current.json", {
        "generation": current.get("generation"),
        "rows": int(read_json(CONFIG_PATH, {}).get("rows", 0)),
        "baseline": {
            "bytes": baseline.get("bytes"),
            "cap_seconds": baseline.get("cap_seconds"),
        },
        "best": {
            "bytes": best.get("bytes"),
            "candidate_id": best.get("candidate_id"),
        },
    })
    reference = read_json(REFERENCE, {})
    if isinstance(reference, dict):
        reference.pop("source", None)
        reference["raw_values"] = "/input/values.i64le"
    atomic_json(research / "reference.json", reference)
    results = PQ / "RESULTS.md"
    if results.is_file():
        shutil.copy2(results, research / "RESULTS.md")


def _status(
    state: str,
    cohort: int,
    slots: list[dict[str, Any]],
    gate: dict[str, Any] | None = None,
    reason: str | None = None,
) -> None:
    value = {
        "status": state,
        "cohort": cohort,
        "updated_at": now_iso(),
        "slots": slots,
        "gate": gate or {"status": "idle", "queue": [], "results": []},
    }
    if reason:
        value["reason"] = reason
    atomic_json(STATUS, value)


def _normalized_history_text(value: Any) -> str:
    return " ".join(str(value or "").casefold().split())


def _markdown_cell(value: Any, limit: int = 180) -> str:
    text = " ".join(str(value or "—").split()).replace("|", "\\|")
    return text if len(text) <= limit else text[: limit - 1] + "…"


def _write_shared_results(records: list[dict[str, Any]], current: dict[str, Any]) -> None:
    """Publish a live, compact ledger visible to every running sandbox."""
    best = current.get("best", {}) if isinstance(current.get("best"), dict) else {}
    best_bytes = int(best.get("bytes", 0))
    source = Path(str(best.get("reproducer", "")))
    c_incumbent = source.is_dir() and (source / ".pqmin-c-only").is_file()
    incumbent = read_json(source / "submission.json", {}) if c_incumbent else {}
    argv = incumbent.get("reproduce_argv", []) if isinstance(incumbent, dict) else []
    board = read_json(COORDINATION / "board.json", {})
    active = board.get("active", []) if isinstance(board, dict) else []
    lines = [
        "# Live shared research results",
        "",
        f"Generation {int(current.get('generation', 1))}; current validated best: {best_bytes:,} bytes.",
        "This file is regenerated after every gate result. Read it before claiming or pivoting.",
        "",
        "## C-generation starting point",
        "",
        (
            "The current winner was produced inside this C-only generation. Its source is your workspace "
            "starting point and its winning argument vector was:"
            if c_incumbent else
            "The validated file-size target predates the C-only generation. Its previous reproducer is deliberately "
            "not exposed. Every workspace starts from the small independent C encoder."
        ),
        "",
        *(('```json', json.dumps(argv, ensure_ascii=False), '```') if c_incumbent else ()),
        "",
        "Use `submission/candidate.column` as the output path under the PQCOL01 bundle contract.",
        "",
        "## Active subjects",
        "",
    ]
    if active:
        for claim in sorted(active, key=lambda item: int(item.get("slot", 0))):
            lines.append(
                f"- Slot {claim.get('slot')}: `{_markdown_cell(claim.get('key'), 80)}` — "
                f"{_markdown_cell(claim.get('subject'), 240)}"
            )
    else:
        lines.append("- None.")
    lines.extend((
        "",
        f"## Completed attempts ({len(records)})",
        "",
        "| Candidate | Phase | Bytes | Delta vs best | Hypothesis | Result |",
        "|---|---:|---:|---:|---|---|",
    ))
    for record in records:
        reproduced = record.get("reproduced_bytes")
        submitted = record.get("submitted_bytes")
        metrics = record.get("metrics") if isinstance(record.get("metrics"), dict) else {}
        measured = metrics.get("carrier_bytes")
        size = reproduced if isinstance(reproduced, int) else submitted if isinstance(submitted, int) else measured
        size_text = f"{size:,}" if isinstance(size, int) else "—"
        delta_text = f"{size - best_bytes:+,}" if isinstance(size, int) and best_bytes else "—"
        lines.append(
            "| " + " | ".join((
                _markdown_cell(record.get("candidate_id"), 40),
                _markdown_cell(record.get("phase", record.get("status")), 40),
                size_text,
                delta_text,
                _markdown_cell(record.get("hypothesis"), 180),
                _markdown_cell(record.get("observation", record.get("notes")), 180),
            )) + " |"
        )
    payload = "\n".join(lines) + "\n"
    (PQ / "RESULTS.md").write_text(payload, encoding="utf-8")
    COORDINATION.mkdir(parents=True, exist_ok=True)
    (COORDINATION / "RESULTS.md").write_text(payload, encoding="utf-8")


def _neutral_notebook(limit: int = 24) -> None:
    current = read_json(CURRENT, {})
    epoch_started_at = current.get("research_started_at") if isinstance(current, dict) else None
    epoch_start: datetime | None = None
    if isinstance(epoch_started_at, str):
        try:
            epoch_start = datetime.fromisoformat(epoch_started_at)
        except ValueError:
            epoch_start = None
    records: list[dict[str, Any]] = []
    if TRIALS.exists():
        for line in TRIALS.read_text().splitlines():
            try:
                value = json.loads(line)
                if isinstance(value, dict):
                    if epoch_start is not None:
                        try:
                            recorded_at = datetime.fromisoformat(str(value.get("timestamp")))
                        except (TypeError, ValueError):
                            continue
                        if recorded_at < epoch_start:
                            continue
                    records.append(value)
            except json.JSONDecodeError:
                continue
    best = current.get("best", {}) if isinstance(current, dict) else {}
    lines = [
        "# Neutral notebook",
        "",
        f"Current validated best: {int(best.get('bytes', 0)):,} bytes.",
        "",
        "Each entry below describes only its exact tested scope. It does not prohibit related work.",
        "",
    ]
    # Repeated wording was occupying nearly the whole prompt and anchoring every
    # researcher on the same winner.  Keep one neutral observation per exact
    # hypothesis or scope while retaining the most recent version.
    selected: list[dict[str, Any]] = []
    seen_hypotheses: set[str] = set()
    seen_scopes: set[str] = set()
    for record in reversed(records):
        hypothesis_key = _normalized_history_text(record.get("hypothesis"))
        scope_key = _normalized_history_text(record.get("tested_scope"))
        if hypothesis_key and hypothesis_key in seen_hypotheses:
            continue
        if scope_key and scope_key in seen_scopes:
            continue
        selected.append(record)
        if hypothesis_key:
            seen_hypotheses.add(hypothesis_key)
        if scope_key:
            seen_scopes.add(scope_key)
        if len(selected) >= limit:
            break
    selected.reverse()
    collapsed = max(0, len(records) - len(selected))
    lines.extend((
        f"Showing {len(selected)} distinct recent scopes; {collapsed} duplicate or older records are collapsed.",
        "Do not repeat an exact scope below, but nearby or recombined ideas remain valid experiments.",
        "",
    ))
    for record in selected:
        result_bytes = record.get("reproduced_bytes", record.get("submitted_bytes"))
        metrics = f"; final bytes={result_bytes}" if result_bytes is not None else ""
        if record.get("elapsed_seconds") is not None:
            metrics += f"; writer seconds={record['elapsed_seconds']}"
        lines.extend((
            f"- **{record.get('hypothesis', 'Untitled trial')}**",
            f"  Scope: {record.get('tested_scope', 'not recorded')}.",
            f"  Observation: {record.get('observation', record.get('notes', 'recorded'))}{metrics}.",
        ))
    NOTEBOOK.write_text("\n".join(lines) + "\n")
    _write_shared_results(records, current)


def _observation(slot_id: int, manifest: dict[str, Any]) -> None:
    append_trial({
        "candidate_id": manifest.get("candidate_id", f"slot-{slot_id}"),
        "slot": slot_id,
        "hypothesis": manifest.get("hypothesis", "Scoped observation"),
        "tested_scope": manifest.get("tested_scope", "not recorded"),
        "submitted_bytes": None,
        "reproduced_bytes": None,
        "elapsed_seconds": None,
        "accepted": False,
        "phase": "observation",
        "status": "recorded",
        "observation": manifest.get("notes", "No full candidate submitted."),
        "metrics": manifest.get("metrics", {}),
    })


def _session_tokens(slot: Path) -> int:
    """Return exact model tokens recorded in a researcher's retained session."""
    total = 0
    for path in sorted((slot / "session").glob("*.jsonl")):
        try:
            lines = path.read_text(encoding="utf-8").splitlines()
        except (OSError, UnicodeError):
            continue
        for line in lines:
            try:
                value = json.loads(line)
            except json.JSONDecodeError:
                continue
            message = value.get("message") if isinstance(value, dict) else None
            usage = message.get("usage") if isinstance(message, dict) else None
            tokens = usage.get("totalTokens") if isinstance(usage, dict) else None
            if isinstance(tokens, int) and not isinstance(tokens, bool) and tokens >= 0:
                total += tokens
    return total


def _last_tracked_tokens() -> int:
    try:
        lines = PROGRESS.read_text(encoding="utf-8").splitlines()
    except (OSError, UnicodeError):
        return 0
    for line in reversed(lines):
        try:
            value = json.loads(line)
        except json.JSONDecodeError:
            continue
        tokens = value.get("cumulative_tokens") if isinstance(value, dict) else None
        if isinstance(tokens, int) and not isinstance(tokens, bool) and tokens >= 0:
            return tokens
    return 0


@dataclass
class WorkerRun:
    slot_id: int
    cpu: int
    run_id: int
    cycle: int
    lens: str
    workspace: Path
    process: subprocess.Popen[bytes]
    log: Any
    started: datetime
    deadline: datetime
    tokens: int = 0
    paused_at: datetime | None = None


@dataclass
class GateItem:
    slot_id: int
    run_id: int
    workspace: Path
    manifest: Path
    hypothesis: str
    artifact_bytes: int | None


@dataclass
class ActiveGate:
    item: GateItem
    process: subprocess.Popen[str]
    paused_workers: list[WorkerRun]


def _terminate_process(process: subprocess.Popen[Any], timeout: float = 15.0) -> None:
    if process.poll() is not None:
        return
    try:
        os.killpg(process.pid, signal.SIGTERM)
        process.wait(timeout=timeout)
    except (ProcessLookupError, subprocess.TimeoutExpired):
        try:
            os.killpg(process.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        process.wait()


class Loop:
    """Continuously refill CPU-pinned research slots and serialize the gate."""

    def __init__(self, *, once: bool = False) -> None:
        self.config = read_json(CONFIG_PATH, {})
        self.once = once
        self.stopping = False
        self.cpus = sorted(os.sched_getaffinity(0))
        self.slot_count = int(self.config.get("researchers", 0))
        state = read_json(STATUS, {})
        current = read_json(CURRENT, {})
        self.base_cycle = max(int(state.get("cohort", 0)), int(current.get("cohort", 0)))
        self.completed = 0
        self.next_run_id = self.base_cycle * 1000
        self.tracked_tokens = _last_tracked_tokens()
        self.plateau_epoch_tokens = self.tracked_tokens
        self.plateau_token_budget = int(self.config.get("plateau_token_budget", 30_000_000))
        self.workers: dict[int, WorkerRun] = {}
        self.gate_queue: deque[GateItem] = deque()
        self.active_gate: ActiveGate | None = None
        self.gate_results: list[dict[str, Any]] = []
        self.continuous_root = PQ / "work" / "continuous"

    def request_stop(self, _signum: int, _frame: Any) -> None:
        self.stopping = True

    def check(self) -> None:
        COORDINATION.mkdir(parents=True, exist_ok=True)
        required = (
            CURRENT,
            REFERENCE,
            NOTEBOOK,
            PQ / "c_seed",
            Path(self.config["raw_values"]),
            PQ / "harness" / "validate.py",
        )
        missing = [str(path) for path in required if not path.exists()]
        if missing:
            raise RuntimeError("bootstrap is incomplete: " + ", ".join(missing))
        for command in ("bwrap", "node", "taskset", "cc", "make"):
            if shutil.which(command) is None:
                raise RuntimeError(f"required command is unavailable: {command}")
        if not 1 <= self.slot_count <= len(self.cpus):
            raise RuntimeError(
                f"researchers must be between 1 and the {len(self.cpus)} available logical CPUs"
            )
        if int(self.config.get("timebox_seconds", 0)) != 900:
            raise RuntimeError("config must specify a 900-second maximum timebox")

    def _cycle(self) -> int:
        return self.base_cycle + self.completed // self.slot_count + 1

    def _source(self) -> Path:
        current = read_json(CURRENT, {})
        source = Path(current.get("best", {}).get("reproducer", PQ / "c_seed"))
        if source.is_dir() and (source / ".pqmin-c-only").is_file():
            return source
        return PQ / "c_seed"

    def _spawn_worker(self, slot_id: int) -> WorkerRun:
        self.next_run_id += 1
        run_id = self.next_run_id
        cycle = self._cycle()
        cpu = self.cpus[slot_id - 1]
        lens = "Choosing own subject"
        workspace = self.continuous_root / f"slot-{slot_id:02d}" / f"run-{run_id:08d}"
        repo = workspace / "repo"
        workspace.mkdir(parents=True)
        _clean_copy(self._source(), repo)
        _refresh_research_context(repo)
        prompt = workspace / "prompt.md"
        _write_worker_prompt(prompt, cycle, slot_id, run_id)
        log_path = PQ / "logs" / f"run-{run_id:08d}-slot-{slot_id:02d}.log"
        log = log_path.open("wb")
        now = datetime.now().astimezone()
        process = subprocess.Popen(
            _agent_command(workspace, prompt, self.config, cycle, slot_id, cpu),
            stdout=log,
            stderr=subprocess.STDOUT,
            start_new_session=True,
        )
        worker = WorkerRun(
            slot_id=slot_id,
            cpu=cpu,
            run_id=run_id,
            cycle=cycle,
            lens=lens,
            workspace=workspace,
            process=process,
            log=log,
            started=now,
            deadline=now + timedelta(seconds=int(self.config["timebox_seconds"])),
        )
        self.workers[slot_id] = worker
        return worker

    def _queue_submission(self, worker: WorkerRun) -> bool:
        manifest_path = worker.workspace / "repo" / "submission.json"
        if not manifest_path.is_file():
            _observation(worker.slot_id, {
                "hypothesis": "No manifest submitted",
                "tested_scope": worker.lens,
                "notes": "Researcher ended or timed out without a submission manifest.",
            })
            return False
        try:
            manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as error:
            _observation(worker.slot_id, {
                "hypothesis": "Unreadable manifest",
                "tested_scope": worker.lens,
                "notes": str(error),
            })
            return False
        artifact = worker.workspace / "repo" / str(manifest.get("artifact", ""))
        self.gate_queue.append(GateItem(
            slot_id=worker.slot_id,
            run_id=worker.run_id,
            workspace=worker.workspace,
            manifest=manifest_path,
            hypothesis=str(manifest.get("hypothesis", "Candidate")),
            artifact_bytes=artifact.stat().st_size if artifact.is_file() else None,
        ))
        return True

    def _finish_worker(self, worker: WorkerRun, *, timed_out: bool, respawn: bool) -> None:
        if timed_out:
            _terminate_process(worker.process)
        else:
            worker.process.wait()
        worker.log.close()
        worker.tokens = _session_tokens(worker.workspace)
        self.tracked_tokens += worker.tokens
        current = read_json(CURRENT, {})
        append_progress({
            "best_bytes": int(current.get("best", {}).get("bytes", 0)),
            "candidate_id": current.get("best", {}).get("candidate_id"),
            "cohort": worker.cycle,
            "cohort_tokens": worker.tokens,
            "cumulative_tokens": self.tracked_tokens,
            "kind": "worker",
            "run_id": worker.run_id,
            "slot": worker.slot_id,
        })
        shutil.rmtree(worker.workspace / "tmp", ignore_errors=True)
        queued = self._queue_submission(worker)
        if not queued:
            shutil.rmtree(worker.workspace, ignore_errors=True)
        self.completed += 1
        finish_run(COORDINATION, worker.run_id, "timed_out" if timed_out else "completed")
        self.workers.pop(worker.slot_id, None)
        if respawn and not self.stopping and not STOP.exists():
            self._spawn_worker(worker.slot_id)

    def _gate_command(self, item: GateItem) -> list[str]:
        current = read_json(CURRENT, {})
        gate_cpu = int(self.config.get("gate_cpu", self.cpus[0]))
        return [
            sys.executable,
            str(PQ / "harness" / "gate.py"),
            str(item.manifest),
            "--pqmin", str(PQ),
            "--input", str(self.config["input"]),
            "--raw-values", str(self.config["raw_values"]),
            "--reference", str(REFERENCE),
            "--validator", str(PQ / "harness" / "validate.py"),
            "--current", str(CURRENT),
            "--trials", str(TRIALS),
            "--best-artifact", str(PQ / "best" / "best.parquet"),
            "--best-reproducer", str(PQ / "best" / "reproducer"),
            "--runtime-cap-seconds", str(float(current["baseline"]["cap_seconds"])),
            "--cpu", str(gate_cpu),
        ]

    def _start_gate(self) -> None:
        if self.active_gate is not None or not self.gate_queue:
            return
        item = self.gate_queue.popleft()
        gate_cpu = int(self.config.get("gate_cpu", self.cpus[0]))
        sibling_cpus = _cpu_siblings(gate_cpu)
        paused_workers: list[WorkerRun] = []
        paused_at = datetime.now().astimezone()
        for worker in self.workers.values():
            if worker.cpu not in sibling_cpus or worker.process.poll() is not None:
                continue
            try:
                os.killpg(worker.process.pid, signal.SIGSTOP)
            except ProcessLookupError:
                continue
            worker.paused_at = paused_at
            paused_workers.append(worker)
        try:
            process = subprocess.Popen(
                self._gate_command(item),
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                start_new_session=True,
            )
        except Exception:
            for worker in paused_workers:
                try:
                    os.killpg(worker.process.pid, signal.SIGCONT)
                except ProcessLookupError:
                    pass
                worker.paused_at = None
            raise
        self.active_gate = ActiveGate(
            item=item,
            process=process,
            paused_workers=paused_workers,
        )

    def _resume_gate_workers(self, active: ActiveGate) -> None:
        resumed_at = datetime.now().astimezone()
        for worker in active.paused_workers:
            paused_at = worker.paused_at
            if paused_at is None:
                continue
            worker.deadline += resumed_at - paused_at
            try:
                os.killpg(worker.process.pid, signal.SIGCONT)
            except ProcessLookupError:
                pass
            worker.paused_at = None
        active.paused_workers.clear()

    def _poll_gate(self) -> None:
        active = self.active_gate
        if active is None or active.process.poll() is None:
            return
        stdout, stderr = active.process.communicate()
        self._resume_gate_workers(active)
        results: list[dict[str, Any]]
        if active.process.returncode == 0:
            try:
                parsed = json.loads(stdout)
                results = parsed if isinstance(parsed, list) else []
            except json.JSONDecodeError:
                results = [{"accepted": False, "phase": "gate", "observation": "invalid gate output"}]
        else:
            results = [{
                "accepted": False,
                "candidate_id": f"slot-{active.item.slot_id}",
                "phase": "gate",
                "observation": (stderr or stdout)[-1000:],
            }]
        for result in results:
            result["slot"] = active.item.slot_id
            result["run_id"] = active.item.run_id
            self.gate_results.append(result)
        self.gate_results = self.gate_results[-48:]
        current = read_json(CURRENT, {})
        if any(bool(result.get("accepted")) for result in results):
            append_progress({
                "best_bytes": int(current.get("best", {}).get("bytes", 0)),
                "candidate_id": current.get("best", {}).get("candidate_id"),
                "cohort": self._cycle(),
                "cohort_tokens": 0,
                "cumulative_tokens": self.tracked_tokens,
                "kind": "promotion",
                "run_id": active.item.run_id,
                "slot": active.item.slot_id,
            })
            self.plateau_epoch_tokens = self.tracked_tokens
        _neutral_notebook()
        shutil.rmtree(active.item.workspace, ignore_errors=True)
        self.active_gate = None

    def _slot_status(self) -> list[dict[str, Any]]:
        slots: list[dict[str, Any]] = []
        for slot_id in range(1, self.slot_count + 1):
            worker = self.workers.get(slot_id)
            if worker is None:
                slots.append({
                    "slot": slot_id,
                    "label": f"Research slot {slot_id}",
                    "lens": "Choosing own subject",
                    "state": "restarting",
                    "cpu": self.cpus[slot_id - 1],
                    "summary": "Refilling immediately",
                })
                continue
            claim = claim_for_run(COORDINATION, worker.run_id)
            subject = str(claim.get("subject")) if claim else worker.lens
            key = str(claim.get("key")) if claim else None
            paused = worker.paused_at is not None
            slots.append({
                "slot": slot_id,
                "label": f"Research slot {slot_id}",
                "lens": subject,
                "subject_key": key,
                "state": "paused for gate" if paused else "running",
                "cpu": worker.cpu,
                "pid": worker.process.pid,
                "run_id": worker.run_id,
                "started_at": _iso(worker.started),
                "deadline_at": _iso(worker.deadline),
                "tokens_used": worker.tokens,
                "summary": (
                    f"Gate owns this physical core temporarily; CPU {worker.cpu}"
                    if paused else f"Claimed {key}; pinned to logical CPU {worker.cpu}"
                    if key else f"Choosing a subject; pinned to logical CPU {worker.cpu}"
                ),
            })
        return slots

    def _gate_status(self) -> dict[str, Any]:
        queued = ([self.active_gate.item] if self.active_gate is not None else []) + list(self.gate_queue)
        return {
            "status": "running" if self.active_gate is not None else ("queued" if queued else "idle"),
            "queue": [{
                "id": f"run-{item.run_id}",
                "slot": item.slot_id,
                "hypothesis": item.hypothesis,
                "status": "validating" if self.active_gate and item is self.active_gate.item else "queued",
                "artifact_bytes": item.artifact_bytes,
            } for item in queued],
            "results": self.gate_results[-24:],
        }

    def _publish_status(self) -> None:
        _status("researching", self._cycle(), self._slot_status(), self._gate_status())

    def run(self) -> None:
        self.check()
        current = read_json(CURRENT, {})
        reset_active(COORDINATION, generation=int(current.get("generation", 1)))
        _neutral_notebook()
        signal.signal(signal.SIGTERM, self.request_stop)
        signal.signal(signal.SIGINT, self.request_stop)
        shutil.rmtree(self.continuous_root, ignore_errors=True)
        self.continuous_root.mkdir(parents=True)
        for slot_id in range(1, self.slot_count + 1):
            self._spawn_worker(slot_id)
        self._publish_status()

        next_token_refresh = 0.0
        try:
            while not self.stopping and not STOP.exists():
                now = datetime.now().astimezone()
                for worker in list(self.workers.values()):
                    if worker.paused_at is not None:
                        continue
                    returncode = worker.process.poll()
                    if returncode is not None:
                        self._finish_worker(worker, timed_out=False, respawn=not self.once)
                    elif now >= worker.deadline:
                        self._finish_worker(worker, timed_out=True, respawn=not self.once)
                self._poll_gate()
                self._start_gate()
                if time.monotonic() >= next_token_refresh:
                    for worker in self.workers.values():
                        worker.tokens = _session_tokens(worker.workspace)
                    self._publish_status()
                    if (
                        self.plateau_token_budget > 0
                        and self.tracked_tokens - self.plateau_epoch_tokens >= self.plateau_token_budget
                    ):
                        # A plateau is an observability checkpoint, not a global stop.
                        # Individual slots keep refilling after every completed timebox.
                        cohort_tokens = self.tracked_tokens - self.plateau_epoch_tokens
                        current = read_json(CURRENT, {})
                        append_progress({
                            "best_bytes": int(current.get("best", {}).get("bytes", 0)),
                            "candidate_id": current.get("best", {}).get("candidate_id"),
                            "cohort": self._cycle(),
                            "cohort_tokens": cohort_tokens,
                            "cumulative_tokens": self.tracked_tokens,
                            "kind": "plateau",
                        })
                        self.plateau_epoch_tokens = self.tracked_tokens
                    next_token_refresh = time.monotonic() + 10.0
                if self.once and self.completed >= self.slot_count:
                    break
                time.sleep(1)
        finally:
            self.stopping = True
            if self.active_gate is not None:
                _terminate_process(self.active_gate.process)
                self._resume_gate_workers(self.active_gate)
                shutil.rmtree(self.active_gate.item.workspace, ignore_errors=True)
                self.active_gate = None
            for worker in list(self.workers.values()):
                _terminate_process(worker.process)
                worker.log.close()
                finish_run(COORDINATION, worker.run_id, "interrupted")
                shutil.rmtree(worker.workspace, ignore_errors=True)
            self.workers.clear()
            for item in self.gate_queue:
                shutil.rmtree(item.workspace, ignore_errors=True)
            self.gate_queue.clear()
            _status("stopped", self._cycle(), self._slot_status(), self._gate_status())


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--check", action="store_true")
    parser.add_argument("--once", action="store_true")
    args = parser.parse_args()
    LOCK.parent.mkdir(parents=True, exist_ok=True)
    with LOCK.open("w") as lock:
        try:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            print("another orchestrator holds the lock", file=sys.stderr)
            return 1
        loop = Loop(once=args.once)
        loop.check()
        if args.check:
            print("orchestrator prerequisites: OK")
            return 0
        STOP.unlink(missing_ok=True)
        PID.write_text(str(os.getpid()) + "\n")
        try:
            loop.run()
        finally:
            PID.unlink(missing_ok=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
