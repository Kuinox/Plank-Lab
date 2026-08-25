#!/usr/bin/env python3
"""Small, dependency-free live dashboard for the pqmin research loop."""

from __future__ import annotations

import argparse
import json
import mimetypes
import os
import re
import threading
from collections.abc import Iterable
from datetime import datetime, timezone
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any
from urllib.parse import unquote, urlsplit

ROOT = Path(__file__).resolve().parent
WEB_ROOT = ROOT / "web"
MAX_RECENT = 24
MAX_ATTEMPTS = 2048


def _read_json(path: Path, warnings: list[str]) -> Any:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError:
        return None
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        warnings.append(f"{path.relative_to(ROOT)} is temporarily unreadable: {exc}")
        return None


def _read_jsonl(path: Path, warnings: list[str], limit: int = MAX_RECENT) -> list[Any]:
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except FileNotFoundError:
        return []
    except (OSError, UnicodeError) as exc:
        warnings.append(f"{path.relative_to(ROOT)} is temporarily unreadable: {exc}")
        return []

    values: list[Any] = []
    # A writer can be interrupted between bytes. Ignore only the incomplete tail.
    for reverse_index, line in enumerate(reversed(lines)):
        if not line.strip():
            continue
        try:
            values.append(json.loads(line))
        except json.JSONDecodeError as exc:
            if reverse_index == 0:
                continue
            warnings.append(f"{path.relative_to(ROOT)} contains an invalid record: {exc}")
        if len(values) >= limit:
            break
    values.reverse()
    return values


def _first(mapping: Any, *names: str, default: Any = None) -> Any:
    if not isinstance(mapping, dict):
        return default
    for name in names:
        value = mapping.get(name)
        if value is not None:
            return value
    return default


def _number(value: Any) -> float | int | None:
    if isinstance(value, bool):
        return None
    if isinstance(value, (int, float)):
        return value
    if isinstance(value, str):
        match = re.search(r"-?\d+(?:\.\d+)?", value.replace(",", ""))
        if match:
            try:
                return float(match.group()) if "." in match.group() else int(match.group())
            except ValueError:
                pass
    return None


def _time(value: Any) -> datetime | None:
    if isinstance(value, (int, float)):
        try:
            return datetime.fromtimestamp(value, tz=timezone.utc)
        except (OverflowError, OSError, ValueError):
            return None
    if not isinstance(value, str) or not value:
        return None
    candidate = value.strip().replace("Z", "+00:00")
    try:
        parsed = datetime.fromisoformat(candidate)
    except ValueError:
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


def _as_records(value: Any, *keys: str) -> list[Any]:
    if isinstance(value, list):
        return value
    if isinstance(value, dict):
        for key in keys:
            nested = value.get(key)
            if isinstance(nested, list):
                return nested
        return list(value.values()) if value and all(isinstance(v, dict) for v in value.values()) else []
    return []


def _load_first(paths: Iterable[Path], warnings: list[str]) -> tuple[Any, str | None]:
    for path in paths:
        if path.is_file():
            return _read_json(path, warnings), str(path.relative_to(ROOT))
    return None, None


def _normalise_size(record: Any) -> int | None:
    value = _first(
        record,
        "size_bytes",
        "artifact_size_bytes",
        "compressed_size_bytes",
        "file_size_bytes",
        "artifact_bytes",
        "best_bytes",
        "bytes",
        "size",
    )
    parsed = _number(value)
    return int(parsed) if parsed is not None and parsed >= 0 else None


def _complete_metric_size(raw: dict[str, Any]) -> int | None:
    """Accept only metrics that describe a complete-data carrier/artifact."""
    metrics = raw.get("metrics") if isinstance(raw.get("metrics"), dict) else {}
    if any("prefix" in str(key).casefold() for key in metrics):
        return None
    scope = str(raw.get("tested_scope", "")).casefold().replace(",", "")
    observation = str(raw.get("observation", "")).casefold()
    if "no complete candidate" in observation or "no candidate artifact" in observation:
        return None
    if "225000000" not in scope and "complete" not in scope:
        return None
    for key in ("carrier_bytes", "artifact_bytes"):
        value = _number(metrics.get(key))
        if value is not None and value > 0:
            return int(value)
    return None


def _normalise_slot(raw: Any, index: int, now: datetime) -> dict[str, Any]:
    raw = raw if isinstance(raw, dict) else {}
    started = _time(_first(raw, "started_at", "start_time", "started", "start"))
    deadline = _time(_first(raw, "deadline_at", "deadline", "ends_at", "end_time"))
    duration = _number(_first(raw, "timebox_seconds", "duration_seconds", "budget_seconds"))
    if deadline is None and started is not None and duration is not None:
        deadline = datetime.fromtimestamp(started.timestamp() + float(duration), tz=timezone.utc)

    explicit_remaining = _number(_first(raw, "remaining_seconds", "seconds_remaining"))
    remaining = explicit_remaining
    if deadline is not None:
        remaining = max(0, int((deadline - now).total_seconds()))

    state = str(_first(raw, "status", "state", default="waiting")).lower()
    if deadline is not None and remaining == 0 and state in {"running", "active", "researching"}:
        state = "timebox ended"

    slot_id = _first(raw, "id", "slot", "worker", "worker_id", default=index + 1)
    tokens = _number(_first(raw, "tokens_used", "token_count", "tokens"))
    return {
        "id": str(slot_id),
        "label": str(_first(raw, "label", "name", default=f"Research slot {index + 1}")),
        "lens": str(_first(raw, "lens", "focus", "track", "role", default="Open exploration")),
        "status": state,
        "remaining_seconds": int(remaining) if remaining is not None else None,
        "started_at": started.isoformat() if started else None,
        "deadline_at": deadline.isoformat() if deadline else None,
        "summary": str(_first(raw, "summary", "activity", "hypothesis", "message", default="")),
        "artifact_size_bytes": _normalise_size(raw),
        "iteration": _first(raw, "iteration", "attempt", "cohort"),
        "tokens_used": int(tokens) if tokens is not None and tokens >= 0 else None,
        "cpu": _first(raw, "cpu", "logical_cpu", "affinity"),
    }


def _normalise_submission(raw: Any, kind: str = "submission") -> dict[str, Any]:
    raw = raw if isinstance(raw, dict) else {}
    status = str(_first(raw, "gate_status", "validation_status", "status", "result", default="queued"))
    created = _first(raw, "submitted_at", "created_at", "finished_at", "timestamp", "time")
    return {
        "id": str(_first(raw, "id", "candidate", "candidate_id", "submission_id", default="—")),
        "slot": str(_first(raw, "slot", "worker", "worker_id", default="—")),
        "hypothesis": str(_first(raw, "hypothesis", "summary", "title", "observation", default="Candidate")),
        "size_bytes": _normalise_size(raw),
        "status": status.lower(),
        "reason": str(_first(raw, "reason", "message", "detail", "error", default="")),
        "timestamp": created,
        "kind": kind,
    }


def _normalise_trial(raw: Any) -> dict[str, Any]:
    raw = raw if isinstance(raw, dict) else {"observation": str(raw)}
    reproduced = _number(raw.get("reproduced_bytes"))
    submitted = _number(raw.get("submitted_bytes"))
    measured = _complete_metric_size(raw)
    return {
        "timestamp": _first(raw, "timestamp", "time", "created_at", "finished_at"),
        "slot": str(_first(raw, "slot", "worker", "worker_id", default="—")),
        "hypothesis": str(_first(raw, "hypothesis", "title", "experiment", default="Untitled trial")),
        "observation": str(_first(raw, "observation", "summary", "result", "notes", default="No observation recorded.")),
        "size_bytes": int(reproduced if reproduced is not None else submitted if submitted is not None else measured)
        if reproduced is not None or submitted is not None or measured is not None else None,
        "status": str(_first(raw, "status", "outcome", default="recorded")).lower(),
    }


def _experiment_details(raw: Any) -> dict[str, Any] | None:
    """Retain the explanatory trial fields needed by chart hover cards."""
    if not isinstance(raw, dict):
        return None
    elapsed = _number(_first(raw, "elapsed_seconds", "runtime_seconds", "writer_seconds"))
    return {
        "candidate_id": str(_first(raw, "candidate_id", "id", default="—")),
        "run_id": _first(raw, "run_id", "run"),
        "slot": str(_first(raw, "slot", "worker", "worker_id", default="—")),
        "hypothesis": str(_first(raw, "hypothesis", "title", "experiment", default="Untitled trial")),
        "tested_scope": str(_first(raw, "tested_scope", "scope", default="")),
        "observation": str(_first(raw, "observation", "summary", "result", "notes", default="")),
        "phase": str(_first(raw, "phase", "status", default="recorded")),
        "accepted": bool(raw.get("accepted", False)),
        "elapsed_seconds": float(elapsed) if elapsed is not None and elapsed >= 0 else None,
        "timestamp": _first(raw, "timestamp", "time", "created_at", "finished_at"),
    }


def _attach_frontier_experiments(
    points: list[dict[str, Any]], records: list[Any],
) -> list[dict[str, Any]]:
    """Join promotion checkpoints back to the experiment that caused the drop."""
    by_run: dict[int, dict[str, Any]] = {}
    by_candidate: dict[str, dict[str, Any]] = {}
    for raw in records:
        details = _experiment_details(raw)
        if details is None:
            continue
        # Frontier points represent validated winners.  A slot can later emit
        # unrelated observations under the same short candidate id, so only a
        # promotion is safe to join onto the green best-size line.
        if not details["accepted"] and details["phase"].casefold() != "promotion":
            continue
        run_id = _number(details.get("run_id"))
        if run_id is None:
            match = re.fullmatch(r"run-0*(\d+)", details["candidate_id"])
            run_id = int(match.group(1)) if match else None
        if run_id is not None:
            by_run[int(run_id)] = details
        candidate_id = details["candidate_id"]
        if candidate_id and candidate_id != "—":
            by_candidate[candidate_id] = details

    enriched: list[dict[str, Any]] = []
    previous_size: int | None = None
    for raw_point in points:
        point = dict(raw_point)
        run_id = _number(point.get("run_id"))
        candidate_id = str(point.get("candidate_id", ""))
        details = by_run.get(int(run_id)) if run_id is not None else None
        if details is None:
            details = by_candidate.get(candidate_id)
        point["experiment"] = details
        point["drop_bytes"] = (
            previous_size - int(point["size_bytes"]) if previous_size is not None else None
        )
        previous_size = int(point["size_bytes"])
        enriched.append(point)
    return enriched


def _normalise_progress(raw: Any) -> dict[str, Any] | None:
    raw = raw if isinstance(raw, dict) else {}
    tokens = _number(_first(raw, "cumulative_tokens", "tokens", "token_count"))
    size = _normalise_size(raw)
    cohort = _number(_first(raw, "cohort", "round", "iteration"))
    if tokens is None or tokens < 0 or size is None:
        return None
    return {
        "tokens": int(tokens),
        "size_bytes": size,
        "cohort": int(cohort) if cohort is not None and cohort >= 0 else None,
        "candidate_id": str(_first(raw, "candidate_id", "id", default="—")),
        "kind": str(_first(raw, "kind", "status", default="cohort")),
        "timestamp": _first(raw, "timestamp", "time"),
        "live": False,
        "token_gap": bool(raw.get("token_gap", False)),
        "run_id": _first(raw, "run_id", "run"),
    }


def _compact_progress(points: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Keep score changes and the live plateau endpoint, not every worker checkpoint."""
    if len(points) <= 2:
        return list(points)
    compact = [points[0]]
    last_size = points[0]["size_bytes"]
    for point in points[1:-1]:
        if point["size_bytes"] != last_size or point.get("token_gap"):
            compact.append(point)
            last_size = point["size_bytes"]
    if points[-1] is not compact[-1]:
        compact.append(points[-1])
    return compact


def _attempt_points(
    records: list[Any], checkpoints: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    """Place every sized trial at its worker's cumulative-token checkpoint."""
    by_run = {
        int(point["run_id"]): int(point["tokens"])
        for point in checkpoints
        if _number(point.get("run_id")) is not None
    }
    timeline = sorted(
        (
            (stamp, int(point["tokens"]))
            for point in checkpoints
            if (stamp := _time(point.get("timestamp"))) is not None
        ),
        key=lambda item: item[0],
    )
    attempts: list[dict[str, Any]] = []
    for raw in records:
        if not isinstance(raw, dict):
            continue
        reproduced = _number(raw.get("reproduced_bytes"))
        submitted = _number(raw.get("submitted_bytes"))
        measured = _complete_metric_size(raw)
        size = reproduced if reproduced is not None else submitted if submitted is not None else measured
        if size is None or size <= 0:
            continue
        run_id = _number(_first(raw, "run_id", "run"))
        if run_id is None:
            match = re.fullmatch(r"run-0*(\d+)", str(raw.get("candidate_id", "")))
            run_id = int(match.group(1)) if match else None
        tokens = by_run.get(int(run_id)) if run_id is not None else None
        token_gap = tokens is None
        if tokens is None and timeline:
            recorded_at = _time(_first(raw, "timestamp", "time"))
            if recorded_at is not None:
                earlier = [item for item in timeline if item[0] <= recorded_at]
                tokens = (earlier[-1] if earlier else timeline[0])[1]
        if tokens is None:
            continue
        attempts.append({
            "tokens": int(tokens),
            "size_bytes": int(size),
            "candidate_id": str(_first(raw, "candidate_id", "id", default="—")),
            "hypothesis": str(_first(raw, "hypothesis", "title", default="Untitled trial")),
            "phase": str(_first(raw, "phase", "status", default="recorded")),
            "accepted": bool(raw.get("accepted", False)),
            "timestamp": _first(raw, "timestamp", "time"),
            "token_gap": token_gap,
            "experiment": _experiment_details(raw),
        })
    return attempts


class DashboardState:
    """Build a stable view over small files that may be replaced atomically."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._last_good: dict[str, Any] | None = None

    def snapshot(self) -> dict[str, Any]:
        warnings: list[str] = []
        now = datetime.now(timezone.utc)

        state, state_source = _load_first(
            (ROOT / "status.json", ROOT / "state.json", ROOT / "dashboard.json"), warnings
        )
        state = state if isinstance(state, dict) else {}

        current, current_source = _load_first((ROOT / "current.json",), warnings)
        current = current if isinstance(current, dict) else {}

        baseline, baseline_source = _load_first(
            (ROOT / "baseline.json", ROOT / "baseline_current.json", ROOT / "truth.json"), warnings
        )
        baseline = baseline if isinstance(baseline, dict) else {}
        if isinstance(current.get("baseline"), dict):
            baseline = {**baseline, **current["baseline"]}
        if isinstance(state.get("baseline"), dict):
            baseline = {**baseline, **state["baseline"]}

        best, best_source = _load_first(
            (
                ROOT / "current_best.json",
                ROOT / "best.json",
                ROOT / "best" / "current.json",
                ROOT / "best" / "manifest.json",
            ),
            warnings,
        )
        best = best if isinstance(best, dict) else {}
        if isinstance(current.get("best"), dict):
            best = {**best, **current["best"]}
        state_best = _first(state, "current_best", "best")
        if isinstance(state_best, dict):
            best = {**best, **state_best}

        baseline_size = _normalise_size(baseline)
        baseline_seconds = _number(
            _first(baseline, "write_seconds", "elapsed_seconds", "duration_seconds", "runtime_seconds")
        )
        runtime_cap = _number(
            _first(baseline, "runtime_cap_seconds", "cap_seconds", "time_limit_seconds", "max_seconds")
        )
        if runtime_cap is None and baseline_seconds is not None:
            runtime_cap = float(baseline_seconds) * 4
        best_size = _normalise_size(best)
        improvement = baseline_size - best_size if baseline_size is not None and best_size is not None else None

        slot_records = _as_records(_first(state, "slots", "workers", default=[]), "slots", "workers")
        if not slot_records:
            for directory in (ROOT / "work", ROOT / "slots"):
                if not directory.is_dir():
                    continue
                for path in sorted(directory.glob("*/status.json")):
                    record = _read_json(path, warnings)
                    if isinstance(record, dict):
                        slot_records.append(record)
                for path in sorted(directory.glob("slot*.json")):
                    record = _read_json(path, warnings)
                    if isinstance(record, dict):
                        slot_records.append(record)
        slots = [_normalise_slot(raw, index, now) for index, raw in enumerate(slot_records[:64])]
        while len(slots) < 4:
            slots.append(_normalise_slot({}, len(slots), now))

        submissions: list[dict[str, Any]] = []
        for raw in _as_records(_first(state, "submissions", "candidates", default=[]), "submissions", "candidates"):
            submissions.append(_normalise_submission(raw))
        gate = state.get("gate")
        for raw in _as_records(gate, "queue", "submissions", "results", "candidates"):
            submissions.append(_normalise_submission(raw, "gate"))
        for path in (ROOT / "submissions.jsonl", ROOT / "logs" / "submissions.jsonl"):
            submissions.extend(_normalise_submission(raw) for raw in _read_jsonl(path, warnings))
        for path in (ROOT / "gate_results.jsonl", ROOT / "logs" / "gate_results.jsonl"):
            submissions.extend(_normalise_submission(raw, "gate") for raw in _read_jsonl(path, warnings))
        submissions = submissions[-MAX_RECENT:]

        trial_records: list[Any] = []
        for raw in _as_records(_first(state, "trials", "recent_trials", default=[]), "trials", "recent_trials"):
            trial_records.append(raw)
        for path in (
            ROOT / "trials.jsonl",
            ROOT / "observations.jsonl",
            ROOT / "logs" / "trials.jsonl",
            ROOT / "logs" / "observations.jsonl",
        ):
            trial_records.extend(_read_jsonl(path, warnings, limit=MAX_ATTEMPTS))
        trials = [_normalise_trial(raw) for raw in trial_records[-MAX_RECENT:]]

        progress: list[dict[str, Any]] = []
        for raw in _read_jsonl(ROOT / "progress.jsonl", warnings, limit=512):
            point = _normalise_progress(raw)
            if point is not None:
                progress.append(point)
        progress.sort(key=lambda point: (point["tokens"], point.get("cohort") or 0))

        current_cohort_raw = _first(state, "cohort", "round", "iteration", default=current.get("cohort"))
        current_cohort_number = _number(current_cohort_raw)
        current_cohort = int(current_cohort_number) if current_cohort_number is not None else None
        last_cohort = max(
            (int(point["cohort"]) for point in progress if point.get("cohort") is not None),
            default=-1,
        )
        tracked_tokens = progress[-1]["tokens"] if progress else 0
        active_tokens = sum(int(slot.get("tokens_used") or 0) for slot in slots)
        if (
            active_tokens > 0
            and best_size is not None
            and current_cohort is not None
            and current_cohort > last_cohort
        ):
            progress.append({
                "tokens": tracked_tokens + active_tokens,
                "size_bytes": best_size,
                "cohort": current_cohort,
                "candidate_id": str(_first(best, "candidate_id", "id", default="current")),
                "kind": "live",
                "timestamp": now.isoformat(),
                "live": True,
                "token_gap": False,
                "run_id": None,
            })

        persisted_cohorts = sorted({
            int(point["cohort"])
            for point in progress
            if point.get("cohort") is not None and not point.get("live")
        })
        missing_cohorts: list[int] = []
        if current_cohort is not None and persisted_cohorts:
            present = set(persisted_cohorts)
            missing_cohorts = [cohort for cohort in range(0, current_cohort) if cohort not in present]
        display_progress = _attach_frontier_experiments(
            _compact_progress(progress), trial_records,
        )
        attempts = _attempt_points(trial_records, progress)

        sources = [source for source in (state_source, current_source, baseline_source, best_source) if source]
        snapshot = {
            "generated_at": now.isoformat(),
            "cohort": _first(state, "cohort", "round", "iteration", default=current.get("cohort")),
            "system_status": str(_first(state, "status", "system_status", default="waiting")).lower(),
            "gate_status": str(_first(gate, "status", "state", default="idle")).lower(),
            "baseline": {
                "size_bytes": baseline_size,
                "write_seconds": baseline_seconds,
                "runtime_cap_seconds": runtime_cap,
                "artifact": _first(baseline, "artifact", "artifact_path", "path", "file"),
            },
            "best": {
                "size_bytes": best_size,
                "artifact": _first(best, "artifact", "artifact_path", "path", "file"),
                "candidate_id": _first(best, "candidate_id", "id", "name"),
                "improvement_bytes": improvement,
                "improvement_percent": (
                    improvement * 100.0 / baseline_size if improvement is not None and baseline_size else None
                ),
            },
            "slots": slots,
            "submissions": submissions,
            "trials": trials,
            "progress": {
                "points": display_progress,
                "attempts": attempts,
                "tracked_tokens": progress[-1]["tokens"] if progress else 0,
                "complete": not missing_cohorts,
                "missing_cohorts": missing_cohorts,
                "checkpoint_count": len(progress),
                "attempt_count": len(attempts),
            },
            "warnings": warnings,
            "sources": sources,
        }

        with self._lock:
            # Parsing a file during replacement should not blank a healthy dashboard.
            if warnings and self._last_good is not None and not sources:
                stale = dict(self._last_good)
                stale["generated_at"] = snapshot["generated_at"]
                stale["warnings"] = warnings + ["Showing the last complete snapshot."]
                stale["stale"] = True
                return stale
            snapshot["stale"] = False
            self._last_good = snapshot
        return snapshot


STATE = DashboardState()


class DashboardHandler(BaseHTTPRequestHandler):
    server_version = "pqmin-dashboard/1"

    def log_message(self, format: str, *args: Any) -> None:
        print(f"{self.log_date_time_string()} {self.client_address[0]} {format % args}", flush=True)

    def _send_bytes(self, payload: bytes, content_type: str, status: HTTPStatus = HTTPStatus.OK) -> None:
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(payload)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Content-Security-Policy", "default-src 'self'; style-src 'self'; script-src 'self'; connect-src 'self'")
        self.end_headers()
        self.wfile.write(payload)

    def do_GET(self) -> None:
        path = unquote(urlsplit(self.path).path)
        if path == "/api/state":
            payload = json.dumps(STATE.snapshot(), separators=(",", ":"), ensure_ascii=False).encode("utf-8")
            self._send_bytes(payload, "application/json; charset=utf-8")
            return
        if path == "/api/health":
            self._send_bytes(b'{"ok":true}', "application/json; charset=utf-8")
            return

        # Keep the URL used by the previous dashboard working across restarts.
        # The root route remains canonical, but old open tabs and bookmarks must
        # not turn into a misleading 404 when the research loop is healthy.
        relative = (
            "index.html"
            if path in {"/", "/research-dashboard.html"}
            else path.lstrip("/")
        )
        candidate = (WEB_ROOT / relative).resolve()
        try:
            candidate.relative_to(WEB_ROOT.resolve())
        except ValueError:
            self._send_bytes(b"Not found", "text/plain; charset=utf-8", HTTPStatus.NOT_FOUND)
            return
        if not candidate.is_file():
            self._send_bytes(b"Not found", "text/plain; charset=utf-8", HTTPStatus.NOT_FOUND)
            return
        mime, _ = mimetypes.guess_type(candidate.name)
        try:
            payload = candidate.read_bytes()
        except OSError:
            self._send_bytes(b"Unavailable", "text/plain; charset=utf-8", HTTPStatus.SERVICE_UNAVAILABLE)
            return
        self._send_bytes(payload, f"{mime or 'application/octet-stream'}; charset=utf-8")


def main() -> None:
    parser = argparse.ArgumentParser(description="Serve the pqmin live dashboard")
    parser.add_argument("--host", default=os.environ.get("PQMIN_DASHBOARD_HOST", "127.0.0.1"))
    parser.add_argument("--port", default=int(os.environ.get("PQMIN_DASHBOARD_PORT", "8765")), type=int)
    args = parser.parse_args()

    server = ThreadingHTTPServer((args.host, args.port), DashboardHandler)
    print(f"pqmin dashboard: http://{args.host}:{server.server_port}", flush=True)
    try:
        server.serve_forever(poll_interval=0.5)
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()


if __name__ == "__main__":
    main()
