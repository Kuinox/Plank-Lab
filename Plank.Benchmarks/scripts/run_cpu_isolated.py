#!/usr/bin/env python3
"""Run a command with one physical core reserved for everything else.

Linux CPU affinity is inherited by new threads and processes.  This runner uses
that property in both directions:

* every existing thread and every IRQ is moved onto one housekeeping core;
* the child command is launched on all remaining logical CPUs;
* exact pre-run affinities are restored when the child exits.

A detached watchdog owns the same snapshot.  If the runner is killed (including
with SIGKILL or because its controlling terminal disappears), the watchdog kills
the benchmark process group and restores the machine.  The snapshot is kept in
``/var/tmp/plank-benchmark-affinity`` until restoration completes.
"""

from __future__ import annotations

import argparse
import json
import os
import pwd
import re
import shutil
import signal
import subprocess
import sys
import time
import uuid
from pathlib import Path
from typing import Any, Iterable

STATE_ROOT = Path("/var/tmp/plank-benchmark-affinity")
PROC = Path("/proc")


def parse_cpu_list(value: str) -> set[int]:
    cpus: set[int] = set()
    for part in value.strip().split(","):
        if not part:
            continue
        bounds = part.split("-", 1)
        first = int(bounds[0])
        last = int(bounds[-1])
        cpus.update(range(first, last + 1))
    return cpus


def format_cpu_list(cpus: Iterable[int]) -> str:
    ordered = sorted(set(cpus))
    if not ordered:
        return ""
    ranges: list[str] = []
    first = previous = ordered[0]
    for cpu in ordered[1:]:
        if cpu == previous + 1:
            previous = cpu
            continue
        ranges.append(str(first) if first == previous else f"{first}-{previous}")
        first = previous = cpu
    ranges.append(str(first) if first == previous else f"{first}-{previous}")
    return ",".join(ranges)


def cpu_mask(cpus: Iterable[int]) -> str:
    mask = 0
    for cpu in cpus:
        mask |= 1 << cpu
    groups: list[str] = []
    while mask:
        groups.append(f"{mask & 0xffffffff:08x}")
        mask >>= 32
    return ",".join(reversed(groups or ["00000000"]))


def thread_siblings(cpu: int, allowed: set[int]) -> set[int]:
    path = Path(f"/sys/devices/system/cpu/cpu{cpu}/topology/thread_siblings_list")
    siblings = parse_cpu_list(path.read_text(encoding="ascii")) if path.exists() else {cpu}
    return siblings & allowed


def choose_layout(housekeeping_cpu: int | None) -> tuple[set[int], set[int], set[int]]:
    allowed = set(os.sched_getaffinity(0))
    if len(allowed) < 2:
        raise SystemExit("CPU isolation needs at least two allowed logical CPUs.")
    selected = min(allowed) if housekeeping_cpu is None else housekeeping_cpu
    if selected not in allowed:
        raise SystemExit(
            f"housekeeping CPU {selected} is outside this process's allowed set "
            f"({format_cpu_list(allowed)}).")
    housekeeping = thread_siblings(selected, allowed)
    benchmark = allowed - housekeeping
    if not benchmark:
        raise SystemExit("The housekeeping physical core leaves no CPU for the benchmark.")
    return allowed, housekeeping, benchmark


def read_thread_identity(tid: int) -> dict[str, Any] | None:
    try:
        stat = (PROC / str(tid) / "stat").read_text(encoding="ascii")
        after_name = stat[stat.rfind(")") + 2:].split()
        start_time = int(after_name[19])
        status = (PROC / str(tid) / "status").read_text(encoding="ascii")
        tgid_match = re.search(r"^Tgid:\s+(\d+)$", status, re.MULTILINE)
        ppid_match = re.search(r"^PPid:\s+(\d+)$", status, re.MULTILINE)
        if tgid_match is None or ppid_match is None:
            return None
        return {
            "tid": tid,
            "tgid": int(tgid_match.group(1)),
            "ppid": int(ppid_match.group(1)),
            "startTime": start_time,
            "affinity": sorted(os.sched_getaffinity(tid)),
        }
    except (FileNotFoundError, ProcessLookupError, PermissionError, ValueError):
        return None


def list_tids() -> list[int]:
    tids: list[int] = []
    for process_path in PROC.iterdir():
        if not process_path.name.isdigit():
            continue
        try:
            tids.extend(int(path.name) for path in (process_path / "task").iterdir()
                        if path.name.isdigit())
        except (FileNotFoundError, PermissionError, ProcessLookupError):
            pass
    return sorted(set(tids))


def snapshot_threads() -> dict[str, dict[str, Any]]:
    snapshot: dict[str, dict[str, Any]] = {}
    for tid in list_tids():
        if (identity := read_thread_identity(tid)) is not None:
            snapshot[str(tid)] = identity
    return snapshot


def snapshot_irqs() -> dict[str, str]:
    snapshot: dict[str, str] = {}
    default_path = PROC / "irq" / "default_smp_affinity"
    try:
        snapshot[str(default_path)] = default_path.read_text(encoding="ascii").strip()
    except (FileNotFoundError, PermissionError, OSError):
        pass
    for path in sorted((PROC / "irq").glob("[0-9]*/smp_affinity_list")):
        try:
            snapshot[str(path)] = path.read_text(encoding="ascii").strip()
        except (FileNotFoundError, PermissionError, OSError):
            pass
    return snapshot


def write_json_atomic(path: Path, value: dict[str, Any]) -> None:
    temporary = path.with_suffix(".tmp")
    temporary.write_text(json.dumps(value, sort_keys=True), encoding="utf-8")
    os.replace(temporary, path)


def load_state(path: Path) -> dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8"))


def pin_threads(snapshot: dict[str, dict[str, Any]], housekeeping: set[int],
                changed_threads: list[str], persist: Any) -> tuple[int, int]:
    changed = failed = 0
    # A second pass catches threads created by a process while the first pass was
    # walking /proc.  Their original mask is captured before it is changed.
    for _ in range(2):
        added = False
        for tid in list_tids():
            key = str(tid)
            if key not in snapshot:
                if (identity := read_thread_identity(tid)) is None:
                    continue
                snapshot[key] = identity
                added = True
        # The watchdog must know the old mask before any newly discovered
        # thread is changed.
        if added:
            persist()
        candidates: list[tuple[str, int, set[int]]] = []
        for key in list(snapshot):
            tid = int(key)
            try:
                current = set(os.sched_getaffinity(tid))
                target = current & housekeeping
                if not target:
                    failed += 1
                    continue
                if current != target:
                    if key not in changed_threads:
                        changed_threads.append(key)
                    candidates.append((key, tid, target))
            except (ProcessLookupError, PermissionError, OSError):
                failed += 1
        # Persist the whole batch before making any affinity change.  This is
        # both crash-safe and dramatically cheaper than serializing a large
        # /proc snapshot once per thread.
        if candidates:
            persist()
        for _key, tid, target in candidates:
            try:
                os.sched_setaffinity(tid, target)
                changed += 1
            except (ProcessLookupError, PermissionError, OSError):
                failed += 1
    return changed, failed


def pin_irqs(snapshot: dict[str, str], housekeeping: set[int], changed: list[str],
             persist: Any) -> tuple[int, int]:
    changed_count = 0
    failed = 0
    default_path = str(PROC / "irq" / "default_smp_affinity")
    for raw_path in snapshot:
        path = Path(raw_path)
        target = cpu_mask(housekeeping) if raw_path == default_path else format_cpu_list(housekeeping)
        try:
            # Record the restore obligation before changing procfs.  If the
            # runner dies after the write, the detached watchdog has enough
            # information to put this IRQ back.
            changed.append(raw_path)
            persist()
            path.write_text(target, encoding="ascii")
            changed_count += 1
        except (FileNotFoundError, PermissionError, OSError):
            changed.remove(raw_path)
            # Managed and per-CPU interrupts commonly reject affinity changes.
            failed += 1
    persist()
    return changed_count, failed


def same_thread(identity: dict[str, Any]) -> bool:
    current = read_thread_identity(int(identity["tid"]))
    return current is not None and current["startTime"] == identity["startTime"]


def inherited_affinity(identity: dict[str, Any], snapshot: dict[str, dict[str, Any]],
                       allowed: set[int]) -> set[int]:
    tgid = str(identity["tgid"])
    if tgid in snapshot:
        return set(snapshot[tgid]["affinity"])
    seen: set[int] = set()
    parent = int(identity["ppid"])
    while parent > 0 and parent not in seen:
        seen.add(parent)
        if str(parent) in snapshot:
            return set(snapshot[str(parent)]["affinity"])
        parent_identity = read_thread_identity(parent)
        if parent_identity is None:
            break
        parent = int(parent_identity["ppid"])
    return allowed


def restore(state: dict[str, Any]) -> tuple[int, int]:
    snapshot: dict[str, dict[str, Any]] = state["threads"]
    allowed = set(state["allowedCpus"])
    housekeeping = set(state["housekeepingCpus"])
    restored = failed = 0
    for key in state.get("changedThreads", snapshot.keys()):
        identity = snapshot.get(key)
        if identity is None:
            continue
        if not same_thread(identity):
            continue
        try:
            target = set(identity["affinity"])
            if set(os.sched_getaffinity(int(identity["tid"]))) == target:
                continue
            os.sched_setaffinity(int(identity["tid"]), target)
            restored += 1
        except (ProcessLookupError, PermissionError, OSError):
            failed += 1

    # Services and kernel workers created during a long run inherited the
    # housekeeping mask but were not in the original snapshot.  Restore those
    # to the closest surviving ancestor's original mask (or the full pre-run
    # mask when no ancestor survives).
    for tid in list_tids():
        if str(tid) in snapshot:
            continue
        identity = read_thread_identity(tid)
        if identity is None:
            continue
        try:
            current = set(os.sched_getaffinity(tid))
            if current and current <= housekeeping:
                target = inherited_affinity(identity, snapshot, allowed)
                if current == target:
                    continue
                os.sched_setaffinity(tid, target)
                restored += 1
        except (ProcessLookupError, PermissionError, OSError):
            # Unknown threads were created after the snapshot, so the runner
            # never changed them directly. Movable children inherit the pinned
            # mask and are restored above; fixed per-CPU kernel workers reject
            # sched_setaffinity and must retain their kernel-owned mask.
            pass

    irq_snapshot: dict[str, str] = state.get("irqs", {})
    for raw_path in state.get("changedIrqs", []):
        try:
            path = Path(raw_path)
            target = irq_snapshot[raw_path]
            if path.read_text(encoding="ascii").strip() == target:
                continue
            path.write_text(target, encoding="ascii")
            restored += 1
        except (FileNotFoundError, KeyError, PermissionError, OSError):
            failed += 1
    return restored, failed


def terminate_process_group(pgid: int | None) -> None:
    if not pgid:
        return
    try:
        os.killpg(pgid, signal.SIGTERM)
    except ProcessLookupError:
        return
    deadline = time.monotonic() + 10
    while time.monotonic() < deadline:
        try:
            os.killpg(pgid, 0)
        except ProcessLookupError:
            return
        time.sleep(0.1)
    try:
        os.killpg(pgid, signal.SIGKILL)
    except ProcessLookupError:
        pass


def watchdog(state_path: Path, owner_pid: int, done_path: Path) -> int:
    while not done_path.exists():
        try:
            os.kill(owner_pid, 0)
        except ProcessLookupError:
            state = load_state(state_path)
            terminate_process_group(state.get("benchmarkPgid"))
            restored, failed = restore(state)
            print(f"watchdog restored {restored} affinities ({failed} failures)", flush=True)
            return 0 if failed == 0 else 1
        time.sleep(0.5)
    return 0


def invoking_user() -> pwd.struct_passwd | None:
    if "SUDO_UID" not in os.environ:
        return None
    return pwd.getpwuid(int(os.environ["SUDO_UID"]))


def child_setup(benchmark: set[int], user: pwd.struct_passwd | None) -> None:
    os.sched_setaffinity(0, benchmark)
    if user is not None:
        os.initgroups(user.pw_name, user.pw_gid)
        os.setgid(user.pw_gid)
        os.setuid(user.pw_uid)


def run(args: argparse.Namespace) -> int:
    if os.geteuid() != 0:
        raise SystemExit("run_cpu_isolated.py must run as root (normally through sudo).")
    allowed, housekeeping, benchmark = choose_layout(args.housekeeping_cpu)
    print(f"housekeeping CPUs: {format_cpu_list(housekeeping)}", flush=True)
    print(f"benchmark CPUs:    {format_cpu_list(benchmark)}", flush=True)
    print(f"benchmark command: {' '.join(args.command)}", flush=True)

    STATE_ROOT.mkdir(mode=0o700, parents=True, exist_ok=True)
    run_directory = STATE_ROOT / f"run-{uuid.uuid4().hex}"
    run_directory.mkdir(mode=0o700)
    state_path = run_directory / "state.json"
    done_path = run_directory / "restored"
    watchdog_log_path = run_directory / "watchdog.log"
    state: dict[str, Any] = {
        "ownerPid": os.getpid(),
        "allowedCpus": sorted(allowed),
        "housekeepingCpus": sorted(housekeeping),
        "benchmarkCpus": sorted(benchmark),
        "threads": snapshot_threads(),
        "changedThreads": [],
        "irqs": {} if args.no_irqs else snapshot_irqs(),
        "changedIrqs": [],
        "benchmarkPgid": None,
    }
    write_json_atomic(state_path, state)

    with watchdog_log_path.open("ab", buffering=0) as watchdog_log:
        monitor = subprocess.Popen(
            [sys.executable, str(Path(__file__).resolve()), "--watchdog", str(state_path),
             str(os.getpid()), str(done_path)],
            stdin=subprocess.DEVNULL,
            stdout=watchdog_log,
            stderr=subprocess.STDOUT,
            start_new_session=True,
            close_fds=True)

    child: subprocess.Popen[bytes] | None = None
    received_signal: int | None = None

    def forward(signum: int, _frame: Any) -> None:
        nonlocal received_signal
        received_signal = signum
        if child is not None:
            try:
                os.killpg(child.pid, signum)
            except ProcessLookupError:
                pass

    previous_handlers = {
        signum: signal.signal(signum, forward)
        for signum in (signal.SIGINT, signal.SIGTERM, signal.SIGHUP)
    }
    try:
        persist = lambda: write_json_atomic(state_path, state)
        changed, pin_failures = pin_threads(
            state["threads"], housekeeping, state["changedThreads"], persist)
        changed_irqs, irq_failures = pin_irqs(
            state["irqs"], housekeeping, state["changedIrqs"], persist)
        print(f"pinned {changed} thread affinities ({pin_failures} unmovable); "
              f"pinned {changed_irqs} IRQ masks ({irq_failures} unmovable)", flush=True)
        if args.settle_seconds:
            time.sleep(args.settle_seconds)

        user = invoking_user()
        environment = os.environ.copy()
        environment["PLANK_BENCHMARK_CPUS"] = format_cpu_list(benchmark)
        environment["PLANK_HOUSEKEEPING_CPUS"] = format_cpu_list(housekeeping)
        if user is not None:
            environment.update(HOME=user.pw_dir, USER=user.pw_name, LOGNAME=user.pw_name)
        child = subprocess.Popen(
            args.command,
            env=environment,
            start_new_session=True,
            preexec_fn=lambda: child_setup(benchmark, user))
        state["benchmarkPgid"] = child.pid
        write_json_atomic(state_path, state)
        result = child.wait()
        if received_signal is not None:
            return 128 + received_signal
        return result
    finally:
        for signum, handler in previous_handlers.items():
            signal.signal(signum, handler)
        if child is not None and child.poll() is None:
            terminate_process_group(child.pid)
            child.wait()
        restored, restore_failures = restore(state)
        print(f"restored {restored} affinities ({restore_failures} failures)", flush=True)
        done_path.touch()
        try:
            monitor.wait(timeout=3)
        except subprocess.TimeoutExpired:
            monitor.terminate()
        if restore_failures == 0:
            shutil.rmtree(run_directory, ignore_errors=True)
        else:
            print(f"recovery snapshot retained at {state_path}", file=sys.stderr, flush=True)


def parse_args() -> argparse.Namespace:
    if len(sys.argv) >= 2 and sys.argv[1] == "--watchdog":
        if len(sys.argv) != 5:
            raise SystemExit("invalid watchdog invocation")
        return argparse.Namespace(
            watchdog=(Path(sys.argv[2]), int(sys.argv[3]), Path(sys.argv[4])))
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--housekeeping-cpu", type=int,
                        help="One logical CPU identifying the physical housekeeping core (default: first allowed).")
    parser.add_argument("--settle-seconds", type=float, default=5,
                        help="Pause after isolation before starting the command (default: 5).")
    parser.add_argument("--no-irqs", action="store_true",
                        help="Do not move interrupt affinities.")
    parser.add_argument("command", nargs=argparse.REMAINDER)
    args = parser.parse_args()
    if args.command[:1] == ["--"]:
        args.command = args.command[1:]
    if not args.command:
        parser.error("a command is required after --")
    args.watchdog = None
    return args


def main() -> int:
    args = parse_args()
    if args.watchdog is not None:
        return watchdog(*args.watchdog)
    return run(args)


if __name__ == "__main__":
    raise SystemExit(main())
