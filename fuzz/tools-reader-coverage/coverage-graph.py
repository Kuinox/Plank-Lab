#!/usr/bin/env python3
"""Render fuzz/<target>-coverage.csv and fuzz/disagreements/ as one HTML page.

Usage: coverage-graph.py <csv> <disagreements_dir> <out.html>
"""
import csv
import json
import os
import re
import sys
from collections import defaultdict


def load_samples(path):
    series = defaultdict(list)
    with open(path) as f:
        for row in csv.DictReader(f):
            try:
                series[row["instance"]].append(
                    [int(row["unix_time"]), int(row["edges_found"]), int(row["corpus_count"]), int(row["execs_done"])]
                )
            except (KeyError, ValueError):
                continue
    return {k: sorted(v) for k, v in series.items()}


# An instance whose execs_done has not moved for this long is not running: its
# fuzzer_stats file is just left over from a stopped fleet.
STALE_AFTER = 300
# A gap between samples longer than this is time the campaign was stopped; it is
# cut out of the x axis and replaced by one nominal sample interval.
GAP = 600
GAP_STEP = 60


def drop_idle(series):
    """Keep only samples taken while an instance was making progress."""
    kept = {}
    for name, rows in series.items():
        out, last_execs, last_change = [], None, None
        for row in rows:
            t, execs = row[0], row[3]
            if execs != last_execs:
                last_execs, last_change = execs, t
            if t - last_change <= STALE_AFTER:
                out.append(row)
        if out:
            kept[name] = out
    return kept


def active_clock(series):
    """Map wall-clock sample times to running time with stopped periods removed."""
    times = sorted({row[0] for rows in series.values() for row in rows})
    mapping, clock, prev = {}, 0, None
    for t in times:
        if prev is not None:
            dt = t - prev
            clock += dt if dt <= GAP else GAP_STEP
        mapping[t] = clock
        prev = t
    return times, mapping


def to_active(t, times, mapping):
    import bisect
    i = bisect.bisect_right(times, t) - 1
    if i < 0:
        return 0
    return mapping[times[i]] + min(t - times[i], GAP_STEP)


def family(key):
    """Coarser grouping for display: one row per cause, not per column name or value."""
    key = re.sub(r"Plank=[^,]*, Parquet\.Net=[^,]*", "Plank=?, Parquet.Net=?", key)
    # Column names and parameter names: short quoted tokens, never the
    # apostrophe in "Couldn't" or a quoted native message.
    key = re.sub(r"(?<![A-Za-z])'[^']{0,16}'(?![A-Za-z])", "'?'", key)
    key = re.sub(r'"[^"]{0,16}"', '"?"', key)
    key = re.sub(r"\(System\.[A-Za-z#]+\)", "(?)", key)
    key = re.sub(r"System\.(U?Int#|Double|Single|DateTime|Boolean|Decimal)", "?", key)
    key = re.sub(r"row group #, column #, row #", "", key)
    return key


def load_buckets(root):
    buckets = []
    if not os.path.isdir(root):
        return buckets
    for name in sorted(os.listdir(root)):
        d = os.path.join(root, name)
        desc = os.path.join(d, "bucket.txt")
        if not os.path.isfile(desc):
            continue
        with open(desc, errors="replace") as f:
            key = f.readline().strip()
        inputs = [p for p in os.listdir(d) if p.endswith(".bin")]
        first = min((os.path.getmtime(os.path.join(d, p)) for p in inputs), default=os.path.getmtime(desc))
        if key.startswith("VALUE-MISMATCH"):
            kind = "value"
        elif key.startswith("PLANK-UNEXPECTED"):
            kind = "plank"
        else:
            kind = "accept"
        buckets.append({"id": name, "key": key, "kind": kind, "first": int(first), "examples": len(inputs)})
    families = {}
    for b in sorted(buckets, key=lambda b: b["first"]):
        f = families.setdefault(family(b["key"]), {"id": b["id"], "key": family(b["key"]), "kind": b["kind"],
                                                   "first": b["first"], "examples": 0, "variants": 0})
        f["examples"] += b["examples"]
        f["variants"] += 1
    return sorted(families.values(), key=lambda b: b["first"])


def main():
    csv_path, buckets_dir, out = sys.argv[1:4]
    series = drop_idle(load_samples(csv_path))
    times, mapping = active_clock(series)
    series = {k: [[mapping[r[0]]] + r[1:] for r in rows] for k, rows in series.items()}
    buckets = load_buckets(buckets_dir)
    for b in buckets:
        b["first"] = to_active(b["first"], times, mapping)
    data = {"series": series, "buckets": buckets}
    template_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "coverage-graph.template.html")
    with open(template_path) as f:
        page = f.read()
    with open(out, "w") as f:
        f.write(page.replace("/*__DATA__*/null", json.dumps(data, separators=(",", ":"))))


if __name__ == "__main__":
    main()
