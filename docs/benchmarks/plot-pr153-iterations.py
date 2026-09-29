#!/usr/bin/env python3
"""Regenerate PR #153 ordered iteration charts from the published JSON samples."""

import json
import math
import re
from pathlib import Path

import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt


HERE = Path(__file__).resolve().parent
OUT = HERE / "iteration-curves"
OUT.mkdir(exist_ok=True)

CAMPAIGNS = (
    ("portable-int32-all-width-candidate", "x64 · INT32 widths"),
    ("portable-int32-arm-pr153", "ARM64 · INT32"),
    ("portable-integer-other-types-pr153", "x64 · nullable INT32 / INT64"),
    ("portable-integer-other-types-arm-pr153", "ARM64 · nullable INT32 / INT64"),
)

COLORS = ("#2176ae", "#d55e00")


def slug(label):
    return re.sub(r"[^a-z0-9]+", "-", label.lower()).strip("-")


def cases(data):
    rows = []
    for row in data["rows"]:
        label = f"Width {row['width']}" if "width" in row else row["case"]
        rows.append((label, row))
    if "mixed_width_run" in data:
        rows.append(("Mixed widths 1–22", data["mixed_width_run"]))
    return rows


def draw(ax, row, *, late=False):
    before = row["baseline_samples_ms"]
    after = row["candidate_samples_ms"]
    assert len(before) == len(after) == 100
    assert all(value > 0 for value in before + after)
    start = 21 if late else 1
    iterations = range(start, 101)
    ax.plot(iterations, before[start - 1 :], color=COLORS[0], linewidth=1.45,
            label="Before · master", alpha=0.9)
    ax.plot(iterations, after[start - 1 :], color=COLORS[1], linewidth=1.45,
            label="After · PR #153", alpha=0.9)
    ax.set_xlim(start, 100)
    ax.grid(alpha=0.22)
    ax.set_xlabel("Iteration")
    ax.set_ylabel("Time / iteration (ms)")
    if not late:
        ax.set_yscale("log")


def individual(stem, campaign, label, row):
    fig, axes = plt.subplots(1, 2, figsize=(12.4, 4.3), layout="constrained")
    draw(axes[0], row)
    draw(axes[1], row, late=True)
    axes[0].set_title("All 100 · log scale")
    axes[1].set_title("Iterations 21–100 · linear scale")
    handles, labels = axes[0].get_legend_handles_labels()
    fig.legend(handles, labels, loc="lower center", ncol=2, bbox_to_anchor=(0.5, -0.055))
    fig.suptitle(f"{campaign} · {label}", y=1.06, fontsize=15, fontweight="bold")
    path = OUT / f"{stem}-{slug(label)}.png"
    fig.savefig(path, dpi=160, bbox_inches="tight")
    plt.close(fig)
    return path


def overview(stem, campaign, rows):
    cols = 2
    fig, axes = plt.subplots(math.ceil(len(rows) / cols), cols,
                             figsize=(14, 3.75 * math.ceil(len(rows) / cols)),
                             layout="constrained")
    axes = list(axes.flat)
    for ax, (label, row) in zip(axes, rows):
        draw(ax, row)
        ax.set_title(label, fontsize=12, fontweight="bold")
    for ax in axes[len(rows):]:
        ax.set_visible(False)
    handles, labels = axes[0].get_legend_handles_labels()
    fig.legend(handles, labels, loc="lower center", ncol=2, bbox_to_anchor=(0.5, -0.025))
    fig.suptitle(f"{campaign} · ordered read time", y=1.02, fontsize=17, fontweight="bold")
    path = HERE / f"{stem}-iterations.png"
    fig.savefig(path, dpi=170, bbox_inches="tight")
    plt.close(fig)
    return path


def main():
    manifest = {}
    for stem, campaign in CAMPAIGNS:
        data = json.loads((HERE / f"{stem}-v1.json").read_text())
        rows = cases(data)
        overview(stem, campaign, rows)
        manifest[stem] = []
        for label, row in rows:
            path = individual(stem, campaign, label, row)
            manifest[stem].append({"label": label, "path": path.relative_to(HERE).as_posix()})
    (OUT / "manifest.json").write_text(json.dumps(manifest, indent=2) + "\n")


if __name__ == "__main__":
    main()
