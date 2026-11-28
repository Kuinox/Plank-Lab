#!/usr/bin/env python3
"""Turn the checked-access rewriter's sites.tsv into fuzz/notes/unchecked-access-sites.md (the per-site table).

Usage: checked-inventory.py <sites.tsv> <header.md> <out.md>
The header (hand-written review: what is not checked and why) is copied first, then a summary and one table per file.
"""
import collections, sys

BOUND = {
    "register": "registers the span's logical length (start of a tracked region)",
    "checked+register": "n elements must fit in the source ref's span; result registered",
    "form": "derived ref must stay within [start, end] of the base's span (one past end allowed)",
    "form-keep": "as form; the derived ref is registered (kept in a ref local / passed on)",
    "form-ptr": "derived pointer within the base's span",
    "access": "sizeof(T) bytes at the element must lie in the base's span",
    "checked": "access width (sizeof(T) / element) must lie in the base's span",
    "checked (vector width)": "whole vector width from the element offset must lie in the span",
    "checked (every lane)": "every gathered lane's address within the base pointer's span",
}


def bound(action):
    if action in BOUND:
        return BOUND[action]
    if action.startswith("checked ("):
        return action[len("checked ("):-1] + " from the pointer must lie in its span"
    return action


def main():
    sites, header, out = sys.argv[1:4]
    rows = [l.rstrip("\n").split("\t") for l in open(sites) if not l.startswith("site\t")]
    rows = [r + [""] * (4 - len(r)) for r in rows]
    by_file = collections.OrderedDict()
    for site, api, action, arg in sorted(rows, key=lambda r: (r[0].rsplit(":", 1)[0], int(r[0].rsplit(":", 1)[1]))):
        by_file.setdefault(site.rsplit(":", 1)[0], []).append((site, api, action, arg))
    actions = collections.Counter(r[2].split(" (")[0] if r[2].startswith(("UNHANDLED", "not checked", "safe")) else r[2] for r in rows)
    with open(out, "w") as f:
        f.write(open(header).read().rstrip() + "\n\n")
        f.write(f"## Per-site table (generated from sites.tsv: {len(rows)} sites in {len(by_file)} files)\n\n")
        f.write("| action | sites |\n|---|---|\n")
        for a, n in actions.most_common():
            f.write(f"| {a} | {n} |\n")
        for file, items in by_file.items():
            f.write(f"\n### {file}\n\n| line | API | buffer (argument) | bound applied |\n|---|---|---|---|\n")
            for site, api, action, arg in items:
                arg = arg.replace("|", "\\|")
                if len(arg) > 90:
                    arg = arg[:87] + "..."
                f.write(f"| {site.rsplit(':', 1)[1]} | `{api}` | `{arg}` | {bound(action)} |\n")


if __name__ == "__main__":
    main()
