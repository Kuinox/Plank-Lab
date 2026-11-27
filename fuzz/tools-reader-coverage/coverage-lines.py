#!/usr/bin/env python3
"""Print source lines with merged hit counts (max over the per-tier coverlet JSON reports).
Usage: coverage-lines.py <tag> <file-suffix> <first> <last>"""
import glob, json, os, sys
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
tag, suffix, a, b = sys.argv[1], sys.argv[2], int(sys.argv[3]), int(sys.argv[4])
hits, src = {}, None
for p in glob.glob(os.path.join(ROOT, 'fuzz/coverage/history', f'reader-{tag}-*..json')):
    for mod in json.load(open(p)).values():
        for f, cls in mod.items():
            if not f.endswith(suffix):
                continue
            src = f
            for ms in cls.values():
                for m in ms.values():
                    for ln, h in m['Lines'].items():
                        hits[int(ln)] = max(hits.get(int(ln), 0), h)
text = open(src).read().split('\n')
for n in range(a, b + 1):
    h = hits.get(n)
    print(f'{"" if h is None else h:>9} {n:5} {text[n-1]}')
