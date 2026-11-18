#!/usr/bin/env python3
"""Reader-side coverage analysis over one or more cobertura reports from coverage.sh.

  coverage-tools.py cold <min-cold-lines> <report.xml>...
      Merge the reports (a line counts as hit if any report hit it) and rank the
      methods with the most unhit lines. Writer-only code and instruction-set
      specific kernels (marked separately) are left out of the reader total.

  coverage-tools.py diff <base.xml> <new.xml> [top]
      Lines the new report hits that the base did not, grouped by method.

  coverage-tools.py annotate <report.xml> <method-name>
      Print a method's source with per-line hit counts.
"""
import collections
import glob
import os
import re
import sys
import xml.etree.ElementTree as ET

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
WRITER = re.compile(r'^(Writing|Dataset\.Dataset(Writer|Buffer))|RowWriter|PipelineRowWriter|RowBufferSlot'
                    r'|RowBufferSize|RowValueSize|RowApiColumnWriteState|AlpEncodingPrimitives')
ISA = re.compile(r'(MiniBlockFastW\d+|Avx512|Avx2|Bmi2|Vector(ized)?|Sse|Simd|Portable|Scalar|Pdep|Interleave)')


def lines(path):
    """{(class, method, file, line): hits}"""
    out = {}
    for c in ET.parse(path).iter('class'):
        cls = c.get('name').split('/')[0].replace('Plank.', '')
        for m in c.iter('method'):
            for l in m.iter('line'):
                key = (cls, m.get('name'), c.get('filename'), int(l.get('number')))
                out[key] = max(out.get(key, 0), int(l.get('hits')))
    return out


def merged(paths):
    u = {}
    for p in paths:
        for k, v in lines(p).items():
            u[k] = max(u.get(k, 0), v)
    return u


def cold(threshold, paths):
    u = merged(paths)
    total = hit = 0
    cold_lines = collections.Counter()
    method_lines = collections.Counter()
    for (cls, method, _, _), h in u.items():
        if WRITER.search(cls):
            continue
        total += 1
        hit += h > 0
        method_lines[(cls, method)] += 1
        cold_lines[(cls, method)] += h == 0
    print(f'reader-side {hit}/{total} = {100 * hit / total:.1f}%')
    rows = sorted(((n, k) for k, n in cold_lines.items() if n >= threshold), reverse=True)
    for n, (cls, method) in rows[:60]:
        mark = '*' if ISA.search(method) else ' '
        print(f'{n:5d}/{method_lines[(cls, method)]:<5d} {mark} {cls.split(".")[-1]}.{method}')


def diff(base, new, top):
    b = {k for k, v in lines(base).items() if v > 0}
    n = {k for k, v in lines(new).items() if v > 0}
    gained = n - b
    by = collections.Counter((k[2].split('/')[-1], k[1]) for k in gained)
    print(f'lines newly covered: {len(gained)}')
    for (f, m), c in by.most_common(top):
        print(f'{c:5d} {f}:{m}')


def annotate(path, method):
    for c in ET.parse(path).iter('class'):
        for m in c.iter('method'):
            if m.get('name') != method:
                continue
            hits = {int(l.get('number')): int(l.get('hits')) for l in m.iter('line')}
            if not hits:
                continue
            name = c.get('filename').split('/')[-1]
            found = glob.glob(f'{ROOT}/library/Plank/Plank/**/{name}', recursive=True)
            src = open(found[0]).read().split('\n') if found else []
            lo, hi = min(hits), max(hits)
            print(f'== {method} {name}:{lo}-{hi}')
            for i in range(lo, hi + 1):
                h = hits.get(i)
                mark = '     ' if h is None else ('  ---' if h == 0 else f'{min(h, 99999):5d}')
                print(f'{mark} {i:5d} {src[i - 1][:150] if i - 1 < len(src) else ""}')


if __name__ == '__main__':
    if len(sys.argv) < 3:
        sys.exit(__doc__)
    cmd = sys.argv[1]
    if cmd == 'cold':
        cold(int(sys.argv[2]), sys.argv[3:])
    elif cmd == 'diff':
        diff(sys.argv[2], sys.argv[3], int(sys.argv[4]) if len(sys.argv) > 4 else 25)
    elif cmd == 'annotate':
        annotate(sys.argv[2], sys.argv[3])
    else:
        sys.exit(__doc__)
