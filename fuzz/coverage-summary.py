#!/usr/bin/env python3
"""Reader-side line and branch coverage, merged over the per-tier coverlet JSON reports.

  coverage-summary.py <tag>            totals + per-area table (JSON on stdout with --json)
  coverage-summary.py <tag> --uncovered <area-or-class-substring>
      list the uncovered branches/methods for one area, to classify them

A branch counts as covered if any tier took it (coverlet branch = Line/Offset/Path/Ordinal).
Writer-only code is left out, as in coverage-tools.py. ISA-specific kernels are kept: the
tiers exist so that they run.
"""
import collections
import glob
import json
import os
import re
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
HIST = os.path.join(ROOT, 'fuzz', 'coverage', 'history')
WRITER = re.compile(r'^(Writing|Dataset\.Dataset(Writer|Buffer))|RowWriter|PipelineRowWriter|RowBufferSlot'
                    r'|RowBufferSize|RowValueSize|RowApiColumnWriteState|AlpEncodingPrimitives')

# Areas, first match wins. Keyed on the class name with the "Plank." prefix removed.
AREAS = [
    ('Thrift / footer metadata', r'^Reading\.(CompactProtocol|Physical\.Internal\.PhysicalMetadata|Physical\.ParquetFileMetadata|Physical\.ParquetRowGroupMetadata|Physical\.ParquetColumnChunkMetadata)|Thrift|Metadata'),
    ('Page headers & cursor', r'PageHeader|PageCursor|ParquetPageReader|PageReader'),
    ('Page index / pruning / bloom', r'PageMetadata|OffsetIndex|ColumnIndex|Pruner|Bloom|XxHash'),
    ('Delta / BSS / ALP decoders', r'Delta|ByteStreamSplit|Alp'),
    ('Column chunk decoding', r'ColumnChunkReader|ColumnBuffer|Rle|Dictionary|Decode'),
    ('Logical conversions', r'Decimal|Timestamp|Int96|Converter|Logical|Float16|Uuid|Date|Time'),
    ('Compression', r'Compression|Snappy|Zstd|Lz4|Gzip|Brotli|Deflate'),
    ('Row API & generated readers', r'^RowApi|RowReader|RowSchema|GeneratedRow|RowView'),
    ('Schema', r'^Schema\.|ColumnDefinition|ParquetSchema|LeafColumn|ColumnOptions'),
    ('Other reader code', r'.'),
]


def load(tag):
    paths = sorted(glob.glob(os.path.join(HIST, f'reader-{tag}-*..json')))
    if not paths:
        sys.exit(f'no reports for tag {tag} in {HIST}')
    lines, branches, methods = {}, {}, {}
    for p in paths:
        data = json.load(open(p))
        for module in data.values():
            for fname, classes in module.items():
                for cls, ms in classes.items():
                    c = cls.replace('Plank.', '', 1).split('/')[0]
                    if WRITER.search(c):
                        continue
                    for mname, m in ms.items():
                        key = (c, mname)
                        methods.setdefault(key, fname)
                        for ln, hits in m.get('Lines', {}).items():
                            k = (fname, int(ln))
                            lines[k] = (c, mname, max(lines.get(k, (0, 0, 0))[2], hits))
                        for b in m.get('Branches', []):
                            k = (fname, b['Line'], b['Offset'], b['Path'], b['Ordinal'])
                            prev = branches.get(k, (c, mname, 0))[2]
                            branches[k] = (c, mname, max(prev, b['Hits']))
    return paths, lines, branches, methods


def area_of(cls):
    for name, rx in AREAS:
        if re.search(rx, cls):
            return name
    return 'Other reader code'


def summarize(tag):
    paths, lines, branches, _ = load(tag)
    per = collections.defaultdict(lambda: [0, 0, 0, 0])
    for (c, _, h) in lines.values():
        a = per[area_of(c)]; a[0] += h > 0; a[1] += 1
    for (c, _, h) in branches.values():
        a = per[area_of(c)]; a[2] += h > 0; a[3] += 1
    tl = sum(v[0] for v in per.values()), sum(v[1] for v in per.values())
    tb = sum(v[2] for v in per.values()), sum(v[3] for v in per.values())
    return {
        'tag': tag, 'tiers': [os.path.basename(p) for p in paths],
        'lines': {'covered': tl[0], 'total': tl[1]},
        'branches': {'covered': tb[0], 'total': tb[1]},
        'areas': [{'area': n, 'lines': [per[n][0], per[n][1]], 'branches': [per[n][2], per[n][3]]}
                  for n, _ in AREAS if per[n][1]],
    }


def uncovered(tag, needle):
    _, lines, branches, methods = load(tag)
    hit_by_method = collections.Counter(); total_by_method = collections.Counter()
    for (c, m, h) in lines.values():
        total_by_method[(c, m)] += 1; hit_by_method[(c, m)] += h > 0
    missed = collections.defaultdict(list)
    for (f, ln, off, path, ordn), (c, m, h) in branches.items():
        if h == 0 and (needle in c or needle == area_of(c)):
            missed[(c, m)].append(ln)
    for (c, m), lns in sorted(missed.items(), key=lambda kv: -len(kv[1])):
        print(f'{len(lns):4} missed branches  lines {hit_by_method[(c, m)]}/{total_by_method[(c, m)]}  '
              f'{c}.{m.split("::")[-1]}  @{os.path.basename(methods[(c, m)])}:{min(lns)}-{max(lns)}')


if __name__ == '__main__':
    tag = sys.argv[1]
    if '--uncovered' in sys.argv:
        uncovered(tag, sys.argv[sys.argv.index('--uncovered') + 1])
    else:
        s = summarize(tag)
        if '--json' in sys.argv:
            print(json.dumps(s))
        else:
            L, B = s['lines'], s['branches']
            print(f"reader-side lines {L['covered']}/{L['total']} = {100*L['covered']/L['total']:.1f}%  "
                  f"branches {B['covered']}/{B['total']} = {100*B['covered']/B['total']:.1f}%")
            for a in s['areas']:
                l, b = a['lines'], a['branches']
                print(f"  {a['area']:32} lines {100*l[0]/l[1]:5.1f}% ({l[0]}/{l[1]})  "
                      f"branches {100*b[0]/max(b[1],1):5.1f}% ({b[0]}/{b[1]})")
