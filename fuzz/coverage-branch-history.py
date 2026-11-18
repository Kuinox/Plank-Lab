#!/usr/bin/env python3
"""Build a self-contained HTML history of merged reader/writer branch coverage.

Usage: python3 fuzz/coverage-branch-history.py [--history DIR] [--output FILE]
Each target is grouped by tag and requires scalar/SSE/AVX2/AVX512 reports. When both exist, a deduplicated library union is also shown.
"""
import argparse
import collections
import datetime
import glob
import html
import importlib.util
import json
import os
import re
from zoneinfo import ZoneInfo

HERE = os.path.dirname(os.path.abspath(__file__))
DEFAULT_HISTORY = os.path.join(HERE, 'coverage', 'history')
DEFAULT_OUTPUT = os.path.join(HERE, 'coverage-branch-history.html')
ISAS = ('scalar', 'sse', 'avx2', 'avx512')

# Writer-only areas are deliberately separate from coverage-summary.py's
# reader-oriented classifier. First match wins; the final bucket keeps the
# partition exhaustive as the writer grows.
WRITER_AREAS = [
    ('Value encoding & serialization', r'Encoding|AlpEncodingPrimitives|SerializedColumn'),
    ('Row API & buffering', r'RowApi|RowWriter|RowGroupWriter|RowBuffer|RowValueSize'),
    ('Dataset writing', r'^Dataset\.|DatasetBufferSlot'),
    ('Schema, statistics & metadata', r'^Schema\.|ColumnStatistics|ParquetMetadataThriftWriter|MutationSchemaValidator|TimestampConversion|AppendSortingOrder|MinMaxScan|LatestRowGroupValues'),
    ('Compression', r'Compression|Deflater'),
    ('Pages, indexes & bloom filters', r'Page|Bloom'),
    ('File & stream writing', r'ParquetWriter|ParquetFileMerger|ParquetSource|BufferWriter'),
    ('Other writer code', r'.'),
]


def writer_area_of(cls):
    for name, pattern in WRITER_AREAS:
        if re.search(pattern, cls):
            return name
    return 'Other writer code'


def branch_areas(branches, classify):
    per_area = collections.defaultdict(lambda: {'covered': 0, 'total': 0})
    for cls, hits in branches.values():
        cell = per_area[classify(cls)]
        cell['total'] += 1
        cell['covered'] += hits > 0
    return dict(per_area)


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--history', default=DEFAULT_HISTORY, help='directory containing reader-<tag>-<isa>..json')
    ap.add_argument('--output', default=DEFAULT_OUTPUT, help='HTML output path')
    args = ap.parse_args()

    spec = importlib.util.spec_from_file_location('coverage_summary', os.path.join(HERE, 'coverage-summary.py'))
    summary = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(summary)
    grouped = collections.defaultdict(lambda: collections.defaultdict(dict))
    for path in glob.glob(os.path.join(args.history, '*-*.json')):
        m = re.fullmatch(r'(reader|writer)-(.+)-(scalar|sse|avx2|avx512)\.\.json', os.path.basename(path))
        if m:
            grouped[m.group(2)][m.group(1)][m.group(3)] = path

    def run_complete(target, tag, isa):
        candidates = [os.path.join(args.history, f'run-{target}-{tag}-{isa}.txt')]
        if target == 'reader':
            candidates.append(os.path.join(args.history, f'run-{tag}-{isa}.txt'))
        path = next((p for p in candidates if os.path.isfile(p)), None)
        if path is None:
            return False
        try:
            with open(path, encoding='utf-8', errors='replace') as f:
                log = f.read()
        except OSError:
            return False
        # The replay's terminal done marker proves the whole input set was consumed;
        # Coverlet's summary proves instrumentation completed and emitted its report.
        return 'done:' in log and '| Average |' in log and '| Total   |' in log

    def run_details(target, tag):
        details = []
        for isa in ISAS:
            candidates = [os.path.join(args.history, f'run-{target}-{tag}-{isa}.txt')]
            if target == 'reader':
                candidates.append(os.path.join(args.history, f'run-{tag}-{isa}.txt'))
            path = next((p for p in candidates if os.path.isfile(p)), None)
            if path is None:
                return None
            with open(path, encoding='utf-8', errors='replace') as f:
                log = f.read()
            done = re.search(r'done:\s*([\d,]+)\s+inputs.*?\b([\d.]+)s\s*$', log, re.M)
            if not done:
                return None
            details.append({'isa': isa, 'inputs': int(done.group(1).replace(',', '')),
                            'seconds': float(done.group(2)), 'mtime': os.path.getmtime(path)})
        counts = {d['inputs'] for d in details}
        completion = max(d['mtime'] for d in details)
        return {
            'inputs': next(iter(counts)) if len(counts) == 1 else None,
            'inputs_by_tier': {d['isa']: d['inputs'] for d in details},
            'seconds_by_tier': {d['isa']: d['seconds'] for d in details},
            'completed_epoch': completion,
            'completed_local': datetime.datetime.fromtimestamp(completion, ZoneInfo('Europe/Paris')).strftime('%Y-%m-%d %H:%M %Z'),
        }

    def target_branches(target, files, partition=True):
        per_tier = {}
        for isa, path in files.items():
            branches = {}
            with open(path, encoding='utf-8') as f:
                data = json.load(f)
            for module in data.values():
                for fname, classes in module.items():
                    for cls, methods in classes.items():
                        c = cls.replace('Plank.', '', 1).split('/')[0]
                        for mname, method in methods.items():
                            short = mname.split('::')[-1].split('(')[0]
                            writer_only = bool(summary.WRITER.search(c) or summary.WRITER_METHODS.match(f'{c}.{short}'))
                            if partition and ((target == 'reader' and writer_only) or (target == 'writer' and not writer_only)):
                                continue
                            for b in method.get('Branches', []):
                                k = (fname, b['Line'], b['Offset'], b['Path'], b['Ordinal'])
                                if k not in branches or b['Hits'] > branches[k][1]:
                                    branches[k] = (c, b['Hits'])
            per_tier[isa] = branches
        merged = {}
        for tier in per_tier.values():
            for key, value in tier.items():
                if key not in merged or value[1] > merged[key][1]:
                    merged[key] = value
        return merged, per_tier

    def stats(branches):
        vals = list(branches.values())
        return {'covered': sum(h > 0 for _, h in vals), 'total': len(vals)}

    snapshots = []
    for tag, targets in sorted(grouped.items()):
        all_branches, target_data = {}, {}
        for target in ('reader', 'writer'):
            files = targets.get(target, {})
            if not all(isa in files and run_complete(target, tag, isa) for isa in ISAS):
                continue
            merged, tiers = target_branches(target, files)
            target_data[target] = {'merged': merged, 'tiers': tiers}
            all_branches.update(merged)
        if 'reader' not in target_data:
            continue
        reader = target_data['reader']
        snapshot = {'tag': tag, 'merged': stats(reader['merged']),
                    'areas': branch_areas(reader['merged'], summary.area_of),
                    'tiers': {isa: stats(tier) for isa, tier in reader['tiers'].items()},
                    'reader_run': run_details('reader', tag),
                    '_branches': {'merged': reader['merged']}}
        if 'writer' in target_data:
            writer = target_data['writer']
            snapshot['writer'] = stats(writer['merged'])
            snapshot['writer_areas'] = branch_areas(writer['merged'], writer_area_of)
            snapshot['_branches']['writer'] = writer['merged']
            snapshot['writer_run'] = run_details('writer', tag)
            snapshot['writer_tiers'] = {isa: stats(tier) for isa, tier in writer['tiers'].items()}
            # A branch key present in both reports is counted once; a hit in either target covers it.
            union = dict(reader['merged'])
            for key, (cls, hits) in writer['merged'].items():
                if key not in union or hits > union[key][1]:
                    union[key] = (cls, hits)
            # Library union deliberately uses the raw complete Plank reports from both targets.
            raw_reader, _ = target_branches('reader', targets['reader'], partition=False)
            raw_writer, _ = target_branches('writer', targets['writer'], partition=False)
            raw_union = dict(raw_reader)
            for key, (cls, hits) in raw_writer.items():
                if key not in raw_union or hits > raw_union[key][1]:
                    raw_union[key] = (cls, hits)
            snapshot['library'] = stats(raw_union)
            snapshot['_branches']['library'] = raw_union
        snapshots.append(snapshot)

    # Timestamp tags and older letter-suffixed tags do not sort chronologically
    # together. Order points by the measured run's completion time instead.
    snapshots.sort(key=lambda s: ((s.get('writer_run') or s.get('reader_run') or {}).get('completed_epoch', 0), s['tag']))

    # A live queue may omit a branch reached in an earlier replay. Show both
    # each run's coverage and the union of observations over a comparable
    # instrumented branch set. Reset when a branch key appears or disappears.
    cumulative = {}
    for snapshot in snapshots:
        snapshot['ever'] = {}
        snapshot['ever_reset'] = {}
        for target, branches in snapshot.pop('_branches').items():
            keys = frozenset(branches)
            prior = cumulative.get(target)
            reset = prior is None or prior[0] != keys
            if reset:
                observed = dict(branches)
            else:
                observed = prior[1]
                for key, value in branches.items():
                    if value[1] > observed[key][1]:
                        observed[key] = value
            cumulative[target] = (keys, observed)
            snapshot['ever'][target] = stats(observed)
            snapshot['ever_reset'][target] = reset

    payload = json.dumps(snapshots, separators=(',', ':')).replace('</', '<\\/')
    labels = ', '.join(html.escape(s['tag']) for s in snapshots)
    template_path = os.path.join(HERE, 'coverage-branch-history.template.html')
    with open(template_path, encoding='utf-8') as f:
        template = f.read()
    output = template.replace('@@DATA@@', payload).replace('@@SNAPSHOTS@@', str(len(snapshots))).replace('@@TAGS@@', labels)
    os.makedirs(os.path.dirname(os.path.abspath(args.output)), exist_ok=True)
    with open(args.output, 'w', encoding='utf-8') as f:
        f.write(output)
    writer_tags = ', '.join(s['tag'] for s in snapshots if 'writer' in s) or 'none yet'
    print(f'Wrote {args.output} ({len(snapshots)} reader snapshots; complete writer/library tags: {writer_tags})')

if __name__ == '__main__':
    main()
