#!/usr/bin/env python3
"""Interleave independent, pinned benchmark processes; preserve every raw round and sample."""
import argparse
import json
import os
from pathlib import Path
import subprocess
import time


def combine(paths, output, label):
    reports = [json.loads(p.read_text()) for p in paths]
    first = reports[0]
    cases = {c['Id']: c for c in first['Cases']}
    for report in reports[1:]:
        if report['Revision'] != first['Revision']:
            raise ValueError(f'revision changed between rounds: {paths}')
        other = {c['Id']: c for c in report['Cases']}
        if set(cases) != set(other):
            raise ValueError(f'case mismatch: {paths}')
        for key, case in cases.items():
            candidate = other[key]
            if (case['InputSha256'], case['Digest']) != (candidate['InputSha256'], candidate['Digest']):
                raise ValueError(f'input or digest changed between rounds: {key}')
            if {s['Operations'] for s in case['Samples']} != {s['Operations'] for s in candidate['Samples']}:
                raise ValueError(f'calibration changed between rounds: {key}')
            case['Samples'].extend(candidate['Samples'])
    first['Label'] = label
    output.write_text(json.dumps(first, indent=2) + '\n')


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--core', type=int, required=True)
    parser.add_argument('--fixtures', default='artifacts/metadata-fixtures')
    parser.add_argument('--builds', default='artifacts/metadata-builds')
    parser.add_argument('--output', default='artifacts/metadata-results')
    parser.add_argument('--worktrees', default='artifacts/metadata-worktrees')
    parser.add_argument('--calibration', required=True, help='shared master calibration JSON')
    parser.add_argument('--iterations', type=int, default=10, help='samples per process per case')
    parser.add_argument('--prs', nargs='*', default=['169','171','173','175','176','177','180','181','182','183','184'])
    args = parser.parse_args()
    if args.core not in os.sched_getaffinity(0):
        raise ValueError('core outside current affinity')
    if args.iterations < 1:
        raise ValueError('iterations must be positive')
    out = Path(args.output)
    out.mkdir(parents=True, exist_ok=True)
    env = dict(os.environ, DOTNET_TieredCompilation='0', DOTNET_gcConcurrent='0')
    def revision(name):
        return subprocess.check_output(['git', '-C', f'{args.worktrees}/{name}', 'rev-parse', 'HEAD'], text=True).strip()
    master = revision('master')
    pairs = [('noise', 'master', 'master')]
    for n in args.prs:
        head = revision('pr' + n)
        base = subprocess.check_output(['git', '-C', f'{args.worktrees}/master', 'merge-base', master, head], text=True).strip()
        base_name = 'master' if base == master else 'base-' + base
        if revision(base_name) != base:
            raise ValueError(f'wrong merge-base checkout for PR {n}')
        pairs.append(('pr' + n, base_name, 'pr' + n))
    for pair, baseline, current in pairs:
        sides = {'a': [], 'b': []}
        for round_no, side in enumerate(('a', 'b', 'a', 'b'), 1):
            build = baseline if side == 'a' else current
            target = out / f'{pair}-{side}-{round_no}.json'
            if target.exists():
                raise FileExistsError(f'refusing to overwrite {target}')
            while float(Path('/proc/loadavg').read_text().split()[0]) > 10:
                print('load > 10; pausing', flush=True)
                time.sleep(5)
            sha = revision(build)
            command = ['taskset', '-c', str(args.core), 'dotnet', f'{args.builds}/{build}/Plank.Benchmarks.dll',
                       '--metadata-regression', '--fixtures', args.fixtures, '--output', str(target),
                       '--label', f'{pair}-{side}-{round_no}', '--revision', sha,
                       '--iterations', str(args.iterations), '--calibration', args.calibration]
            print(f'{pair} round {round_no}: {build}', flush=True)
            subprocess.run(command, check=True, env=env)
            sides[side].append(target)
        for side, paths in sides.items():
            combine(paths, out / f'{pair}-{side}.json', f'{pair}-{side}')


if __name__ == '__main__':
    main()
