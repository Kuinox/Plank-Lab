#!/usr/bin/env python3
"""Merge the per-target cobertura reports of fuzz/coverage-all.sh into a gap map.

  coverage-gaps.py <all-dir> <library-root> [out.md]

Emits per-namespace and per-file branch/line coverage, per-target attribution
(writer / reader / merger), whole files at zero, and zero-hit methods (public
declarations first), each with the target that should own it.
"""
import collections, os, re, sys
import xml.etree.ElementTree as ET

alldir, libroot = sys.argv[1], sys.argv[2]
out = open(sys.argv[3], 'w') if len(sys.argv) > 3 else sys.stdout
TARGETS = ['writer', 'reader', 'merger']

# per target: file -> line -> [hits, cov, tot];  methods: (file, class, name, firstline) -> {target: hit lines, total lines}
lines = {t: collections.defaultdict(dict) for t in TARGETS}
ldef = {t: collections.defaultdict(dict) for t in TARGETS}  # default ISA tier only
methods = {}
import glob
def reports(t):
    # default tier is "<t>..cobertura.xml"; other ISA tiers are "<t>-<tier>.cobertura.xml"
    return sorted(glob.glob(os.path.join(alldir, f'{t}..cobertura.xml')) + glob.glob(os.path.join(alldir, f'{t}-*.cobertura.xml')))
for t in TARGETS:
  for p in reports(t):
    for c in ET.parse(p).iter('class'):
          f = c.get('filename')
          cls = c.get('name')
          for m in c.iter('method'):
              ls = list(m.iter('line'))
              if not ls:
                  continue
              first = min(int(l.get('number')) for l in ls)
              key = (f, cls.split('/')[0], m.get('name'), first)
              rec = methods.setdefault(key, {'tot': len(ls), **{t2: 0 for t2 in TARGETS}})
              rec['tot'] = max(rec['tot'], len(ls))
              hit = 0
              for l in ls:
                  n = int(l.get('number')); h = int(l.get('hits'))
                  cc = re.search(r'\((\d+)/(\d+)\)', l.get('condition-coverage') or '')
                  cov, tot = (int(cc.group(1)), int(cc.group(2))) if cc else (0, 0)
                  for dst in ([lines[t], ldef[t]] if os.path.basename(p) == f'{t}..cobertura.xml' else [lines[t]]):
                      old = dst[f].get(n, [0, 0, 0])
                      dst[f][n] = [max(old[0], h), max(old[1], cov), max(old[2], tot)]
                  hit += h > 0
              rec[t] = max(rec[t], hit)

def union(src=None):
    src = src or lines
    u = collections.defaultdict(dict)
    for t in TARGETS:
        for f, d in src[t].items():
            for n, (h, cv, tt) in d.items():
                o = u[f].get(n, [0, 0, 0])
                u[f][n] = [max(o[0], h), max(o[1], cv), max(o[2], tt)]
    return u

U = union()
UD = union(ldef)

def stats(d):
    L = len(d); Lh = sum(1 for v in d.values() if v[0] > 0)
    B = sum(v[2] for v in d.values()); Bh = sum(v[1] for v in d.values())
    return L, Lh, B, Bh

def pct(a, b): return f'{100 * a / b:.1f}%' if b else 'n/a'

def asm(f): return 'Plank.K4os.LZ4' if f.startswith('third_party/K4os') else 'Plank'
def ns(f):
    if '/obj/' in f: return 'generated (obj/' + f.split('/')[-2].replace('Plank.InternalGen.', '') + ')'
    if f.startswith('third_party/K4os'):
        return 'K4os.LZ4/' + ('/'.join(f.split('/src/K4os.Compression.LZ4/')[1].split('/')[:-1]) or '.')
    parts = f.split('/')[1:]  # drop leading "Plank"
    return ('/'.join(parts[:-1]) or '(root)')

OWNER_RULES = [
    (r'^Plank/Reading/.*(Bloom|Index|Statistics|Dictionary|Decoder|Encoding)', 'reader (+ writer round trip for the matching encoder)'),
    (r'^Plank/Reading/', 'reader'),
    (r'^Plank/Compression/', 'NEW compression-codec target (PlankDecompressorFuzzTarget exists; extend) + writer compression-level options'),
    (r'^Plank/RowApi/', 'rowapi'),
    (r'^Plank/Dataset/.*(Merge|Append|Import)', 'rowapi-dataset-merger (merger target)'),
    (r'^Plank/Dataset/', 'rowapi-dataset-merger (dataset targets)'),
    (r'^Plank/BloomFilters/', 'writer (bloom options) + reader (bloom probe)'),
    (r'^Plank/Schema/', 'writer (schema conversion/validation) + reader'),
    (r'^Plank/Writing/', 'writer'),
    (r'^Plank/(ParquetBuffer|DefaultParquetBufferPool|IParquetBufferPool|ParquetBufferPoolExtensions|ParquetBufferHeader|ParquetBufferRetentionPolicy|ParquetWorkerContext|ParquetExecutionOptions)', 'NEW buffer-pool/execution-options target (nobody owns)'),
    (r'^third_party/K4os', 'NEW compression-codec target (LZ4 raw/frame/block via Parquet LZ4_RAW + LZ4 pages); mostly unreachable library surface otherwise'),
]
def owner(f):
    for r, o in OWNER_RULES:
        if re.search(r, f): return o
    return 'writer'

w = out.write
tot = stats({(f, n): v for f, d in U.items() for n, v in d.items()})
w(f'# Plank fuzz coverage gaps\n\n')
for a in ('Plank', 'Plank.K4os.LZ4'):
    d = {(f, n): v for f, dd in U.items() if asm(f) == a for n, v in dd.items()}
    L, Lh, B, Bh = stats(d)
    dd = {(f, n): v for f, dx in UD.items() if asm(f) == a for n, v in dx.items()}
    _, Ldh, _, Bdh = stats(dd)
    w(f'- **{a}**: lines {Lh}/{L} ({pct(Lh, L)}), branches {Bh}/{B} ({pct(Bh, B)}) — union of writer+reader+merger replays over all ISA tiers; host-default tier only: lines {pct(Ldh, L)}, branches {pct(Bdh, B)}\n')
w('- **Plank.Native.Zlib**: ships only `libz` native binaries (no managed code); exercised indirectly through Plank\'s GZIP codec, measured as part of Plank.\n')
w('\nPer-target (Plank only): ')
for t in TARGETS:
    d = {(f, n): v for f, dd in lines[t].items() if asm(f) == 'Plank' for n, v in dd.items()}
    L, Lh, B, Bh = stats(d)
    w(f'{t} {pct(Bh, B)} branch / {pct(Lh, L)} line; ')
w('\n\n## Per namespace (directory)\n\n| namespace | assembly | lines | line % | branches | branch % | writer br% | reader br% | merger br% |\n|---|---|---|---|---|---|---|---|---|\n')
byns = collections.defaultdict(list)
for f in U: byns[(asm(f), ns(f))].append(f)
def agg(files, src):
    L = Lh = B = Bh = 0
    for f in files:
        a, b, c, d = stats(src.get(f, {})); L += a; Lh += b; B += c; Bh += d
    return L, Lh, B, Bh
rows = []
for (a, n), fs in byns.items():
    L, Lh, B, Bh = agg(fs, U)
    per = []
    for t in TARGETS:
        _, _, b2, bh2 = agg(fs, lines[t]); per.append(pct(bh2, B) if B else 'n/a')
    rows.append((Bh / B if B else 1, a, n, L, Lh, B, Bh, per))
for _, a, n, L, Lh, B, Bh, per in sorted(rows):
    w(f'| {n} | {a} | {L} | {pct(Lh, L)} | {B} | {pct(Bh, B)} | {" | ".join(per)} |\n')

w('\n## Per file (Plank, lowest branch coverage first; files with ≥ 99% omitted)\n\n| file | lines | line % | branches | branch % | covered by | owner |\n|---|---|---|---|---|---|---|\n')
frows = []
for f, d in U.items():
    L, Lh, B, Bh = stats(d)
    if (B and Bh / B >= .99) or (not B and Lh == L): continue
    cov = ','.join(t for t in TARGETS if any(v[0] > 0 for v in lines[t].get(f, {}).values())) or 'NONE'
    frows.append(((Bh / B) if B else (Lh / L), f, L, Lh, B, Bh, cov))
for _, f, L, Lh, B, Bh, cov in sorted(frows):
    w(f'| {f} | {L} | {pct(Lh, L)} | {B} | {pct(Bh, B)} | {cov} | {owner(f)} |\n')

w('\n## Whole files with zero covered lines\n\n')
z = [(f, len(d)) for f, d in U.items() if all(v[0] == 0 for v in d.values())]
for f, n in sorted(z): w(f'- `{f}` ({n} lines) — owner: {owner(f)}\n')
if not z: w('(none)\n')

# source decl lookup
srccache = {}
def src(f):
    if f not in srccache:
        p = os.path.join(libroot, f)
        srccache[f] = open(p, encoding='utf-8-sig').read().split('\n') if os.path.exists(p) else []
    return srccache[f]
def decl(f, first, name):
    s = src(f); base = re.sub(r'^(get_|set_|add_|remove_)', '', name).replace('.ctor', '').replace('.cctor', '')
    for i in range(min(first - 1, len(s) - 1), max(first - 12, -1), -1):
        ln = s[i]
        if (base and base in ln or '.ctor' in name) and re.search(r'\b(public|internal|private|protected)\b', ln):
            return re.search(r'\b(public|internal|private protected|private|protected internal|protected)\b', ln).group(1)
    return '?'

w('\n## Zero-hit methods (never executed by any target), grouped by file\n\n'
  'Compiler-generated (lambda/state machine/local-function) bodies are folded out; accessibility is read from the source declaration line (`?` = could not tell).\n')
zero = collections.defaultdict(list)
for (f, cls, name, first), r in methods.items():
    if any(r[t] for t in TARGETS): continue
    if '<' in name and not name.startswith('<'): pass
    if name.startswith('<') or '>g__' in name or 'b__' in name: continue
    zero[f].append((first, cls, name, r['tot'], decl(f, first, name)))
tot_zero = sum(len(v) for v in zero.values())
pub = sum(1 for v in zero.values() for x in v if x[4] == 'public')
w(f'\n{tot_zero} methods, {pub} declared `public`.\n')
for f in sorted(zero, key=lambda f: -sum(x[3] for x in zero[f])):
    items = sorted(zero[f]); lt = sum(x[3] for x in items)
    w(f'\n### `{f}` — {len(items)} zero-hit methods, {lt} lines — owner: {owner(f)}\n\n')
    for first, cls, name, n, acc in items[:60]:
        w(f'- L{first} `{cls.split(".")[-1]}.{name}` ({acc}, {n} lines)\n')
    if len(items) > 60: w(f'- … {len(items) - 60} more\n')
