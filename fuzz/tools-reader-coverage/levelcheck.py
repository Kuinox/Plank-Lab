import re, sys
blocks = open(sys.argv[1]).read().split('==== ')[1:]
tot = {'files': 0, 'schemas': {}, 'bad_files': 0}
for b in blocks:
    name = b.split(' ')[0]
    sch = re.search(r'^schema: (.*)$', b, re.M)
    leaves = re.findall(r'(\S+):(\w+) rep<=(\d+) def<=(\d+)', sch.group(1)) if sch else []
    key = tuple((l[2], l[3]) for l in leaves if l[2] != '0')
    tot['schemas'][key] = tot['schemas'].get(key, 0) + 1
    # first columnar record
    m = re.search(r'\[columnar rg0 [^\]]*\] rows=(\d+) entries=(\d+) values=(\d+) rep=\[([\d,]*)\] def=\[([\d,]*)\]', b)
    if not m or not key: continue
    R, D = int(key[0][0]), int(key[0][1])
    rep = list(map(int, m.group(4).split(','))); dfn = list(map(int, m.group(5).split(',')))
    bad = [i for i in range(len(rep)) if rep[i] > 0 and dfn[i] < D - (R - rep[i])]
    if bad:
        tot['bad_files'] += 1
        if tot['bad_files'] <= 6: print(name, 'R', R, 'D', D, 'positions with rep>0 and def below the element level:', bad[:6], [(rep[i], dfn[i]) for i in bad[:6]], 'rows', m.group(1), 'entries', m.group(2))
    tot['files'] += 1
print(tot)
