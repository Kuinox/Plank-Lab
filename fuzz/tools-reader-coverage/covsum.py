import sys,re,xml.etree.ElementTree as ET
t=ET.parse(sys.argv[1]).getroot()
pat=re.compile(sys.argv[2]) if len(sys.argv)>2 else None
rows=[]
tot=[0,0]
for c in t.iter('class'):
    fn=c.get('filename')
    if 'Reading' not in fn and 'BloomFilters' not in fn and 'Compression' not in fn: continue
    lines={};br=[0,0]
    for m in c.iter('method'):
        for l in m.iter('line'):
            lines[int(l.get('number'))]=max(lines.get(int(l.get('number')),0),int(l.get('hits')))
            if l.get('branch')=='True':
                cov,tt=re.search(r'\((\d+)/(\d+)\)',l.get('condition-coverage')).groups(); br[0]+=int(cov);br[1]+=int(tt)
    rows.append((fn,len(lines),sum(1 for v in lines.values() if v),br))
agg={}
for fn,n,h,b in rows:
    a=agg.setdefault(fn,[0,0,0,0]);a[0]+=n;a[1]+=h;a[2]+=b[0];a[3]+=b[1]
for fn,(n,h,bc,bt) in sorted(agg.items()):
    if pat and not pat.search(fn): continue
    print(f"{fn.split('Plank/Plank/')[-1]:70} lines {h}/{n} branches {bc}/{bt}")
