import sys,re,xml.etree.ElementTree as ET
# usage: covunion.py pattern file1 file2 ... -> per-file line/branch union; and zero methods
pat=re.compile(sys.argv[1]); files=sys.argv[2:]
lines={}; brs={}; meth={}
for f in files:
    for c in ET.parse(f).getroot().iter('class'):
        fn=c.get('filename')
        if not pat.search(fn): continue
        for m in c.iter('method'):
            key=(fn,c.get('name'),m.get('name'),m.get('signature'))
            ls=meth.setdefault(key,{})
            for l in m.iter('line'):
                n=int(l.get('number')); h=int(l.get('hits'))
                ls[n]=max(ls.get(n,0),h)
                lines[(fn,n)]=max(lines.get((fn,n),0),h)
                if l.get('branch')=='True':
                    cov,tt=map(int,re.search(r'\((\d+)/(\d+)\)',l.get('condition-coverage')).groups())
                    k=(fn,n); o=brs.get(k,(0,tt)); brs[k]=(max(o[0],cov),tt)
agg={}
for (fn,n),h in lines.items():
    a=agg.setdefault(fn,[0,0,0,0]); a[0]+=1; a[1]+= h>0
for (fn,n),(c,t) in brs.items():
    a=agg.setdefault(fn,[0,0,0,0]); a[2]+=c; a[3]+=t
T=[0,0,0,0]
for fn,a in sorted(agg.items()):
    print(f"{fn.split('Plank/Plank/')[-1]:68} lines {a[1]}/{a[0]} br {a[2]}/{a[3]}")
    for i in range(4): T[i]+=a[i]
print("TOTAL lines %d/%d br %d/%d (%.1f%%)"%(T[1],T[0],T[2],T[3],100*T[2]/max(1,T[3])))
print("--- zero-ish methods")
for (fn,cn,mn,sig),ls in meth.items():
    if len(ls)>=8:
        h=sum(1 for v in ls.values() if v>0)
        if h/len(ls)<0.3: print(f"{h}/{len(ls)} {cn.split('.')[-1]}::{mn[:55]}")
