import sys,re,xml.etree.ElementTree as ET
t=ET.parse(sys.argv[1]).getroot(); pat=re.compile(sys.argv[2]); thr=float(sys.argv[3]) if len(sys.argv)>3 else 0.5
for c in t.iter('class'):
    if not pat.search(c.get('filename')): continue
    for m in c.iter('method'):
        ls=list(m.iter('line'))
        if not ls: continue
        h=sum(1 for l in ls if int(l.get('hits'))>0)
        if h/len(ls)<thr and len(ls)>=8: print(f"{h}/{len(ls)} {c.get('name').split('.')[-1]}::{m.get('name')[:60]}")
