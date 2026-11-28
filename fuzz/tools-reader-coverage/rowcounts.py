import sys, re, glob, os
import pyarrow.parquet as pq
tri = open(sys.argv[2]).read().split('==== ')[1:]
seen = {}
for blk in tri:
    name = blk.split(' ')[0]
    d = open(os.path.join(sys.argv[1], name), 'rb').read()[1:]
    open('/tmp/_c.parquet', 'wb').write(d)
    try: decl = pq.ParquetFile('/tmp/_c.parquet').metadata.num_rows
    except Exception as e: decl = 'ERR'
    col = re.findall(r'\[columnar rg\d+ [^\]]*\] rows=(\d+) entries=(\d+) values=(\d+)', blk)
    row = re.findall(r'\[rowapi\] (\d+) rows', blk)
    thr = re.findall(r'\[rowapi\] THROWS (\w+)', blk)
    print(name, 'declared', decl, 'columnar rows', [c[0] for c in col], 'rowapi', row or thr)
