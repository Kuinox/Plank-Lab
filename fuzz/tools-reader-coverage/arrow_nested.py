import sys, os, glob
import pyarrow.parquet as pq
for fn in sorted(glob.glob(sys.argv[1] + '/*.bin')):
    d = open(fn, 'rb').read()[1:]
    open('/tmp/_t.parquet', 'wb').write(d)
    try:
        f = pq.ParquetFile('/tmp/_t.parquet')
        t = f.read()
        res = 'OK rows=%d %s' % (t.num_rows, str(t.to_pydict())[:300])
    except Exception as e:
        res = 'ERR ' + str(e)[:150]
    print(os.path.basename(fn), res)
