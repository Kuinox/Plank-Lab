# Binary statistics are never truncated: a large value makes page headers and the footer unreadable for Arrow

Found by `Plank.Fuzzing.Scale` (`run columnar 6 0`: 1000 columns, 50 rows, some string values of 17 MB), 2026-11-28,
Plank `3a6a28a`.

Plank stores the full minimum and maximum of a BYTE_ARRAY column in every data page header (and in the column chunk
statistics and the column index). A page that holds one 9 MB string gets an 18.9 MB page header, and the footer grows by
another 18.9 MB: a 9 MB value makes a 66 MB file. Arrow C++ (ParquetSharp 24) refuses page headers above its 16 MB
limit ("Couldn't deserialize thrift: No more data to read. Deserializing page header failed."), so the file Plank wrote
cannot be read by Arrow at all. Plank reads it back correctly; no value is wrong.

The format allows truncated bounds (`is_min_value_exact` / `is_max_value_exact`), and other writers truncate (parquet-mr
column index: 64 bytes; Arrow `max_statistics_size`). Plank's own reader already understands inexact bounds.

Repro (writes the file into the given directory, prints both readers' view):

```
Plank.Fuzzing.Scale/bin/Release/net10.0/Plank.Fuzzing.Scale repro page-header-untruncated-statistics /tmp/rp
Plank: DataPageV2 header 18874414 bytes, payload 9437188 bytes
Plank: footer 18874489 bytes, file 66060505 bytes
Arrow: ParquetException: ... Couldn't deserialize thrift: No more data to read. Deserializing page header failed.
```

The scale driver skips exactly the chunks with a page header above 16 MB in its Arrow comparison (`arrowHugeHeader` counter).
