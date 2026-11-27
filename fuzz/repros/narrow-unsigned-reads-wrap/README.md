# `RowGroup.Column<byte|ushort|uint|ulong>` silently wraps INT32/INT64 values

Found 2026-11-27 by the read-API matrix (`Plank.Fuzzing/ReadApiMatrix.cs`) against Plank master 3a6a28a,
on ordinary pyarrow/parquet-testing seeds (no mutation needed).

Reading any INT32 column as `byte`/`byte?`, `ushort`/`ushort?`, `uint`/`uint?` (and INT64 as `ulong`/`ulong?`)
is accepted for every annotation — unannotated, `DATE`, `TIME(MILLIS)`, `INT(16, signed)`, `INT(32, unsigned)` —
and returns the value truncated to the CLR width (an unchecked cast), with no error:

```
INT32 values        -300, 300, 18000, 5, -1
Column<byte?>        212,  44,    80, 5, 255
Column<ushort?>    65236, 300, 18000, 5, 65535
Column<uint?>  4294966996, 300, 18000, 5, 4294967295
Column<sbyte?>     NotSupportedException ("Unsupported CLR type")
INT64 -1 as ulong?  18446744073709551615
```

So a DATE column read as `byte?` gives 80 for 2019-04-15 (day 18000), and a UINT_32 value 300000 read as
`byte` gives 224. Signed narrow types are refused, unsigned ones wrap: either the unsigned reads must be refused
unless the column's annotation is the matching unsigned INT (or narrower), or out-of-range values must be rejected.
The same holds for `NestedColumn<byte>` and the row reader's descriptors. Nothing downstream can detect it: the
returned values are well-formed.

Repro: `Plank.Lab.Tests --treenode-filter '/*/*/FullValueOracleTests/Repro_NarrowUnsignedReadsWrapSilently'`
(explicit test; prints the table above). Any reader seed with an INT32 column shows it, e.g.
`fuzz/reader-pyarrow-seeds/pa-date-v1.0-dp2.0-d0-r04.bin` with `PLANK_FUZZ_STRICT_NARROWING=1`.

The read-API matrix excludes exactly this shape (the returned value equals the wrap and the annotation does not
promise the range) so other findings stay visible; `PLANK_FUZZ_STRICT_NARROWING=1` reports it again.
