# Random schema shapes for the source generator

`gen_random_schemas.py` writes N deterministic random `[ParquetSchema]` row types (nesting of lists, arrays, maps and
records; every supported leaf with nullability; column names needing escaping; field ids; encodings; compression;
bloom filters; converters; decimal precision; and a minority of deliberately illegal shapes). Each schema file also holds
the adapter (`<Name>Case : RandomSchemaCase`) that the `RRS1` route drives.

1. `gen_random_schemas.py generate --seed 1 --count 240 --out fuzz/probe/SchemaProbe/Schemas`
2. `flock $W/agents/build2.lock bash fuzz/tools/probe-random-schemas.sh` builds the isolated `fuzz/probe/SchemaProbe`
   project, removes every schema the generator rejected, and repeats until the probe compiles. A generator crash or
   uncompilable generated output ends up in `fuzz/probe/SchemaProbe/findings.json` / the `uncompilable generated output`
   kind (library findings); `PLANKGEN*` diagnostics are expected rejections.
3. `gen_random_schemas.py install --schemas fuzz/probe/SchemaProbe/Schemas --dest Plank.Fuzzing/RandomSchemas` copies
   the accepted schemas and the registry into the fuzzing project and rewrites `fuzz/notes/random-schema-rejections.md`.

The committed set is `--seed 1 --count 240` (162 accepted). `PLANK_FUZZ_SELFTEST_RRS=1` redraws the expected rows after
writing, which must make the comparison fail (it does in 305 of 396 replayed cases; the rest project no value column).

## Routes over the installed schemas (747 accepted, each with a mutated twin)
`gen_random_schemas.py generate --plan 1:240,2:300,3:300,4:300` is what is committed.
- `RRS1`: write via pipeline / cursor / multi-group direct writer, Arrow full-value oracle, projected read, reader reuse; some rows leave
  columns unassigned (nullable references, collections and maps must read null; unassigned scalars have no defined value).
- `RRD1`: the generated dataset writer (partitions, file pool, pending capacity, parts, append options) with an injected I/O fault
  plan; permanent-fault contract and per-partition order checked.
- `RRE1`: a schema's file read through its mutated twin (drop/add/rename/reorder/toggle nullability/widen) and the reverse, with the
  documented evolution rules as the expectation. An absent required group reads as a record with default leaves.
