# Optional FixedLenByteArray with ReadOnlyMemory

This public-API repro writes one optional `FIXED_LEN_BYTE_ARRAY(4)` column as
`ReadOnlyMemory<byte>?` values. The writer closes successfully, but its PLAIN
payload contains a 4-byte length before each present value. Plank's reader
rejects the resulting file; PyArrow currently accepts it and returns shifted
fixed-width values.

Run the repro from the repository root:

```bash
dotnet run -c Release --project fuzz/repros/optional-fixed-memory-plain/OptionalFixedMemoryPlain.csproj -- /tmp/optional-fixed-memory-plain.parquet
python3 - <<'PY'
import pyarrow.parquet as pq
print(pq.read_table('/tmp/optional-fixed-memory-plain.parquet').to_pylist())
PY
```

Observed output:

```text
writer closed successfully; wrote 269 bytes to /tmp/optional-fixed-memory-plain.parquet
Plank reader rejected writer output: CorruptParquetException: PlainBinary payload contains 8 trailing bytes.
```

PyArrow decoded the same file as:

```text
[{'fixed-memory-plain': b'\x04\x00\x00\x00'}, {'fixed-memory-plain': None}, {'fixed-memory-plain': b'\x10 0@'}]
```

The input values were `[10 20 30 40]`, `null`, and `[50 60 70 80]` in hex.
