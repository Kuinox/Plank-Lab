# Decimal inferred from precision/scale with no DECIMAL annotation

`footer-legacy-both-dropped-r00.bin` (route byte 0x00, then a pyarrow file whose footer was rewritten by `fuzz/footer-seeds.py`): the schema element of an
INT32/FIXED_LEN_BYTE_ARRAY column keeps `precision`/`scale` but has **neither `logicalType` nor `converted_type`**. Plank reports `LogicalType.Decimal(9,0)`;
Arrow/ParquetSharp report no logical type. The full-value oracle flags it ("metadata: logical type differs — column 1 'dec' (FixedLenByteArray): Plank=Decimal(9,0), Arrow=None").

Per the format, `precision`/`scale` are only meaningful on a DECIMAL-annotated element, so a reader should ignore them (or reject). Plank instead promotes the column to a decimal, which then
decodes FIXED_LEN_BYTE_ARRAY bytes as `decimal` where other readers expose raw bytes. Leniency rather than memory unsafety; severity low. Replay: `Plank.Fuzzing.Replay reader <this dir>` prints a MISMATCH line.
