# `ParquetColumnChunkInfo` value equality throws on first use (library defect, found by route PHY1)

`Plank.Reading.Physical.ParquetColumnChunkInfo` is a public `readonly record struct`. Its generated `Equals(ParquetColumnChunkInfo)` and
`Equals(object)` compare the `Encodings` member (`ParquetColumnChunkEncodings`), a struct wrapping an internal `[InlineArray(10)]`
buffer without its own equality. The first call in a process throws
`NotSupportedException: Calling built-in Equals() or GetHashCode() on type marked as InlineArray is invalid.`; later calls return `true`
(so the behaviour depends on call order / JIT state). `GetHashCode` and `==` did not throw here, but `==` goes through the same `Equals`.

`dotnet run --project fuzz/repros/chunk-info-equality -c Release` prints it. The PHY1 route
(`PhysicalReaderSurfaceCases`, marker 0xC5) detects it and counts it (`knownInlineArrayEquality`); set
`PLANK_FUZZ_STRICT_INLINEARRAY_EQUALITY=1` to make it a fault. Expected fix: give `ParquetColumnChunkEncodings` an `Equals`/`GetHashCode`
that compares `Count` and the first `Count` elements.
