# Boolean RLE: the batched decoder does not enforce the 4-byte section length

Two leftovers of the 63 nested-triage mutants (they are flat optional BOOLEAN columns with `RLE` encoding, not nested):

* `m1014-1653.bin` — DataPageV2, 300 values, RLE section length prefix `0x26` (38) but the bit-packed run header `0x4d` announces 38 groups = 38 data bytes, so the section needs 39 bytes; the page holds 38 data bytes
  (the last one lies *outside* the declared section). The columnar (batched) reader reads the file in full — the final 4 values come from the byte beyond the declared section — while the whole-page decoder used by the row API
  rejects it: `CorruptParquetException: Boolean RLE literal group claims 38 bytes but only 37 remain.` ParquetSharp rejects the file ("Unexpected end of stream"). Two Plank read paths disagree about one file.
* `m1019-3887.bin` — DataPage v1, the declared section (39 bytes) covers the run exactly but 34 junk bytes follow; the columnar reader ignores them (Arrow/ParquetSharp: "Unexpected end of stream"). Lenient, values are correct.

Verdict: low severity inconsistency (no out-of-page read: the bytes are inside the page buffer). The batched boolean RLE path (`StartRleBatch` / `DecodeBooleanRleBatch`) should bound the run by the declared section length like
`ReadBooleanRlePayload` does. Note for readers of `nest-triage`: calling the row API with a *non-nullable* `bool` descriptor on an optional column makes it throw `NotSupportedException ... cannot be decoded into pooled values of type Boolean` even for valid files
(`third_party/parquet-testing/data/rle_boolean_encoding.parquet`) — that is the triage tool's descriptor, not a library defect.
