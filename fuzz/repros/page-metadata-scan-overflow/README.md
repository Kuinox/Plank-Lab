# OverflowException from PageMetadataReader.ScanPageLocations

A data page header declaring `compressed_page_size = int.MaxValue` (2147483647) makes the page-metadata scan throw `System.OverflowException` instead of `CorruptParquetException`.
Seeds (route byte 0x00 + a pyarrow file whose first page header was rewritten by `fuzz/resource-seeds.py`): `footer-res-page-nodict-compressed-2147483647-r00.bin`
(uncompressed file) and `footer-res-page-bloom-compressed-2147483647-r00.bin`.

Reproduce: `Plank.Fuzzing.Reader.Target --replay <dir containing a seed>`. The stack is `PageMetadataReader.ScanPageLocations` <- `OpenHandle` <- `Open` <-
`ParquetColumnChunkMetadata.OpenPages()` (called by the harness's `DrainMetadata`), i.e. the public page-metadata enumeration: checked arithmetic adding the declared compressed size
to the header length/offset overflows `int`. The data read path rejects the same file cleanly; only the page-metadata enumeration misses the bound.
Malformed input must give `CorruptParquetException`.
