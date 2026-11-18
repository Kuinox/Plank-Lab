# Floating append sorting metadata findings

Replay each file separately with `dotnet Plank.Fuzzing.Replay.dll writer <file>` from the built replay output.

Both inputs request a one-column sorted append with finite monotonic values and assert retention of the original sorting metadata. The initial file has exactly the requested sorting metadata; the writer preserves the appended row count and values, but the output reports zero sorting columns instead of one. The generated comparator pairs are finite and nonzero: double ascending compares each prior key below its incoming key, and float descending compares each prior key above its incoming key (then applies descending order). These are deterministic harness findings; do not add them to the active AFL corpus until triaged.

- `double-ascending.bin`: bytes `F8 03 00 02 02 80`; five retained values ascend from 0 by 1.75, then five incoming values continue ascending from 8.75.
- `float-descending.bin`: bytes `F8 04 01 03 04 80`; three retained values descend from 0 by 2.25, then three incoming values continue descending from -6.75.
