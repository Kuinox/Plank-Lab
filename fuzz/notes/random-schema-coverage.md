# Coverage of the random-schema routes (RRS1 / RRD1 / RRE1), 2026-11-27

Replay driver under coverlet, `writer` target, ovh. Base = every committed `rowapi-*` seed except the random-schema ones
(74 inputs); after = base + the 20 committed random-schema seeds (8 RRS1, 6 RRD1, 6 RRE1) = 94 inputs.

| area | lines base | lines after | branches base | branches after |
|---|---|---|---|---|
| Plank.Dataset | 896/1066 (84.1%) | 902/1066 (84.6%) | 448/576 (77.8%) | 448/576 (77.8%) |
| Plank.RowApi | 2432/2958 (82.2%) | 2444/2958 (82.6%) | 1070/1568 (68.2%) | 1090/1568 (69.5%) |
| SourceGen-emitted, hand-written schemas | 6696/13304 (50.3%) | 6696/13304 (50.3%) | 1732/4224 (41.0%) | 1732/4224 (41.0%) |
| SourceGen-emitted, random schemas (747 + twins) | 0/885748 | 5340/885748 (0.6%) | 0/315376 | 1202/315376 (0.4%) |

Twenty seeds touch about twenty schemas, so the emitted-code percentage is dominated by the 1,494 schema types that no committed
seed names. The library-side gain is small and real (RowApi +12 lines, +20 branches). The meaningful number for the emitted
code is per touched schema, from a larger replay (`tmp/covbig.sh`: 300 RRS1 + 300 RRD1 + RRE1 inputs on top of the seeds),
which was queued behind the ovh CPU quota when this was written.
