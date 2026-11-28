# TIME(NANOS) values -1 … -99 are read as 00:00:00 instead of being refused

Found by `Plank.Fuzzing.Scale` (`SCALE_LKIND=Time SCALE_DOMAIN=1 campaign types 500 25 0`: "returned 00:00 for a value outside
the CLR type (raw -5)"), 2026-11-28, Plank `3a6a28a`.

A TIME value is a time of day, so a negative value is invalid. Plank refuses it everywhere except TIME(NANOS) values in
-99 … -1: the range check runs after the value is divided down to 100 ns ticks (truncating toward zero), so -1 … -99 become
0 ticks and come back as `TimeOnly` 00:00:00. -100 and below are refused (`CorruptParquetException: Time value -100 is outside
the range representable by a time of day`), and TIME(MICROS) refuses every negative value. The silent mapping is inconsistent
with both. Low severity (invalid input only), but it is a wrong value returned without error.

```
Plank.Fuzzing.Scale/bin/Release/net10.0/Plank.Fuzzing.Scale repro time-nanos-negative /tmp/x
TIME(Nanos) raw   -1: TimeOnly 00:00:00.0000000 (0 ticks)  <-- invalid time of day accepted
TIME(Nanos) raw  -99: TimeOnly 00:00:00.0000000 (0 ticks)  <-- invalid time of day accepted
TIME(Nanos) raw -100: CorruptParquetException: Time value -100 is outside the range representable by a time of day.
TIME(Micros) raw  -1: CorruptParquetException: Time value -1 is outside the range representable by a time of day.
```

(Not a defect, for contrast: INT96 accepts nanoseconds of day outside [0, 1 day) and computes day + nanoseconds, the way Arrow
reads INT96; `repro int96-negative-nanos` shows it.)
