# A required Guid property throws for a missing column under MissingColumns = MaterializeDefault

Found by `Plank.Fuzzing.Scale` (`campaign evolve 1 60 0`, the INT96-into-TIMESTAMP case), 2026-11-28, Plank `3a6a28a`.

With `ParquetSchemaEvolutionOptions.MissingColumns = MaterializeDefault`, the generated row reader materializes defaults for
every missing column (0, null, `DateTime.MinValue`, `DateOnly.MinValue`...), except a required `Guid` property: the source
generator's getter is `new Guid(value.Value, bigEndian: true)` with no check, and the materialized binary value is empty, so it
throws `ArgumentException: Byte array for Guid must be exactly 16 bytes long`. The nullable form (`Guid?`) checks `IsNull` and
returns null. Expected: `Guid.Empty`. (Generated code, `ParquetRowGenerator`'s Guid read accessor.)

```
Plank.Fuzzing.Scale/bin/Release/net10.0/Plank.Fuzzing.Scale repro guid-missing-default /tmp/x
Id=1 Dec9=0 Stamp=0001-01-01T00:00:00.0000000 Day=01/01/0001 U32=0 MaybeKey=null Doc=null
Key: ArgumentException: Byte array for Guid must be exactly 16 bytes long. (Parameter 'b')
```
