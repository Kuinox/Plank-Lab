# .NET JIT: by-value struct copy reads past the struct with HW intrinsics off (not a Plank bug)

Found by the guard-page allocator (`PLANK_FUZZ_GUARD=end`) in the scalar tier: 646 reader seeds died with an
`AccessViolationException` in `ParquetFileMetadata.SchemaNodeNameUtf8`, which passes a `ParquetSchemaNodeInfo`
(92 bytes) by value out of an exactly sized native buffer. The same happens with no Plank code at all:

```
dotnet build -c Release
./bin/Release/net10.0/JitStructOverread s                              # survives
DOTNET_EnableHWIntrinsic=0 ./bin/Release/net10.0/JitStructOverread s   # AccessViolation
DOTNET_EnableHWIntrinsic=0 ./bin/Release/net10.0/JitStructOverread p   # 96-byte struct: survives
```

`S` is 68 bytes (4 mod 8), placed so it ends exactly at a PROT_NONE page and passed by value to a NoInlining
method. With hardware intrinsics disabled the JIT's block copy reads 4 bytes past the end (an 8-byte load for the
tail, presumably); with SIMD on, or a struct size that is a multiple of 8, it does not. Runtime
10.0.1526.53008 (commit 8e0f8ed2), x64, Linux. Harmless in practice (the extra bytes are never used, and a struct
inside a larger allocation never sits at a page end) and only when `DOTNET_EnableHWIntrinsic=0`.

Consequence for the guard runs: the scalar tier sets `PLANK_FUZZ_GUARD_SLACK=8` (buffers end 8 bytes before the
guard page), so overruns of 8 bytes or fewer are not caught in that tier only. Worth reporting to
dotnet/runtime.
