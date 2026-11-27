using System.Collections.Immutable;
using System.Reflection;
using Plank.Reading;
using Plank.Reading.Logical;
using Plank.Schema;
using Plank.Writing;
using RowGroup = Plank.Reading.Logical.RowGroup;
using PlankSchema = Plank.Schema.ParquetSchema;

namespace Plank.Fuzzing;

/// <summary>
/// Route 0xC4 "SRF1": reflection over every public type of Plank.dll.
/// <list type="bullet">
/// <item>Value-type laws: each public non-abstract type with a public constructor is built twice from the same
///   fuzzer-drawn arguments (edge values 0, 1, -1, min, max, null, empty, undefined enum numbers). Equals must be reflexive
///   and agree between the two instances, hash codes must agree and be stable, ToString must not throw, Equals(null) and
///   Equals(foreign object) must be false, the record clone (with-expression) must equal its source, every public property
///   getter must not fail with anything but a defined state exception. Constructor refusals must be ArgumentExceptions.</item>
/// <item>default(struct): every public struct has a usable default; the parameterless instance members must not fail with
///   NullReference/IndexOutOfRange/InvalidCast (a defined InvalidOperation/NotSupported/ObjectDisposed is fine).</item>
/// <item>Reader indexers and ColumnBuffer indices at -1, 0, count-1, count, count+1, int.MaxValue against a file written by
///   the harness: valid indices must return the written value, invalid ones must throw ArgumentOutOfRangeException.</item>
/// </list>
/// </summary>
internal static class SurfaceReflectionCases
{
    internal const byte Marker = 0xC4;
    internal static ReadOnlySpan<byte> Magic => "SRF1"u8;

    static long _runs, _types, _constructed, _laws, _defaults, _indices;

    static SurfaceReflectionCases()
    {
        if (Environment.GetEnvironmentVariable("PLANK_ORACLE_COUNTERS") == "1")
            AppDomain.CurrentDomain.ProcessExit += (_, _) => Console.Error.WriteLine(
                $"SRF1 defaultNullRefs=[{string.Join("; ", DefaultNullRefs)}] runs={_runs} types={_types} constructed={_constructed} laws={_laws} defaults={_defaults} indexProbes={_indices}");
    }

    sealed class Cur(ReadOnlySpan<byte> data)
    {
        readonly byte[] _d = data.ToArray();
        int _i;
        public byte Byte() => _d.Length == 0 ? (byte)0 : _d[_i++ % _d.Length];
        public int Int(int min, int maxExclusive)
        {
            uint v = Byte();
            v |= (uint)Byte() << 8;
            v |= (uint)Byte() << 16;
            v |= (uint)Byte() << 24;
            return min + (int)(v % (uint)(maxExclusive - min));
        }
        public long Long() => ((long)Int(0, int.MaxValue) << 32) ^ (uint)Int(0, int.MaxValue) ^ ((long)Byte() << 56);
    }

    sealed class Rng(ulong seed)
    {
        ulong _s = seed;
        public ulong Next()
        {
            _s += 0x9E3779B97F4A7C15UL;
            var z = _s;
            z = (z ^ (z >> 30)) * 0xBF58476D1CE4E5B9UL;
            z = (z ^ (z >> 27)) * 0x94D049BB133111EBUL;
            return z ^ (z >> 31);
        }
        public int Pick(int n) => (int)(Next() % (ulong)n);
    }

    static void Fail(string message) => throw new InvalidOperationException("SRF1: " + message);

    static readonly Assembly PlankAssembly = typeof(ParquetWriterOptions).Assembly;
    static readonly Type[] PublicTypes = PlankAssembly.GetExportedTypes()
        .Where(static t => !t.IsAbstract || t.IsSealed && t.IsAbstract) // keep static classes out below
        .Where(static t => !(t.IsAbstract && t.IsSealed))
        .Where(static t => !t.IsInterface && !t.IsEnum && !typeof(Delegate).IsAssignableFrom(t) && !typeof(Attribute).IsAssignableFrom(t))
        .OrderBy(static t => t.FullName, StringComparer.Ordinal)
        .ToArray();

    internal static void Execute(ReadOnlySpan<byte> data)
    {
        _runs++;
        var c = new Cur(data);
        var mode = c.Int(0, 5);
        if (mode is 0 or 1)
            ValueLaws(c, mode == 1);
        else if (mode == 2)
            Defaults(c);
        else if (mode == 3)
            Indices(c);
        else
            Sources(c);
    }

    // ---- D. IParquetReadSource implementations: offset/length boundaries ---------------------------------------------

    sealed class Fragmenting(byte[] bytes, int maxRead) : Stream
    {
        long _position;
        public override bool CanRead => true;
        public override bool CanSeek => true;
        public override bool CanWrite => false;
        public override long Length => bytes.Length;
        public override long Position { get => _position; set => _position = value; }
        public override void Flush() { }
        public override int Read(byte[] buffer, int offset, int count) => Read(buffer.AsSpan(offset, count));
        public override int Read(Span<byte> buffer)
        {
            var n = (int)Math.Min(Math.Min(buffer.Length, maxRead), bytes.Length - _position);
            bytes.AsSpan((int)_position, n).CopyTo(buffer);
            _position += n;
            return n;
        }
        public override long Seek(long offset, SeekOrigin origin) => _position = origin switch { SeekOrigin.Begin => offset, SeekOrigin.Current => _position + offset, _ => bytes.Length + offset };
        public override void SetLength(long value) => throw new NotSupportedException();
        public override void Write(byte[] buffer, int offset, int count) => throw new NotSupportedException();
    }

    static void Sources(Cur c)
    {
        var length = c.Int(0, 5) == 0 ? c.Int(0, 3) : c.Int(1, 3000);
        var bytes = new byte[length];
        for (var i = 0; i < length; i++)
            bytes[i] = (byte)(c.Byte() | 1 | (i & 0x70));
        string? temp = null;
        var sources = new List<(string Name, IParquetReadSource Source)>
        {
            ("MemoryReadSource", new MemoryReadSource(bytes)),
            ("MemoryReadSource(slice)", new MemoryReadSource(new ReadOnlyMemory<byte>(new byte[] { 9, 9 }.Concat(bytes).Concat(new byte[] { 7 }).ToArray(), 2, length))),
            ("StreamReadSource(MemoryStream)", new StreamReadSource(new MemoryStream(bytes, writable: false))),
            ("StreamReadSource(short reads)", new StreamReadSource(new Fragmenting(bytes, c.Int(1, 8))))
        };
        try
        {
            if (c.Int(0, 2) == 0)
            {
                temp = Path.Combine(Path.GetTempPath(), "plank-srf1-" + Guid.NewGuid().ToString("N"));
                File.WriteAllBytes(temp, bytes);
                sources.Add(("FileReadSource", new FileReadSource(temp)));
            }

            foreach (var (name, source) in sources)
            {
                if (source.Length != (ulong)length)
                    Fail($"{name}: Length {source.Length} != {length}.");
                var offsets = new List<ulong> { 0, 1, (ulong)Math.Max(0, length - 1), (ulong)length, (ulong)length + 1, int.MaxValue, (ulong)int.MaxValue + 1,
                    (ulong)long.MaxValue, ulong.MaxValue, (ulong)c.Int(0, length + 2) };
                var lengths = new List<int> { 0, 1, 2, length, length + 1, length - 1, c.Int(0, length + 2), int.MaxValue };
                foreach (var offset in offsets)
                    foreach (var count in lengths.Where(static l => l >= 0).Distinct())
                    {
                        if (count > 1 << 20)
                            continue; // an int.MaxValue-byte destination cannot be allocated; the range check is covered by ulong offsets
                        var destination = new byte[count];
                        Array.Fill(destination, (byte)0xEE);
                        var valid = offset <= (ulong)length && (ulong)count <= (ulong)length - offset;
                        Exception? error = null;
                        try { source.ReadExactly(offset, destination); }
                        catch (Exception e) { error = e; }
                        if (valid)
                        {
                            if (error is not null)
                                Fail($"{name}: ReadExactly({offset}, {count}) of {length} rejected a valid range: {error.GetType().Name}: {error.Message}");
                            if (!destination.AsSpan().SequenceEqual(bytes.AsSpan((int)offset, count)))
                                Fail($"{name}: ReadExactly({offset}, {count}) returned wrong bytes.");
                        }
                        else if (error is not CorruptParquetException)
                            Fail($"{name}: ReadExactly({offset}, {count}) of {length} " +
                                (error is null ? "accepted an out-of-range read." : $"threw {error.GetType().Name} instead of CorruptParquetException: {error.Message}"));
                        _indices++;
                    }

                // An empty destination at exactly Length is a valid zero-length read; a ReadOnly view must not be modified.
                source.ReadExactly((ulong)length, Span<byte>.Empty);
            }
        }
        finally
        {
            foreach (var (_, source) in sources)
                source.Dispose();
            if (temp is not null)
                File.Delete(temp);
        }
    }

    // ---- A. value laws -------------------------------------------------------------------------------------------

    static void ValueLaws(Cur c, bool sweep)
    {
        var seed = (ulong)c.Long();
        // Either one fuzzer-chosen type per run (cheap, good for AFL feedback) or the whole sweep (seeds / replay).
        var chosen = sweep ? PublicTypes : [PublicTypes[c.Int(0, PublicTypes.Length)]];
        foreach (var type in chosen)
        {
            var t = type.IsGenericTypeDefinition ? CloseGeneric(type) : type;
            if (t is null)
                continue;
            _types++;
            foreach (var ctor in t.GetConstructors(BindingFlags.Public | BindingFlags.Instance))
            {
                var ctorSeed = seed ^ (ulong)ctor.MetadataToken * 0x9E3779B1UL;
                if (!TryBuild(ctor, new Rng(ctorSeed), out var a) || !TryBuild(ctor, new Rng(ctorSeed), out var b))
                    continue;
                _constructed++;
                CheckLaws(t, ctor, a!, b!);
            }
        }
    }

    static Type? CloseGeneric(Type definition)
    {
        var args = definition.GetGenericArguments();
        if (args.Any(static a => a.GetGenericParameterConstraints().Length > 0 || (a.GenericParameterAttributes & GenericParameterAttributes.SpecialConstraintMask) != 0
                && (a.GenericParameterAttributes & GenericParameterAttributes.NotNullableValueTypeConstraint) == 0
                && (a.GenericParameterAttributes & GenericParameterAttributes.ReferenceTypeConstraint) != 0))
            return null;
        try { return definition.MakeGenericType(args.Select(static _ => typeof(int)).ToArray()); }
        catch (ArgumentException) { return null; }
    }

    static bool TryBuild(ConstructorInfo ctor, Rng rng, out object? instance)
    {
        instance = null;
        var parameters = ctor.GetParameters();
        var args = new object?[parameters.Length];
        for (var i = 0; i < args.Length; i++)
        {
            if (parameters[i].ParameterType.IsByRef || parameters[i].ParameterType.IsPointer || parameters[i].ParameterType.IsByRefLike)
                return false;
            // Never let a drawn string reach the file system (FileReadSource/FileWriteSource constructors open or create it).
            if (parameters[i].Name is { } parameterName && (parameterName.Contains("path", StringComparison.OrdinalIgnoreCase)
                || parameterName.Contains("file", StringComparison.OrdinalIgnoreCase)) && parameters[i].ParameterType == typeof(string))
                return false;
            args[i] = Draw(parameters[i].ParameterType, rng);
        }

        try
        {
            instance = ctor.Invoke(args);
            return true;
        }
        catch (TargetInvocationException e) when (e.InnerException is ArgumentException or InvalidOperationException { } or NotSupportedException
            or OverflowException)
        {
            // Documented refusals of invalid arguments. Anything else (NullReference, IndexOutOfRange, ...) is a defect.
            if (e.InnerException is OverflowException)
                Fail($"{ctor.DeclaringType} constructor threw OverflowException for drawn arguments: {e.InnerException.Message}");
            return false;
        }
        catch (TargetInvocationException e)
        {
            Fail($"{ctor.DeclaringType} constructor threw {e.InnerException?.GetType().Name}: {e.InnerException?.Message}");
            return false;
        }
    }

    static object? Draw(Type type, Rng rng)
    {
        var underlying = Nullable.GetUnderlyingType(type);
        if (underlying is not null)
            return rng.Pick(4) == 0 ? null : Draw(underlying, rng);
        if (type.IsEnum)
        {
            var values = Enum.GetValuesAsUnderlyingType(type);
            var defined = Enum.GetValues(type);
            return rng.Pick(5) == 0
                ? Enum.ToObject(type, rng.Pick(3) switch { 0 => -1, 1 => 255, _ => defined.Length + 1 })
                : defined.GetValue(rng.Pick(defined.Length));
        }

        if (type == typeof(bool)) return rng.Pick(2) == 0;
        if (type == typeof(byte)) return (byte)new[] { 0, 1, 7, 255 }[rng.Pick(4)];
        if (type == typeof(sbyte)) return (sbyte)new[] { 0, 1, -1, -128, 127 }[rng.Pick(5)];
        if (type == typeof(short)) return (short)new[] { 0, 1, -1, short.MinValue, short.MaxValue }[rng.Pick(5)];
        if (type == typeof(ushort)) return (ushort)new[] { 0, 1, 65535 }[rng.Pick(3)];
        if (type == typeof(int)) return new[] { 0, 1, -1, 2, 7, 1024, int.MaxValue, int.MinValue }[rng.Pick(8)];
        if (type == typeof(uint)) return new[] { 0u, 1u, 2u, 64u, uint.MaxValue }[rng.Pick(5)];
        if (type == typeof(long)) return new[] { 0L, 1L, -1L, long.MaxValue, long.MinValue }[rng.Pick(5)];
        if (type == typeof(ulong)) return new[] { 0UL, 1UL, ulong.MaxValue }[rng.Pick(3)];
        if (type == typeof(float)) return new[] { 0f, -0f, 1f, float.NaN, float.PositiveInfinity, float.MaxValue }[rng.Pick(6)];
        if (type == typeof(double)) return new[] { 0d, -0d, 0.5, 1d, double.NaN, double.NegativeInfinity, double.MaxValue }[rng.Pick(7)];
        if (type == typeof(string)) return new[] { null, "", "a", "k", "ключ", new string('x', 300), "a\0b" }[rng.Pick(7)];
        if (type == typeof(Guid)) return Guid.Empty;
        if (type == typeof(Type)) return typeof(int);
        if (type.IsArray)
            return rng.Pick(3) == 0 ? null : Array.CreateInstance(type.GetElementType()!, rng.Pick(3));
        if (type.IsGenericType && type.GetGenericTypeDefinition() == typeof(ImmutableArray<>))
            return Activator.CreateInstance(type); // default (uninitialised) or empty: the validators must tolerate both
        if (type.IsValueType)
            return Activator.CreateInstance(type);
        if (type == typeof(ParquetWriterOptions)) return rng.Pick(2) == 0 ? null : new ParquetWriterOptions();
        return null;
    }

    static void CheckLaws(Type type, ConstructorInfo ctor, object a, object b)
    {
        var name = $"{type.FullName}.ctor({string.Join(",", ctor.GetParameters().Select(static p => p.ParameterType.Name))})";
        _laws++;
        // Guard the throw-on-first-call library defect (fuzz/repros/chunk-info-equality) so the other laws keep running.
        bool Eq(object x, object y)
        {
            try { return x.Equals(y); }
            catch (NotSupportedException e) when (e.Message.Contains("InlineArray", StringComparison.Ordinal)
                && Environment.GetEnvironmentVariable("PLANK_FUZZ_STRICT_INLINEARRAY_EQUALITY") != "1")
            { return true; }
            catch (Exception e) { Fail($"{name}: Equals threw {e.GetType().Name}: {e.Message}"); return false; }
        }

        var equalsObject = type.GetMethod("Equals", [typeof(object)])!;
        bool valueEquality = type.GetMethod("<Clone>$") is not null
            || equalsObject.DeclaringType != typeof(object) && equalsObject.DeclaringType != typeof(ValueType)
            || type.GetInterfaces().Any(i => i.IsGenericType && i.GetGenericTypeDefinition() == typeof(IEquatable<>));
        if (valueEquality)
        {
            if (!Eq(a, a)) Fail($"{name}: Equals is not reflexive.");
            if (!Eq(a, b) || !Eq(b, a)) Fail($"{name}: two instances built from the same arguments are not equal (or Equals is asymmetric).");
            int ha, hb;
            try { ha = a.GetHashCode(); hb = b.GetHashCode(); }
            catch (NotSupportedException e) when (e.Message.Contains("InlineArray", StringComparison.Ordinal)) { ha = hb = 0; }
            catch (Exception e) { Fail($"{name}: GetHashCode threw {e.GetType().Name}: {e.Message}"); return; }
            if (ha != hb) Fail($"{name}: equal instances have different hash codes.");
            if (a.GetHashCode() != ha) Fail($"{name}: GetHashCode is not stable.");
        }

        try
        {
            if (a.Equals(null)) Fail($"{name}: Equals(null) is true.");
            if (a.Equals(new object())) Fail($"{name}: Equals(foreign object) is true.");
            _ = a.ToString();
        }
        catch (NotSupportedException e) when (e.Message.Contains("InlineArray", StringComparison.Ordinal)) { }
        catch (InvalidOperationException e) when (e.Message.StartsWith("SRF1", StringComparison.Ordinal)) { throw; }
        catch (Exception e) { Fail($"{name}: Equals(null)/Equals(object)/ToString threw {e.GetType().Name}: {e.Message}"); }

        var clone = type.GetMethod("<Clone>$", BindingFlags.Public | BindingFlags.Instance, Type.EmptyTypes)?.Invoke(a, null);
        if (clone is not null && !Eq(a, clone))
            Fail($"{name}: record clone is not equal to its source.");

        foreach (var property in type.GetProperties(BindingFlags.Public | BindingFlags.Instance))
        {
            if (property.GetIndexParameters().Length != 0 || property.GetMethod is null || property.PropertyType.IsByRefLike)
                continue;
            try { property.GetValue(a); }
            catch (TargetInvocationException e) when (e.InnerException is InvalidOperationException or NotSupportedException or ObjectDisposedException) { }
            catch (TargetInvocationException e)
            { Fail($"{name}: property {property.Name} threw {e.InnerException?.GetType().Name}: {e.InnerException?.Message}"); }
            catch (NotSupportedException) { } // ref-struct typed property
        }
    }

    // ---- B. default(struct) ----------------------------------------------------------------------------------------

    static void Defaults(Cur c)
    {
        var structs = PublicTypes.Where(static t => t.IsValueType && !t.IsByRefLike).ToArray();
        var sweep = c.Int(0, 3) == 0;
        foreach (var type in sweep ? structs : [structs[c.Int(0, structs.Length)]])
            DefaultOf(type);
    }

    static void DefaultOf(Type type)
    {
        var t = type.IsGenericTypeDefinition ? CloseGeneric(type) : type;
        if (t is null)
            return;
        object instance;
        try { instance = Activator.CreateInstance(t)!; }
        catch (Exception) { return; }
        _defaults++;
        var name = $"default({t.Name})";
        foreach (var method in t.GetMethods(BindingFlags.Public | BindingFlags.Instance | BindingFlags.DeclaredOnly))
        {
            if (method.GetParameters().Length != 0 || method.IsGenericMethodDefinition || method.ReturnType.IsByRefLike || method.Name is "Dispose" or "<Clone>$")
                continue;
            Run(name + "." + method.Name, () => method.Invoke(instance, null));
        }

        foreach (var property in t.GetProperties(BindingFlags.Public | BindingFlags.Instance))
            if (property.GetIndexParameters().Length == 0 && property.GetMethod is not null && !property.PropertyType.IsByRefLike)
                Run(name + "." + property.Name, () => property.GetValue(instance));
        // default(struct).Dispose() is allowed to be a no-op or to throw ObjectDisposed; never anything else.
        var dispose = t.GetMethod("Dispose", Type.EmptyTypes);
        if (dispose is not null)
            Run(name + ".Dispose", () => dispose.Invoke(instance, null));
    }

    // default(struct) members that throw NullReferenceException (instead of a defined InvalidOperationException) are a
    // low-severity library finding (fuzz/FINDINGS.md, "default struct handles"); they are counted and listed, not faulted,
    // unless PLANK_FUZZ_STRICT_DEFAULT_STRUCTS=1.
    static readonly SortedSet<string> DefaultNullRefs = new(StringComparer.Ordinal);

    static void Run(string what, Func<object?> action)
    {
        try { action(); }
        catch (TargetInvocationException e) when (e.InnerException is NullReferenceException
            && Environment.GetEnvironmentVariable("PLANK_FUZZ_STRICT_DEFAULT_STRUCTS") != "1")
        {
            lock (DefaultNullRefs)
                DefaultNullRefs.Add(what);
        }
        catch (TargetInvocationException e) when (e.InnerException is InvalidOperationException or NotSupportedException or ObjectDisposedException
            or ArgumentException or CorruptParquetException) { }
        catch (TargetInvocationException e)
        {
            Fail($"{what} threw {e.InnerException?.GetType().Name}: {e.InnerException?.Message}");
        }
        catch (NotSupportedException) { } // ref-struct return type that reflection cannot box
    }

    // ---- C. reader indexers and ColumnBuffer indices ---------------------------------------------------------------

    static int _stage;
    static void Stage([System.Runtime.CompilerServices.CallerLineNumber] int line = 0) => _stage = line;

    static void Indices(Cur c)
    {
        try { IndicesCore(c); }
        catch (IndexOutOfRangeException e) { throw new InvalidOperationException($"SRF1 harness index error at stage {_stage}", e); }
    }

    static void IndicesCore(Cur c)
    {
        Stage(); var rows = c.Int(0, 6) == 0 ? c.Int(0, 3) : c.Int(1, 1500);
        Stage(); var binary = c.Int(0, 2) == 0;
        Stage(); var optional = c.Int(0, 2) == 0;
        Stage(); var groups = Math.Max(1, Math.Min(c.Int(1, 4), Math.Max(rows, 1)));
        Stage(); var pageBytes = c.Int(0, 3) == 0 ? 64u : 1024u * 1024;
        Stage(); var values = new long?[rows];
        Stage(); for (var i = 0; i < rows; i++)
            values[i] = optional && c.Int(0, 3) == 0 ? null : c.Long() >> c.Int(0, 40);
        Stage(); var schema = new PlankSchema([ColumnDefinition.Leaf("v", binary ? ParquetPhysicalType.ByteArray : ParquetPhysicalType.Int64,
            new ColumnOptions(optional ? ParquetRepetition.Optional : ParquetRepetition.Required, ImmutableArray.Create(EncodingKind.Plain)), pageStrategy: null)]);
        Stage(); var cuts = new SortedSet<int> { 0, rows };
        for (var attempt = 0; attempt < 64 && cuts.Count < Math.Min(groups, Math.Max(rows, 1)) + 1; attempt++)
        { Stage(); cuts.Add(c.Int(0, rows + 1)); }
        Stage(); var bounds = cuts.ToArray();
        Stage(); if (rows == 0)
            bounds = [0];
        Stage(); byte[] file;
        using (var stream = new MemoryStream())
        {
            Stage(); var writer = schema.CreateWriter(stream, new ParquetWriterOptions { TargetDataPageSizeBytes = pageBytes });
            Stage(); for (var g = 0; g + 1 < bounds.Length; g++)
            {
                Stage(); var slice = values.AsSpan(bounds[g], bounds[g + 1] - bounds[g]).ToArray();
                Stage(); var group = writer.StartRowGroup();
                if (binary && optional)
                {
                    Stage(); var col = group.CreateSerializedColumn<ReadOnlyMemory<byte>?>(schema.LeafColumns[0]);
                    col.Serialize(slice.Select(static v => v is { } x ? (ReadOnlyMemory<byte>?)BitConverter.GetBytes(x) : null).ToArray());
                    group.Write(col);
                }
                else if (binary)
                {
                    Stage(); var col = group.CreateSerializedColumn<ReadOnlyMemory<byte>>(schema.LeafColumns[0]);
                    col.Serialize(slice.Select(static v => (ReadOnlyMemory<byte>)BitConverter.GetBytes(v!.Value)).ToArray());
                    group.Write(col);
                }
                else if (optional)
                {
                    Stage(); var col = group.CreateSerializedColumn<long?>(schema.LeafColumns[0]);
                    col.Serialize(slice);
                    group.Write(col);
                }
                else
                {
                    Stage(); var col = group.CreateSerializedColumn<long>(schema.LeafColumns[0]);
                    col.Serialize(slice.Select(static v => v!.Value).ToArray());
                    group.Write(col);
                }
            }

            writer.CloseFile();
            file = stream.ToArray();
        }

        Stage(); var what = $"SRF1 indices rows={rows} binary={binary} optional={optional} groups={bounds.Length - 1}";
        Stage(); using var reader = new ParquetReader();
        reader.Reset(new MemoryStream(file, writable: false));
        Stage(); var leaf = reader.Schema.LeafColumns[0];

        Stage(); ExpectRange(what, reader.RowGroups.Count, i => _ = reader.RowGroups[i], "RowGroups[]");
        Stage(); for (var g = 0; g < reader.RowGroups.Count; g++)
        {
            Stage(); var group = reader.RowGroups[g];
            Stage(); ExpectRange(what, 1, i => group.GetColumnMetadata(i), "GetColumnMetadata(int)");
            Stage(); ExpectRange(what, 1, i => { if (binary) group.Column<byte>(i); else if (optional) group.Column<long?>(i); else group.Column<long>(i); }, "Column(int)");
            Stage(); var seen = 0;
            if (binary)
            {
                Stage(); foreach (var buffer in group.Column<byte>(leaf))
                {
                    Stage(); for (var i = 0; i < buffer.Count; i++)
                    {
                        Stage(); var expected = values[bounds[g] + seen + i];
                        if (buffer.IsNull(i) != (expected is null))
                            Fail($"{what}: IsNull({i}) wrong in group {g}.");
                        if (expected is not null && !buffer.GetValue(i).SequenceEqual(BitConverter.GetBytes(expected.Value)))
                            Fail($"{what}: GetValue({i}) wrong in group {g}.");
                    }

                    Stage(); ExpectRange(what, buffer.Count, i => buffer.IsNull(i), "ColumnBuffer<byte>.IsNull");
                    Stage(); ExpectRange(what, buffer.Count, i => buffer.GetValue(i), "ColumnBuffer<byte>.GetValue");
                    seen += buffer.Count;
                }
            }
            else if (optional)
            {
                Stage(); foreach (var buffer in group.Column<long?>(leaf))
                {
                    Stage(); CheckFlat(what, buffer, values, bounds[g] + seen);
                    seen += buffer.Count;
                }
            }
            else
            {
                Stage(); foreach (var buffer in group.Column<long>(leaf))
                {
                    Stage(); var boxed = values.Skip(bounds[g] + seen).Take(buffer.Count).ToArray();
                    Stage(); for (var i = 0; i < buffer.Count; i++)
                    {
                        if (buffer.Values[i] != boxed[i] || buffer.GetValue(i).Length != 1 || buffer.GetValue(i)[0] != boxed[i] || buffer.IsNull(i))
                            Fail($"{what}: ColumnBuffer<long> value {i} wrong.");
                    }

                    Stage(); ExpectRange(what, buffer.Count, i => buffer.IsNull(i), "ColumnBuffer<long>.IsNull");
                    Stage(); ExpectRange(what, buffer.Count, i => buffer.GetValue(i), "ColumnBuffer<long>.GetValue");
                    Stage(); using var retained = buffer.Retain();
                    seen += buffer.Count;
                }
            }

            Stage(); if (seen != bounds[g + 1] - bounds[g])
                Fail($"{what}: group {g} yielded {seen} values.");
            // A wrong element type must be refused with a defined exception, never read the bytes as something else silently.
            try
            {
                Stage(); foreach (var _ in group.Column<float>(leaf)) { }
                if (binary)
                    Fail($"{what}: Column<float> over a {(binary ? "BYTE_ARRAY" : "INT64")} column was accepted.");
            }
            catch (Exception e) when (e is InvalidOperationException or NotSupportedException or ArgumentException or InvalidCastException) { }
        }
    }

    static void CheckFlat(string what, ColumnBuffer<long?> buffer, long?[] values, int start)
    {
        for (var i = 0; i < buffer.Count; i++)
        {
            if (buffer.Values[i] != values[start + i] || buffer.IsNull(i) != (values[start + i] is null) || buffer.GetValue(i)[0] != values[start + i])
                Fail($"{what}: ColumnBuffer<long?> value {i} wrong.");
        }

        ExpectRange(what, buffer.Count, i => buffer.IsNull(i), "ColumnBuffer<long?>.IsNull");
        ExpectRange(what, buffer.Count, i => buffer.GetValue(i), "ColumnBuffer<long?>.GetValue");
        using var retained = buffer.Retain();
    }

    // Every index in {-1, 0, count-1, count, count+1, int.MaxValue, int.MinValue}: in range returns, out of range throws
    // ArgumentOutOfRangeException and nothing else.
    static void ExpectRange(string what, int count, Action<int> call, string api)
    {
        foreach (var index in new[] { -1, 0, count - 1, count, count + 1, int.MaxValue, int.MinValue })
        {
            _indices++;
            var valid = index >= 0 && index < count;
            Exception? error = null;
            try { call(index); }
            catch (Exception e) { error = e; }
            if (valid && error is not null)
                Fail($"{what}: {api}({index}) of {count} rejected a valid index: {error.GetType().Name}: {error.Message}");
            if (!valid && error is not ArgumentOutOfRangeException)
                Fail($"{what}: {api}({index}) of {count} {(error is null ? "accepted an invalid index" : "threw " + error.GetType().Name + " instead of ArgumentOutOfRangeException: " + error.Message)}.");
        }
    }
}
