#!/usr/bin/env python3
"""Random [ParquetSchema] row types for the source generator, plus the adapter each one needs for the
RRS1 route (Plank.Fuzzing/RandomSchemaCases.cs).  Deterministic for a given --seed.

Workflow (see fuzz/tools/README-random-schemas.md):
  gen_random_schemas.py generate --seed 1 --count 240 --out fuzz/probe/SchemaProbe/Schemas
  <build fuzz/probe/SchemaProbe; the build log is the input of the next step>
  gen_random_schemas.py classify --log build.log --generated GEN_DIR --schemas fuzz/probe/SchemaProbe/Schemas
  gen_random_schemas.py install --schemas fuzz/probe/SchemaProbe/Schemas --dest Plank.Fuzzing/RandomSchemas
`classify` deletes every schema the generator rejected (a PLANKGEN diagnostic: expected, listed in
fuzz/notes/random-schema-rejections.md) and reports generator crashes and uncompilable generated output as
findings. Repeat generate-less build/classify until the probe builds clean, then install.
"""
import argparse
import collections
import glob
import json
import os
import random
import re
import shutil
import sys

# ---------------------------------------------------------------- type model -------------------------------------
# leaf: (clr, nullable-capable value type?)
VALUE_LEAVES = ["bool", "byte", "ushort", "uint", "ulong", "int", "long", "float", "double", "decimal",
                "Guid", "DateOnly", "TimeOnly", "DateTime", "DateTimeOffset", "RowFuzzId"]
REF_LEAVES = ["string", "byte[]", "ReadOnlyMemory<byte>"]
# logical type needed for the temporal/unsigned leaves when they are root columns
LOGICAL = {
    "byte": "LogicalType = LogicalTypeKind.Integer", "ushort": "LogicalType = LogicalTypeKind.Integer",
    "uint": "LogicalType = LogicalTypeKind.Integer", "ulong": "LogicalType = LogicalTypeKind.Integer",
    "DateOnly": "LogicalType = LogicalTypeKind.Date", "TimeOnly": "LogicalType = LogicalTypeKind.Time",
    "DateTime": "LogicalType = LogicalTypeKind.Timestamp", "DateTimeOffset": "LogicalType = LogicalTypeKind.Timestamp",
}
ENCODINGS = {
    "int": ["DeltaBinaryPacked", "RleDictionary", "Plain"], "long": ["DeltaBinaryPacked", "RleDictionary", "Plain"],
    "float": ["ByteStreamSplit", "Plain"], "double": ["ByteStreamSplit", "Alp", "Plain"],
    "string": ["DeltaByteArray", "DeltaLengthByteArray", "RleDictionary", "Plain"],
    "byte[]": ["DeltaByteArray", "DeltaLengthByteArray", "Plain"], "bool": ["Plain"],
}
NAMES = ["naïve col", "tab\\there", "back\\\\slash", "it's", "dot.ted", "e\\u0301x", "smile \\U0001F600", "{braces}",
         "$dollar", "new\\nline", "ctl\\u0001x", "  padded  ", "UPPER", "a_b-c", "very" + "long" * 20]
COMPRESSIONS = ["Snappy", "Gzip", "Zstd", "Lz4", "Brotli", "None"]
# Shapes the generator is not expected to accept; they are generated on purpose so rejections are listed.
EXOTIC_COLLECTIONS = ["IReadOnlyList<{}>", "IList<{}>", "IEnumerable<{}>", "ICollection<{}>", "HashSet<{}>",
                      "System.Collections.Immutable.ImmutableArray<{}>", "Memory<{}>", "LinkedList<{}>", "Queue<{}>"]
EXOTIC_MAPS = ["IDictionary<{},{}>", "IReadOnlyDictionary<{},{}>", "SortedDictionary<{},{}>", "KeyValuePair<{},{}>[]"]


class Gen:
    """Draws shapes mostly inside what the generator documents as supported, with a deliberate minority of
    illegal ones (collections inside groups, attributes on groups, converters in nested positions, exotic
    collection types), so the rejections are exercised and listed rather than assumed."""

    def __init__(self, rnd, tag):
        self.r = rnd
        self.tag = tag
        self.records = []      # (name, [(prop, type, attr parts, kind, leaf)])
        self.counter = 0

    def pick_leaf(self, ctx):
        r = self.r
        pool = list(VALUE_LEAVES) + REF_LEAVES + REF_LEAVES
        if ctx != "root" and r.random() > 0.05:
            pool.remove("RowFuzzId")          # converters are only supported on root columns
        if ctx in ("elem", "mapval") and r.random() > 0.05:
            pool.remove("decimal")            # nested decimals have no attribute to carry precision
        if ctx == "mapkey":
            return r.choice(["int", "long", "string", "Guid", "int", "string"]) if r.random() > 0.05 else "short"
        return r.choice(pool)

    @staticmethod
    def render_leaf(t, nullable):
        if nullable:
            return t + "?"
        return t

    def leaf_type(self, ctx, nullable_p=0.35):
        t = self.pick_leaf(ctx)
        return self.render_leaf(t, self.r.random() < nullable_p), t

    def elem_type(self):
        """The element of a list/array."""
        r = self.r
        if r.random() < 0.12:
            inner, _ = self.leaf_type("elem")
            return (r.choice(["List<{}>", "{}[]"])).format(inner) + ("?" if r.random() < 0.3 else "")
        if r.random() < 0.15:
            return self.record(allow_optional_inside=False, collections=False) + ""
        return self.leaf_type("elem")[0]

    def collection(self, element):
        r = self.r
        nullable = "?" if r.random() < 0.4 else ""
        shape = r.random()
        if shape < 0.5:
            return f"List<{element}>{nullable}"
        if shape < 0.9:
            return f"{element}[]{nullable}"
        return r.choice(EXOTIC_COLLECTIONS).format(element) + nullable

    def root_type(self):
        r = self.r
        pick = r.random()
        if pick < 0.35:
            t, leaf = self.leaf_type("root")
            return t, "leaf", leaf
        if pick < 0.65:
            return self.collection(self.elem_type()), "collection", None
        if pick < 0.8:
            key = self.render_leaf(self.pick_leaf("mapkey"), False)
            value, _ = self.leaf_type("mapval")
            nullable = "?" if r.random() < 0.4 else ""
            if r.random() < 0.1:
                return r.choice(EXOTIC_MAPS).format(key, value) + nullable, "map", None
            if r.random() < 0.08:
                return f"Dictionary<{key}, List<{value}>>{nullable}", "map", None
            return f"Dictionary<{key}, {value}>{nullable}", "map", None
        nullable = r.random() < 0.5
        name = self.record(allow_optional_inside=not nullable, collections=r.random() < 0.06)
        return name + ("?" if nullable else ""), "record", None

    def record(self, allow_optional_inside, collections):
        r = self.r
        self.counter += 1
        name = f"{self.tag}_R{self.counter}"
        props = []
        for i in range(r.randint(1, 4)):
            pick = r.random()
            parts = []
            if pick < 0.12:
                # nested record; optional boundaries along a leaf's path must stay at most one
                inner_nullable = allow_optional_inside and r.random() < 0.4
                inner = self.record(allow_optional_inside=allow_optional_inside and not inner_nullable, collections=False)
                texpr, kind, leaf = inner + ("?" if inner_nullable else ""), "record", None
            elif collections and pick < 0.2:
                texpr, kind, leaf = self.collection(self.leaf_type("elem")[0]), "collection", None
            else:
                t, leaf = self.leaf_type("root" if False else "elem" if False else "record",
                                         nullable_p=0.4 if allow_optional_inside else 0.0)
                texpr, kind = t, "leaf"
                if leaf == "decimal":
                    p = r.choice([5, 9, 12, 18])
                    parts.append(f"Precision = {p}, Scale = {r.randint(0, min(p, 6))}")
            props.append((f"P{i}", texpr, parts, kind, leaf))
        self.records.append((name, props))
        return name

    def schema(self, index):
        r = self.r
        name = f"Rnd{index:03d}"
        self.tag = name
        props = []
        used_ids = set()
        for i in range(r.randint(1, 7)):
            texpr, kind, leaf = self.root_type()
            parts = []
            if leaf == "decimal" or (leaf is None and kind == "collection" and "decimal" in texpr):
                p = r.choice([5, 9, 12, 18, 20, 28])
                parts.append(f"Precision = {p}, Scale = {r.randint(0, min(p, 8))}")
            if kind == "leaf" and leaf in LOGICAL:
                parts.append(LOGICAL[leaf])
            if kind == "leaf" and leaf == "RowFuzzId":
                parts.append("Converter = typeof(RowFuzzIdConverter)")
            # Column options belong on leaf columns; the rest is the minority that must be rejected.
            options_ok = kind == "leaf" or r.random() < 0.08
            if options_ok:
                if leaf in ENCODINGS and r.random() < 0.5:
                    parts.append("Encodings = [EncodingKind." + r.choice(ENCODINGS[leaf]) + "]")
                if r.random() < 0.25:
                    parts.append("Compression = CompressionKind." + r.choice(COMPRESSIONS))
                if r.random() < 0.15:
                    parts.append("BloomFilter = true")
            if r.random() < 0.25:
                fid = r.randint(1, 200)
                if fid not in used_ids:
                    used_ids.add(fid)
                    parts.append(f"FieldId = {fid}")
            col = r.choice(NAMES) + f"{i}" if r.random() < 0.35 else None
            attr = ""
            if col is not None:
                attr = f'[ParquetColumn("{col}"' + (", " + ", ".join(parts) if parts else "") + ")]"
            elif parts:
                attr = "[ParquetColumn(" + ", ".join(parts) + ")]"
            props.append((f"P{i}", texpr, attr, kind, leaf))
        return name, props, 0


def col_name(pname, attr):
    m = re.match(r'\[ParquetColumn\("((?:[^"\\]|\\.)*)"', attr or "")
    return m.group(1) if m else pname


def rename_attr(attr, new):
    if attr.startswith('[ParquetColumn("'):
        return re.sub(r'^\[ParquetColumn\("(?:[^"\\]|\\.)*"', f'[ParquetColumn("{new}"', attr, count=1)
    if attr.startswith("[ParquetColumn("):
        return f'[ParquetColumn("{new}", ' + attr[len("[ParquetColumn("):]
    return f'[ParquetColumn("{new}")]'


def mutate(rnd, props):
    """A related schema: root scalar columns dropped, added, renamed, reordered, made (non)nullable or widened.
    Returns (mutated props, list of human-readable mutations)."""
    props = [list(p) for p in props]
    notes = []
    n_ops = rnd.randint(1, 3)
    for _ in range(n_ops):
        op = rnd.choice(["drop", "add", "rename", "reorder", "toggle", "widen"])
        leaves = [i for i, p in enumerate(props) if p[3] == "leaf" and "Converter" not in p[2] and "LogicalType" not in p[2]]
        if op == "drop" and len(props) > 1:
            i = rnd.randrange(len(props))
            notes.append(f"drop {props[i][0]}")
            del props[i]
        elif op == "add":
            k = len([p for p in props if p[0].startswith("X")])
            props.append([f"X{k}", rnd.choice(["int", "string?", "long?", "double"]), "", "leaf", "int"])
            notes.append(f"add X{k}")
        elif op == "rename" and props:
            i = rnd.randrange(len(props))
            props[i][2] = rename_attr(props[i][2], f"renamed{i}")
            notes.append(f"rename {props[i][0]}")
        elif op == "reorder":
            rnd.shuffle(props)
            notes.append("reorder")
        elif op == "toggle" and leaves:
            i = rnd.choice(leaves)
            props[i][1] = props[i][1][:-1] if props[i][1].endswith("?") else props[i][1] + "?"
            notes.append(f"toggle nullability {props[i][0]}")
        elif op == "widen" and leaves:
            i = rnd.choice(leaves)
            base = props[i][1].rstrip("?")
            if base in ("int", "float") and "Encodings" not in props[i][2]:
                wide = {"int": "long", "float": "double"}[base]
                props[i][1] = wide + ("?" if props[i][1].endswith("?") else "")
                notes.append(f"widen {props[i][0]} to {wide}")
    return [tuple(p) for p in props], notes


def emit_schema(rnd, index):
    g = Gen(rnd, "")
    name, props, depth = g.schema(index)
    twin_props, notes = mutate(random.Random(rnd.random()), props)
    out = []
    w = out.append
    w("// <auto-generated by fuzz/tools/gen_random_schemas.py; do not edit by hand. -->")
    w("#nullable enable")
    w("using System.Collections.Generic;")
    w("using Plank.Dataset;")
    w("using Plank.Reading;")
    w("using Plank.RowApi;")
    w("using Plank.Schema;")
    w("using Plank.Writing;")
    w("")
    w("namespace Plank.Fuzzing.RandomSchemas;")
    w("")
    for rname, rprops in g.records:
        w(f"public sealed class {rname}")
        w("{")
        for pname, texpr, parts, kind, leaf in rprops:
            if parts:
                w(f"    [ParquetColumn({', '.join(parts)})]")
            w(f"    public {texpr} {pname} {{ get; set; }}" + (" = default!;" if is_nonnull_ref(texpr) else ""))
        w("}")
        w("")
    record_names = {r[0] for r in g.records}
    for cls, plist in ((name, props), (name + "v", twin_props)):
        w("[ParquetSchema(AllowAllocatingValues = true)]")
        w(f"public sealed partial class {cls}")
        w("{")
        w("    public int Seq { get; set; }")
        w("")
        for pname, texpr, attr, kind, leaf in plist:
            if attr:
                w(f"    {attr}")
            w(f"    public {texpr} {pname} {{ get; set; }}" + (" = default!;" if is_nonnull_ref(texpr) else ""))
        w("}")
        w("")
    w(emit_case(name, props, record_names, twin=name + "v", mutations="; ".join(notes)))
    w("")
    w(emit_case(name + "v", twin_props, record_names, twin=None, mutations=""))
    return name, "\n".join(out), depth, props


def is_nonnull_ref(texpr):
    """A reference-typed property without a nullable annotation needs an initializer to keep the build quiet."""
    if texpr.endswith("?"):
        return False
    value_types = {"bool", "byte", "ushort", "uint", "ulong", "int", "long", "float", "double", "decimal", "Guid",
                   "DateOnly", "TimeOnly", "DateTime", "DateTimeOffset", "RowFuzzId", "ReadOnlyMemory<byte>"}
    return texpr not in value_types


VALUE_TYPE_SET = {"bool", "byte", "ushort", "uint", "ulong", "int", "long", "float", "double", "decimal", "Guid",
                  "DateOnly", "TimeOnly", "DateTimeOffset", "RowFuzzId", "ReadOnlyMemory<byte>", "short"}


def unset_kind(texpr, record_names):
    """What an unassigned column reads as. Reference-typed buffers are cleared on slot reuse (null); scalar and record
    buffers are not, so a skipped scalar has no defined value; unassigned required references are rejected input."""
    base = texpr.rstrip("?")
    nullable = texpr.endswith("?")
    if base == "DateTime":
        return "no"           # default(DateTime) is not a UTC timestamp
    if base in VALUE_TYPE_SET:
        return "skip"
    if base in record_names:
        return "skip" if nullable else "no"
    return "null" if nullable else "no"


def emit_case(name, props, record_names, twin, mutations):
    cols = ["Seq"] + [p[0] for p in props]
    types = ["int"] + [p[1] for p in props]
    colnames = ["Seq"] + [col_name(p[0], p[2]) for p in props]
    kinds = ["no"] + [unset_kind(p[1], record_names) for p in props]
    optional = ["false"] + ["true" if p[1].endswith("?") else "false" for p in props]
    # a collection of bytes (byte[] built as an array shape) is a binary column to the generated reader too
    binary = {p[0]: p[1] for p in props if p[1].rstrip("?") in ("byte[]", "ReadOnlyMemory<byte>")}
    has_repeated = any(p[3] in ("collection", "map") and p[1].rstrip("?") != "byte[]" for p in props)
    has_converter = any("Converter" in p[2] for p in props)
    o = []
    w = o.append

    def q(text):
        return '"' + text.replace("\\", "\\\\").replace('"', '\\"') + '"'

    w(f"internal sealed class {name}Case : RandomSchemaCase")
    w("{")
    w(f'    public override string Name => "{name}";')
    w(f"    public override Type RowType => typeof({name});")
    w(f"    public override int ColumnCount => {len(cols)};")
    w(f"    public override ParquetSchema Schema => {name}.Schema;")
    w(f"    public override void SetSeq(object row, int seq) => (({name})row).Seq = seq;")
    w(f"    public override RandomSchemaCase? Twin => {'new ' + twin + 'Case()' if twin else 'null'};")
    w(f"    public override string Mutations => {q(mutations)};")
    w(f"    public override string[] Props {{ get; }} = [{', '.join(q(c) for c in cols)}];")
    # column names are C# literals written exactly as they appear in the [ParquetColumn] attribute
    w(f"    public override string[] ColumnNames {{ get; }} = [{', '.join(('@' if False else '') + ('\"Seq\"' if i == 0 else cn_literal(props[i - 1])) for i in range(len(cols)))}];")
    w(f"    public override string[] Clr {{ get; }} = [{', '.join(q(t) for t in types)}];")
    w(f"    public override bool[] Optional {{ get; }} = [{', '.join(optional)}];")
    w(f"    public override string[] UnsetKinds {{ get; }} = [{', '.join(q(k) for k in kinds)}];")
    w(f"    public override bool AppendLatestSafe => {str(not has_repeated and not has_converter).lower()};")
    w("")
    w("    public override object? Get(object row, int index) => index switch")
    w("    {")
    for i, c in enumerate(cols):
        w(f"        {i} => (object?)(({name})row).{c},")
    w("        _ => throw new ArgumentOutOfRangeException(nameof(index))")
    w("    };")
    w("")
    w("    public override object? DefaultOf(int index) => index switch")
    w("    {")
    for i, t in enumerate(types):
        # A required group that is absent from the file reads as a record with default leaves, not null.
        w(f"        {i} => (object?)new {t}()," if t in record_names else f"        {i} => (object?)default({t}),")
    w("        _ => throw new ArgumentOutOfRangeException(nameof(index))")
    w("    };")
    w("")
    w("    public override void ApplyUnset(object row, int mask)")
    w("    {")
    w(f"        var v = ({name})row;")
    w("        var effective = 0;")
    for i, c in enumerate(cols):
        if kinds[i] == "null":
            w(f"        if ((mask & {1 << i}) != 0) {{ v.{c} = default; effective |= {1 << i}; }}")
        elif kinds[i] == "skip":
            w(f"        if ((mask & {1 << i}) != 0) effective |= {1 << i};")
    w("        UnsetColumns.Remember(v, effective);")
    w("    }")
    w("")
    def assign(indent, target):
        for i, c in enumerate(cols):
            if i == 0 or kinds[i] == "no":
                w(f"{indent}{target}.{c} = v.{c};")
            else:
                w(f"{indent}if ((unset & {1 << i}) == 0) {target}.{c} = v.{c};")

    w("    public override byte[] Write(object[] rows, ParquetWriterOptions options, int route, int groups)")
    w("    {")
    w("        using var stream = new MemoryStream();")
    w("        if (route == 2)")
    w("        {")
    w(f"            using var parquetWriter = {name}.Schema.CreateWriter(stream, options);")
    w("            var per = Math.Max(1, (rows.Length + groups - 1) / groups);")
    w("            for (var start = 0; start < rows.Length || start == 0; start += per)")
    w("            {")
    w(f"                var group = {name}.CreateRowWriter(parquetWriter.StartRowGroup(), options);")
    w("                for (var i = start; i < Math.Min(rows.Length, start + per); i++)")
    w("                {")
    w(f"                    var v = ({name})rows[i];")
    w("                    var unset = UnsetColumns.Of(v);")
    w("                    var r = group.GetRow();")
    assign("                    ", "r")
    w("                }")
    w("                group.Write();")
    w("                if (rows.Length == 0)")
    w("                    break;")
    w("            }")
    w("            parquetWriter.CloseFile();")
    w("            return stream.ToArray();")
    w("        }")
    w("")
    w(f"        using (var writer = {name}.CreateRowWriter(stream, options))")
    w("        {")
    w("            if (route == 1)")
    w("            {")
    w("                var cursor = writer.CreateCursor();")
    w("                foreach (var row in rows)")
    w("                {")
    w(f"                    var v = ({name})row;")
    w("                    var unset = UnsetColumns.Of(v);")
    w("                    cursor.NextRow();")
    assign("                    ", "cursor")
    w("                }")
    w("            }")
    w("            else")
    w("            {")
    w("                foreach (var row in rows)")
    w("                {")
    w(f"                    var v = ({name})row;")
    w("                    var unset = UnsetColumns.Of(v);")
    w("                    var r = writer.GetRow();")
    assign("                    ", "r")
    w("                }")
    w("            }")
    w("            writer.Complete();")
    w("        }")
    w("        return stream.ToArray();")
    w("    }")
    w("")
    w(f"    static {name}.Projection Project(int mask)")
    w("    {")
    w(f"        var p = {name}.Projection.None;")
    for i, c in enumerate(cols):
        w(f"        if ((mask & {1 << i}) != 0) p |= {name}.Projection.{c};")
    w("        return p;")
    w("    }")
    w("")
    w(f"    static string? Compare({name}.ReadRow r, {name} v, int mask)")
    w("    {")
    w("        var unset = UnsetColumns.Of(v);")
    for i, c in enumerate(cols):
        if c in binary:
            expr = f"!DeepEq.Binary(r.{c}.IsNull ? null : r.{c}.Value.ToArray(), v.{c})"
        else:
            expr = f"!DeepEq.Of(r.{c}, v.{c})"
        skip = f"(unset & {1 << i}) == 0 && " if kinds[i] == "skip" else ""
        w(f'        if ((mask & {1 << i}) != 0 && {skip}{expr}) return "{c}";')
    w("        return null;")
    w("    }")
    w("")
    w(f"    static string? CompareEvolved({name}.ReadRow r, object?[] expected, int mask)")
    w("    {")
    for i, c in enumerate(cols):
        if c in binary:
            expr = f"!DeepEq.Binary(r.{c}.IsNull ? null : r.{c}.Value.ToArray(), expected[{i}])"
        else:
            expr = f"!DeepEq.Of(r.{c}, expected[{i}])"
        w(f'        if ((mask & {1 << i}) != 0 && {expr}) return "{c}";')
    w("        return null;")
    w("    }")
    w("")
    w("    public override void Check(byte[] bytes, object[] rows, int mask, RowReaderOptions options, bool viaSource, bool reuse)")
    w("    {")
    w("        var projection = Project(mask);")
    w(f"        using var reader = viaSource ? {name}.CreateRowReader(FullValueOracle.Source(bytes), projection, options)")
    w(f"            : {name}.CreateRowReader(new MemoryStream(bytes, writable: false), projection, options);")
    w("        for (var pass = 0; pass < (reuse ? 2 : 1); pass++)")
    w("        {")
    w("            if (pass == 1)")
    w("            {")
    w("                if (viaSource)")
    w("                    reader.Reset(FullValueOracle.Source(bytes), projection);")
    w("                else")
    w("                    reader.Reset(new MemoryStream(bytes, writable: false), projection);")
    w("            }")
    w("            var index = 0;")
    w("            while (reader.MoveNext())")
    w("            {")
    w("                if (index >= rows.Length)")
    w('                    throw new PlankRowApiFuzzTarget.RowApiRoundTripException($"{Name} returned an extra row {index}.");')
    w(f"                var diff = Compare(reader.Current, ({name})rows[index], mask);")
    w("                if (diff is not null)")
    w('                    throw new PlankRowApiFuzzTarget.RowApiRoundTripException($"{Name} lost \'{diff}\' at row {index} (mask {mask:x}).");')
    w("                index++;")
    w("            }")
    w("            if (index != rows.Length)")
    w('                throw new PlankRowApiFuzzTarget.RowApiRoundTripException($"{Name} read {index} rows; expected {rows.Length}.");')
    w("        }")
    w("    }")
    w("")
    w("    public override void CheckEvolved(byte[] bytes, object?[][] expected, int mask, ParquetSchemaEvolutionOptions? evolution, RowReaderOptions options)")
    w("    {")
    w(f"        using var reader = {name}.CreateRowReader(new MemoryStream(bytes, writable: false), Project(mask), options, evolution);")
    w("        var index = 0;")
    w("        while (reader.MoveNext())")
    w("        {")
    w("            if (index >= expected.Length)")
    w('                throw new PlankRowApiFuzzTarget.RowApiRoundTripException($"{Name} evolved read returned an extra row {index}.");')
    w("            var diff = CompareEvolved(reader.Current, expected[index], mask);")
    w("            if (diff is not null)")
    w('                throw new PlankRowApiFuzzTarget.RowApiRoundTripException($"{Name} evolved read lost \'{diff}\' ({Clr[Array.IndexOf(Props, diff)]}) at row {index} (mask {mask:x}); expected {DeepEq.Describe(expected[index][Array.IndexOf(Props, diff)])}.");')
    w("            index++;")
    w("        }")
    w("        if (index != expected.Length)")
    w('            throw new PlankRowApiFuzzTarget.RowApiRoundTripException($"{Name} evolved read returned {index} of {expected.Length} rows.");')
    w("    }")
    w("")
    w("    public override List<int> ReadSeqs(byte[] bytes, object[] rows, RowReaderOptions options)")
    w("    {")
    w("        var seqs = new List<int>();")
    w(f"        using var reader = {name}.CreateRowReader(new MemoryStream(bytes, writable: false), default, options);")
    w("        while (reader.MoveNext())")
    w("        {")
    w("            var seq = reader.Current.Seq;")
    w("            if ((uint)seq >= (uint)rows.Length)")
    w('                throw new PlankRowApiFuzzTarget.RowApiRoundTripException($"{Name} dataset file returned unknown Seq {seq}.");')
    w(f"            var diff = Compare(reader.Current, ({name})rows[seq], {(1 << len(cols)) - 1});")
    w("            if (diff is not null)")
    w('                throw new PlankRowApiFuzzTarget.RowApiRoundTripException($"{Name} dataset lost \'{diff}\' of row {seq}.");')
    w("            seqs.Add(seq);")
    w("        }")
    w("        return seqs;")
    w("    }")
    w("")
    w("    public override IRandomDatasetSink CreateDataset(Func<object, int> partitionOf, bool ownedPath, bool createParts, FaultingDatasetFile[] files, DatasetWriterOptions options)")
    w("    {")
    w(f"        {name}.Route route = ({name} row, IParquetBufferPool pool, out ParquetBuffer? allocation) =>")
    w("            RandomDatasetKeys.Select(partitionOf(row), ownedPath, pool, out allocation);")
    w("        DatasetFilePath filePath = (ReadOnlySpan<byte> key, ulong index, IParquetBufferPool pool, out ParquetBuffer? allocation) =>")
    w("            RandomDatasetKeys.FilePath(key, index, out allocation);")
    w(f"        return new Sink(createParts ? {name}.CreateDatasetWriter(route, filePath, files, options)")
    w(f"            : {name}.CreateDatasetWriter(route, files, options));")
    w("    }")
    w("")
    w("    sealed class Sink(" + name + ".DatasetWriter writer) : IRandomDatasetSink")
    w("    {")
    w(f"        public void Queue(object row) => writer.Queue(({name})row);")
    w("        public void Dispose() => writer.Dispose();")
    w("    }")
    w("}")
    return "\n".join(o)


def cn_literal(prop):
    """The column name as a C# literal, exactly as the attribute spells it (or the property name)."""
    m = re.match(r'\[ParquetColumn\(("(?:[^"\\]|\\.)*")', prop[2] or "")
    return m.group(1) if m else '"' + prop[0] + '"'


# ------------------------------------------------------------------ commands -------------------------------------
def cmd_generate(a):
    os.makedirs(a.out, exist_ok=True)
    for f in glob.glob(os.path.join(a.out, "*.cs")):
        os.remove(f)
    meta = {}
    index = 0
    # --plan "1:240,2:300": seed:count pairs, numbered consecutively so the names stay unique and stable
    plan = [(int(x.split(":")[0]), int(x.split(":")[1])) for x in a.plan.split(",")] if a.plan else [(a.seed, a.count)]
    for seed, count in plan:
        rnd = random.Random(seed)
        for _ in range(count):
            name, src, depth, props = emit_schema(random.Random(rnd.random()), index)
            with open(os.path.join(a.out, f"{name}.cs"), "w") as fh:
                fh.write(src)
            meta[name] = [{"name": p[0], "type": p[1]} for p in props]
            index += 1
    with open(os.path.join(a.out, "..", "schemas.json"), "w") as fh:
        json.dump(meta, fh, indent=1)
    print(f"generated {index} schemas into {a.out}")


ERROR_RE = re.compile(r"^(?P<file>[^\s(][^(]*)\((?P<line>\d+),(?P<col>\d+)\): error (?P<id>[A-Z]+\d+): (?P<msg>.*?)(?: \[.*)?$")


def cmd_classify(a):
    """Reads a dotnet build log, removes rejected schemas, and records generator crashes / bad output as findings."""
    generated = {}
    for f in glob.glob(os.path.join(a.generated, "**", "*.g.cs"), recursive=True):
        text = open(f, errors="replace").read()
        m = re.search(r"partial class (Rnd\d+)\b", text)
        if m:
            generated[os.path.abspath(f)] = m.group(1)
    rejected = collections.OrderedDict()
    findings = []
    crash = re.compile(r"(AD0001|CS8785|threw an exception|Generator '.*' failed)")
    seen = set()
    for line in open(a.log, errors="replace"):
        line = line.rstrip()
        if crash.search(line) and line not in seen:
            seen.add(line)
            findings.append(("generator crash", line))
            continue
        m = ERROR_RE.match(line)
        if not m:
            continue
        f = os.path.abspath(m.group("file").strip())
        d = m.groupdict()
        schema = None
        origin = None
        if os.path.basename(f).startswith("Rnd") and f.endswith(".cs") and "obj" not in f:
            schema = re.match(r"(Rnd\d+)", os.path.basename(f)).group(1)
            origin = "schema"
        elif f in generated:
            schema = generated[f]
            origin = "generated"
        else:
            base = os.path.basename(f)
            hit = [n for p, n in generated.items() if os.path.basename(p) == base]
            if hit:
                schema, origin = hit[0], "generated"
        if schema is None:
            findings.append(("unattributed error", line))
            continue
        kind = "diagnostic" if d["id"].startswith("PLANKGEN") else ("uncompilable generated output" if origin == "generated" else "adapter/compile error")
        rejected.setdefault(schema, []).append((kind, d["id"], d["msg"]))
    # A rejected schema generates nothing, so the adapter's references to its generated members fail too:
    # those follow-on errors are not separate findings.
    for schema, items in list(rejected.items()):
        if any(kind == "diagnostic" for kind, _, _ in items):
            rejected[schema] = [it for it in items if it[0] == "diagnostic"]
    removed = 0
    for schema in rejected:
        path = os.path.join(a.schemas, schema + ".cs")
        if os.path.exists(path):
            os.makedirs(os.path.join(a.schemas, "..", "rejected"), exist_ok=True)
            shutil.move(path, os.path.join(a.schemas, "..", "rejected", schema + ".cs.txt"))
            removed += 1
    state = os.path.join(a.schemas, "..", "rejections.json")
    old = json.load(open(state)) if os.path.exists(state) else {}
    for schema, items in rejected.items():
        old[schema] = items
    json.dump(old, open(state, "w"), indent=1)
    other = os.path.join(a.schemas, "..", "findings.json")
    oldf = json.load(open(other)) if os.path.exists(other) else []
    json.dump(oldf + findings, open(other, "w"), indent=1)
    print(f"removed {removed} schemas; {len(findings)} findings; {len(rejected)} rejected this round")
    for f in findings[:20]:
        print("FINDING", f)
    for s, items in list(rejected.items())[:5]:
        print(s, items[:2])


def cmd_install(a):
    os.makedirs(a.dest, exist_ok=True)
    for f in glob.glob(os.path.join(a.dest, "*.cs")):
        os.remove(f)
    names = []
    for f in sorted(glob.glob(os.path.join(a.schemas, "Rnd*.cs"))):
        shutil.copy(f, a.dest)
        names.append(os.path.basename(f)[:-3])
    with open(os.path.join(a.dest, "RandomSchemaRegistry.g.cs"), "w") as fh:
        fh.write("// <auto-generated by fuzz/tools/gen_random_schemas.py install; do not edit by hand. -->\n")
        fh.write("namespace Plank.Fuzzing.RandomSchemas;\n\ninternal static class RandomSchemaRegistry\n{\n")
        fh.write("    internal static readonly RandomSchemaCase[] All =\n    [\n")
        for n in names:
            fh.write(f"        new {n}Case(),\n")
        fh.write("    ];\n}\n")
    # rejection report
    state = os.path.join(a.schemas, "..", "rejections.json")
    rej = json.load(open(state)) if os.path.exists(state) else {}
    meta = json.load(open(os.path.join(a.schemas, "..", "schemas.json")))
    report = os.path.join(a.report)
    os.makedirs(os.path.dirname(report), exist_ok=True)
    with open(report, "w") as fh:
        fh.write("# Random schema shapes: accepted and rejected by the source generator\n\n")
        fh.write(f"Generated by `fuzz/tools/gen_random_schemas.py` (deterministic). {len(names)} schemas accepted and compiled into "
                 f"`Plank.Fuzzing/RandomSchemas`; {len(rej)} rejected.\n\n")
        by = collections.OrderedDict()
        for schema, items in sorted(rej.items()):
            for kind, ident, msg in items[:1]:
                key = (kind, ident, re.sub(r"'[^']*'", "'…'", msg))
                by.setdefault(key, []).append(schema)
        fh.write("## Rejection reasons (first diagnostic of each rejected schema)\n\n| kind | id | message | schemas |\n|---|---|---|---|\n")
        for (kind, ident, msg), schemas in sorted(by.items(), key=lambda kv: -len(kv[1])):
            example = schemas[0]
            props = "; ".join(p["type"] for p in meta.get(example, []))
            fh.write(f"| {kind} | {ident} | {msg} | {len(schemas)} (e.g. {example}: `{props}`) |\n")
        fh.write("\nOnly `diagnostic` rows are expected rejections. `uncompilable generated output` and generator crashes are library findings.\n")
    print(f"installed {len(names)} schemas; report {report}")


def main():
    p = argparse.ArgumentParser()
    sub = p.add_subparsers(dest="cmd", required=True)
    g = sub.add_parser("generate")
    g.add_argument("--seed", type=int, default=1)
    g.add_argument("--count", type=int, default=240)
    g.add_argument("--plan", default="")
    g.add_argument("--out", required=True)
    c = sub.add_parser("classify")
    c.add_argument("--log", required=True)
    c.add_argument("--generated", required=True)
    c.add_argument("--schemas", required=True)
    i = sub.add_parser("install")
    i.add_argument("--schemas", required=True)
    i.add_argument("--dest", required=True)
    i.add_argument("--report", default="fuzz/notes/random-schema-rejections.md")
    a = p.parse_args()
    {"generate": cmd_generate, "classify": cmd_classify, "install": cmd_install}[a.cmd](a)


if __name__ == "__main__":
    main()
