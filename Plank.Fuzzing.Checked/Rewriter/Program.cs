// Plank checked-access rewriter (see ../README.md).
// Usage: Plank.Fuzzing.Checked.Rewriter <response-file>
// Response-file lines: out=<dir> root=<Plank project dir> define=<A;B> ref=<path> src=<path> gen=<generator dll>
//                      report=<tsv path>
// Builds a semantic model of the library sources (plus the output of the `gen=` source generators, which the
// build then stops running), rewrites every unchecked access to Plank.CheckedAccess.C (same line layout, so
// stack traces keep the original file:line through a `#line` directive), and writes:
//   <out>/originals.txt  the Compile items replaced,  <out>/rewritten.txt  the files to compile instead.
using System.Text;
using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.CSharp;
using Microsoft.CodeAnalysis.CSharp.Syntax;

namespace Plank.Fuzzing.Checked.Rewriter;

static class Program
{
    static int Main(string[] args)
    {
        var lines = File.ReadAllLines(args[0]).Where(l => l.Contains('=')).Select(l => (Key: l[..l.IndexOf('=')], Value: l[(l.IndexOf('=') + 1)..].Trim())).ToList();
        string One(string key) => lines.Single(l => l.Key == key).Value;
        IEnumerable<string> Many(string key) => lines.Where(l => l.Key == key).Select(l => l.Value).Where(v => v.Length > 0);
        var outDir = One("out");
        var root = Path.GetFullPath(One("root")).TrimEnd('/') + "/";
        var defines = Many("define").SelectMany(d => d.Split(new[] { ';', ',' }, StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries)).ToArray();
        var parse = new CSharpParseOptions(LanguageVersion.Preview, preprocessorSymbols: defines);
        // src=<full path>|<Compile item identity> (the identity is written back to originals.txt for `Compile Remove`).
        var identities = new Dictionary<string, string>(StringComparer.Ordinal);
        foreach (var src in Many("src"))
        {
            var parts = src.Split('|');
            identities[Path.GetFullPath(parts[0])] = parts.Length > 1 ? parts[1] : parts[0];
        }

        var sources = identities.Keys.ToList();
        var hand = HandRewrites.Load(Many("hand"));
        // A Compile item that is itself a generated copy of a library file (agent guard's -p:PlankGuardArrays=true writes
        // obj/.../guard-arrays/X.cs starting with `#line 1 "<original>"`) is named after its original for sites, hand
        // rewrites and the output #line.
        var logical = new Dictionary<string, string>(StringComparer.Ordinal);
        var texts = new Dictionary<string, string>(StringComparer.Ordinal);
        foreach (var p in sources)
        {
            var text = File.ReadAllText(p);
            var name = p;
            if (text.StartsWith("#line 1 \"", StringComparison.Ordinal))
            {
                var end = text.IndexOf('"', 9);
                var original = Path.GetFullPath(text[9..end]);
                if (original.StartsWith(root, StringComparison.Ordinal))
                {
                    name = original;
                    text = text[(text.IndexOf('\n') + 1)..];
                }
            }

            logical[p] = name;
            texts[p] = text;
        }

        var trees = sources.Select(p => CSharpSyntaxTree.ParseText(
            hand.Apply(logical[p].StartsWith(root, StringComparison.Ordinal) ? logical[p][root.Length..] : null, texts[p]),
            parse, p, Encoding.UTF8)).ToList();
        hand.ThrowIfUnused();
        var refs = Many("ref").Select(p => (MetadataReference)MetadataReference.CreateFromFile(p)).ToList();
        var options = new CSharpCompilationOptions(OutputKind.DynamicallyLinkedLibrary, allowUnsafe: true,
            nullableContextOptions: NullableContextOptions.Enable);
        Compilation compilation = CSharpCompilation.Create("Plank", trees, refs, options);

        var generated = new List<SyntaxTree>();
        var generators = Many("gen").SelectMany(LoadGenerators).ToList();
        if (generators.Count > 0)
        {
            var driver = CSharpGeneratorDriver.Create(generators.Select(g => g is IIncrementalGenerator i ? i.AsSourceGenerator() : (ISourceGenerator)g),
                parseOptions: parse);
            driver.RunGeneratorsAndUpdateCompilation(compilation, out var updated, out var genDiagnostics);
            foreach (var d in genDiagnostics)
                Console.Error.WriteLine("generator: " + d);
            generated = updated.SyntaxTrees.Where(t => !trees.Contains(t)).ToList();
            compilation = updated;
        }

        var errors = compilation.GetDiagnostics().Where(d => d.Severity == DiagnosticSeverity.Error).ToList();
        Console.WriteLine($"PlankCheckedAccess: semantic model of {trees.Count} file(s) + {generated.Count} generated, {errors.Count} error(s)");
        // Printed without the canonical "file(line,col): error" shape, which MSBuild's Exec would turn into build errors.
        // Expected: CS8795 for [LibraryImport] partials (that generator is not run here; it does not touch the sites).
        foreach (var e in errors.Take(20))
            Console.WriteLine($"  semantic-model {e.Id} {Path.GetFileName(e.Location.SourceTree?.FilePath)}:{e.Location.GetLineSpan().StartLinePosition.Line + 1} {e.GetMessage()}");

        Directory.CreateDirectory(outDir);
        var report = new List<string>();
        var originals = new List<string>();
        var rewritten = new List<string>();
        var total = 0;
        foreach (var tree in compilation.SyntaxTrees)
        {
            var isGenerated = generated.Contains(tree);
            var path = tree.FilePath;
            if (!isGenerated && !Path.GetFullPath(path).StartsWith(root, StringComparison.Ordinal))
                continue;
            var logicalPath = isGenerated ? path : logical[Path.GetFullPath(path)];
            var relative = isGenerated ? "generated/" + Path.GetFileName(path) : logicalPath[root.Length..];
            var model = compilation.GetSemanticModel(tree);
            var rewriter = new CheckedRewriter(model, relative, report);
            var result = rewriter.Visit(tree.GetRoot());
            if (rewriter.Count == 0 && !isGenerated && !hand.Touched.Contains(relative))
                continue;
            total += rewriter.Count;
            var target = Path.Combine(outDir, relative.Replace('/', '_'));
            var text = (isGenerated ? "" : "#line 1 \"" + logicalPath + "\"\n") + result.ToFullString();
            if (!File.Exists(target) || File.ReadAllText(target) != text)
                File.WriteAllText(target, text);
            if (!isGenerated)
                originals.Add(identities[Path.GetFullPath(path)]);
            rewritten.Add(target);
        }

        File.WriteAllLines(Path.Combine(outDir, "originals.txt"), originals);
        File.WriteAllLines(Path.Combine(outDir, "rewritten.txt"), rewritten);
        var reportPath = lines.Where(l => l.Key == "report").Select(l => l.Value).FirstOrDefault() ?? Path.Combine(outDir, "sites.tsv");
        File.WriteAllLines(reportPath, new[] { "site\tapi\taction\targument" }.Concat(report));
        var unhandled = report.Count(r => r.Contains("\tUNHANDLED", StringComparison.Ordinal));
        Console.WriteLine($"PlankCheckedAccess: {total} site(s) rewritten in {rewritten.Count} file(s), {unhandled} unhandled (report {reportPath})");
        return 0;
    }

    static IEnumerable<object> LoadGenerators(string path)
    {
        var assembly = System.Reflection.Assembly.LoadFrom(path);
        foreach (var type in assembly.GetTypes())
        {
            if (type.IsAbstract || type.GetCustomAttributes(typeof(GeneratorAttribute), false).Length == 0)
                continue;
            yield return Activator.CreateInstance(type)!;
        }
    }
}

/// <summary>Exact-text replacements from hand-rewrites.txt (format documented there).</summary>
sealed class HandRewrites
{
    readonly List<(string File, string Old, string New)> _blocks = new();
    readonly HashSet<int> _used = new();
    public HashSet<string> Touched { get; } = new(StringComparer.Ordinal);

    public static HandRewrites Load(IEnumerable<string> paths)
    {
        var result = new HandRewrites();
        foreach (var path in paths)
        {
            string? file = null;
            List<string>? old = null, current = null, replacement = null;
            foreach (var line in File.ReadAllLines(path))
            {
                if (current is null)
                {
                    if (line.StartsWith("### ", StringComparison.Ordinal)) file = line[4..].Trim();
                    else if (line == "<<<") { old = new(); replacement = new(); current = old; }
                    continue;
                }

                if (line == "===") { current = replacement; continue; }
                if (line == ">>>")
                {
                    if (file is null || old!.Count != replacement!.Count)
                        throw new InvalidOperationException($"hand rewrite for {file}: old and new text must have the same line count");
                    result._blocks.Add((file, string.Join("\n", old), string.Join("\n", replacement)));
                    current = null;
                    continue;
                }

                current.Add(line);
            }
        }

        return result;
    }

    public string Apply(string? relative, string text)
    {
        if (relative is null)
            return text;
        var normalized = text.Replace("\r\n", "\n");
        for (var i = 0; i < _blocks.Count; i++)
        {
            var (file, old, replacement) = _blocks[i];
            if (file != relative)
                continue;
            var at = normalized.IndexOf(old, StringComparison.Ordinal);
            if (at < 0 || normalized.IndexOf(old, at + 1, StringComparison.Ordinal) >= 0)
                throw new InvalidOperationException($"hand rewrite for {file} does not match exactly once: {old.Split('\n')[0].Trim()}");
            normalized = normalized[..at] + replacement + normalized[(at + old.Length)..];
            _used.Add(i);
            Touched.Add(relative);
            Console.WriteLine($"PlankCheckedAccess: hand rewrite applied in {file}: {old.Split('\n')[0].Trim()}");
        }

        return normalized;
    }

    public void ThrowIfUnused()
    {
        for (var i = 0; i < _blocks.Count; i++)
            if (!_used.Contains(i))
                throw new InvalidOperationException($"hand rewrite for {_blocks[i].File} matched no file");
    }
}

sealed class CheckedRewriter : CSharpSyntaxRewriter
{
    const string Shim = "global::Plank.CheckedAccess.C.";
    readonly SemanticModel _model;
    readonly string _file;
    readonly List<string> _report;

    public CheckedRewriter(SemanticModel model, string file, List<string> report)
        : base(visitIntoStructuredTrivia: false)
    {
        _model = model;
        _file = file;
        _report = report;
    }

    public int Count { get; private set; }

    string Site(SyntaxNode node) => _file + ":" + (node.GetLocation().GetLineSpan().StartLinePosition.Line + 1);

    void Report(SyntaxNode node, string api, string action, string argument = "")
        => _report.Add(Site(node) + "\t" + api + "\t" + action + "\t" + argument.Replace('\t', ' ').Replace('\n', ' ').Replace('\r', ' '));

    static ArgumentSyntax SiteArgument(string site)
        => SyntaxFactory.Argument(SyntaxFactory.LiteralExpression(SyntaxKind.StringLiteralExpression, SyntaxFactory.Literal(site)));

    static string TypeName(ITypeSymbol type) => type.ToDisplayString(SymbolDisplayFormat.FullyQualifiedFormat);

    static bool IsType(ITypeSymbol? type, string metadataName)
        => type is not null && type.OriginalDefinition.ToDisplayString() == metadataName;

    static string? ContainingTypeName(IMethodSymbol method) => (method.ReducedFrom ?? method).ContainingType?.ToDisplayString();

    static readonly HashSet<string> ShimTypes = new(StringComparer.Ordinal)
    {
        "System.Runtime.CompilerServices.Unsafe", "System.Runtime.InteropServices.MemoryMarshal",
        "System.Runtime.Intrinsics.Vector64", "System.Runtime.Intrinsics.Vector128", "System.Runtime.Intrinsics.Vector256",
        "System.Runtime.Intrinsics.Vector512", "System.Numerics.Vector",
    };

    enum Ctx { Value, RefConsumed, RefKept }

    /// <summary>How the ref an invocation returns is used: as a value (read/written), formed and handed straight
    /// to a checked API (hint only), or kept in a ref local / passed to another method (registered).</summary>
    Ctx RefContext(ExpressionSyntax node)
    {
        var parent = node.Parent;
        while (parent is ParenthesizedExpressionSyntax)
            parent = parent.Parent;
        if (parent is RefExpressionSyntax refExpression)
        {
            var up = refExpression.Parent;
            return up is ArgumentSyntax argument ? ArgumentContext(argument) : Ctx.RefKept;
        }

        if (parent is ArgumentSyntax arg && !arg.RefKindKeyword.IsKind(SyntaxKind.None))
            return ArgumentContext(arg);
        return Ctx.Value;
    }

    Ctx ArgumentContext(ArgumentSyntax argument)
    {
        if (argument.Parent?.Parent is InvocationExpressionSyntax invocation
            && _model.GetSymbolInfo(invocation).Symbol is IMethodSymbol method
            && ContainingTypeName(method) is { } type
            && (ShimTypes.Contains(type) || type.StartsWith("System.Runtime.Intrinsics.", StringComparison.Ordinal)))
            return Ctx.RefConsumed;
        return Ctx.RefKept;
    }

    InvocationExpressionSyntax Call(InvocationExpressionSyntax visited, string name, SimpleNameSyntax? originalName,
        SyntaxNode original, IEnumerable<ArgumentSyntax>? leading = null)
    {
        var typeArgs = originalName is GenericNameSyntax g ? g.TypeArgumentList.ToString() : "";
        var expression = SyntaxFactory.ParseExpression(Shim + name + typeArgs).WithTriviaFrom(visited.Expression);
        var arguments = visited.ArgumentList.Arguments;
        if (leading is not null)
            arguments = SyntaxFactory.SeparatedList(leading.Concat(arguments));
        arguments = arguments.Add(SiteArgument(Site(original)));
        Count++;
        return visited.WithExpression(expression).WithArgumentList(visited.ArgumentList.WithArguments(arguments));
    }

    static int VectorBytes(ITypeSymbol? type) => type?.OriginalDefinition.ToDisplayString() switch
    {
        "System.Runtime.Intrinsics.Vector64<T>" => 8,
        "System.Runtime.Intrinsics.Vector128<T>" => 16,
        "System.Runtime.Intrinsics.Vector256<T>" => 32,
        "System.Runtime.Intrinsics.Vector512<T>" => 64,
        _ => 0,
    };

    static int ScalarBytes(ITypeSymbol? type) => type?.SpecialType switch
    {
        SpecialType.System_Byte or SpecialType.System_SByte or SpecialType.System_Boolean => 1,
        SpecialType.System_Int16 or SpecialType.System_UInt16 or SpecialType.System_Char => 2,
        SpecialType.System_Int32 or SpecialType.System_UInt32 or SpecialType.System_Single => 4,
        SpecialType.System_Int64 or SpecialType.System_UInt64 or SpecialType.System_Double => 8,
        _ => 0,
    };

    public override SyntaxNode? VisitInvocationExpression(InvocationExpressionSyntax node)
    {
        var symbol = _model.GetSymbolInfo(node).Symbol as IMethodSymbol;
        var ctx = symbol is null ? Ctx.Value : RefContext(node);
        var visited = (InvocationExpressionSyntax)base.VisitInvocationExpression(node)!;
        if (symbol is null)
            return visited;
        var type = ContainingTypeName(symbol);
        var name = symbol.Name;
        var memberName = (node.Expression as MemberAccessExpressionSyntax)?.Name;
        var firstArg = node.ArgumentList.Arguments.FirstOrDefault()?.ToString() ?? "";
        var api = (type?.Split('.').Last() ?? "?") + "." + name;
        switch (type)
        {
            case "System.Runtime.CompilerServices.Unsafe":
                switch (name)
                {
                    case "Add" or "Subtract" or "AddByteOffset" or "SubtractByteOffset":
                        if (symbol.Parameters[0].Type is IPointerTypeSymbol)
                        {
                            if (name != "Add")
                                break;
                            Report(node, api, "form-ptr", firstArg);
                            return Call(visited, "Add", memberName, node);
                        }

                        var suffix = ctx switch { Ctx.Value => "V", Ctx.RefKept => "Keep", _ => "" };
                        Report(node, api, ctx == Ctx.Value ? "access" : ctx == Ctx.RefKept ? "form-keep" : "form", firstArg);
                        return Call(visited, name + suffix, memberName, node);
                    case "ReadUnaligned" or "WriteUnaligned" or "Read" or "Write" or "CopyBlock" or "CopyBlockUnaligned"
                        or "InitBlock" or "InitBlockUnaligned":
                        if (name is "InitBlock" or "InitBlockUnaligned" && symbol.Parameters[0].Type is IPointerTypeSymbol)
                            break;
                        Report(node, api, "checked", firstArg);
                        return Call(visited, name, memberName, node);
                    case "As" when symbol.TypeArguments.Length == 2:
                        if (symbol.TypeArguments.Any(t => t.IsRefLikeType))
                        {
                            Report(node, api, "safe (span struct reinterpretation, no memory access)", firstArg);
                            return visited;
                        }

                        if (ctx != Ctx.Value)
                        {
                            Report(node, api, "ref-passthrough (same address)", firstArg);
                            return visited;
                        }

                        Report(node, api, "access", firstArg);
                        return Call(visited, "AsV", memberName, node);
                    case "AsRef" or "AsPointer" or "NullRef" or "IsNullRef" or "SkipInit" or "Unbox" or "Copy":
                        Report(node, api, "UNHANDLED (no length)", firstArg);
                        return visited;
                    case "SizeOf" or "AreSame" or "IsAddressLessThan" or "IsAddressGreaterThan" or "ByteOffset" or "BitCast" or "As":
                        return visited;
                }

                Report(node, api, "UNHANDLED", firstArg);
                return visited;
            case "System.Runtime.InteropServices.MemoryMarshal":
                switch (name)
                {
                    case "GetReference":
                        Report(node, api, "register", firstArg);
                        return Call(visited, name, memberName, node);
                    case "GetArrayDataReference" when symbol.Parameters[0].Type is IArrayTypeSymbol:
                        Report(node, api, "register", firstArg);
                        return Call(visited, name, memberName, node);
                    case "CreateSpan" or "CreateReadOnlySpan":
                        Report(node, api, "checked+register", firstArg);
                        return Call(visited, name, memberName, node);
                    case "Cast" or "AsBytes" or "Read" or "TryRead" or "Write" or "TryWrite" or "TryGetArray" or "AsMemory"
                        or "ToEnumerable" or "TryGetMemoryManager" or "TryGetString" or "AsRef":
                        Report(node, api, "safe (span length-checked)", firstArg);
                        return visited;
                }

                Report(node, api, "UNHANDLED", firstArg);
                return visited;
            case "System.Runtime.Intrinsics.Vector64" or "System.Runtime.Intrinsics.Vector128" or "System.Runtime.Intrinsics.Vector256"
                or "System.Runtime.Intrinsics.Vector512" or "System.Numerics.Vector":
            {
                var prefix = type switch
                {
                    "System.Runtime.Intrinsics.Vector64" => "V64",
                    "System.Runtime.Intrinsics.Vector128" => "V128",
                    "System.Runtime.Intrinsics.Vector256" => "V256",
                    "System.Runtime.Intrinsics.Vector512" => "V512",
                    _ => "V",
                };
                if (name == "LoadUnsafe")
                {
                    Report(node, api, "checked (vector width)", firstArg);
                    return Call(visited, prefix + "LoadUnsafe", memberName, node);
                }

                if (name == "StoreUnsafe")
                {
                    Report(node, api, "checked (vector width)", node.ArgumentList.Arguments.Count > 0 ? node.ArgumentList.Arguments[0].ToString() : "");
                    if (symbol.ReducedFrom is not null && visited.Expression is MemberAccessExpressionSyntax receiver)
                        return Call(visited, "StoreUnsafe", null, node, new[] { SyntaxFactory.Argument(receiver.Expression.WithoutTrivia()) });
                    return Call(visited, "StoreUnsafe", null, node);
                }

                if (name.StartsWith("Load", StringComparison.Ordinal) || name.StartsWith("Store", StringComparison.Ordinal))
                {
                    if (symbol.Parameters.Any(p => p.Type is IPointerTypeSymbol))
                        return WrapPointerArgument(node, visited, symbol, api);
                    Report(node, api, "UNHANDLED", firstArg);
                }

                return visited;
            }
        }

        if (type is not null && type.StartsWith("System.Runtime.Intrinsics.", StringComparison.Ordinal))
        {
            if (name.StartsWith("Gather", StringComparison.Ordinal))
            {
                var a = node.ArgumentList.Arguments;
                if (name.StartsWith("GatherMask", StringComparison.Ordinal) || a.Count != 3
                    || !IsPureIndexExpression(a[1].Expression))
                {
                    Report(node, api, "UNHANDLED (gather form)", firstArg);
                    return visited;
                }

                var v = visited.ArgumentList.Arguments;
                var bytes = VectorBytes(symbol.ReturnType);
                var check = SyntaxFactory.ParseExpression(
                    $"{Shim}Gather({v[0].Expression}, {v[1].Expression}, (byte)({v[2].Expression}), {bytes}, \"{Site(node)}\")");
                Report(node, api, "checked (every lane)", firstArg);
                Count++;
                return visited.WithArgumentList(visited.ArgumentList.WithArguments(v.Replace(v[0], v[0].WithExpression(check))));
            }

            if ((name.StartsWith("Load", StringComparison.Ordinal) || name.StartsWith("Store", StringComparison.Ordinal)
                 || name.StartsWith("Broadcast", StringComparison.Ordinal) || name.StartsWith("Prefetch", StringComparison.Ordinal))
                && symbol.Parameters.Any(p => p.Type is IPointerTypeSymbol))
            {
                if (name.StartsWith("Prefetch", StringComparison.Ordinal))
                    return visited;
                return WrapPointerArgument(node, visited, symbol, api);
            }

            if (symbol.Parameters.Any(p => p.Type is IPointerTypeSymbol || p.RefKind != RefKind.None))
                Report(node, api, "UNHANDLED (intrinsic with pointer)", firstArg);
            return visited;
        }

        if (type == "System.Buffer" && name == "MemoryCopy")
        {
            Report(node, api, "checked", firstArg);
            return Call(visited, "MemoryCopy", null, node);
        }

        if (type == "System.Runtime.InteropServices.NativeMemory" && name is "Copy" or "Clear" or "Fill")
        {
            Report(node, api, "UNHANDLED (native memory op)", firstArg);
            return visited;
        }

        // Anything else that receives a raw pointer (native codecs, P/Invoke): listed for review.
        for (var i = 0; i < symbol.Parameters.Length && i < node.ArgumentList.Arguments.Count; i++)
        {
            if (symbol.Parameters[i].Type is IPointerTypeSymbol)
            {
                Report(node, api, "pointer passed (not checked; lengths reviewed by hand)", node.ArgumentList.Arguments[i].ToString());
                break;
            }
        }

        return visited;
    }

    /// <summary>Index vectors the gather check may evaluate a second time: locals, literals, `v.GetLower()`/`v.GetUpper()`.</summary>
    static bool IsPureIndexExpression(ExpressionSyntax e) => e switch
    {
        IdentifierNameSyntax or LiteralExpressionSyntax => true,
        InvocationExpressionSyntax { ArgumentList.Arguments.Count: 0, Expression: MemberAccessExpressionSyntax { Expression: IdentifierNameSyntax, Name.Identifier.Text: "GetLower" or "GetUpper" } } => true,
        _ => false,
    };

    SyntaxNode WrapPointerArgument(InvocationExpressionSyntax node, InvocationExpressionSyntax visited, IMethodSymbol symbol, string api)
    {
        var index = symbol.Parameters.ToList().FindIndex(p => p.Type is IPointerTypeSymbol);
        var pointerType = (IPointerTypeSymbol)symbol.Parameters[index].Type;
        var isStore = symbol.Name.StartsWith("Store", StringComparison.Ordinal);
        int width;
        if (symbol.Name.Contains("Scalar", StringComparison.Ordinal))
            width = ScalarBytes(pointerType.PointedAtType);
        else if (isStore)
            width = symbol.Parameters.Select(p => VectorBytes(p.Type)).FirstOrDefault(b => b > 0);
        else
            width = VectorBytes(symbol.ReturnType);
        if (symbol.Name.StartsWith("Broadcast", StringComparison.Ordinal) || symbol.Name.Contains("Scalar", StringComparison.Ordinal) && width == 0)
            width = ScalarBytes(pointerType.PointedAtType);
        if (width == 0 || pointerType.PointedAtType.SpecialType == SpecialType.System_Void || index >= visited.ArgumentList.Arguments.Count)
        {
            Report(node, api, "UNHANDLED (pointer width)", node.ArgumentList.Arguments.ElementAtOrDefault(index)?.ToString() ?? "");
            return visited;
        }

        var args = visited.ArgumentList.Arguments;
        var wrapped = SyntaxFactory.ParseExpression(
            $"{Shim}Width({args[index].Expression}, {width}, \"{(isStore ? "store" : "load")}{width * 8}\", \"{Site(node)}\")");
        Report(node, api, $"checked ({width} bytes)", node.ArgumentList.Arguments[index].ToString());
        Count++;
        return visited.WithArgumentList(visited.ArgumentList.WithArguments(args.Replace(args[index], args[index].WithExpression(wrapped))));
    }

    public override SyntaxNode? VisitObjectCreationExpression(ObjectCreationExpressionSyntax node)
    {
        var symbol = _model.GetSymbolInfo(node).Symbol as IMethodSymbol;
        var visited = (ObjectCreationExpressionSyntax)base.VisitObjectCreationExpression(node)!;
        if (symbol is null || symbol.Parameters.Length != 2 || symbol.Parameters[0].Type is not IPointerTypeSymbol)
            return visited;
        var span = symbol.ContainingType;
        var which = span.OriginalDefinition.ToDisplayString() switch
        {
            "System.Span<T>" => "NewSpan",
            "System.ReadOnlySpan<T>" => "NewReadOnlySpan",
            _ => null,
        };
        if (which is null || visited.ArgumentList is null)
            return visited;
        Report(node, span.Name + "..ctor(void*, int)", "checked+register", node.ArgumentList!.Arguments[0].ToString());
        Count++;
        var arguments = visited.ArgumentList.Arguments.Add(SiteArgument(Site(node)));
        return SyntaxFactory.InvocationExpression(
                SyntaxFactory.ParseExpression(Shim + which + "<" + TypeName(span.TypeArguments[0]) + ">"),
                SyntaxFactory.ArgumentList(arguments))
            .WithTriviaFrom(visited);
    }

    static bool IsWalkableElement(ITypeSymbol type)
        => type.SpecialType is not SpecialType.None and not SpecialType.System_Object and not SpecialType.System_String
           || type.OriginalDefinition.SpecialType == SpecialType.System_Nullable_T
           || type.TypeKind is TypeKind.Enum or TypeKind.TypeParameter;

    /// <summary>`ref span[i]` / `ref array[i]` of a primitive element: register the span and keep the derived ref.</summary>
    ExpressionSyntax? ElementRef(ElementAccessExpressionSyntax original, ExpressionSyntax visited)
    {
        if (visited is not ElementAccessExpressionSyntax access || original.ArgumentList.Arguments.Count != 1)
            return null;
        var receiverType = _model.GetTypeInfo(original.Expression).Type;
        var indexType = _model.GetTypeInfo(original.ArgumentList.Arguments[0].Expression).ConvertedType;
        if (indexType?.SpecialType != SpecialType.System_Int32)
            return null;
        ITypeSymbol? element = receiverType switch
        {
            IArrayTypeSymbol { Rank: 1 } array => array.ElementType,
            INamedTypeSymbol named when IsType(named, "System.Span<T>") || IsType(named, "System.ReadOnlySpan<T>") => named.TypeArguments[0],
            _ => null,
        };
        if (element is null || !IsWalkableElement(element))
            return null;
        Report(original, "ref " + (receiverType is IArrayTypeSymbol ? "array" : receiverType!.Name) + "[i]", "register", original.Expression.ToString());
        Count++;
        return SyntaxFactory.ParseExpression(
                $"{Shim}ElemRef({access.Expression}, {access.ArgumentList.Arguments[0].Expression}, \"{Site(original)}\")")
            .WithTriviaFrom(visited);
    }

    public override SyntaxNode? VisitRefExpression(RefExpressionSyntax node)
    {
        var visited = (RefExpressionSyntax)base.VisitRefExpression(node)!;
        if (node.Expression is ElementAccessExpressionSyntax original && ElementRef(original, visited.Expression) is { } replaced)
            return visited.WithExpression(replaced);
        return visited;
    }

    public override SyntaxNode? VisitArgument(ArgumentSyntax node)
    {
        var visited = (ArgumentSyntax)base.VisitArgument(node)!;
        if (!node.RefKindKeyword.IsKind(SyntaxKind.None) && node.Expression is ElementAccessExpressionSyntax original
            && ElementRef(original, visited.Expression) is { } replaced)
            return visited.WithExpression(replaced);
        return visited;
    }

    public override SyntaxNode? VisitPrefixUnaryExpression(PrefixUnaryExpressionSyntax node)
    {
        var visited = (PrefixUnaryExpressionSyntax)base.VisitPrefixUnaryExpression(node)!;
        if (!node.IsKind(SyntaxKind.PointerIndirectionExpression))
            return visited;
        if (_model.GetTypeInfo(node.Operand).Type is not IPointerTypeSymbol pointer || pointer.PointedAtType.SpecialType == SpecialType.System_Void)
            return visited;
        if (ScalarBytes(pointer.PointedAtType) == 0)
        {
            Report(node, "*pointer", "not checked (struct metadata)", node.Operand.ToString());
            return visited;
        }

        var operand = node.Operand;
        while (operand is ParenthesizedExpressionSyntax parenthesized)
            operand = parenthesized.Expression;
        if (operand is CastExpressionSyntax cast && _model.GetTypeInfo(cast.Expression).Type is not IPointerTypeSymbol)
        {
            // `*(int*)address` on a raw integer address (buffer-pool bookkeeping): no span provenance.
            Report(node, "*pointer", "not checked (raw address cast)", node.Operand.ToString());
            return visited;
        }
        if (node.Parent is PrefixUnaryExpressionSyntax parent && parent.IsKind(SyntaxKind.AddressOfExpression))
            return visited;
        Report(node, "*pointer", "checked", node.Operand.ToString());
        Count++;
        return visited.WithOperand(SyntaxFactory.ParseExpression($"{Shim}P({visited.Operand}, \"{Site(node)}\")"));
    }

    public override SyntaxNode? VisitElementAccessExpression(ElementAccessExpressionSyntax node)
    {
        var visited = (ElementAccessExpressionSyntax)base.VisitElementAccessExpression(node)!;
        if (_model.GetTypeInfo(node.Expression).Type is not IPointerTypeSymbol pointer || pointer.PointedAtType.SpecialType == SpecialType.System_Void)
            return visited;
        if (ScalarBytes(pointer.PointedAtType) == 0)
        {
            Report(node, "pointer[i]", "not checked (struct metadata)", node.Expression.ToString());
            return visited;
        }

        if (node.Parent is PrefixUnaryExpressionSyntax parent && parent.IsKind(SyntaxKind.AddressOfExpression))
        {
            Report(node, "&pointer[i]", "not checked (address only)", node.Expression.ToString());
            return visited;
        }

        Report(node, "pointer[i]", "checked", node.Expression.ToString());
        Count++;
        return SyntaxFactory.ParseExpression(
                $"(*{Shim}At({visited.Expression}, {visited.ArgumentList.Arguments[0].Expression}, \"{Site(node)}\"))")
            .WithTriviaFrom(visited);
    }

    public override SyntaxNode? VisitMemberAccessExpression(MemberAccessExpressionSyntax node)
    {
        var visited = (MemberAccessExpressionSyntax)base.VisitMemberAccessExpression(node)!;
        if (!node.IsKind(SyntaxKind.PointerMemberAccessExpression))
            return visited;
        if (_model.GetTypeInfo(node.Expression).Type is not IPointerTypeSymbol)
            return visited;
        // Struct pointers (buffer-pool headers, zlib stream state) are allocator/native-library metadata, not
        // views of a logical span: listed, not checked.
        Report(node, "pointer->member", "not checked (struct metadata)", node.Expression.ToString());
        return visited;
        Report(node, "pointer->member", "checked", node.Expression.ToString());
        Count++;
        return visited.WithExpression(SyntaxFactory.ParseExpression($"{Shim}P({visited.Expression}, \"{Site(node)}\")"));
    }

    public override SyntaxNode? VisitFixedStatement(FixedStatementSyntax node)
    {
        var registrations = new List<StatementSyntax>();
        foreach (var variable in node.Declaration.Variables)
        {
            var initializer = variable.Initializer?.Value;
            if (initializer is null)
                continue;
            var type = _model.GetTypeInfo(initializer).Type;
            var ok = type is IArrayTypeSymbol { Rank: 1 } || type?.SpecialType == SpecialType.System_String
                     || IsType(type, "System.Span<T>") || IsType(type, "System.ReadOnlySpan<T>");
            if (!ok || initializer is not (IdentifierNameSyntax or MemberAccessExpressionSyntax or ElementAccessExpressionSyntax))
            {
                Report(node, "fixed", "UNHANDLED (pinned expression)", initializer.ToString());
                continue;
            }

            Report(node, "fixed", "register", initializer.ToString());
            Count++;
            registrations.Add(SyntaxFactory.ParseStatement(
                $"{Shim}RegisterFixed({variable.Identifier.Text}, {initializer}, \"{Site(node)}\"); "));
        }

        var visited = (FixedStatementSyntax)base.VisitFixedStatement(node)!;
        if (registrations.Count == 0)
            return visited;
        BlockSyntax body;
        if (visited.Statement is BlockSyntax block)
        {
            var open = block.OpenBraceToken;
            var first = registrations[0].WithLeadingTrivia(SyntaxFactory.Space);
            registrations[0] = first;
            registrations[^1] = registrations[^1].WithTrailingTrivia(open.TrailingTrivia);
            body = block.WithOpenBraceToken(open.WithTrailingTrivia())
                .WithStatements(SyntaxFactory.List(registrations.Concat(block.Statements)));
        }
        else
        {
            body = SyntaxFactory.Block(registrations.Append(visited.Statement))
                .WithOpenBraceToken(SyntaxFactory.Token(SyntaxKind.OpenBraceToken).WithTrailingTrivia(SyntaxFactory.Space))
                .WithCloseBraceToken(SyntaxFactory.Token(SyntaxKind.CloseBraceToken));
        }

        return visited.WithStatement(body);
    }
}
