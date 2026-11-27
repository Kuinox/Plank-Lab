using System.Reflection;
using System.Text;

// Enumerates the public surface of Plank.dll by reflection, plus the members the Plank.SourceGen
// output adds to the fuzz assembly (generated Row types, CreateRowWriter/CreateRowReader overloads, cursors).
// Output: TSV  assembly \t kind \t type \t member \t signature   (one line per public member).
// Usage: ApiSurface > api-surface.tsv
static string Name(Type t) => t.IsGenericParameter ? t.Name
    : t.IsGenericType ? t.Namespace + "." + (t.Name.Contains('`') ? t.Name[..t.Name.IndexOf('`')] : t.Name) + "<" + string.Join(",", t.GetGenericArguments().Select(Name)) + ">"
    : t.IsArray ? Name(t.GetElementType()!) + "[]"
    : t.IsByRef ? "ref " + Name(t.GetElementType()!)
    : t.FullName ?? t.Name;
static string Sig(MethodBase m) => "(" + string.Join(", ", m.GetParameters().Select(p => Name(p.ParameterType) + " " + p.Name + (p.HasDefaultValue ? "=" : ""))) + ")";
const BindingFlags F = BindingFlags.Public | BindingFlags.Instance | BindingFlags.Static | BindingFlags.DeclaredOnly;
var sb = new StringBuilder();
void Dump(Assembly a, Func<Type, bool> include)
{
    foreach (var t in a.GetExportedTypes().Where(include).OrderBy(t => t.FullName))
    {
        var tn = t.FullName!;
        var kind = t.IsEnum ? "enum" : t.IsInterface ? "interface" : t.IsValueType ? "struct" : t.IsAbstract && t.IsSealed ? "static class" : t.IsAbstract ? "abstract class" : "class";
        sb.Append($"{a.GetName().Name}\ttype\t{tn}\t{kind}\t{(t.IsGenericTypeDefinition ? "generic" : "")}\n");
        if (t.IsEnum) { sb.Append($"{a.GetName().Name}\tenum\t{tn}\t{string.Join("|", Enum.GetNames(t))}\t\n"); continue; }
        foreach (var c in t.GetConstructors(BindingFlags.Public | BindingFlags.Instance)) sb.Append($"{a.GetName().Name}\tctor\t{tn}\t.ctor\t{Sig(c)}\n");
        foreach (var m in t.GetMethods(F).Where(m => !m.IsSpecialName))
            sb.Append($"{a.GetName().Name}\t{(m.IsDefined(typeof(System.Runtime.CompilerServices.ExtensionAttribute), false) ? "ext" : m.IsStatic ? "static" : "method")}\t{tn}\t{m.Name}\t{Sig(m)}:{Name(m.ReturnType)}\n");
        foreach (var p in t.GetProperties(F))
            sb.Append($"{a.GetName().Name}\tprop\t{tn}\t{p.Name}\t{Name(p.PropertyType)} {(p.CanRead && p.GetMethod!.IsPublic ? "get" : "")}{(p.CanWrite && p.SetMethod!.IsPublic ? " set" : "")}\n");
        foreach (var f in t.GetFields(F))
            sb.Append($"{a.GetName().Name}\tfield\t{tn}\t{f.Name}\t{Name(f.FieldType)}\n");
        foreach (var e in t.GetEvents(F)) sb.Append($"{a.GetName().Name}\tevent\t{tn}\t{e.Name}\t{Name(e.EventHandlerType!)}\n");
    }
}
var plank = typeof(Plank.Writing.ParquetWriterOptions).Assembly;
Dump(plank, _ => true);
// Source-generator output lives in the fuzz assembly: report only types/members that are generated (not hand written targets).
var fuzz = typeof(Plank.Fuzzing.PlankReaderFuzzTarget).Assembly;
Dump(fuzz, t => t.GetCustomAttributes().Any(x => x.GetType().Name.Contains("GeneratedCode") || x.GetType().Name.Contains("ParquetSchema") || x.GetType().Name.Contains("ParquetRow"))
    || t.GetMethods(BindingFlags.Public | BindingFlags.Static).Any(m => m.Name.Contains("CreateRowWriter") || m.Name.Contains("CreateRowReader")));
Console.Out.Write(sb);
