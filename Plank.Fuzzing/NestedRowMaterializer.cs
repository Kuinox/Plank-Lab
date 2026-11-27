using Plank.RowApi;
using Plank.Schema;

namespace Plank.Fuzzing;

/// <summary>
/// Rebuilds the nested shape of one row from the raw repetition levels, definition levels and
/// dense values that <c>RowReaderCore.GetCurrentNested</c> returns. Plank moved this
/// materialization into generated code, so the harness carries its own independent
/// implementation: the row reader's level/value bookkeeping is checked here, and the shape is
/// compared against the column reader's values by the callers.
/// </summary>
/// <remarks>
/// The shape is <c>object?[]?</c> for one collection level and <c>object?[]?[]?</c> for two; a
/// null collection, an empty one and a null element are all distinguished. An empty row (no
/// levels at all) is a column missing from the file and materializes as null.
/// </remarks>
internal static class NestedRowMaterializer
{
    internal static object? Materialize<TValue>(RowApiNestedLeafRow<TValue> row, LeafColumn leaf,
        RowApiCollectionLevel[] collections)
    {
        var repetitions = row.RepetitionLevels;
        var definitions = row.DefinitionLevels;
        var values = row.Values;

        if (repetitions.Length != definitions.Length)
            throw new InvalidOperationException(
                $"Nested row returned {repetitions.Length} repetition levels but {definitions.Length} definition levels.");
        if (repetitions.Length == 0)
        {
            if (values.Length != 0)
                throw new InvalidOperationException("Nested row has values but no levels.");
            return null;
        }

        var max = leaf.MaxDefinitionLevel;
        var dense = 0;
        for (var i = 0; i < definitions.Length; i++)
        {
            if (definitions[i] > max || repetitions[i] > leaf.MaxRepetitionLevel)
                throw new InvalidOperationException(
                    $"Nested row level out of range at {i}: repetition {repetitions[i]}, definition {definitions[i]}.");
            if (definitions[i] == max)
                dense++;
        }
        if (dense != values.Length)
            throw new InvalidOperationException(
                $"Nested row has {values.Length} dense values but its definition levels define {dense}.");
        if (repetitions[0] != 0)
            throw new InvalidOperationException("Nested row does not start at repetition level 0.");

        var next = 0;
        if (collections.Length == 1)
        {
            var outer = collections[0];
            if (definitions[0] < outer.DefinedDefinitionLevel)
                return Single(repetitions.Length, "null outer collection");
            var list = new List<object?>();
            for (var i = 0; i < definitions.Length; i++)
            {
                if (definitions[i] < outer.ElementDefinitionLevel)
                {
                    if (i != 0)
                        throw new InvalidOperationException($"Empty/null collection marker at position {i}.");
                    continue;
                }
                if (i != 0 && repetitions[i] != 1)
                    throw new InvalidOperationException($"Unexpected repetition level {repetitions[i]} at {i}.");
                list.Add(definitions[i] == max ? values[next++] : null);
            }
            return list.ToArray();
        }

        if (collections.Length == 2)
        {
            var outer = collections[0];
            var inner = collections[1];
            if (definitions[0] < outer.DefinedDefinitionLevel)
                return Single(repetitions.Length, "null outer collection");
            var outerList = new List<object?[]?>();
            List<object?>? current = null;
            for (var i = 0; i < definitions.Length; i++)
            {
                var definition = definitions[i];
                var repetition = repetitions[i];
                if (repetition <= 1)
                {
                    if (definition < outer.ElementDefinitionLevel)
                    {
                        if (i != 0)
                            throw new InvalidOperationException($"Empty/null outer marker at position {i}.");
                        continue;
                    }
                    if (current is not null)
                        outerList.Add(current.ToArray());
                    current = null;
                    if (definition < inner.DefinedDefinitionLevel)
                    {
                        outerList.Add(null);
                        continue;
                    }
                    current = [];
                    if (definition < inner.ElementDefinitionLevel)
                        continue;
                    current.Add(definition == max ? values[next++] : null);
                }
                else
                {
                    if (current is null || definition < inner.ElementDefinitionLevel)
                        throw new InvalidOperationException($"Inner element expected at position {i}.");
                    current.Add(definition == max ? values[next++] : null);
                }
            }
            if (current is not null)
                outerList.Add(current.ToArray());
            return outerList.ToArray();
        }

        throw new InvalidOperationException("Unsupported nesting depth.");
    }

    // A row whose first position is below the outermost defined level is a null collection and
    // carries exactly one position.
    static object? Single(int positions, string what)
    {
        if (positions != 1)
            throw new InvalidOperationException($"A {what} spans {positions} positions.");
        return null;
    }
}
