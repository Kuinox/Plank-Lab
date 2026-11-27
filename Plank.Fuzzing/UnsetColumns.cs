using System.Runtime.CompilerServices;

namespace Plank.Fuzzing;

/// <summary>
/// Remembers which columns of a generated expected row are deliberately never assigned when it is written.
/// The expected object already holds the CLR default in those properties; the writer routes skip the assignment.
/// </summary>
static class UnsetColumns
{
    static readonly ConditionalWeakTable<object, StrongBox<int>> Masks = [];

    internal static void Remember(object row, int mask)
        => Masks.AddOrUpdate(row, new StrongBox<int>(mask));

    internal static int Of(object row)
        => Masks.TryGetValue(row, out var box) ? box.Value : 0;
}
