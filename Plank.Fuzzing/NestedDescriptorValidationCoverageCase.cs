using Plank.RowApi;
using Plank.Schema;

namespace Plank.Fuzzing;

internal static class NestedDescriptorValidationCoverageCase
{
    internal static void Execute(byte mode)
    {
        var listSchema = new ParquetSchema([
            ColumnDefinition.List("items", ColumnDefinition.RequiredLeaf("element", ParquetPhysicalType.Int32),
                ParquetRepetition.Optional)
        ]);
        var repeated = listSchema.LeafColumns[0];
        var flat = new ParquetSchema([
            ColumnDefinition.RequiredLeaf("value", ParquetPhysicalType.Int32)
        ]).LeafColumns[0];
        var valid = new RowApiCollectionLevel(1, 1, 2);

        switch (mode % 11)
        {
            case 0:
                Expect<ArgumentNullException>(() =>
                    _ = new RowApiNestedColumnDescriptor<int>("items", repeated, null!));
                break;
            case 1:
                Expect<ArgumentException>(() =>
                    _ = new RowApiNestedColumnDescriptor<int>("items", flat, valid));
                break;
            case 2:
                Expect<ArgumentException>(() =>
                    _ = new RowApiNestedColumnDescriptor<int>("items", repeated, []));
                break;
            case 3:
                Expect<ArgumentException>(() =>
                    _ = new RowApiNestedColumnDescriptor<int>("items", repeated,
                        new RowApiCollectionLevel(0, 1, 2)));
                break;
            case 4:
                Expect<ArgumentException>(() =>
                    _ = new RowApiNestedColumnDescriptor<int>("items", repeated,
                        new RowApiCollectionLevel(1, -1, 2)));
                break;
            case 5:
                Expect<ArgumentException>(() =>
                    _ = new RowApiNestedColumnDescriptor<int>("items", repeated,
                        new RowApiCollectionLevel(1, 1, 1)));
                break;
            case 6:
                Expect<ArgumentException>(() =>
                    _ = new RowApiNestedColumnDescriptor<int>("items", repeated,
                        new RowApiCollectionLevel(1, 1, repeated.MaxDefinitionLevel + 1)));
                break;
            case 7:
                Expect<ArgumentException>(() =>
                    _ = new RowApiNestedColumnDescriptor<byte[]>("items", repeated, valid));
                break;
            case 8:
                Expect<ArgumentException>(() =>
                    _ = new RowApiNestedColumnDescriptor<string>("items", repeated, valid));
                break;
            case 9:
                Expect<ArgumentException>(() =>
                    _ = new RowApiNestedColumnDescriptor<long>("items", repeated, valid));
                break;
            default:
                _ = new RowApiNestedColumnDescriptor<int>("items", repeated, valid);
                break;
        }
    }

    static void Expect<TException>(Action action) where TException : Exception
    {
        try
        {
            action();
        }
        catch (TException)
        {
            return;
        }
        throw new InvalidOperationException($"Expected {typeof(TException).Name}.");
    }
}
