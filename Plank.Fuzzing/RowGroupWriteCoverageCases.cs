using Plank.Schema;

namespace Plank.Fuzzing;

internal static class RowGroupWriteCoverageCases
{
    internal static void Execute(byte selector)
    {
        var schema = new ParquetSchema([
            ColumnDefinition.RequiredLeaf("first", ParquetPhysicalType.Int32),
            ColumnDefinition.RequiredLeaf("second", ParquetPhysicalType.Int32)
        ]);
        using var stream = new MemoryStream();
        using var writer = schema.CreateWriter(stream);
        var first = writer.CreateSerializedColumn<int>(schema.LeafColumns[0]);
        var second = writer.CreateSerializedColumn<int>(schema.LeafColumns[1]);
        var rowGroup = writer.StartRowGroup();

        switch (selector % 5)
        {
            case 0:
                using (var otherStream = new MemoryStream())
                using (var other = schema.CreateWriter(otherStream))
                {
                    var foreign = other.CreateSerializedColumn<int>(schema.LeafColumns[0]);
                    foreign.Serialize([1]);
                    ExpectInvalid(() => rowGroup.Write(foreign), "SerializedColumn belongs to another ParquetWriter.");
                }
                break;
            case 1:
                ExpectInvalid(() => rowGroup.Write(first),
                    "SerializedColumn has no serialized data. Call serialized.Serialize(values) before Write(...).");
                break;
            case 2:
                first.Serialize([1]);
                rowGroup.Write(first);
                second.Serialize([2]);
                rowGroup.Write(second);
                first.Serialize([3]);
                ExpectInvalid(() => rowGroup.Write(first),
                    "All columns for this row group have already been written. Call writer.StartRowGroup() to start a new row group.");
                break;
            case 3:
                second.Serialize([1]);
                ExpectInvalid(() => rowGroup.Write(second),
                    "Invalid column order for this row group. Expected 'first' (ordinal 0) next, but got 'second' (ordinal 1). Write columns in schema order.");
                break;
            default:
                first.Serialize([1, 2]);
                rowGroup.Write(first);
                second.Serialize([3]);
                ExpectInvalid(() => rowGroup.Write(second),
                    "Row count mismatch for row group. Expected 2, got 1.");
                break;
        }
    }

    static void ExpectInvalid(Action action, string message)
    {
        try
        {
            action();
        }
        catch (InvalidOperationException exception) when (exception.Message == message)
        {
            return;
        }
        throw new InvalidOperationException($"RowGroupWriter did not reject invalid state: {message}");
    }
}
