using System.Collections.Immutable;
using Plank.Reading;
using Plank.Schema;
using Plank.Writing;

namespace Plank.Fuzzing;

// Public schema construction and overload defaults need direct API calls.
internal static class SchemaApiValidationCases
{
    internal const int Count = 28;

    internal static void Execute(byte selector)
    {
        var mode = selector % Count;
        var leaf = ColumnDefinition.RequiredLeaf("v", ParquetPhysicalType.Int32);
        switch (mode)
        {
            case 0:
                _ = new ParquetSchema(default(ImmutableArray<ColumnDefinition>));
                return;
            case 1:
                ExpectInvalidSchema([ColumnDefinition.RequiredGroup("empty")]);
                return;
            case 2:
                ExpectInvalidSchema([leaf with
                {
                    PhysicalType = ParquetPhysicalType.Int64,
                    LogicalType = new LogicalType.Date()
                }]);
                return;
            case 3:
                ExpectInvalidSchema([leaf with { PhysicalType = null }]);
                return;
            case 4:
                ExpectInvalidSchema([ColumnDefinition.List("list", leaf) with { Children = [] }]);
                return;
            case 5:
                ExpectInvalidSchema([ColumnDefinition.Map("map", leaf, leaf) with { Children = [] }]);
                return;
            case 6:
                ExpectInvalidSchema([ColumnDefinition.Map("map", leaf, leaf) with
                {
                    Children = [leaf, leaf, leaf]
                }]);
                return;
            case 7:
                ExpectInvalidSchema([leaf with { Kind = (NodeKind)255 }]);
                return;
            case 13:
                _ = new ParquetSchema([leaf with { Options = null }]);
                return;
            case 14:
                ExpectInvalidDefinition(() => _ = ColumnDefinition.RequiredLeaf("date",
                    ParquetPhysicalType.Int64, logicalType: new LogicalType.Date()));
                return;
            case 15:
                ExpectInvalidDefinition(() => _ = ColumnDefinition.RequiredGroup("group",
                    new LogicalType.Date(), leaf));
                return;
            case 16:
                ExpectInvalidDefinition(() => _ = ColumnDefinition.RequiredLeaf("decimal",
                    ParquetPhysicalType.Int32, logicalType: new LogicalType.Decimal(1, 0) with
                    {
                        Precision = 0
                    }));
                return;
            case 17:
                ExpectInvalidDefinition(() => _ = ColumnDefinition.RequiredLeaf("decimal",
                    ParquetPhysicalType.Int32, logicalType: new LogicalType.Decimal(1, 0) with
                    {
                        Scale = 2
                    }));
                return;
            case 18:
                ExpectInvalidDefinition(() => _ = ColumnDefinition.RequiredGroup("variant",
                    new LogicalType.Variant(),
                    ColumnDefinition.RequiredLeaf("metadata", ParquetPhysicalType.ByteArray) with
                    {
                        Repetition = ParquetRepetition.Optional
                    },
                    ColumnDefinition.RequiredLeaf("value", ParquetPhysicalType.ByteArray)));
                return;
            case 19:
                _ = new ParquetSchema([ColumnDefinition.RequiredGroup("variant",
                    new LogicalType.Variant(),
                    ColumnDefinition.RequiredLeaf("metadata", ParquetPhysicalType.ByteArray),
                    ColumnDefinition.RequiredLeaf("value", ParquetPhysicalType.ByteArray))]);
                return;
            case 20:
                ExpectInvalidDefinition(() => _ = ColumnDefinition.RequiredGroup("variant",
                    new LogicalType.Variant(),
                    ColumnDefinition.RequiredLeaf("metadata", ParquetPhysicalType.ByteArray) with
                    {
                        PhysicalType = null
                    },
                    ColumnDefinition.RequiredLeaf("value", ParquetPhysicalType.ByteArray)));
                return;
            case 21:
                ExpectInvalidDefinition(() => _ = ColumnDefinition.Leaf("converted",
                    ParquetPhysicalType.Int32,
                    new ColumnOptions(repetition: ParquetRepetition.Repeated),
                    converter: new IntBoxConverter()));
                return;
            case 22:
                ExpectInvalidDefinition(() => _ = ColumnDefinition.RequiredLeaf("converted",
                    ParquetPhysicalType.Int32, converter: new DateTimeStorageConverter()));
                return;
            case 23:
                ExpectInvalidDefinition(() => _ = ColumnDefinition.RequiredLeaf("converted",
                    ParquetPhysicalType.Int64, converter: new IntBoxConverter()));
                return;
            case 24:
                ExpectInvalidDefinition(() => _ = ColumnDefinition.RequiredLeaf("converted",
                    ParquetPhysicalType.FixedLenByteArray, new ColumnOptions(typeLength: 8),
                    converter: new GuidStorageConverter()));
                return;
            case 25:
                ExpectInvalidDefinition(() => _ = ColumnDefinition.RequiredLeaf("decimal",
                    ParquetPhysicalType.Int32, logicalType: new LogicalType.Decimal(1, 0) with
                    {
                        Scale = -1
                    }));
                return;
            case 26:
                _ = ColumnDefinition.RequiredLeaf("decimal",
                    ParquetPhysicalType.FixedLenByteArray,
                    new ColumnOptions(typeLength: uint.MaxValue),
                    logicalType: new LogicalType.Decimal(1, 0));
                return;
            case 27:
                ExpectInvalidDefinition(() => _ = ColumnDefinition.RequiredLeaf("converted",
                    ParquetPhysicalType.Int32, converter: new CharStorageConverter()));
                return;
        }

        var schema = new ParquetSchema([leaf]);
        switch (mode)
        {
            case 8:
                ExpectNull(() => _ = schema.CreateWriter((IParquetWriteSource)null!, null));
                break;
            case 9:
                ExpectNull(() => _ = schema.CreateAppender((Stream)null!, null));
                break;
            case 10:
                ExpectNull(() => _ = schema.CreateAppender((IParquetReadSource)null!,
                    (IParquetWriteSource)null!, null));
                break;
            case 11:
                ExpectNull(() => _ = schema.CreateMerger((IParquetReadWriteSource)null!, null));
                break;
            default:
                ExpectNull(() => _ = schema.CreateMerger((IParquetReadSource)null!,
                    (IParquetWriteSource)null!, null));
                break;
        }
    }

    static void ExpectInvalidSchema(ImmutableArray<ColumnDefinition> definitions)
    {
        try { _ = new ParquetSchema(definitions); }
        catch (ArgumentException) { return; }
        throw new InvalidOperationException("Invalid schema was accepted.");
    }

    static void ExpectNull(Action action)
    {
        try { action(); }
        catch (ArgumentNullException) { return; }
        throw new InvalidOperationException("Null source or destination was accepted.");
    }

    static void ExpectInvalidDefinition(Action action)
    {
        try { action(); }
        catch (ArgumentException) { return; }
        throw new InvalidOperationException("Invalid column definition was accepted.");
    }

    sealed class DateTimeStorageConverter : ParquetValueConverter<int, DateTime>
    {
        public override DateTime ConvertToPhysical(int value) => DateTime.UnixEpoch;
        public override int ConvertFromPhysical(DateTime value) => 0;
    }

    sealed class GuidStorageConverter : ParquetValueConverter<int, Guid>
    {
        public override Guid ConvertToPhysical(int value) => Guid.Empty;
        public override int ConvertFromPhysical(Guid value) => 0;
    }

    sealed class CharStorageConverter : ParquetValueConverter<int, char>
    {
        public override char ConvertToPhysical(int value) => 'x';
        public override int ConvertFromPhysical(char value) => 0;
    }
}
