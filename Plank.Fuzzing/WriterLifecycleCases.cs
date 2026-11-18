using Plank.Schema;

namespace Plank.Fuzzing;

/// <summary>Small public writer state transitions for branch reachability.</summary>
internal static class WriterLifecycleCases
{
    internal static void Execute()
    {
        var schema = new ParquetSchema([
            ColumnDefinition.RequiredLeaf("value", ParquetPhysicalType.Int32)
        ]);

        using (var openStream = new MemoryStream())
        using (var openWriter = schema.CreateWriter(openStream))
        {
            openWriter.StartRowGroup();
            ExpectInvalid(() => openWriter.StartRowGroup(), "A row group is already open for this writer.");
            ExpectInvalid(() => openWriter.CloseFile(), "Cannot close the file while a row group is still open.");
        }

        using var closedStream = new MemoryStream();
        var closedWriter = schema.CreateWriter(closedStream);
        closedWriter.CloseFile();
        ExpectInvalid(() => closedWriter.StartRowGroup(),
            "The current file is closed. Call Reset(file) to start a new file.");
        closedWriter.Dispose();
        closedWriter.Dispose();
        try
        {
            closedWriter.StartRowGroup();
            throw new InvalidOperationException("A disposed writer accepted StartRowGroup.");
        }
        catch (ObjectDisposedException exception) when (exception.ObjectName == "ParquetWriter")
        {
        }
    }

    static void ExpectInvalid(Action action, string expectedMessage)
    {
        try
        {
            action();
        }
        catch (InvalidOperationException exception) when (exception.Message == expectedMessage)
        {
            return;
        }
        throw new InvalidOperationException($"Writer did not reject transition: {expectedMessage}");
    }
}
