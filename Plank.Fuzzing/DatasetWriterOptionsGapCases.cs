using Plank;
using Plank.Dataset;
using Plank.RowApi;
using Plank.Writing;

namespace Plank.Fuzzing;

// Public generated-writer construction reaches the otherwise unhit capacity guard.
internal static class DatasetWriterOptionsGapCases
{
    internal static void Execute(byte mode)
    {
        using var file = new InMemoryDatasetFile(new InMemoryFileStore());
        RowFuzzDatasetBinary.Route route = static (RowFuzzDatasetBinary row,
            IParquetBufferPool pool, out ParquetBuffer? allocation) =>
        {
            allocation = null;
            return "p"u8;
        };
        DatasetFilePath path = static (ReadOnlySpan<byte> key, ulong index,
            IParquetBufferPool pool, out ParquetBuffer? allocation) =>
        {
            allocation = null;
            return "p-0"u8;
        };
        var options = new DatasetWriterOptions { PendingRowCapacity = uint.MaxValue };
        IParquetWriteSource[] files = (mode % 5) switch
        {
            1 => [],
            2 => [file, file],
            3 => [null!],
            _ => [file],
        };
        if (mode % 5 != 0)
            options = new DatasetWriterOptions();
        if (mode % 5 == 4)
        {
            using var writer = RowFuzzDatasetBinary.CreateDatasetWriter(route, path, files, options);
            try
            {
                writer.Queue(null!);
            }
            catch (ArgumentNullException exception) when (exception.ParamName == "row")
            {
                return;
            }
            throw new InvalidOperationException("A null dataset row was accepted.");
        }
        try
        {
            using var writer = RowFuzzDatasetBinary.CreateDatasetWriter(route, path, files, options);
        }
        catch (ArgumentOutOfRangeException exception)
            when (mode % 5 == 0 && exception.ParamName == nameof(DatasetWriterOptions.PendingRowCapacity))
        {
            return;
        }
        catch (ArgumentException exception) when (mode % 5 != 0 && exception.ParamName == "files")
        {
            return;
        }

        throw new InvalidOperationException($"Invalid dataset options/files were accepted for mode {mode % 5}.");
    }
}
