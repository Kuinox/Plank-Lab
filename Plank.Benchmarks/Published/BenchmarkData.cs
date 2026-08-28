using System.Text;
using ParquetSharp.RowOriented;

namespace Plank.Benchmarks;

static class BenchmarkData
{
    public static int SyntheticRows
        => int.Parse(Environment.GetEnvironmentVariable("PLANK_BENCHMARK_ROWS") ?? "1000000");

    public static int TaxiRows
        => int.Parse(Environment.GetEnvironmentVariable("PLANK_BENCHMARK_TAXI_ROWS") ?? "2964624");

    public static string TaxiFile
        => Environment.GetEnvironmentVariable("PLANK_BENCHMARK_TAXI_FILE")
           ?? throw new InvalidOperationException("PLANK_BENCHMARK_TAXI_FILE is not set.");

    public static string[] StringValues { get; } = CreateStrings();

    public static byte[][] Utf8Values { get; } = CreateUtf8();

    public static int OutputCapacity(int fileBytes)
    {
        var headroom = Math.Max(1024 * 1024L, fileBytes / 20L);
        return checked((int)Math.Min(int.MaxValue, fileBytes + headroom));
    }

    public static T[] LoadTaxiRows<T>() where T : class
    {
        using var reader = ParquetFile.CreateRowReader<T>(TaxiFile);
        var rows = new T[TaxiRows];
        var index = 0;
        for (var group = 0; group < reader.FileMetaData.NumRowGroups && index < rows.Length; group++)
        foreach (var row in reader.ReadRows(group))
        {
            rows[index++] = row;
            if (index == rows.Length) break;
        }
        if (index != rows.Length)
            throw new InvalidOperationException($"Taxi input returned {index:N0} rows; expected {rows.Length:N0}.");
        return rows;
    }

    static string[] CreateStrings()
    {
        var values = new string[2048];
        for (var index = 0; index < values.Length; index++)
            values[index] = $"value-{index:D4}";
        return values;
    }

    static byte[][] CreateUtf8()
    {
        var values = new byte[StringValues.Length][];
        for (var index = 0; index < values.Length; index++)
            values[index] = Encoding.UTF8.GetBytes(StringValues[index]);
        return values;
    }
}
