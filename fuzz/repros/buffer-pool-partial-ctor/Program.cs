using System.Runtime.CompilerServices;
using Plank;

for (var i = 0; i < 1; i++)
    RejectInvalidPolicy();
Console.WriteLine("Expected constructor rejections observed.");
GC.Collect();
GC.WaitForPendingFinalizers();
Console.WriteLine("Finalizers completed.");

[MethodImpl(MethodImplOptions.NoInlining)]
static void RejectInvalidPolicy()
{
    try
    {
        _ = new DefaultParquetBufferPool((ParquetBufferRetentionPolicy)255);
        throw new InvalidOperationException("Invalid policy was accepted.");
    }
    catch (ArgumentOutOfRangeException error) when (error.ParamName == "retentionPolicy")
    {
    }
}
