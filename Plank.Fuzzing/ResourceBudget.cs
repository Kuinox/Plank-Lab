using System.Diagnostics;

namespace Plank.Fuzzing;

/// <summary>Thrown when reading one input used more memory or time than a file of that size can justify.</summary>
public sealed class ResourceBudgetException(string message) : Exception(message);

/// <summary>
/// Allocation and time budget for one reader input: a malformed file that declares huge sizes or counts must be
/// rejected quickly and cheaply, not after the reader has trusted the declaration.
/// </summary>
/// <remarks>
/// Native buffers come from the pool, so <see cref="BudgetPool"/> counts and refuses oversized rents <em>before</em> allocating (a
/// declared 2 GiB page would otherwise take the worker down before it could be reported). Managed allocation is the thread's
/// <c>GC.GetAllocatedBytesForCurrentThread</c> delta, and time a stopwatch; both are checked when the input finishes.
/// Limits scale with the input length because decompression and RLE legitimately expand — but only by bounded factors
/// (the budget is generous: 64 MiB per rent, 512 MiB per input, plus 64x/512x/256x the input length, 10 s). Everything the
/// seed corpora do fits. <c>PLANK_FUZZ_BUDGET=0</c> disables it.
/// </remarks>
sealed class ResourceBudget
{
    internal static readonly bool Enabled = Environment.GetEnvironmentVariable("PLANK_FUZZ_BUDGET") != "0";

    const long MiB = 1 << 20;
    readonly long _singleRentLimit, _totalRentLimit, _managedLimit;
    readonly TimeSpan _timeLimit = TimeSpan.FromSeconds(10);
    readonly Stopwatch _clock = Stopwatch.StartNew();
    readonly long _managedStart = GC.GetAllocatedBytesForCurrentThread();
    long _rented, _largest;

    public ResourceBudget(int inputLength)
    {
        _singleRentLimit = 64 * MiB + 64L * inputLength;
        _totalRentLimit = 512 * MiB + 512L * inputLength;
        _managedLimit = 256 * MiB + 256L * inputLength;
    }

    public IParquetBufferPool Wrap(IParquetBufferPool inner) => new BudgetPool(this, inner);

    public void Check()
    {
        var managed = GC.GetAllocatedBytesForCurrentThread() - _managedStart;
        if (managed > _managedLimit)
            throw new ResourceBudgetException(
                $"Reading allocated {managed:N0} managed bytes (budget {_managedLimit:N0}); largest pool rent {_largest:N0}.");
        if (_clock.Elapsed > _timeLimit)
            throw new ResourceBudgetException($"Reading took {_clock.Elapsed.TotalSeconds:F1}s (budget {_timeLimit.TotalSeconds:F0}s).");
    }

    sealed class BudgetPool(ResourceBudget budget, IParquetBufferPool inner) : IParquetBufferPool
    {
        public ParquetBuffer Rent(uint minimumByteLength)
        {
            budget._largest = Math.Max(budget._largest, minimumByteLength);
            budget._rented += minimumByteLength;
            if (minimumByteLength > budget._singleRentLimit)
                throw new ResourceBudgetException(
                    $"A single {minimumByteLength:N0}-byte buffer was requested (budget {budget._singleRentLimit:N0}).");
            if (budget._rented > budget._totalRentLimit)
                throw new ResourceBudgetException(
                    $"{budget._rented:N0} buffer bytes were requested in total (budget {budget._totalRentLimit:N0}).");
            return inner.Rent(minimumByteLength);
        }
    }
}
