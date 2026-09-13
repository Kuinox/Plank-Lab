using BenchmarkDotNet.Engines;
using BenchmarkDotNet.Jobs;
using System.Globalization;

namespace Plank.Benchmarks.Published;

// Public so BenchmarkDotNet's generated child executable can construct it.
public sealed class PrComparisonEngineFactory : IEngineFactory
{
    internal const string MeasurementTimeVariable = "PLANK_PR_MEASUREMENT_TIME_MS";
    internal const int DefaultMeasurementTimeMilliseconds = 500;
    internal const int MinimumIterations = 15;
    internal const int MaximumIterations = 1_000;
    const int CalibrationIterations = 3;

    public IEngine CreateReadyToRun(EngineParameters engineParameters)
    {
        var targetMilliseconds = ReadTargetMilliseconds();
        var minimumIterations = engineParameters.TargetJob.Run.IterationCount;
        var originalCleanup = engineParameters.GlobalCleanupAction;
        var setupCompleted = false;

        try
        {
            void RunGlobalSetup()
            {
                engineParameters.GlobalSetupAction?.Invoke();
                setupCompleted = true;
            }

            var calibrationParameters = Copy(
                engineParameters,
                engineParameters.TargetJob.WithIterationCount(CalibrationIterations),
                RunGlobalSetup,
                static () => { });
            using var calibrationEngine = new EngineFactory().CreateReadyToRun(calibrationParameters);

            var measurements = new double[CalibrationIterations];
            for (var index = 0; index < measurements.Length; index++)
            {
                measurements[index] = calibrationEngine.RunIteration(new IterationData(
                    IterationMode.Workload, IterationStage.Warmup, index + 1, 1, 1)).Nanoseconds;
            }

            Array.Sort(measurements);
            var calibrationMedianNanoseconds = measurements[measurements.Length / 2];
            var iterationCount = CalculateIterationCount(
                calibrationMedianNanoseconds, targetMilliseconds, minimumIterations);
            var measurementJob = engineParameters.TargetJob.WithIterationCount(iterationCount);
            var measurementParameters = Copy(
                engineParameters, measurementJob, static () => { }, originalCleanup);
            var engine = new EngineFactory().CreateReadyToRun(measurementParameters);
            var calibrationMilliseconds = (calibrationMedianNanoseconds / 1_000_000)
                .ToString("F3", CultureInfo.InvariantCulture);
            engine.WriteLine(
                $"// PR measurement plan: {iterationCount} iterations, " +
                $"{calibrationMilliseconds} ms calibration median, {targetMilliseconds} ms target");
            return engine;
        }
        catch
        {
            if (setupCompleted) originalCleanup?.Invoke();
            throw;
        }
    }

    internal static int CalculateIterationCount(
        double calibrationNanoseconds,
        int targetMilliseconds = DefaultMeasurementTimeMilliseconds,
        int minimumIterations = MinimumIterations)
    {
        if (!double.IsFinite(calibrationNanoseconds) || calibrationNanoseconds <= 0)
            throw new ArgumentOutOfRangeException(nameof(calibrationNanoseconds));
        if (targetMilliseconds <= 0)
            throw new ArgumentOutOfRangeException(nameof(targetMilliseconds));
        if (minimumIterations <= 0)
            throw new ArgumentOutOfRangeException(nameof(minimumIterations));

        var targetNanoseconds = targetMilliseconds * 1_000_000d;
        var estimated = (long)Math.Ceiling(targetNanoseconds / calibrationNanoseconds);
        return (int)Math.Clamp(estimated, minimumIterations, Math.Max(minimumIterations, MaximumIterations));
    }

    static int ReadTargetMilliseconds()
    {
        var value = Environment.GetEnvironmentVariable(MeasurementTimeVariable);
        return int.TryParse(value, NumberStyles.None, CultureInfo.InvariantCulture, out var parsed) && parsed > 0
            ? parsed
            : DefaultMeasurementTimeMilliseconds;
    }

    static EngineParameters Copy(
        EngineParameters source,
        Job targetJob,
        Action? globalSetup,
        Action? globalCleanup) => new()
    {
        Host = source.Host,
        WorkloadActionNoUnroll = source.WorkloadActionNoUnroll,
        WorkloadActionUnroll = source.WorkloadActionUnroll,
        Dummy1Action = source.Dummy1Action,
        Dummy2Action = source.Dummy2Action,
        Dummy3Action = source.Dummy3Action,
        OverheadActionNoUnroll = source.OverheadActionNoUnroll,
        OverheadActionUnroll = source.OverheadActionUnroll,
        TargetJob = targetJob,
        OperationsPerInvoke = source.OperationsPerInvoke,
        GlobalSetupAction = globalSetup!,
        GlobalCleanupAction = globalCleanup!,
        IterationSetupAction = source.IterationSetupAction,
        IterationCleanupAction = source.IterationCleanupAction,
        MeasureExtraStats = source.MeasureExtraStats,
        BenchmarkName = source.BenchmarkName
    };
}
