using BenchmarkDotNet.Running;
using Plank.Benchmarks;
using Plank.Benchmarks.EncodingRegression;
using Plank.Benchmarks.Published;
using Plank.Benchmarks.S3Footer;

if (args is ["--s3-footer", ..])
    return await S3FooterCommand.RunAsync(args[1..]);

if (args is ["--prepare-published-fixture", var stem, var read, .. var writers])
{
    await BenchmarkFixtures.Prepare(stem, bool.Parse(read), writers);
    return 0;
}

if (args is ["--encoding-regression", ..])
{
    await EncodingRegressionCommand.RunAsync(args[1..]);
    return 0;
}

if (args is ["--encoding-regression-compare", ..])
    return await EncodingRegressionCommand.CompareAsync(args[1..]);

if (args is ["--published-write", ..])
{
    PublishedBenchmarkCommand.Run(args[1..], "Write");
    return 0;
}

if (args is ["--published-read", ..])
{
    PublishedBenchmarkCommand.Run(args[1..], "Read");
    return 0;
}

if (args is ["--published", ..])
{
    PublishedBenchmarkCommand.Run(args[1..]);
    return 0;
}

if (args is ["--audit-encodings", ..])
{
    await EncodingActualEncodingAudit.RunAsync();
    return 0;
}

BenchmarkSwitcher.FromAssembly(typeof(EncodingBenchmark).Assembly)
    .Run(args);
return 0;
