namespace Plank.Benchmarks.S3Footer;

public sealed record S3FooterReport(
    int SchemaVersion,
    DateTimeOffset GeneratedAt,
    S3FooterDataset Dataset,
    S3FooterEnvironment Environment,
    S3FooterProtocol Protocol,
    IReadOnlyList<S3FooterRun> Runs);

public sealed record S3FooterDataset(
    string Name,
    string? SourceUrl,
    string Mode,
    long FileSizeBytes,
    long FooterOffset,
    long FooterLengthBytes,
    string FooterSha256);

public sealed record S3FooterEnvironment(
    string OperatingSystem,
    string Architecture,
    string Runtime,
    int ProcessorCount,
    string? LabCommit,
    string? PlankCommit,
    bool? LabDirty,
    bool? PlankDirty);

public sealed record S3FooterProtocol(int Iterations, double LatencyMs, string Description);

public sealed record S3FooterRun(
    string Library,
    string Version,
    int Iteration,
    double ElapsedMs,
    long? RowCount,
    int? RowGroupCount,
    int? ColumnCount,
    string? Error,
    IReadOnlyList<S3RequestTrace> Requests);
