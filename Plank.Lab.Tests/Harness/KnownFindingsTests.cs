using Plank.Fuzzing;
using Plank.Fuzzing.Harness;

namespace Plank.Lab.Tests.Harness;

// PLANK_FUZZ_KNOWN_FINDINGS must recognise exactly the documented findings, from the real inputs that
// reproduce them, and nothing else.
[NotInParallel]
public class KnownFindingsTests
{
    [Test]
    [Arguments("repros/rowapi-unset-column-stale-value/RUS1-stale-id.bin", "stale-scalar-slot-reuse")]
    [Arguments("writer-gap-seeds/delta-binary-packed-int32/public-generic-dispatch.bin", "uint-ulong-signed-stats")]
    [Arguments("repros/statistics-ulong-in-signed-int64-order/wtm1-converter-uint-physical-in-signed-int32-delta.bin", "uint-ulong-signed-stats")]
    [Arguments("repros/statistics-ulong-in-signed-int64-order/wtm1-converter-ulong-physical-in-signed-int64-plain.bin", "uint-ulong-signed-stats")]
    [Arguments("corpus/encoding-plain-int96.bin", "distinct-count-zero-unordered")]
    [Arguments("repros/statistics-distinct-count-zero-unordered/append-sorting-geometry-key.bin", "distinct-count-zero-unordered")]
    public async Task ReproInputIsRecognisedAsItsKnownFinding(string relativePath, string expectedId)
    {
        var data = File.ReadAllBytes(Path.Combine(FuzzDirectory(), relativePath));
        Exception? fault = null;
        try { PlankWriterFuzzTarget.Execute(data); }
        catch (Exception ex) { fault = ex; }

        await Assert.That(fault).IsNotNull();
        await Assert.That(KnownFindings.Match(fault!, KnownFindings.ParseIds("all"))).IsEqualTo(expectedId);
        // Off by default, and not matched when only another finding is enabled.
        await Assert.That(KnownFindings.Match(fault!, KnownFindings.ParseIds(""))).IsNull();
        await Assert.That(KnownFindings.Match(fault!, KnownFindings.ParseIds("276,chunk-info-equality"))).IsNull();
    }

    [Test]
    public async Task UnrelatedExceptionsAreNeverRecognised()
    {
        var all = KnownFindings.ParseIds("all");
        await Assert.That(KnownFindings.Match(new InvalidOperationException("boom"), all)).IsNull();
        await Assert.That(KnownFindings.Match(new OverflowException("Arithmetic operation resulted in an overflow."), all)).IsNull();
        await Assert.That(KnownFindings.Match(new NotSupportedException("something else"), all)).IsNull();
        await Assert.That(KnownFindings.Match(new ArgumentOutOfRangeException("rowIndex", 1, "Row index is outside the buffer slot."), all)).IsNull(); // no BeginRow frame in the text
        // Same oracle message, but distinct_count != 0 is a different bug.
        await Assert.That(KnownFindings.Match(new InvalidOperationException(
            "written: statistics distinct_count differs from the values — row group 0, column 0 'x' (Int96, None, def=0, rep=0): distinct_count=5, actual=3"), all)).IsNull();
        await Assert.That(KnownFindings.Match(new InvalidOperationException(
            "written: statistics distinct_count differs from the values — row group 0, column 0 'x' (Int32, None, def=0, rep=0): distinct_count=0, actual=3"), all)).IsNull();
        // A plain unannotated BYTE_ARRAY column (any other name) reporting distinct_count = 0 is not the geometry finding.
        await Assert.That(KnownFindings.Match(new InvalidOperationException(
            "written: statistics distinct_count differs from the values — row group 0, column 0 'name' (ByteArray, none, def=0, rep=0): distinct_count=0, actual=3"), all)).IsNull();
    }

    [Test]
    public async Task SignaturesOfFindingsWithoutAFastReproMatchTheirTextAndFrames()
    {
        var all = KnownFindings.ParseIds("all");
        await Assert.That(KnownFindings.Match(new InvalidOperationException(
            "Column 'Tag' uses a converter for 'Plank.Fuzzing.RowFuzzId' and cannot be read as 'System.Int32'."), all))
            .IsEqualTo("dataset-append-latest-converter");
        await Assert.That(KnownFindings.Match(new InvalidOperationException("Row API round trip lost 'No more row slots are available.'"), all)).IsEqualTo("276");
    }

    [Test]
    public async Task OutOfMemoryIsOnlyAnArtifactForTheWriterTarget()
    {
        var all = KnownFindings.ParseIds("all");
        await Assert.That(KnownFindings.Match(new OutOfMemoryException(), all, "writer")).IsEqualTo("writer-oom-memory-cap");
        await Assert.That(KnownFindings.Match(new OutOfMemoryException(), all, "reader")).IsNull();
        await Assert.That(KnownFindings.Match(new InvalidOperationException("x", new OutOfMemoryException()), all, "writer")).IsEqualTo("writer-oom-memory-cap");
    }

    [Test]
    public async Task NewSurfaceFindingSignaturesAreNarrow()
    {
        var all = KnownFindings.ParseIds("all");
        // PendingRowCapacity = int.MaxValue: dataset OOM with the array-dimension message (not any OOM, which the writer artifact id covers separately).
        await Assert.That(KnownFindings.Match(new OutOfMemoryException("Array dimensions exceeded supported range.",
            new InvalidOperationException("at DatasetWriter.Enqueue")), all, "reader")).IsEqualTo("pending-row-capacity-oom");
        await Assert.That(KnownFindings.Match(new OutOfMemoryException("Array dimensions exceeded supported range."), all, "reader")).IsNull();
        try { _ = ((object?)null)!.ToString(); } catch (NullReferenceException) { }
        await Assert.That(KnownFindings.Match(new NullReferenceException(), all)).IsNull(); // no NestedRowGroupColumn frame
        await Assert.That(KnownFindings.Match(new OverflowException("x"), all)).IsNull();   // no ScanPageLocations frame
    }

    static string FuzzDirectory()
    {
        for (var directory = new DirectoryInfo(AppContext.BaseDirectory); directory is not null; directory = directory.Parent)
        {
            var fuzz = Path.Combine(directory.FullName, "fuzz");
            if (Directory.Exists(Path.Combine(fuzz, "corpus")))
                return fuzz;
        }
        throw new DirectoryNotFoundException("fuzz directory not found above " + AppContext.BaseDirectory);
    }
}
