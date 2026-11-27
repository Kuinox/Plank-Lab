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
    [Arguments("repros/statistics-ulong-in-signed-int64-order/wtm1-uint-in-signed-int32-plain.bin", "uint-ulong-signed-stats")]
    [Arguments("repros/statistics-ulong-in-signed-int64-order/wtm1-ulong-optional-in-signed-int64-plain-dictionary.bin", "uint-ulong-signed-stats")]
    [Arguments("writer-gap-seeds/delta-binary-packed-int32/public-generic-dispatch.bin", "uint-ulong-signed-stats")]
    [Arguments("corpus/encoding-plain-int96.bin", "distinct-count-zero-unordered")]
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
