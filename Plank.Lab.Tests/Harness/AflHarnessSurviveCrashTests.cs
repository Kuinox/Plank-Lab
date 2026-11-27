using Plank.Fuzzing.Harness;

namespace Plank.Lab.Tests.Harness;

[NotInParallel]
public class AflHarnessSurviveCrashTests
{
    [Test]
    public async Task ExceptionReportsStatus11AndLoopContinuesWhenSurviving()
    {
        var dir = Path.Combine(Path.GetTempPath(), "plank-harness-" + Guid.NewGuid().ToString("N"));
        Environment.SetEnvironmentVariable("PLANK_FUZZ_CRASH_DIR", dir);
        try
        {
            int calls = 0;
            void Execute(byte[] data) { calls++; if (data.Length == 1) throw new InvalidOperationException("boom"); }

            var ok = AflPersistentHarness.ExecuteOne("test", Execute, [0, 0], true, out bool fatal1);
            var bad = AflPersistentHarness.ExecuteOne("test", Execute, [7], true, out bool fatal2);
            var after = AflPersistentHarness.ExecuteOne("test", Execute, [0, 0, 0], true, out bool fatal3);

            await Assert.That(ok).IsEqualTo(0u);
            await Assert.That(bad).IsEqualTo(11u);
            await Assert.That(after).IsEqualTo(0u);
            await Assert.That(fatal1 || fatal2 || fatal3).IsFalse();
            await Assert.That(calls).IsEqualTo(3);
            await Assert.That(Directory.GetFiles(dir).Length).IsEqualTo(1);
        }
        finally
        {
            Environment.SetEnvironmentVariable("PLANK_FUZZ_CRASH_DIR", null);
            if (Directory.Exists(dir)) Directory.Delete(dir, true);
        }
    }

    [Test]
    public async Task ExceptionIsFatalWithoutSurviveMode()
    {
        var status = AflPersistentHarness.ExecuteOne("test", _ => throw new ArgumentException("x"), [1], false, out bool fatal);
        await Assert.That(status).IsEqualTo(2u);
        await Assert.That(fatal).IsTrue();
    }
}
