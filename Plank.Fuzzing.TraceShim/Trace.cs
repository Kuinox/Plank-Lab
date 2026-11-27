using System;

namespace SharpFuzz.Common
{
	/// <summary>
	/// Drop-in replacement for SharpFuzz.Common 2.2.0's Trace with a per-thread previous-location.
	/// SharpFuzz instruments with one process-wide PrevLocation, so code running on several threads
	/// (a row-writer pipeline's worker plus its producer) makes the edge hashes depend on thread
	/// interleaving: the same input maps different bitmap bytes on every run. A [ThreadStatic]
	/// PrevLocation keeps each thread's edge chain deterministic.
	/// </summary>
	public static unsafe class Trace
	{
		public static byte* SharedMem;

		[ThreadStatic]
		public static int PrevLocation;

		public static Action<int, string> OnBranch;
	}
}
