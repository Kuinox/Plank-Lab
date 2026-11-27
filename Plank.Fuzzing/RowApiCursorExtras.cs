using System.Globalization;
using System.Text;

namespace Plank.Fuzzing;

public static partial class PlankRowApiFuzzTarget
{
    // Value generators shared by the wide-schema routes. Every generator maps any
    // byte stream onto a value that is valid for the column, including extremes.
    internal ref partial struct Cursor
    {
        internal bool NextBool() => NextByte() % 2 == 0;

        // Extremes are drawn on purpose: a uniformly random digit string almost never
        // yields 0, the precision maximum or a fractional-only value.
        internal decimal NextDecimal(int precision, int scale)
        {
            var mode = NextInt(0, 8);
            if (mode == 0)
                return 0m;
            var digits = new StringBuilder();
            var negative = NextBool();
            var length = mode == 1 ? precision : NextInt(1, precision + 1);
            for (var i = 0; i < length; i++)
                digits.Append(mode == 1 ? '9' : (char)('0' + (NextByte() % 10)));
            var unscaled = digits.ToString().PadLeft(scale + 1, '0');
            var text = scale == 0
                ? unscaled
                : unscaled[..^scale] + "." + unscaled[^scale..];
            var value = decimal.Parse(text, NumberStyles.Number, CultureInfo.InvariantCulture);
            return negative ? -value : value;
        }

        // A small vocabulary so dictionary encoding actually repeats values.
        internal string NextDictLabel()
            => "dict-" + (NextByte() % 5);

        internal DateOnly NextDate()
            => DateOnly.FromDayNumber(NextInt(0, 4) switch
            {
                0 => 0,
                1 => DateOnly.MaxValue.DayNumber,
                _ => (int)((uint)NextInt32() % (uint)DateOnly.MaxValue.DayNumber)
            });

        internal TimeOnly NextTime()
            => new(NextInt(0, 4) switch
            {
                0 => 0,
                1 => TimeOnly.MaxValue.Ticks / 10 * 10,
                _ => (long)((ulong)NextInt64() % (ulong)(TimeOnly.MaxValue.Ticks / 10)) * 10
            });

        // Microsecond resolution: coarser would not survive the round trip, finer would be a false positive.
        internal DateTime NextTimestamp()
            => new(NextInt(0, 4) switch
            {
                0 => 0,
                1 => DateTime.MaxValue.Ticks / 10 * 10,
                _ => (long)((ulong)NextInt64() % (ulong)(DateTime.MaxValue.Ticks / 10)) * 10
            }, DateTimeKind.Utc);

        internal DateTimeOffset NextTimestampOffset()
        {
            // Keep the UTC instant two days clear of both year bounds so any offset stays representable.
            const long Margin = 2 * TimeSpan.TicksPerDay;
            var ticks = (long)((ulong)NextInt64() % (ulong)((DateTime.MaxValue.Ticks - 2 * Margin) / 10)) * 10 + Margin;
            return new DateTimeOffset(ticks, TimeSpan.Zero).ToOffset(TimeSpan.FromMinutes(NextInt(0, 29) * 30 - 14 * 30));
        }
    }
}
