namespace HookMap.Core.Bisect;

/// <summary>The outcome of one test run of the game with a given set of units switched on.</summary>
public enum TestResult
{
    /// <summary>The crash (or freeze) happened.</summary>
    Fail,
    /// <summary>It did not happen within the agreed test.</summary>
    Pass,
    /// <summary>The run was no use (a different crash, the game did not start, the test could not be done).</summary>
    Unresolved,
}

public abstract record NextStep;
/// <summary>The next game run to do: these units on, all other candidates off.</summary>
public sealed record NeedTest(IReadOnlyList<int> Enabled, string Why) : NextStep;
/// <summary>Finished. <see cref="Culprits"/> is the smallest set of units that still makes the game crash; null when it never crashed.</summary>
public sealed record Done(IReadOnlyList<int>? Culprits, string Summary) : NextStep;

/// <summary>
/// Delta debugging (Zeller's ddmin) for "which of these SKSE mods have to be on together to crash". Unlike a plain halving search it finds
/// pairs: two mods that only crash together are both kept, because removing either one makes the crash go away.
/// The algorithm is deterministic and asks a stored list of earlier answers first, so a session can be saved and resumed.
/// </summary>
public static class Ddmin
{
    private sealed class NeedTestException(IReadOnlyList<int> config, string why) : Exception
    {
        public IReadOnlyList<int> Config { get; } = config;
        public string Why { get; } = why;
    }

    public static string Key(IEnumerable<int> config) => string.Join(',', config.OrderBy(x => x));

    /// <param name="universe">Unit ids, most suspicious first (the first chunks are tried first).</param>
    /// <param name="known">Answers recorded so far, by <see cref="Key"/>.</param>
    public static NextStep Next(IReadOnlyList<int> universe, IReadOnlyDictionary<string, TestResult> known)
    {
        try { return Run(universe, known); }
        catch (NeedTestException e) { return new NeedTest(e.Config, e.Why); }
    }

    private static Done Run(IReadOnlyList<int> universe, IReadOnlyDictionary<string, TestResult> known)
    {
        bool Fails(List<int> config, string why)
        {
            if (known.TryGetValue(Key(config), out var r)) return r == TestResult.Fail;
            throw new NeedTestException(config.ToList(), why);
        }

        var c = universe.ToList();
        if (c.Count == 0) return new Done([], "There is nothing to test: no candidate mods.");

        if (!Fails(c, "Everything on, as in your normal game. This has to crash first.")) return new Done(null, "The game did not crash with everything switched on, so there is nothing to narrow down. Try a longer test or the exact place where it crashes.");
        if (Fails([], "Every candidate off. This should not crash.")) return new Done([], "The game still crashes with every candidate mod off. The cause is not one of these SKSE mods (or not only them).");

        int n = 2;
        while (c.Count >= 2)
        {
            var subsets = Split(c, n);
            bool reduced = false;
            foreach (var s in subsets)
            {
                if (Fails(s, $"{s.Count} of {c.Count} on")) { c = s; n = 2; reduced = true; break; }
            }
            if (!reduced)
            {
                foreach (var s in subsets)
                {
                    var comp = c.Except(s).ToList();
                    if (comp.Count == 0) continue;
                    if (Fails(comp, $"{comp.Count} of {c.Count} on")) { c = comp; n = Math.Max(n - 1, 2); reduced = true; break; }
                }
            }
            if (!reduced)
            {
                if (n >= c.Count) break;
                n = Math.Min(c.Count, n * 2);
            }
        }
        return new Done(c, c.Count == 1
            ? "One mod is enough to crash (with the always-on mods)."
            : $"These {c.Count} mods crash together, and removing any one of them stops it.");
    }

    private static List<List<int>> Split(List<int> c, int n)
    {
        var parts = new List<List<int>>();
        int size = c.Count / n, extra = c.Count % n, pos = 0;
        for (int i = 0; i < n; i++)
        {
            int len = size + (i < extra ? 1 : 0);
            if (len == 0) continue;
            parts.Add(c.GetRange(pos, len));
            pos += len;
        }
        return parts;
    }
}
