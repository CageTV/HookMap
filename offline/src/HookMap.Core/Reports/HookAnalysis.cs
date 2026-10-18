using HookMap.Core.Crash;

namespace HookMap.Core.Reports;

public sealed class MergedHook
{
    public required ReportHook Hook { get; init; }
    public List<string> SeenIn { get; } = [];
    /// <summary>Installed after the main menu snapshot: a plugin that hooks late (on the first save load or the first menu).</summary>
    public bool Late { get; set; }
    public string Describe => $"{Hook.Kind} at {Hook.Site} ({Hook.Bytes})";
}

public sealed class OverlapGroup
{
    public string Group { get; init; } = "";
    public long FuncRva { get; init; }
    public long FuncSize { get; init; }
    public List<string> Names { get; init; } = [];
    public List<string> Owners { get; init; } = [];
    public string Severity { get; init; } = "";
    public List<MergedHook> Hooks { get; init; } = [];
    public string Title => Names.Count > 0 ? Names[0] : (FuncRva != 0 ? $"function at +{FuncRva:X}" : Group);
}

public sealed class ModuleSummary
{
    public string Module { get; init; } = "";
    public string Plugin { get; set; } = "";
    public string Author { get; set; } = "";
    public bool Skse { get; set; }
    public int Hooks { get; set; }
    public int LateHooks { get; set; }
    public int OverlapGroups { get; set; }
    public SortedSet<string> Partners { get; } = new(StringComparer.OrdinalIgnoreCase);
    public SortedDictionary<string, int> Kinds { get; } = new();
}

/// <summary>Reads one or more snapshots together: which DLL patches what, and where two DLLs patch the same function.</summary>
public sealed class HookAnalysis
{
    public List<HookReport> Reports { get; } = [];
    public List<MergedHook> Hooks { get; } = [];
    public List<OverlapGroup> Overlaps { get; } = [];
    public List<ModuleSummary> Modules { get; } = [];
    public string ExeVersion => Reports.FirstOrDefault()?.ExeVersion ?? "";

    public static HookAnalysis Build(IEnumerable<HookReport> reports)
    {
        var a = new HookAnalysis();
        a.Reports.AddRange(reports.OrderBy(r => r.Time, StringComparer.Ordinal));
        var byKey = new Dictionary<(long, string, string), MergedHook>();
        for (int i = 0; i < a.Reports.Count; i++)
        {
            var r = a.Reports[i];
            foreach (var h in r.Hooks)
            {
                var key = (h.SiteRva, h.Owner, h.Kind);
                if (!byKey.TryGetValue(key, out var m))
                {
                    m = new MergedHook { Hook = h, Late = i > 0 };
                    byKey[key] = m;
                    a.Hooks.Add(m);
                }
                if (!m.SeenIn.Contains(r.Reason)) m.SeenIn.Add(r.Reason);
            }
        }

        // A class with several virtual tables (multiple inheritance) has a slot 1 in each: only the same table address is the same slot, so "V:Class#slot" keys of older reports are replaced by the slot itself.
        foreach (var g in a.Hooks.GroupBy(h => h.Hook.Group.StartsWith("V:", StringComparison.Ordinal) ? "P:" + h.Hook.Site : h.Hook.Group))
        {
            var list = g.ToList();
            if (list.Count < 2) continue;
            var owners = list.Where(h => h.Hook.OwnerKnown).Select(h => h.Hook.Owner).Distinct(StringComparer.OrdinalIgnoreCase).OrderBy(x => x, StringComparer.OrdinalIgnoreCase).ToList();
            bool unknown = list.Any(h => !h.Hook.OwnerKnown);
            // One memory slot can only hold one owner at a time: two owners on the same site means a later snapshot found it taken over by another DLL.
            bool oneSite = list.Select(h => h.Hook.Site).Distinct().Count() == 1;
            string sev = owners.Count >= 2 ? (oneSite ? "taken-over" : "two-modules") : owners.Count == 1 && unknown ? "possible" : "";
            if (sev.Length == 0) continue;
            var first = list.OrderBy(h => h.Hook.Names.Count == 0).First().Hook;
            a.Overlaps.Add(new OverlapGroup
            {
                Group = g.Key, FuncRva = first.FuncRva, FuncSize = first.FuncSize, Names = first.Names, Owners = owners, Severity = sev,
                Hooks = list.OrderBy(h => h.Hook.SiteRva).ToList(),
            });
        }
        a.Overlaps.Sort((x, y) =>
        {
            int c = Rank(y.Severity).CompareTo(Rank(x.Severity));
            return c != 0 ? c : y.Owners.Count.CompareTo(x.Owners.Count);
        });

        var mods = new Dictionary<string, ModuleSummary>(StringComparer.OrdinalIgnoreCase);
        foreach (var r in a.Reports)
            foreach (var m in r.Modules.Where(m => m.Skse))
                if (!mods.ContainsKey(m.Name)) mods[m.Name] = new ModuleSummary { Module = m.Name, Plugin = m.Plugin, Author = m.Author, Skse = true };
        foreach (var h in a.Hooks)
        {
            var o = h.Hook.Owner;
            if (!mods.TryGetValue(o, out var s)) mods[o] = s = new ModuleSummary { Module = o };
            s.Hooks++;
            if (h.Late) s.LateHooks++;
            s.Kinds[h.Hook.Kind] = s.Kinds.GetValueOrDefault(h.Hook.Kind) + 1;
        }
        foreach (var o in a.Overlaps.Where(o => o.Severity is "two-modules" or "taken-over"))
            foreach (var owner in o.Owners)
            {
                var s = mods[owner];
                s.OverlapGroups++;
                foreach (var p in o.Owners.Where(p => !p.Equals(owner, StringComparison.OrdinalIgnoreCase))) s.Partners.Add(p);
            }
        a.Modules.AddRange(mods.Values.OrderByDescending(m => m.OverlapGroups).ThenByDescending(m => m.Hooks).ThenBy(m => m.Module, StringComparer.OrdinalIgnoreCase));
        return a;
    }

    private static int Rank(string severity) => severity switch { "two-modules" => 2, "taken-over" => 1, _ => 0 };

    // ------------------------------------------------------------------ with a crash log

    public sealed record StackHit(CrashFrame Frame, MergedHook[] HooksInFunction, OverlapGroup? Overlap);

    public sealed class CrashCorrelation
    {
        public required CrashLog Log { get; init; }
        public List<StackHit> Hits { get; } = [];
        /// <summary>Per DLL file name: how suspicious it is for this crash (higher = look first).</summary>
        public Dictionary<string, double> Suspicion { get; } = new(StringComparer.OrdinalIgnoreCase);
        public List<string> Notes { get; } = [];
    }

    public CrashCorrelation Correlate(CrashLog log)
    {
        var c = new CrashCorrelation { Log = log };
        void Add(string dll, double v) => c.Suspicion[dll] = c.Suspicion.GetValueOrDefault(dll) + v;

        foreach (var (module, first, probable, scan) in log.DllsOnStack())
        {
            Add(module, probable * 5 + scan * 2 + (first.Probable ? 2 : 0));
            c.Notes.Add($"{module} is on the call stack ({probable} probable, {scan} stack-scan frame{(scan == 1 ? "" : "s")}); first at frame {first.Index}.");
        }

        var ranges = Hooks.Where(h => h.Hook.FuncKnown && h.Hook.FuncSize > 0).ToList();
        foreach (var f in log.Frames.Where(f => f.InExe))
        {
            var inside = ranges.Where(h => f.Offset >= h.Hook.FuncRva && f.Offset < h.Hook.FuncRva + h.Hook.FuncSize).ToArray();
            if (inside.Length == 0) continue;
            var ov = Overlaps.FirstOrDefault(o => o.FuncRva == inside[0].Hook.FuncRva && o.Severity == "two-modules");
            c.Hits.Add(new StackHit(f, inside, ov));
            var owners = inside.Where(h => h.Hook.OwnerKnown).Select(h => h.Hook.Owner).Distinct(StringComparer.OrdinalIgnoreCase).ToList();
            foreach (var o in owners) Add(o, f.Probable ? 4 : 2);
            string what = f.Symbol ?? $"+{f.Offset:X}";
            c.Notes.Add($"Frame {f.Index} ({what}) is inside a function patched by {string.Join(" and ", owners.DefaultIfEmpty("an unknown patch"))}"
                        + (ov is not null ? " - two different DLLs patch this function." : "."));
            if (ov is not null) foreach (var o in ov.Owners) Add(o, 6);
        }

        // Anything that patches the game but is not on the stack still gets a little weight when it shares a function with a DLL that is.
        foreach (var o in Overlaps.Where(o => o.Severity == "two-modules"))
            if (o.Owners.Any(w => c.Suspicion.GetValueOrDefault(w) >= 5))
                foreach (var w in o.Owners) Add(w, 1);
        return c;
    }
}
