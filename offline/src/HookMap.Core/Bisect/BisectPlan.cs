using HookMap.Core.Mo2;

namespace HookMap.Core.Bisect;

/// <summary>One thing the search switches on or off: an SKSE mod, together with the mods that cannot work without it
/// (patches whose plugin has its plugin as master) and any other SKSE mod that is tied to it the same way.</summary>
public sealed class BisectUnit
{
    public int Id { get; set; }
    public string Name { get; set; } = "";
    public List<string> Mods { get; set; } = [];            // the SKSE mods of this unit
    public List<string> Dependents { get; set; } = [];      // mods without a DLL that go off with it
    public double Suspicion { get; set; }
    public override string ToString() => Name;
}

public sealed class BisectPlan
{
    public List<BisectUnit> Units { get; set; } = [];       // the ones the search can switch, most suspicious first
    public List<string> AlwaysOn { get; set; } = [];        // SKSE mods that stay enabled (chosen by the user or needed by an always-on mod)
    public Dictionary<string, string> AlwaysOnWhy { get; set; } = [];

    /// <summary>Mods to disable in the test profile when only these units are switched on.</summary>
    public HashSet<string> DisabledFor(IEnumerable<int> enabledUnits)
    {
        var on = new HashSet<int>(enabledUnits);
        var off = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        foreach (var u in Units)
        {
            if (on.Contains(u.Id)) continue;
            foreach (var m in u.Mods) off.Add(m);
            foreach (var m in u.Dependents) off.Add(m);
        }
        return off;
    }

    /// <param name="skseMods">The profile's mods with DLLs (enabled ones become candidates).</param>
    /// <param name="keep">Mods the user wants always on (frameworks, the crash logger).</param>
    /// <param name="suspicion">Score per mod name; higher goes first. Missing = 0.</param>
    public static BisectPlan Build(Mo2Instance inst, string profile, IReadOnlyList<SkseMod> skseMods, Func<SkseMod, bool> keep, IReadOnlyDictionary<string, double>? suspicion = null, int maxSharedDependents = 3)
    {
        var lines = Mo2Instance.ReadModList(Path.Combine(inst.ProfilesDir, profile));
        var enabled = lines.Where(l => l is { Enabled: true, IsSeparator: false, IsManaged: true }).Select(l => l.Name).ToList();

        // Which mod provides each plugin (the highest-priority enabled mod, MO2 lists those first), and what its masters are.
        var plugins = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);                   // plugin -> mod
        var modPlugins = new Dictionary<string, List<string>>(StringComparer.OrdinalIgnoreCase);          // mod -> plugins it wins
        foreach (var mod in enabled)
        {
            var folder = Path.Combine(inst.ModsDir, mod);
            if (!Directory.Exists(folder)) continue;
            foreach (var p in Mo2Instance.PluginFiles(folder))
                if (plugins.TryAdd(p, mod))
                {
                    if (!modPlugins.TryGetValue(mod, out var l)) modPlugins[mod] = l = [];
                    l.Add(p);
                }
        }
        // masters -> the mods whose plugins need them
        var needs = new Dictionary<string, HashSet<string>>(StringComparer.OrdinalIgnoreCase);            // master plugin -> mods that need it
        foreach (var (mod, list) in modPlugins)
            foreach (var p in list)
                foreach (var master in PluginMasters.Read(Path.Combine(inst.ModsDir, mod, p)))
                {
                    if (!needs.TryGetValue(master, out var set)) needs[master] = set = new(StringComparer.OrdinalIgnoreCase);
                    set.Add(mod);
                }

        var byName = skseMods.Where(m => m.Enabled).ToDictionary(m => m.Name, StringComparer.OrdinalIgnoreCase);
        var plan = new BisectPlan();
        var pinned = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        foreach (var m in byName.Values)
            if (keep(m)) { pinned.Add(m.Name); plan.AlwaysOnWhy[m.Name] = "chosen as always on"; }

        // A group of SKSE mods that are tied together; its dependents are the other mods that need its plugins.
        var group = new Dictionary<string, int>(StringComparer.OrdinalIgnoreCase);
        var members = new Dictionary<int, HashSet<string>>();
        var deps = new Dictionary<int, HashSet<string>>();
        int next = 0;
        foreach (var m in byName.Values.Where(m => !pinned.Contains(m.Name)))
        {
            group[m.Name] = next;
            members[next] = new(StringComparer.OrdinalIgnoreCase) { m.Name };
            deps[next] = new(StringComparer.OrdinalIgnoreCase);
            next++;
        }

        // Two mods with a DLL of the same name: whichever wins in MO2 is the one that loads, so they are switched together.
        foreach (var shadow in byName.Values.Where(m => m.ShadowedBy.Count > 0 && group.ContainsKey(m.Name)))
            foreach (var winnerName in shadow.ShadowedBy.Values.Distinct(StringComparer.OrdinalIgnoreCase))
            {
                if (!group.TryGetValue(winnerName, out var gw)) continue;
                var gs = group[shadow.Name];
                if (gw == gs) continue;
                foreach (var m in members[gs]) { members[gw].Add(m); group[m] = gw; }
                members.Remove(gs);
                deps.Remove(gs);
            }

        IEnumerable<string> Dependents(string mod) =>
            modPlugins.TryGetValue(mod, out var ps)
                ? ps.SelectMany(p => needs.TryGetValue(p, out var s) ? s : []).Where(x => !x.Equals(mod, StringComparison.OrdinalIgnoreCase)).Distinct(StringComparer.OrdinalIgnoreCase)
                : [];

        bool changed = true;
        while (changed)
        {
            changed = false;
            foreach (var g in members.Keys.ToList())
            {
                if (!members.TryGetValue(g, out var mem)) continue;
                var queue = new Queue<string>(mem.Concat(deps[g]));
                var seen = new HashSet<string>(queue, StringComparer.OrdinalIgnoreCase);
                while (queue.Count > 0)
                {
                    var cur = queue.Dequeue();
                    foreach (var x in Dependents(cur))
                    {
                        if (seen.Contains(x)) continue;
                        if (pinned.Contains(x))
                        {
                            // An always-on mod needs this one: it cannot go off.
                            foreach (var m in mem) { pinned.Add(m); plan.AlwaysOnWhy[m] = $"needed by {x} (always on)"; }
                            members.Remove(g);
                            deps.Remove(g);
                            foreach (var m in mem) group.Remove(m);
                            changed = true;
                            goto nextGroup;
                        }
                        if (group.TryGetValue(x, out var other) && other != g)
                        {
                            // Another SKSE mod depends on this one: they are switched together.
                            foreach (var m in members[other]) { mem.Add(m); group[m] = g; }
                            foreach (var d in deps[other]) deps[g].Add(d);
                            members.Remove(other);
                            deps.Remove(other);
                            changed = true;
                            goto nextGroup;
                        }
                        seen.Add(x);
                        queue.Enqueue(x);
                        if (!group.ContainsKey(x)) { if (deps[g].Add(x)) changed = true; }
                    }
                }
            nextGroup:;
            }
        }

        // A patch that needs the plugins of many different SKSE mods (a Synthesis or PGPatcher output, a merged patch) cannot be switched off for one of them,
        // and switching it off for all would change the test far more than the one mod. Those mods stay on, and the plan says why.
        var shared = deps.Values.SelectMany(d => d).GroupBy(d => d, StringComparer.OrdinalIgnoreCase).Where(g => g.Count() >= maxSharedDependents).Select(g => g.Key).ToHashSet(StringComparer.OrdinalIgnoreCase);
        foreach (var g in members.Keys.ToList())
        {
            var hit = deps[g].FirstOrDefault(shared.Contains);
            if (hit is null) continue;
            foreach (var m in members[g]) { pinned.Add(m); plan.AlwaysOnWhy[m] = $"the patch \"{hit}\" needs its plugin and is shared with many mods"; }
            members.Remove(g);
            deps.Remove(g);
        }

        int id = 0;
        var units = new List<BisectUnit>();
        foreach (var (g, mem) in members)
        {
            var u = new BisectUnit
            {
                Mods = mem.OrderBy(x => x, StringComparer.OrdinalIgnoreCase).ToList(),
                Dependents = deps[g].Where(d => !mem.Contains(d)).OrderBy(x => x, StringComparer.OrdinalIgnoreCase).ToList(),
            };
            u.Suspicion = u.Mods.Max(m => suspicion is not null && suspicion.TryGetValue(m, out var s) ? s : 0);
            u.Name = u.Mods.Count == 1 ? u.Mods[0] : $"{u.Mods[0]} (+{u.Mods.Count - 1} tied)";
            units.Add(u);
        }
        foreach (var u in units.OrderByDescending(u => u.Suspicion).ThenBy(u => u.Name, StringComparer.OrdinalIgnoreCase)) { u.Id = id++; plan.Units.Add(u); }
        plan.AlwaysOn = pinned.OrderBy(x => x, StringComparer.OrdinalIgnoreCase).ToList();
        return plan;
    }
}
