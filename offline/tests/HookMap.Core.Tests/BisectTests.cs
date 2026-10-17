using System.Text;
using HookMap.Core.Bisect;
using HookMap.Core.Mo2;

namespace HookMap.Core.Tests;

public class DdminTests
{
    /// <summary>Plays the game: crashes when every one of <paramref name="culprits"/> is switched on.</summary>
    private static (IReadOnlyList<int>? result, int tests, string summary) Solve(int units, int[] culprits, Func<int, int>? order = null)
    {
        var universe = Enumerable.Range(0, units).Select(i => order?.Invoke(i) ?? i).ToList();
        var known = new Dictionary<string, TestResult>();
        int tests = 0;
        for (; ; )
        {
            var step = Ddmin.Next(universe, known);
            if (step is Done d) return (d.Culprits, tests, d.Summary);
            var need = (NeedTest)step;
            tests++;
            Assert.DoesNotContain(Ddmin.Key(need.Enabled), known.Keys);   // never asks the same question twice
            known[Ddmin.Key(need.Enabled)] = culprits.All(need.Enabled.Contains) && culprits.Length > 0 ? TestResult.Fail : TestResult.Pass;
            Assert.True(tests < 500, "runaway search");
        }
    }

    [Fact]
    public void One_culprit_among_many_is_found()
    {
        var (r, tests, _) = Solve(100, [37]);
        Assert.Equal([37], r);
        Assert.InRange(tests, 2, 30);
    }

    [Fact]
    public void Two_mods_that_only_crash_together_are_both_found()
    {
        var (r, _, _) = Solve(60, [5, 44]);
        Assert.NotNull(r);
        Assert.Equal([5, 44], r!.OrderBy(x => x).ToArray());
    }

    [Fact]
    public void Three_mods_together_are_found_too()
    {
        var (r, _, _) = Solve(40, [1, 20, 39]);
        Assert.Equal([1, 20, 39], r!.OrderBy(x => x).ToArray());
    }

    [Fact]
    public void No_crash_at_all_ends_at_once()
    {
        var (r, tests, summary) = Solve(10, []);
        Assert.Null(r);
        Assert.Equal(1, tests);
        Assert.Contains("did not crash", summary);
    }

    [Fact]
    public void A_crash_with_every_candidate_off_means_it_is_not_these_mods()
    {
        var universe = Enumerable.Range(0, 8).ToList();
        var known = new Dictionary<string, TestResult>
        {
            [Ddmin.Key(universe)] = TestResult.Fail,
            [Ddmin.Key([])] = TestResult.Fail,
        };
        var done = Assert.IsType<Done>(Ddmin.Next(universe, known));
        Assert.Empty(done.Culprits!);
    }

    [Fact]
    public void Suspects_listed_first_save_runs()
    {
        // The same culprit, once at the front of the list and once at the back: the front is found with fewer game runs.
        var (_, front, _) = Solve(256, [2]);
        var (_, back, _) = Solve(256, [250]);
        Assert.True(front <= back, $"front {front}, back {back}");
    }

    [Fact]
    public void An_unusable_run_counts_as_no_crash_and_the_search_still_finishes()
    {
        var universe = Enumerable.Range(0, 16).ToList();
        var known = new Dictionary<string, TestResult>();
        int n = 0;
        for (; ; )
        {
            var s = Ddmin.Next(universe, known);
            if (s is Done d) { Assert.NotNull(d.Culprits); break; }
            var need = (NeedTest)s;
            // every third answer is "unresolved"
            known[Ddmin.Key(need.Enabled)] = ++n % 3 == 0 ? TestResult.Unresolved : need.Enabled.Contains(7) ? TestResult.Fail : TestResult.Pass;
            Assert.True(n < 200);
        }
    }
}

public class Mo2Tests : IDisposable
{
    private readonly string _root = Path.Combine(Path.GetTempPath(), "hookmap-test-" + Guid.NewGuid().ToString("N"));

    public Mo2Tests() => Directory.CreateDirectory(_root);
    public void Dispose() { try { Directory.Delete(_root, true); } catch (IOException) { } }

    private static byte[] Esp(params string[] masters)
    {
        var data = new List<byte>();
        foreach (var m in masters)
        {
            var name = Encoding.UTF8.GetBytes(m + "\0");
            data.AddRange("MAST"u8.ToArray());
            data.AddRange(BitConverter.GetBytes((ushort)name.Length));
            data.AddRange(name);
            data.AddRange("DATA"u8.ToArray());
            data.AddRange(BitConverter.GetBytes((ushort)8));
            data.AddRange(new byte[8]);
        }
        var file = new List<byte>();
        file.AddRange("TES4"u8.ToArray());
        file.AddRange(BitConverter.GetBytes((uint)data.Count));
        file.AddRange(new byte[16]);
        file.AddRange(data);
        return file.ToArray();
    }

    private void Mod(string name, string[]? dlls = null, Dictionary<string, string[]>? plugins = null)
    {
        var dir = Path.Combine(_root, "mods", name);
        Directory.CreateDirectory(dir);
        foreach (var d in dlls ?? [])
        {
            Directory.CreateDirectory(Path.Combine(dir, "SKSE", "Plugins"));
            File.WriteAllBytes(Path.Combine(dir, "SKSE", "Plugins", d), [1, 2, 3]);
        }
        foreach (var (p, masters) in plugins ?? []) File.WriteAllBytes(Path.Combine(dir, p), Esp(masters));
    }

    private Mo2Instance Instance(params string[] modlistTopFirst)
    {
        File.WriteAllText(Path.Combine(_root, "ModOrganizer.ini"), "[General]\r\nselected_profile=@ByteArray(p)\r\n");
        var prof = Path.Combine(_root, "profiles", "p");
        Directory.CreateDirectory(prof);
        File.WriteAllText(Path.Combine(prof, "modlist.txt"), "# This file was automatically generated by Mod Organizer.\r\n" + string.Join("\r\n", modlistTopFirst) + "\r\n");
        File.WriteAllText(Path.Combine(prof, "plugins.txt"), "*A.esp\r\n");
        Directory.CreateDirectory(Path.Combine(prof, "saves"));
        File.WriteAllText(Path.Combine(prof, "saves", "Save1.ess"), "x");
        return new Mo2Instance(_root);
    }

    [Fact]
    public void Masters_are_read_from_the_plugin_header()
    {
        Assert.Equal(["Skyrim.esm", "My Mod.esp"], PluginMasters.Parse(Esp("Skyrim.esm", "My Mod.esp")[24..]));
    }

    [Fact]
    public void Modlist_and_ini_are_read()
    {
        var inst = Instance("+One", "-Two", "-Sep_separator", "*Unmanaged");
        Assert.Equal("p", inst.SelectedProfile);
        var l = Mo2Instance.ReadModList(Path.Combine(inst.ProfilesDir, "p"));
        Assert.Equal(4, l.Count);
        Assert.True(l[0].Enabled);
        Assert.False(l[1].Enabled);
        Assert.True(l[2].IsSeparator);
        Assert.False(l[3].IsManaged);
    }

    [Fact]
    public void A_patch_that_needs_a_candidates_plugin_goes_off_with_it()
    {
        Mod("Fix", ["Fix.dll"], new() { ["Fix.esp"] = ["Skyrim.esm"] });
        Mod("FixPatch", plugins: new() { ["FixPatch.esp"] = ["Skyrim.esm", "Fix.esp"] });
        Mod("Other", ["Other.dll"]);
        var inst = Instance("+FixPatch", "+Other", "+Fix");
        var mods = inst.FindSkseMods("p");
        var plan = BisectPlan.Build(inst, "p", mods, _ => false);
        var fix = plan.Units.Single(u => u.Mods.Contains("Fix"));
        Assert.Equal(["FixPatch"], fix.Dependents);
        // With Fix off and Other on, the patch has to go too; with both on nothing is disabled.
        Assert.Equal(["Fix", "FixPatch"], plan.DisabledFor([plan.Units.Single(u => u.Mods.Contains("Other")).Id]).OrderBy(x => x).ToArray());
        Assert.Empty(plan.DisabledFor(plan.Units.Select(u => u.Id)));
    }

    [Fact]
    public void Two_candidates_tied_by_a_master_are_one_unit()
    {
        Mod("Base", ["Base.dll"], new() { ["Base.esp"] = [] });
        Mod("Addon", ["Addon.dll"], new() { ["Addon.esp"] = ["Base.esp"] });
        var inst = Instance("+Addon", "+Base");
        var plan = BisectPlan.Build(inst, "p", inst.FindSkseMods("p"), _ => false);
        Assert.Single(plan.Units);
        Assert.Equal(["Addon", "Base"], plan.Units[0].Mods);
    }

    [Fact]
    public void A_mod_an_always_on_mod_needs_cannot_be_switched()
    {
        Mod("Lib", ["Lib.dll"], new() { ["Lib.esp"] = [] });
        Mod("Framework", ["Crash.dll"], new() { ["Framework.esp"] = ["Lib.esp"] });
        var inst = Instance("+Framework", "+Lib");
        var plan = BisectPlan.Build(inst, "p", inst.FindSkseMods("p"), m => m.Name == "Framework");
        Assert.Empty(plan.Units);
        Assert.Contains("Lib", plan.AlwaysOn);
        Assert.Contains("needed by Framework", plan.AlwaysOnWhy["Lib"]);
    }

    [Fact]
    public void A_patch_shared_by_many_mods_pins_them()
    {
        var masters = Enumerable.Range(1, 4).Select(i => $"M{i}.esp").Prepend("Skyrim.esm").ToArray();
        for (int i = 1; i <= 4; i++) Mod($"M{i}", [$"M{i}.dll"], new() { [$"M{i}.esp"] = [] });
        Mod("BigPatch", plugins: new() { ["Big.esp"] = masters });
        var inst = Instance(new[] { "+BigPatch" }.Concat(Enumerable.Range(1, 4).Select(i => $"+M{i}")).ToArray());
        var plan = BisectPlan.Build(inst, "p", inst.FindSkseMods("p"), _ => false);
        Assert.Empty(plan.Units);
        Assert.Equal(4, plan.AlwaysOn.Count);
    }

    [Fact]
    public void Mods_with_a_dll_of_the_same_name_are_switched_together()
    {
        Mod("Winner", ["Same.dll"]);
        Mod("Loser", ["Same.dll"]);
        Mod("Alone", ["Alone.dll"]);
        var inst = Instance("+Winner", "+Alone", "+Loser");
        var mods = inst.FindSkseMods("p");
        Assert.Equal("Winner", mods.Single(m => m.Name == "Loser").ShadowedBy["Same.dll"]);
        var plan = BisectPlan.Build(inst, "p", mods, _ => false);
        Assert.Equal(2, plan.Units.Count);
        Assert.Contains(plan.Units, u => u.Mods.SequenceEqual(["Loser", "Winner"]));
    }

    [Fact]
    public void The_test_profile_is_a_copy_with_the_off_mods_disabled_and_the_source_is_untouched()
    {
        Mod("A", ["A.dll"]);
        Mod("B", ["B.dll"]);
        var inst = Instance("+A", "+B", "-C");
        var plan = BisectPlan.Build(inst, "p", inst.FindSkseMods("p"), _ => false);
        var session = new BisectSession { InstanceRoot = _root, SourceProfile = "p", Plan = plan };
        var before = File.ReadAllText(Path.Combine(inst.ProfilesDir, "p", "modlist.txt"));
        var a = plan.Units.Single(u => u.Mods.Contains("A"));
        var res = session.WriteTestProfile(inst, [a.Id]);
        var text = File.ReadAllText(Path.Combine(res.ProfileFolder, "modlist.txt"));
        Assert.Contains("+A\r\n", text);
        Assert.Contains("-B\r\n", text);
        Assert.Contains("-C\r\n", text);
        Assert.StartsWith("# This file was automatically generated", text);
        Assert.Equal(before, File.ReadAllText(Path.Combine(inst.ProfilesDir, "p", "modlist.txt")));
        Assert.True(File.Exists(Path.Combine(res.ProfileFolder, "plugins.txt")));
        Assert.True(File.Exists(Path.Combine(res.ProfileFolder, "saves", "Save1.ess")));
        // A second write refreshes it; a profile that HookMap did not make is never overwritten.
        session.WriteTestProfile(inst, plan.Units.Select(u => u.Id));
        Assert.Contains("+B\r\n", File.ReadAllText(Path.Combine(res.ProfileFolder, "modlist.txt")));
        var foreign = Path.Combine(inst.ProfilesDir, "Mine");
        Directory.CreateDirectory(foreign);
        File.WriteAllText(Path.Combine(foreign, "modlist.txt"), "+X\r\n");
        session.TestProfile = "Mine";
        Assert.Throws<InvalidOperationException>(() => session.WriteTestProfile(inst, []));
        Assert.Equal("+X\r\n", File.ReadAllText(Path.Combine(foreign, "modlist.txt")));
    }

    [Fact]
    public void A_session_survives_saving_and_loading_and_continues_where_it_stopped()
    {
        Mod("A", ["A.dll"]);
        Mod("B", ["B.dll"]);
        Mod("C", ["C.dll"]);
        var inst = Instance("+A", "+B", "+C");
        var s = new BisectSession { Name = "t", InstanceRoot = _root, SourceProfile = "p", Plan = BisectPlan.Build(inst, "p", inst.FindSkseMods("p"), _ => false) };
        var first = Assert.IsType<NeedTest>(s.Next());
        s.Record(first.Enabled, TestResult.Fail);
        var file = Path.Combine(_root, "session.json");
        s.Save(file);
        var loaded = BisectSession.Load(file);
        Assert.Single(loaded.History);
        var second = Assert.IsType<NeedTest>(loaded.Next());
        Assert.NotEqual(Ddmin.Key(first.Enabled), Ddmin.Key(second.Enabled));
        Assert.True(loaded.UndoLast());
        Assert.Equal(Ddmin.Key(first.Enabled), Ddmin.Key(((NeedTest)loaded.Next()).Enabled));
    }
}
