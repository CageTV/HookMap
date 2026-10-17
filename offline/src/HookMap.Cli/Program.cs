using HookMap.Core.Bisect;
using HookMap.Core.Crash;
using HookMap.Core.Mo2;
using HookMap.Core.Reports;

// Command line front end for the same code the app uses: handy for checking a result without opening the window.
const string Usage = """
    HookMap (offline side)
      HookMap mods   <MO2 folder> [--profile NAME]           SKSE mods of a profile and what their DLLs say
      HookMap report <report.json|folder>... [--crash LOG]   who patches what, and where two DLLs patch the same function
      HookMap crash  <crash.log> [--report <json|folder>]    DLLs on the call stack (with a report: functions patched twice)
      HookMap plan   <MO2 folder> [--profile NAME] [--crash LOG --report R]   the bisect units, most suspicious first
    """;

if (args.Length == 0) { Console.WriteLine(Usage); return 1; }
string Opt(string name) => Array.IndexOf(args, name) is var i and >= 0 && i + 1 < args.Length ? args[i + 1] : "";
IEnumerable<string> Positional() => args.Skip(1).TakeWhile(a => !a.StartsWith("--"));

IEnumerable<string> ReportFiles(IEnumerable<string> paths)
{
    foreach (var p in paths)
    {
        if (Directory.Exists(p))
            foreach (var f in Directory.GetFiles(p, "HookMap_*_latest.json")) yield return f;
        else yield return p;
    }
}

HookAnalysis? Analysis(IEnumerable<string> paths)
{
    var reports = new List<HookReport>();
    foreach (var f in ReportFiles(paths)) { try { reports.Add(HookReport.Load(f)); } catch (Exception e) { Console.WriteLine($"  skipped {f}: {e.Message}"); } }
    return reports.Count == 0 ? null : HookAnalysis.Build(reports);
}

switch (args[0])
{
    case "mods":
        {
            var inst = new Mo2Instance(Positional().First());
            var profile = Opt("--profile") is { Length: > 0 } p ? p : inst.SelectedProfile ?? inst.ProfileNames().First();
            var mods = inst.FindSkseMods(profile);
            Console.WriteLine($"{mods.Count} mods with SKSE DLLs in profile \"{profile}\" ({mods.Count(m => m.Enabled)} enabled)\n");
            foreach (var m in mods)
                foreach (var d in m.Dlls)
                    Console.WriteLine($"{(m.Enabled ? "on " : "off")}  {d.FileName,-44} {d.PluginName ?? "-",-34} {d.Author ?? "-",-20} v{d.PluginVersion,-9} {(d.UsesAddressLibrary ? "AddrLib" : d.VersionIndependent ? "any-ver" : "fixed")}  [{m.Name}]");
            foreach (var (where, d) in inst.FindLooseDlls()) Console.WriteLine($"     {d.FileName,-44} {d.PluginName ?? "-",-34} ({where})");
            return 0;
        }
    case "report":
        {
            var a = Analysis(Positional());
            if (a is null) { Console.WriteLine("no reports found"); return 1; }
            Console.WriteLine($"{a.Reports.Count} snapshot(s), game {a.ExeVersion}, {a.Hooks.Count} patches, {a.Overlaps.Count} functions patched by more than one source\n");
            foreach (var r in a.Reports) Console.WriteLine($"  {r.Reason,-8} {r.Time}  {(r.DiskUsed ? "disk compare" : "pattern scan")}  {r.Hooks.Count} patches  {r.Seconds:F2}s  {r.DiskNote}");
            Console.WriteLine("\nPatches per module:");
            foreach (var m in a.Modules.Where(m => m.Hooks > 0))
                Console.WriteLine($"  {m.Module,-40} {m.Hooks,4}  shared {m.OverlapGroups,3}  late {m.LateHooks,3}  {string.Join(',', m.Kinds.Select(k => k.Key + "=" + k.Value))}");
            Console.WriteLine("\nFunctions patched by more than one module:");
            foreach (var o in a.Overlaps)
                Console.WriteLine($"  [{o.Severity}] {o.Title}  (+{o.FuncRva:X}, {o.FuncSize} bytes)  <- {string.Join(", ", o.Owners)}");
            if (Opt("--crash") is { Length: > 0 } cl) PrintCrash(a.Correlate(CrashLog.Load(cl)));
            return 0;
        }
    case "crash":
        {
            var log = CrashLog.Load(Positional().First());
            Console.WriteLine($"{log.Time}  {log.GameVersion}\n{log.Exception} at {log.ExceptionAt}  (thread: {log.ThreadRole}, up {log.Uptime})\n");
            var a = Opt("--report") is { Length: > 0 } rp ? Analysis([rp]) : null;
            if (a is not null) PrintCrash(a.Correlate(log));
            else foreach (var (m, first, pr, sc) in log.DllsOnStack()) Console.WriteLine($"  {m,-36} {pr} probable, {sc} scan  first: frame {first.Index}");
            return 0;
        }
    case "plan":
        {
            var inst = new Mo2Instance(Positional().First());
            var profile = Opt("--profile") is { Length: > 0 } p ? p : inst.SelectedProfile ?? inst.ProfileNames().First();
            var mods = inst.FindSkseMods(profile);
            var susp = new Dictionary<string, double>(StringComparer.OrdinalIgnoreCase);
            if (Opt("--crash") is { Length: > 0 } cl && Opt("--report") is { Length: > 0 } rp && Analysis([rp]) is { } an)
            {
                var corr = an.Correlate(CrashLog.Load(cl));
                foreach (var m in mods) susp[m.Name] = m.Dlls.Sum(d => corr.Suspicion.GetValueOrDefault(d.FileName));
            }
            var plan = BisectPlan.Build(inst, profile, mods, m => DefaultKeep.Matches(m), susp);
            Console.WriteLine($"{plan.Units.Count} units can be switched, {plan.AlwaysOn.Count} SKSE mods stay on\n");
            foreach (var u in plan.Units) Console.WriteLine($"{u.Id,3}  {u.Suspicion,6:F1}  {u.Name}{(u.Dependents.Count > 0 ? "   + " + string.Join(", ", u.Dependents) : "")}");
            Console.WriteLine("\nAlways on:");
            foreach (var m in plan.AlwaysOn) Console.WriteLine($"     {m}   ({plan.AlwaysOnWhy.GetValueOrDefault(m)})");
            return 0;
        }
    default:
        Console.WriteLine(Usage);
        return 1;
}

static void PrintCrash(HookAnalysis.CrashCorrelation c)
{
    foreach (var n in c.Notes) Console.WriteLine("  " + n);
    Console.WriteLine("\nSuspicion:");
    foreach (var (dll, score) in c.Suspicion.OrderByDescending(k => k.Value).Take(15)) Console.WriteLine($"  {score,5:F0}  {dll}");
}
