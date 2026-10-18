using System.Collections.ObjectModel;
using System.ComponentModel;
using System.Diagnostics;
using System.IO;
using System.Runtime.CompilerServices;
using System.Text;
using System.Text.Json;
using System.Windows;
using System.Windows.Controls;
using HookMap.Core.Bisect;
using HookMap.Core.Crash;
using HookMap.Core.Mo2;
using HookMap.Core.Reports;
using Microsoft.Win32;

namespace HookMap.App;

public sealed class ModRow(SkseMod mod, HookMap.Core.Pe.SkseDllInfo dll, Dictionary<string, bool> keep) : INotifyPropertyChanged
{
    public string Mod => mod.Name;
    public string Dll => dll.FileName;
    public string Plugin => dll.PluginName ?? (dll.IsSkseDll ? "(no version data)" : "(not an SKSE DLL)");
    public string Author => dll.Author ?? "";
    public string Version => dll.PluginVersion;
    public string Runtime => !dll.HasVersionBlock ? "old style" : dll.UsesAddressLibrary ? "Addr. Lib." : dll.VersionIndependent ? "any" : "fixed";
    public string State => !mod.Enabled ? "mod disabled" : mod.ShadowedBy.TryGetValue(dll.FileName, out var w) ? $"hidden by {w}" : "loads";
    public int Hooks { get; set; }
    public int Shared { get; set; }
    public double Suspicion { get; set; }
    public bool Keep
    {
        get => keep.GetValueOrDefault(mod.Name);
        set { keep[mod.Name] = value; PropertyChanged?.Invoke(this, new(nameof(Keep))); }
    }
    public event PropertyChangedEventHandler? PropertyChanged;
}

public sealed record ModuleRow(string Module, int Hooks, int OverlapGroups, int LateHooks, string KindText);

public sealed class OverlapRow(OverlapGroup g)
{
    public OverlapGroup Group => g;
    public string Severity => g.Severity switch { "two-modules" => "2+ DLLs", "taken-over" => "taken over", _ => "possible" };
    public string Title => g.Title;
    public string OwnersText => string.Join(", ", g.Owners);
}

public sealed class AppSettings
{
    public string InstanceRoot { get; set; } = @"E:\Tabula Rasa";
    public string Profile { get; set; } = "";
    public Dictionary<string, bool> Keep { get; set; } = [];

    private static string FilePath => Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "HookMap", "settings.json");
    public static AppSettings Load()
    {
        try { return JsonSerializer.Deserialize<AppSettings>(File.ReadAllText(FilePath)) ?? new(); } catch { return new(); }
    }
    public void Save()
    {
        try { Directory.CreateDirectory(Path.GetDirectoryName(FilePath)!); File.WriteAllText(FilePath, JsonSerializer.Serialize(this, new JsonSerializerOptions { WriteIndented = true })); } catch { }
    }
}

public partial class MainWindow : Window
{
    private readonly AppSettings _settings = AppSettings.Load();
    private Mo2Instance? _inst;
    private List<SkseMod> _mods = [];
    private readonly ObservableCollection<ModRow> _rows = [];
    private HookAnalysis? _analysis;
    private HookAnalysis.CrashCorrelation? _corr;
    private BisectSession? _session;
    private NextStep? _step;
    private bool _loadingCrash;

    public MainWindow()
    {
        InitializeComponent();
        ModsGrid.ItemsSource = _rows;
        InstanceBox.Text = _settings.InstanceRoot;
        Loaded += (_, _) =>
        {
            TryOpenInstance(false);
            RefreshSessions();
            RefreshCrashList();
        };
        Closing += (_, _) => { _settings.InstanceRoot = InstanceBox.Text; _settings.Profile = ProfileBox.Text; _settings.Save(); };
    }

    private void Status(string text) => StatusText.Text = text;

    // ------------------------------------------------------------------ instance and mods

    private void BrowseInstance_Click(object s, RoutedEventArgs e)
    {
        var d = new OpenFolderDialog { Title = "Pick the Mod Organizer 2 folder (the one with ModOrganizer.ini)" };
        if (d.ShowDialog() == true) { InstanceBox.Text = d.FolderName; TryOpenInstance(true); }
    }

    private bool TryOpenInstance(bool announce)
    {
        var root = InstanceBox.Text.Trim();
        if (!Mo2Instance.LooksLikeInstance(root)) { if (announce) Status("There is no ModOrganizer.ini in that folder."); return false; }
        _inst = new Mo2Instance(root);
        var names = _inst.ProfileNames().ToList();
        ProfileBox.ItemsSource = names;
        ProfileBox.SelectedItem = names.FirstOrDefault(n => n.Equals(_settings.Profile, StringComparison.OrdinalIgnoreCase)) ?? names.FirstOrDefault(n => n.Equals(_inst.SelectedProfile, StringComparison.OrdinalIgnoreCase)) ?? names.FirstOrDefault();
        Status($"{names.Count} profiles in {root}");
        return true;
    }

    private async void Scan_Click(object s, RoutedEventArgs e) => await ReadModsAsync();

    private async Task<bool> ReadModsAsync()
    {
        if (!TryOpenInstance(true) || _inst is null || ProfileBox.SelectedItem is not string profile) return false;
        ScanButton.IsEnabled = false;
        Status("Reading the SKSE mods...");
        try
        {
            var inst = _inst;
            var (mods, loose) = await Task.Run(() => (inst.FindSkseMods(profile), inst.FindLooseDlls()));
            _mods = mods;
            foreach (var m in mods)
                if (!_settings.Keep.ContainsKey(m.Name)) _settings.Keep[m.Name] = DefaultKeep.Matches(m);
            RebuildRows();
            int dlls = mods.Where(m => m.Enabled).Sum(m => m.Dlls.Count);
            ModsInfo.Text = $"{mods.Count} mods carry SKSE DLLs in \"{profile}\" ({mods.Count(m => m.Enabled)} enabled, {dlls} DLLs). "
                            + $"{loose.Count} more DLLs sit outside MO2's mod list ({string.Join(", ", loose.GroupBy(l => l.Where).Select(g => $"{g.Count()} in {g.Key}"))}). "
                            + "Tick \"Always on\" for the mods a bisect must never switch off.";
            Status($"Read {mods.Count} SKSE mods.");
            _settings.InstanceRoot = InstanceBox.Text; _settings.Profile = profile; _settings.Save();
            if (_analysis is null) LoadReports(false);
            return true;
        }
        catch (Exception ex) { Status("Could not read the mods: " + ex.Message); return false; }
        finally { ScanButton.IsEnabled = true; }
    }

    private void RebuildRows()
    {
        _rows.Clear();
        var perModule = _analysis?.Modules.ToDictionary(m => m.Module, StringComparer.OrdinalIgnoreCase);
        foreach (var m in _mods)
            foreach (var d in m.Dlls)
            {
                var row = new ModRow(m, d, _settings.Keep);
                if (perModule is not null && perModule.TryGetValue(d.FileName, out var ms)) { row.Hooks = ms.Hooks; row.Shared = ms.OverlapGroups; }
                if (_corr is not null) row.Suspicion = _corr.Suspicion.GetValueOrDefault(d.FileName);
                _rows.Add(row);
            }
        var sorted = _rows.OrderByDescending(r => r.Suspicion).ThenByDescending(r => r.Shared).ThenBy(r => r.Mod, StringComparer.OrdinalIgnoreCase).ToList();
        if (_corr is not null || _analysis is not null) { _rows.Clear(); foreach (var r in sorted) _rows.Add(r); }
    }

    private void ResetKeep_Click(object s, RoutedEventArgs e)
    {
        foreach (var m in _mods) _settings.Keep[m.Name] = DefaultKeep.Matches(m);
        RebuildRows();
        InstallInfo.Text = $"{_mods.Count(DefaultKeep.Matches)} mods are always on now (the defaults).";
    }

    private void InstallPlugin_Click(object s, RoutedEventArgs e)
    {
        if (!TryOpenInstance(true) || _inst is null) return;
        var src = FindPluginDll();
        if (src is null) { InstallInfo.Text = "HookMap.dll was not found next to the program."; return; }
        var dst = Path.Combine(_inst.ModsDir, "HookMap", "SKSE", "Plugins");
        Directory.CreateDirectory(dst);
        File.Copy(src, Path.Combine(dst, "HookMap.dll"), true);
        InstallInfo.Text = "Done. In MO2 press F5, tick the mod \"HookMap\", start the game, load a save, then come back and press \"Load reports from MO2\".";
    }

    private static string? FindPluginDll()
    {
        var p = Path.Combine(AppContext.BaseDirectory, "Plugin", "SKSE", "Plugins", "HookMap.dll");
        if (File.Exists(p)) return p;
        for (var d = new DirectoryInfo(AppContext.BaseDirectory); d is not null; d = d.Parent)   // running from the build folder
        {
            var q = Path.Combine(d.FullName, "plugin", "build", "Release", "HookMap.dll");
            if (File.Exists(q)) return q;
        }
        return null;
    }

    // ------------------------------------------------------------------ hook reports

    private void LoadReports_Click(object s, RoutedEventArgs e) => LoadReports(true);

    private void LoadReports(bool announce)
    {
        if (_inst is null) { if (announce) Status("Open the MO2 folder first."); return; }
        var files = _inst.ReportFolders(_mods).SelectMany(f => Directory.GetFiles(f, "HookMap_*_latest.json")).ToList();
        if (files.Count == 0) { if (announce) ReportInfo.Text = "No HookMap_*_latest.json found in the HookMap mod folder or in overwrite. Start the game with the plugin on first."; return; }
        ShowReports(files);
    }

    private void OpenReports_Click(object s, RoutedEventArgs e)
    {
        var d = new OpenFileDialog { Title = "HookMap reports", Filter = "HookMap reports (*.json)|*.json", Multiselect = true };
        if (d.ShowDialog() == true) ShowReports(d.FileNames);
    }

    private void ShowReports(IEnumerable<string> files)
    {
        var reports = new List<HookReport>();
        var skipped = new List<string>();
        foreach (var f in files)
        {
            try { reports.Add(HookReport.Load(f)); }
            catch (Exception ex) { skipped.Add($"{Path.GetFileName(f)}: {ex.Message}"); }
        }
        if (reports.Count == 0) { ReportInfo.Text = "None of the files is a HookMap report. " + string.Join("; ", skipped); return; }
        _analysis = HookAnalysis.Build(reports);
        ModuleGrid.ItemsSource = _analysis.Modules.Where(m => m.Hooks > 0).Select(m => new ModuleRow(m.Module, m.Hooks, m.OverlapGroups, m.LateHooks, string.Join(", ", m.Kinds.Select(k => $"{k.Key} {k.Value}")))).ToList();
        OverlapGrid.ItemsSource = _analysis.Overlaps.Select(o => new OverlapRow(o)).ToList();
        OverlapDetail.Text = "";
        var first = reports.OrderBy(r => r.Time).First();
        ReportInfo.Text = $"{reports.Count} snapshot(s) ({string.Join(", ", reports.OrderBy(r => r.Time).Select(r => r.Reason))}), game {first.ExeVersion}: {_analysis.Hooks.Count} patches, {_analysis.Overlaps.Count} functions patched by more than one source. "
                          + (first.DiskUsed ? "Compared with the exe file." : "Pattern scan (the exe on disk is copy-protected).")
                          + (skipped.Count > 0 ? " Skipped: " + string.Join("; ", skipped) : "");
        Status("Reports loaded.");
        if (_corr is not null || CrashBox.SelectedItem is not null) AnalyzeSelectedCrash();
        RebuildRows();
    }

    private void OverlapGrid_SelectionChanged(object s, SelectionChangedEventArgs e)
    {
        if (OverlapGrid.SelectedItem is not OverlapRow row) { OverlapDetail.Text = ""; return; }
        var g = row.Group;
        var sb = new StringBuilder();
        sb.AppendLine($"{g.Title}   (+{g.FuncRva:X}, {g.FuncSize} bytes)");
        sb.AppendLine($"Patched by {g.Owners.Count} module(s): {string.Join(", ", g.Owners)}");
        foreach (var n in g.Names.Skip(1)) sb.AppendLine("also known as " + n);
        sb.AppendLine();
        foreach (var h in g.Hooks)
        {
            var x = h.Hook;
            sb.AppendLine($"  {x.Owner,-34} {x.Kind,-9} +{x.Site,-9} {Spaced(x.Bytes),-40} {(x.OwnerKnown ? $"-> {x.Owner}+0x{x.OwnerOffset} ({x.How}, {x.Hops} hop)" : "(could not be followed)")}{(h.Late ? "  [installed late]" : "")}");
            if (x.Original.Length > 0) sb.AppendLine($"  {"",-34} was       {Spaced(x.Original)}");
        }
        sb.AppendLine();
        sb.AppendLine("Two patches in one function are not a fault by themselves: they work when both plugins call on to the original code.");
        sb.AppendLine("It matters when the crash is in or just below this function, or when one patch replaced the other's.");
        OverlapDetail.Text = sb.ToString();
    }

    private static string Spaced(string hex) => string.Join(' ', Enumerable.Range(0, hex.Length / 2).Select(i => hex.Substring(i * 2, 2)));

    // ------------------------------------------------------------------ crash logs

    private static IEnumerable<string> CrashFolders()
    {
        var docs = Environment.GetFolderPath(Environment.SpecialFolder.MyDocuments);
        var games = Path.Combine(docs, "My Games");
        if (!Directory.Exists(games)) yield break;
        foreach (var g in Directory.GetDirectories(games, "Skyrim*"))
        {
            var skse = Path.Combine(g, "SKSE");
            if (Directory.Exists(skse)) yield return skse;
        }
    }

    private void RefreshCrash_Click(object s, RoutedEventArgs e) => RefreshCrashList();

    private void RefreshCrashList()
    {
        var files = CrashFolders().SelectMany(f => Directory.GetFiles(f, "crash-*.log")).Select(f => new FileInfo(f)).OrderByDescending(f => f.LastWriteTime).Take(40).ToList();
        _loadingCrash = true;
        CrashBox.ItemsSource = files.Select(f => new CrashItem(f.FullName, $"{f.LastWriteTime:yyyy-MM-dd HH:mm:ss}   {f.Directory?.Parent?.Name}   {f.Name}")).ToList();
        CrashBox.DisplayMemberPath = nameof(CrashItem.Label);
        _loadingCrash = false;
        if (files.Count > 0) CrashBox.SelectedIndex = 0;
        else CrashText.Text = "No crash-*.log files found under Documents\\My Games\\Skyrim*\\SKSE. Use Browse to open one.";
    }

    private sealed record CrashItem(string Path, string Label);

    private void BrowseCrash_Click(object s, RoutedEventArgs e)
    {
        var d = new OpenFileDialog { Title = "Crash log", Filter = "Crash logs (*.log;*.txt)|*.log;*.txt" };
        if (d.ShowDialog() != true) return;
        var items = (CrashBox.ItemsSource as IEnumerable<CrashItem>)?.ToList() ?? [];
        items.Insert(0, new CrashItem(d.FileName, d.FileName));
        _loadingCrash = true;
        CrashBox.ItemsSource = items;
        CrashBox.DisplayMemberPath = nameof(CrashItem.Label);
        _loadingCrash = false;
        CrashBox.SelectedIndex = 0;
    }

    private void CrashBox_SelectionChanged(object s, SelectionChangedEventArgs e)
    {
        if (!_loadingCrash) AnalyzeSelectedCrash();
    }

    private void AnalyzeSelectedCrash()
    {
        if (CrashBox.SelectedItem is not CrashItem item) return;
        try
        {
            var log = CrashLog.Load(item.Path);
            var (text, corr) = DescribeCrash(log);
            CrashText.Text = text;
            _corr = corr;
            RebuildRows();
        }
        catch (Exception ex) { CrashText.Text = "Could not read the crash log: " + ex.Message; }
    }

    private (string, HookAnalysis.CrashCorrelation) DescribeCrash(CrashLog log)
    {
        var corr = (_analysis ?? HookAnalysis.Build([])).Correlate(log);
        var dllToMod = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        foreach (var m in _mods.Where(m => m.Enabled))
            foreach (var d in m.Dlls) dllToMod.TryAdd(d.FileName, m.Name);

        var sb = new StringBuilder();
        sb.AppendLine($"{log.Time}   {log.GameVersion}");
        sb.AppendLine($"{log.Exception} at {log.ExceptionAt}   thread: {log.ThreadRole}   up {log.Uptime}");
        var top = log.Frames.FirstOrDefault();
        if (top?.Symbol is { } sym) sb.AppendLine($"Crashing function: {sym}");
        if (log.RelevantObjects.Count > 0) { sb.AppendLine(); sb.AppendLine("Objects the crash dump points at:"); foreach (var o in log.RelevantObjects.Take(8)) sb.AppendLine("  " + o); }

        sb.AppendLine();
        sb.AppendLine("Call stack, DLLs only (top = closest to the crash):");
        foreach (var f in log.Frames.Where(f => !f.InExe && !CrashLog.IsSystem(f.Module)))
        {
            var what = f.Tail.Contains('|') ? f.Tail[(f.Tail.IndexOf('|') + 1)..].Trim() : "";
            if (what.Length > 150) what = what[..150] + "...";
            sb.AppendLine($"  [{f.Index,2}]{(f.Probable ? "P" : "S")} {f.Module,-34} +{f.Offset:X}  {what}");
        }

        if (_analysis is null)
        {
            sb.AppendLine();
            sb.AppendLine("No hook report loaded yet. With one, this also lists which game functions on the stack other DLLs have patched.");
        }
        else
        {
            sb.AppendLine();
            foreach (var n in corr.Notes.Where(n => n.StartsWith("Frame"))) sb.AppendLine("- " + n);
            if (corr.Hits.Count == 0) sb.AppendLine("No frame of the call stack lies in a function the report shows as patched.");
        }

        sb.AppendLine();
        sb.AppendLine("Where to look first:");
        foreach (var (dll, score) in corr.Suspicion.Where(k => !CrashLog.IsSystem(k.Key)).OrderByDescending(k => k.Value).Take(15))
            sb.AppendLine($"  {score,4:F0}  {dll,-36} {(dllToMod.TryGetValue(dll, out var mod) ? "[" + mod + "]" : "")}");
        return (sb.ToString(), corr);
    }

    // ------------------------------------------------------------------ bisect

    private void RefreshSessions()
    {
        Directory.CreateDirectory(BisectSession.DefaultFolder);
        SessionsBox.ItemsSource = Directory.GetFiles(BisectSession.DefaultFolder, "*.json").Select(f => new FileInfo(f)).OrderByDescending(f => f.LastWriteTime).Select(f => f.FullName).ToList();
        SessionsBox.DisplayMemberPath = null;
        SessionsBox.ItemTemplate = null;
        if (SessionsBox.Items.Count > 0) SessionsBox.SelectedIndex = 0;
    }

    private async void CreatePlan_Click(object s, RoutedEventArgs e)
    {
        if (_mods.Count == 0)
        {
            PlanInfo.Text = "Reading the SKSE mods of the profile first...";
            if (!await ReadModsAsync()) { PlanInfo.Text = "Could not read the SKSE mods: " + StatusText.Text; return; }
        }
        if (_inst is null || ProfileBox.SelectedItem is not string profile) { PlanInfo.Text = "Pick the MO2 folder and a profile at the top first."; return; }
        var testName = TestProfileBox.Text.Trim();
        if (testName.Length == 0 || testName.Equals(profile, StringComparison.OrdinalIgnoreCase)) { PlanInfo.Text = "Choose a test profile name that is different from your profile."; return; }
        PlanInfo.Text = "Working out which mods depend on which...";
        var susp = new Dictionary<string, double>(StringComparer.OrdinalIgnoreCase);
        if (UseSuspicion.IsChecked == true && _corr is not null)
            foreach (var m in _mods) susp[m.Name] = m.Dlls.Sum(d => _corr.Suspicion.GetValueOrDefault(d.FileName));
        var inst = _inst;
        var mods = _mods;
        var keep = new Dictionary<string, bool>(_settings.Keep, StringComparer.OrdinalIgnoreCase);
        BisectPlan plan;
        try { plan = await Task.Run(() => BisectPlan.Build(inst, profile, mods, m => keep.GetValueOrDefault(m.Name), susp)); }
        catch (Exception ex) { PlanInfo.Text = "Could not build the plan: " + ex.Message; return; }

        _session = new BisectSession
        {
            Name = SafeName(SessionName.Text), InstanceRoot = inst.Root, SourceProfile = profile, TestProfile = testName,
            CopySaves = int.TryParse(SavesBox.Text, out var n) ? Math.Clamp(n, 0, 5) : 1, Plan = plan,
        };
        PlanInfo.Text = $"{plan.Units.Count} switchable units, {plan.AlwaysOn.Count} SKSE mods stay on. "
                        + (susp.Values.Any(v => v > 0) ? $"The most suspicious come first: {string.Join(", ", plan.Units.Take(3).Select(u => u.Name))}." : "");
        _session.Save();
        RefreshSessions();
        Advance();
    }

    private static string SafeName(string s)
    {
        foreach (var c in Path.GetInvalidFileNameChars()) s = s.Replace(c, '_');
        return string.IsNullOrWhiteSpace(s) ? "Bisect" : s.Trim();
    }

    private void ResumeSession_Click(object s, RoutedEventArgs e)
    {
        if (SessionsBox.SelectedItem is not string path) return;
        try
        {
            _session = BisectSession.Load(path);
            if (!_session.InstanceRoot.Equals(InstanceBox.Text.Trim(), StringComparison.OrdinalIgnoreCase)) { InstanceBox.Text = _session.InstanceRoot; TryOpenInstance(true); }
            SessionName.Text = _session.Name;
            TestProfileBox.Text = _session.TestProfile;
            SavesBox.Text = _session.CopySaves.ToString();
            PlanInfo.Text = $"Resumed \"{_session.Name}\": {_session.Plan.Units.Count} units, {_session.History.Count} answers so far.";
            Advance();
        }
        catch (Exception ex) { Status("Could not open the session: " + ex.Message); }
    }

    private void DeleteSession_Click(object s, RoutedEventArgs e)
    {
        if (SessionsBox.SelectedItem is not string path) return;
        try { File.Delete(path); } catch (IOException) { }
        RefreshSessions();
    }

    private void SetButtons(bool prepare, bool answers, bool undo)
    {
        PrepareButton.IsEnabled = prepare;
        OpenMo2Button.IsEnabled = prepare;
        CrashedButton.IsEnabled = OkButton.IsEnabled = SkipButton.IsEnabled = answers;
        UndoButton.IsEnabled = undo;
    }

    private void Advance()
    {
        if (_session is null) return;
        FillHistory();
        _step = _session.Next();
        bool canUndo = _session.History.Count > 0;
        switch (_step)
        {
            case NeedTest need:
                {
                    int total = _session.Plan.Units.Count;
                    StepTitle.Text = $"Test {_session.History.Count + 1}: {need.Enabled.Count} of {total} candidate units on";
                    var on = _session.UnitNames(need.Enabled).ToList();
                    var offIds = _session.Plan.Units.Select(u => u.Id).Except(need.Enabled).ToList();
                    var sb = new StringBuilder();
                    sb.AppendLine(need.Why);
                    sb.AppendLine();
                    sb.AppendLine("How to do this test:");
                    sb.AppendLine("  1. Press \"Prepare the test profile\". HookMap writes the profile \"" + _session.TestProfile + "\" (a copy of \"" + _session.SourceProfile + "\") with the mods below switched off.");
                    sb.AppendLine("  2. In Mod Organizer choose that profile (close and reopen MO2 if it is not in the list yet) and start the game.");
                    sb.AppendLine("  3. Do the same thing every time: the same save, the same walk to the place where it crashes, for about the same time.");
                    sb.AppendLine("  4. Answer \"It crashed\" only for the crash you are chasing. A different crash, or a game that does not start, is \"Unusable\".");
                    if (Process.GetProcessesByName("ModOrganizer").Length > 0)
                        sb.AppendLine("\n  Mod Organizer is running now. Close it before preparing if it has the test profile open, or it may write its own copy back over the changes.");
                    sb.AppendLine();
                    sb.AppendLine($"ON ({on.Count}):  " + Join(on, 40));
                    sb.AppendLine();
                    sb.AppendLine($"OFF ({offIds.Count} units):  " + Join(_session.UnitNames(offIds), 40));
                    if (_session.Plan.AlwaysOn.Count > 0) { sb.AppendLine(); sb.AppendLine($"Always on ({_session.Plan.AlwaysOn.Count}):  " + Join(_session.Plan.AlwaysOn, 40)); }
                    StepText.Text = sb.ToString();
                    SetButtons(true, false, canUndo);
                    break;
                }
            case Done done:
                {
                    StepTitle.Text = done.Culprits is null ? "Finished: it never crashed" : done.Culprits.Count == 0 ? "Finished: not these mods" : $"Finished: {done.Culprits.Count} mod unit(s)";
                    var sb = new StringBuilder();
                    sb.AppendLine(done.Summary);
                    if (done.Culprits is null && _session.History.Any(h => h.Result == TestResult.Unresolved))
                        sb.AppendLine("
An earlier run was answered \"Unusable\", which counts as no crash. If that run did crash, press \"Undo last\" and answer \"It crashed\" instead.");
                    if (done.Culprits is { Count: > 0 })
                    {
                        sb.AppendLine();
                        foreach (var id in done.Culprits)
                        {
                            var u = _session.Plan.Units.First(x => x.Id == id);
                            sb.AppendLine("  " + u.Name);
                            foreach (var m in u.Mods.Skip(u.Mods.Count == 1 ? 1 : 0)) sb.AppendLine("      mod: " + m);
                        }
                        sb.AppendLine();
                        sb.AppendLine("Taken after " + _session.History.Count + " game runs. Check them against the Hook map tab: do they patch the same function?");
                    }
                    StepText.Text = sb.ToString();
                    SetButtons(false, false, canUndo);
                    break;
                }
        }
        _session.Save();
    }

    private static string Join(IEnumerable<string> names, int max)
    {
        var l = names.ToList();
        return l.Count <= max ? string.Join(", ", l) : string.Join(", ", l.Take(max)) + $", ... and {l.Count - max} more";
    }

    private void FillHistory()
    {
        if (_session is null) return;
        HistoryList.ItemsSource = _session.History.Select((h, i) =>
            $"#{i + 1,-3} {(h.Result == TestResult.Fail ? "CRASH " : h.Result == TestResult.Pass ? "ok    " : "skip  ")} {h.Enabled.Count,3} of {_session.Plan.Units.Count} on   {Join(_session.UnitNames(h.Enabled), 4)}").Reverse().ToList();
    }

    private void Prepare_Click(object s, RoutedEventArgs e)
    {
        if (_session is null || _inst is null || _step is not NeedTest need) return;
        try
        {
            var r = _session.WriteTestProfile(_inst, need.Enabled);
            Status($"Profile \"{_session.TestProfile}\" {(r.Created ? "created" : "updated")}: {r.ModsSwitchedOff} mods switched off. " + (r.SavesCopied > 0 ? $"{r.SavesCopied} save(s) copied. " : "") + "Pick it in Mod Organizer.");
            SetButtons(true, true, _session.History.Count > 0);
        }
        catch (Exception ex) { Status("Could not write the test profile: " + ex.Message); }
    }

    private void OpenMo2_Click(object s, RoutedEventArgs e)
    {
        if (_inst is null) return;
        var exe = Path.Combine(_inst.Root, "ModOrganizer.exe");
        if (File.Exists(exe)) Process.Start(new ProcessStartInfo(exe) { WorkingDirectory = _inst.Root, UseShellExecute = true });
    }

    private void Answer(TestResult r)
    {
        if (_session is null || _step is not NeedTest need) return;
        _session.Record(need.Enabled, r);
        Advance();
    }

    private void Crashed_Click(object s, RoutedEventArgs e) => Answer(TestResult.Fail);
    private void NoCrash_Click(object s, RoutedEventArgs e) => Answer(TestResult.Pass);
    private void Skip_Click(object s, RoutedEventArgs e) => Answer(TestResult.Unresolved);

    private void Undo_Click(object s, RoutedEventArgs e)
    {
        if (_session?.UndoLast() == true) Advance();
    }
}
