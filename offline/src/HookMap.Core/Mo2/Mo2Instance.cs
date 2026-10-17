using System.Text;
using HookMap.Core.Pe;

namespace HookMap.Core.Mo2;

/// <summary>One line of a profile's modlist.txt. MO2 writes the highest priority on top: "+" is enabled, "-" disabled, "*" is a game DLC entry.</summary>
public sealed record ModListLine(string Name, bool Enabled, bool IsSeparator, bool IsManaged);

/// <summary>A mod folder that carries SKSE plugin DLLs, with what each DLL says about itself.</summary>
public sealed class SkseMod
{
    public required string Name { get; init; }
    public required string Folder { get; init; }
    public bool Enabled { get; set; }
    public int Priority { get; set; }                       // 0 = highest (top of modlist.txt)
    public List<SkseDllInfo> Dlls { get; } = [];
    public List<string> Plugins { get; } = [];              // esp/esm/esl file names in the mod's root
    /// <summary>DLL file name -> the higher-priority enabled mod that has a DLL with the same name (MO2 shows that one to the game, so this one never loads).</summary>
    public Dictionary<string, string> ShadowedBy { get; } = new(StringComparer.OrdinalIgnoreCase);
    public override string ToString() => Name;
}

/// <summary>A portable or normal MO2 instance folder (the one with ModOrganizer.ini).</summary>
public sealed class Mo2Instance
{
    public string Root { get; }
    public string ModsDir { get; }
    public string ProfilesDir { get; }
    public string OverwriteDir { get; }
    public string? GamePath { get; }
    public string? SelectedProfile { get; }

    public Mo2Instance(string root)
    {
        Root = Path.GetFullPath(root);
        var ini = ReadIni(Path.Combine(Root, "ModOrganizer.ini"));
        string Dir(string key, string fallback)
        {
            if (!ini.TryGetValue(key, out var v) || string.IsNullOrWhiteSpace(v)) return Path.Combine(Root, fallback);
            return Path.GetFullPath(v.Replace("%BASE_DIR%", Root, StringComparison.OrdinalIgnoreCase).Replace('/', '\\'));
        }
        ModsDir = Dir("mod_directory", "mods");
        ProfilesDir = Dir("profiles_directory", "profiles");
        OverwriteDir = Dir("overwrite_directory", "overwrite");
        GamePath = ini.GetValueOrDefault("gamePath");
        SelectedProfile = ini.GetValueOrDefault("selected_profile");
    }

    public static bool LooksLikeInstance(string root) => File.Exists(Path.Combine(root, "ModOrganizer.ini"));

    public IEnumerable<string> ProfileNames() =>
        Directory.Exists(ProfilesDir)
            ? Directory.GetDirectories(ProfilesDir).Where(p => File.Exists(Path.Combine(p, "modlist.txt"))).Select(p => Path.GetFileName(p)!).OrderBy(n => n, StringComparer.OrdinalIgnoreCase)
            : [];

    /// <summary>The [General] keys of ModOrganizer.ini. Qt writes strings as @ByteArray(...) and doubles backslashes.</summary>
    public static Dictionary<string, string> ReadIni(string path)
    {
        var d = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        if (!File.Exists(path)) return d;
        bool general = true;
        foreach (var raw in File.ReadLines(path, Encoding.UTF8))
        {
            var line = raw.Trim();
            if (line.StartsWith('[')) { general = line.Equals("[General]", StringComparison.OrdinalIgnoreCase); continue; }
            if (!general) continue;
            int eq = line.IndexOf('=');
            if (eq <= 0) continue;
            d[line[..eq].Trim()] = Unwrap(line[(eq + 1)..].Trim());
        }
        return d;
    }

    private static string Unwrap(string v)
    {
        if (v.StartsWith("@ByteArray(", StringComparison.Ordinal) && v.EndsWith(')')) v = v[11..^1];
        return v.Replace("\\\\", "\\");
    }

    public static List<ModListLine> ReadModList(string profileDir)
    {
        var list = new List<ModListLine>();
        var file = Path.Combine(profileDir, "modlist.txt");
        if (!File.Exists(file)) return list;
        foreach (var raw in File.ReadLines(file, Encoding.UTF8))
        {
            if (raw.Length < 2 || raw[0] == '#') continue;
            char c = raw[0];
            if (c != '+' && c != '-' && c != '*') continue;
            var name = raw[1..];
            list.Add(new ModListLine(name, c == '+', name.EndsWith("_separator", StringComparison.OrdinalIgnoreCase), c != '*'));
        }
        return list;
    }

    /// <summary>Every mod of the profile that has a top-level DLL in SKSE\Plugins (the only place SKSE looks), plus the plugins in its root.</summary>
    public List<SkseMod> FindSkseMods(string profileName, bool readPlugins = true, IProgress<string>? progress = null)
    {
        var lines = ReadModList(Path.Combine(ProfilesDir, profileName));
        var result = new List<SkseMod>();
        for (int i = 0; i < lines.Count; i++)
        {
            var l = lines[i];
            if (l.IsSeparator || !l.IsManaged) continue;
            var folder = Path.Combine(ModsDir, l.Name);
            var plug = Path.Combine(folder, "SKSE", "Plugins");
            if (!Directory.Exists(plug)) continue;
            string[] dlls;
            try { dlls = Directory.GetFiles(plug, "*.dll"); } catch (IOException) { continue; }
            if (dlls.Length == 0) continue;
            var mod = new SkseMod { Name = l.Name, Folder = folder, Enabled = l.Enabled, Priority = i };
            foreach (var dll in dlls.OrderBy(x => x, StringComparer.OrdinalIgnoreCase)) mod.Dlls.Add(SkseDllInfo.Read(dll));
            if (readPlugins) mod.Plugins.AddRange(PluginFiles(folder));
            progress?.Report(l.Name);
            result.Add(mod);
        }
        var winner = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        foreach (var m in result.Where(m => m.Enabled))
            foreach (var d in m.Dlls)
                if (!winner.TryAdd(d.FileName, m.Name)) m.ShadowedBy[d.FileName] = winner[d.FileName];
        return result;
    }

    public static IEnumerable<string> PluginFiles(string folder)
    {
        try
        {
            return Directory.EnumerateFiles(folder).Select(f => Path.GetFileName(f)!)
                .Where(n => n.EndsWith(".esp", StringComparison.OrdinalIgnoreCase) || n.EndsWith(".esm", StringComparison.OrdinalIgnoreCase) || n.EndsWith(".esl", StringComparison.OrdinalIgnoreCase)).ToList();
        }
        catch (IOException) { return []; }
    }

    /// <summary>SKSE plugin DLLs that are not in a managed mod: the game's own Data folder and MO2's overwrite folder.</summary>
    public List<(string Where, SkseDllInfo Info)> FindLooseDlls()
    {
        var list = new List<(string, SkseDllInfo)>();
        void Add(string label, string folder)
        {
            if (!Directory.Exists(folder)) return;
            foreach (var dll in Directory.GetFiles(folder, "*.dll").OrderBy(x => x, StringComparer.OrdinalIgnoreCase)) list.Add((label, SkseDllInfo.Read(dll)));
        }
        if (GamePath is not null) Add("game Data folder", Path.Combine(GamePath, "Data", "SKSE", "Plugins"));
        Add("overwrite", Path.Combine(OverwriteDir, "SKSE", "Plugins"));
        return list;
    }

    /// <summary>Where reports written by the in-game plugin end up for this instance: the plugin's mod folder, and overwrite when MO2 redirected the writes.</summary>
    public IEnumerable<string> ReportFolders(IEnumerable<SkseMod> mods)
    {
        var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        foreach (var m in mods)
            foreach (var d in m.Dlls)
                if (d.FileName.Equals("HookMap.dll", StringComparison.OrdinalIgnoreCase))
                {
                    var p = Path.Combine(m.Folder, "SKSE", "Plugins", "HookMap");
                    if (Directory.Exists(p) && seen.Add(p)) yield return p;
                }
        var ow = Path.Combine(OverwriteDir, "SKSE", "Plugins", "HookMap");
        if (Directory.Exists(ow) && seen.Add(ow)) yield return ow;
    }
}
