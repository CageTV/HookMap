using System.Text;
using System.Text.Json;
using HookMap.Core.Mo2;

namespace HookMap.Core.Bisect;

public sealed class BisectRecord
{
    public List<int> Enabled { get; set; } = [];
    public TestResult Result { get; set; }
    public string Note { get; set; } = "";
    public DateTime When { get; set; } = DateTime.Now;
}

/// <summary>A search for the SKSE mods that crash together: the plan, every answer so far, and the test profile it writes.
/// Saved as JSON so it survives closing the program between game runs.</summary>
public sealed class BisectSession
{
    public string Name { get; set; } = "Bisect";
    public string InstanceRoot { get; set; } = "";
    public string SourceProfile { get; set; } = "";
    public string TestProfile { get; set; } = "HookMap Bisect";
    public int CopySaves { get; set; } = 1;
    public BisectPlan Plan { get; set; } = new();
    public List<BisectRecord> History { get; set; } = [];
    public DateTime Created { get; set; } = DateTime.Now;

    public static string DefaultFolder => Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "HookMap", "sessions");

    private static readonly JsonSerializerOptions Json = new() { WriteIndented = true, Converters = { new System.Text.Json.Serialization.JsonStringEnumConverter() } };

    public void Save(string? path = null)
    {
        path ??= Path.Combine(DefaultFolder, Name + ".json");
        Directory.CreateDirectory(Path.GetDirectoryName(path)!);
        File.WriteAllText(path, JsonSerializer.Serialize(this, Json));
    }

    public static BisectSession Load(string path) => JsonSerializer.Deserialize<BisectSession>(File.ReadAllText(path), Json) ?? throw new InvalidDataException("empty session file");

    public Dictionary<string, TestResult> Known() =>
        History.GroupBy(h => Ddmin.Key(h.Enabled)).ToDictionary(g => g.Key, g => g.Last().Result);

    public NextStep Next() => Ddmin.Next(Plan.Units.Select(u => u.Id).ToList(), Known());

    public void Record(IEnumerable<int> enabled, TestResult result, string note = "") =>
        History.Add(new BisectRecord { Enabled = enabled.OrderBy(x => x).ToList(), Result = result, Note = note });

    public bool UndoLast()
    {
        if (History.Count == 0) return false;
        History.RemoveAt(History.Count - 1);
        return true;
    }

    public IEnumerable<string> UnitNames(IEnumerable<int> ids) => ids.Select(i => Plan.Units.FirstOrDefault(u => u.Id == i)?.Name ?? $"#{i}");

    // ------------------------------------------------------------------ the MO2 test profile

    /// <summary>Makes (or refreshes) the test profile as a copy of the source profile with the mods of the units that are off disabled.
    /// The source profile and every mod folder stay untouched.</summary>
    public ProfileWriteResult WriteTestProfile(Mo2Instance inst, IEnumerable<int> enabledUnits)
    {
        var src = Path.Combine(inst.ProfilesDir, SourceProfile);
        var dst = Path.Combine(inst.ProfilesDir, TestProfile);
        if (SourceProfile.Equals(TestProfile, StringComparison.OrdinalIgnoreCase)) throw new InvalidOperationException("The test profile must not be the profile it copies.");
        if (!Directory.Exists(src)) throw new DirectoryNotFoundException(src);
        bool created = !Directory.Exists(dst);
        // Never overwrite a profile the user made: only a folder this program created (it leaves a marker file) is refreshed.
        var marker = Path.Combine(dst, ".hookmap");
        if (!created && !File.Exists(marker)) throw new InvalidOperationException($"The profile \"{TestProfile}\" already exists and was not made by HookMap. Pick another name for the test profile.");
        Directory.CreateDirectory(dst);
        File.WriteAllText(marker, "Made by HookMap for bisecting SKSE mods. Safe to delete." + Environment.NewLine);

        // Copy the small settings files each time, so the test always starts from the source profile's current state.
        foreach (var f in Directory.GetFiles(src))
        {
            var n = Path.GetFileName(f);
            if (IsBackupName(n) || n.Equals("modlist.txt", StringComparison.OrdinalIgnoreCase)) continue;
            File.Copy(f, Path.Combine(dst, n), true);
        }

        var off = Plan.DisabledFor(enabledUnits);
        var text = File.ReadAllText(Path.Combine(src, "modlist.txt"), Encoding.UTF8);
        var sb = new StringBuilder(text.Length);
        int switched = 0;
        foreach (var raw in SplitKeepEnds(text))
        {
            var line = raw.TrimEnd('\r', '\n');
            if (line.Length > 1 && line[0] == '+' && off.Contains(line[1..]))
            {
                sb.Append('-').Append(raw.AsSpan(1));
                switched++;
            }
            else sb.Append(raw);
        }
        File.WriteAllText(Path.Combine(dst, "modlist.txt"), sb.ToString(), new UTF8Encoding(false));

        int saves = CopyNewestSaves(src, dst, CopySaves);
        return new ProfileWriteResult(dst, created, switched, off.Count, saves);
    }

    private static IEnumerable<string> SplitKeepEnds(string s)
    {
        int start = 0;
        for (int i = 0; i < s.Length; i++)
            if (s[i] == '\n') { yield return s[start..(i + 1)]; start = i + 1; }
        if (start < s.Length) yield return s[start..];
    }

    private static bool IsBackupName(string n) =>
        n.Contains(".bak", StringComparison.OrdinalIgnoreCase) || System.Text.RegularExpressions.Regex.IsMatch(n, @"\.\d{4}_\d{2}_\d{2}_\d{2}_\d{2}_\d{2}$") || n.EndsWith(".html", StringComparison.OrdinalIgnoreCase);

    private static int CopyNewestSaves(string srcProfile, string dstProfile, int count)
    {
        var srcSaves = Path.Combine(srcProfile, "saves");
        if (count <= 0 || !Directory.Exists(srcSaves)) return 0;
        var dstSaves = Path.Combine(dstProfile, "saves");
        Directory.CreateDirectory(dstSaves);
        // Only the newest saves, so the test profile starts from the same place each time; older copies from earlier steps stay.
        int copied = 0;
        foreach (var ess in new DirectoryInfo(srcSaves).GetFiles("*.ess").OrderByDescending(f => f.LastWriteTimeUtc).Take(count))
        {
            var target = Path.Combine(dstSaves, ess.Name);
            if (!File.Exists(target)) { ess.CopyTo(target); copied++; }
            var co = Path.ChangeExtension(ess.FullName, ".skse");
            var coTarget = Path.Combine(dstSaves, Path.GetFileName(co));
            if (File.Exists(co) && !File.Exists(coTarget)) File.Copy(co, coTarget);
        }
        return copied;
    }
}

public sealed record ProfileWriteResult(string ProfileFolder, bool Created, int ModsSwitchedOff, int ModsOff, int SavesCopied);
