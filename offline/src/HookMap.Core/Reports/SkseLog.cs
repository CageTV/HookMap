using System.Text.RegularExpressions;

namespace HookMap.Core.Reports;

/// <summary>What skse64.log says about the plugins of the last run: which loaded, which were refused, and how many bytes of branch
/// trampoline each asked for (a rough measure of how many hooks it installs).</summary>
public sealed class SkseLog
{
    public string Path { get; init; } = "";
    public List<string> Loaded { get; } = [];
    public List<string> Problems { get; } = [];
    public Dictionary<string, int> BranchPoolBytes { get; } = new(StringComparer.OrdinalIgnoreCase);
    public Dictionary<string, int> LocalPoolBytes { get; } = new(StringComparer.OrdinalIgnoreCase);
    public string Runtime { get; private set; } = "";

    private static readonly Regex Loading = new(@"^loading plugin ""(.+)""", RegexOptions.Compiled);
    private static readonly Regex Alloc = new(@"^plugin \d+ allocated (\d+) bytes from (branch|local) pool", RegexOptions.Compiled);
    private static readonly Regex Plugin = new(@"^plugin (.+?\.dll) \(", RegexOptions.Compiled | RegexOptions.IgnoreCase);

    public static SkseLog Load(string path) => Parse(File.ReadAllLines(path), path);

    public static SkseLog Parse(IEnumerable<string> lines, string path = "")
    {
        var log = new SkseLog { Path = path };
        string? current = null;
        foreach (var raw in lines)
        {
            var line = raw.Trim();
            if (line.StartsWith("SKSE64 runtime:", StringComparison.Ordinal)) { log.Runtime = line; continue; }
            var m = Loading.Match(line);
            if (m.Success) { current = m.Groups[1].Value; continue; }
            m = Alloc.Match(line);
            if (m.Success && current is not null)
            {
                var target = m.Groups[2].Value == "branch" ? log.BranchPoolBytes : log.LocalPoolBytes;
                target[current] = target.GetValueOrDefault(current) + int.Parse(m.Groups[1].Value);
                continue;
            }
            if (line.Contains("loaded correctly", StringComparison.OrdinalIgnoreCase))
            {
                var p = Plugin.Match(line);
                log.Loaded.Add(p.Success ? System.IO.Path.GetFileName(p.Groups[1].Value) : line);
                continue;
            }
            if (line.StartsWith("plugin ", StringComparison.OrdinalIgnoreCase) &&
                (line.Contains("disabled", StringComparison.OrdinalIgnoreCase) || line.Contains("couldn't", StringComparison.OrdinalIgnoreCase) || line.Contains("incompatible", StringComparison.OrdinalIgnoreCase)
                 || line.Contains("fatal error", StringComparison.OrdinalIgnoreCase) || line.Contains("failed", StringComparison.OrdinalIgnoreCase)))
                log.Problems.Add(line);
        }
        return log;
    }
}
