using System.Globalization;
using System.Text.RegularExpressions;

namespace HookMap.Core.Crash;

public sealed record CrashFrame(int Index, bool Probable, ulong Address, string Module, long Offset, string Tail)
{
    public bool InExe => Module.EndsWith(".exe", StringComparison.OrdinalIgnoreCase);
    /// <summary>The Address Library id CrashLogger names after "->", e.g. "107633" in "... -> 107633+0x54".</summary>
    public string? Symbol
    {
        get
        {
            int bar = Tail.IndexOf('|');
            if (bar < 0) return null;
            var s = Tail[(bar + 1)..].Trim();
            int arrow = s.IndexOf(" ->", StringComparison.Ordinal);
            if (arrow >= 0) s = s[..arrow];
            return s.Length > 0 ? s : null;
        }
    }
}

public sealed class CrashLog
{
    public string Path { get; init; } = "";
    public string Time { get; init; } = "";
    public string GameVersion { get; init; } = "";
    public string Exception { get; init; } = "";
    public string ExceptionAt { get; init; } = "";
    public string ThreadRole { get; init; } = "";
    public string Uptime { get; init; } = "";
    public List<CrashFrame> Frames { get; } = [];
    public List<string> RelevantObjects { get; } = [];
    public List<string> SksePlugins { get; } = [];
    public Dictionary<string, ulong> Modules { get; } = new(StringComparer.OrdinalIgnoreCase);

    private static readonly Regex FrameRx = new(@"^\s*\[\s*(\d+)\]\[([PS])\]\s+0x([0-9A-Fa-f]+)\s+(\S+?)\+([0-9A-Fa-f]+)(?:\s+(.*))?$", RegexOptions.Compiled);

    public static CrashLog Load(string path) => Parse(File.ReadAllLines(path), path);

    public static CrashLog Parse(IReadOnlyList<string> lines, string path = "")
    {
        string time = "", game = "", exc = "", at = "", role = "", uptime = "";
        var frames = new List<CrashFrame>();
        var objects = new List<string>();
        var plugins = new List<string>();
        var modules = new Dictionary<string, ulong>(StringComparer.OrdinalIgnoreCase);
        string section = "";
        foreach (var raw in lines)
        {
            if (raw.Length == 0) continue;
            bool indented = raw[0] == '\t' || raw[0] == ' ';
            if (!indented)
            {
                if (raw.StartsWith("CRASH TIME:", StringComparison.Ordinal)) { time = raw[11..].Trim(); continue; }
                if (raw.StartsWith("Skyrim ", StringComparison.Ordinal) && game.Length == 0) { game = raw.Trim(); continue; }
                if (raw.StartsWith("Unhandled exception", StringComparison.Ordinal))
                {
                    exc = raw;
                    var m = Regex.Match(raw, @"""([^""]+)"" at 0x[0-9A-Fa-f]+ (\S+\+[0-9A-Fa-f]+)");
                    if (m.Success) { exc = m.Groups[1].Value; at = m.Groups[2].Value; }
                    continue;
                }
                if (raw.StartsWith("CALL STACK", StringComparison.Ordinal)) { section = "CALL STACK"; continue; }
                if (raw.EndsWith(':')) { section = raw.TrimEnd(':'); continue; }
                section = "";
                continue;
            }
            var line = raw.Trim();
            switch (section)
            {
                case "CALL STACK":
                    var fm = FrameRx.Match(raw);
                    if (fm.Success)
                        frames.Add(new CrashFrame(int.Parse(fm.Groups[1].Value), fm.Groups[2].Value == "P",
                            ulong.Parse(fm.Groups[3].Value, NumberStyles.HexNumber), fm.Groups[4].Value, long.Parse(fm.Groups[5].Value, NumberStyles.HexNumber), fm.Groups[6].Value));
                    break;
                case "POSSIBLE RELEVANT OBJECTS": objects.Add(line); break;
                case "THREAD CONTEXT (HEURISTIC)":
                    if (line.StartsWith("Likely Role:", StringComparison.Ordinal)) role = line[12..].Trim();
                    break;
                case "PROCESS INFO":
                    if (line.StartsWith("Process Uptime:", StringComparison.Ordinal)) uptime = line[15..].Trim();
                    break;
                case "MODULES":
                    {
                        var parts = Regex.Match(line, @"^(.+?)\s+0x([0-9A-Fa-f]+)$");
                        if (parts.Success) modules[parts.Groups[1].Value] = ulong.Parse(parts.Groups[2].Value, NumberStyles.HexNumber);
                        break;
                    }
                case "SKSE PLUGINS": plugins.Add(line); break;
            }
        }
        var log = new CrashLog { Path = path, Time = time, GameVersion = game, Exception = exc, ExceptionAt = at, ThreadRole = role, Uptime = uptime };
        log.Frames.AddRange(frames);
        log.RelevantObjects.AddRange(objects);
        log.SksePlugins.AddRange(plugins);
        foreach (var (k, v) in modules) log.Modules[k] = v;
        return log;
    }

    /// <summary>DLLs on the call stack in order of appearance, with the first frame each one has.</summary>
    public IEnumerable<(string Module, CrashFrame First, int Probable, int Scan)> DllsOnStack() =>
        Frames.Where(f => !f.InExe && !IsSystem(f.Module))
              .GroupBy(f => f.Module, StringComparer.OrdinalIgnoreCase)
              .Select(g => (g.Key, g.First(), g.Count(f => f.Probable), g.Count(f => !f.Probable)));

    public static bool IsSystem(string module)
    {
        var m = module.ToLowerInvariant();
        return m is "kernel32.dll" or "kernelbase.dll" or "ntdll.dll" or "user32.dll" or "ucrtbase.dll" or "msvcp140.dll" or "vcruntime140.dll" or "d3d11.dll" or "dxgi.dll"
            or "gameoverlayrenderer64.dll" or "win32u.dll" or "gdi32.dll" or "combase.dll" or "ole32.dll" or "rpcrt4.dll" or "msvcrt.dll";
    }
}
