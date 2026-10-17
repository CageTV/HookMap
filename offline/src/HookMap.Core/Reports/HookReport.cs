using System.Globalization;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace HookMap.Core.Reports;

/// <summary>One snapshot written by the in-game plugin (HookMap\HookMap_menu_*.json and friends).</summary>
public sealed class HookReport
{
    public string Tool { get; set; } = "";
    public string Version { get; set; } = "";
    public string Reason { get; set; } = "";
    public string Time { get; set; } = "";
    public string ExePath { get; set; } = "";
    public string ExeVersion { get; set; } = "";
    public string ExeBase { get; set; } = "";
    public long ExeSize { get; set; }
    public bool DiskUsed { get; set; }
    public string DiskNote { get; set; } = "";
    public long DiffBytes { get; set; }
    public int UnresolvedCandidates { get; set; }
    public int Vtables { get; set; }
    public int NamedFunctions { get; set; }
    public double Seconds { get; set; }
    public List<ReportModule> Modules { get; set; } = [];
    public List<ReportHook> Hooks { get; set; } = [];
    public List<ReportOverlap> Overlaps { get; set; } = [];

    [JsonIgnore] public string SourceFile { get; set; } = "";

    private static readonly JsonSerializerOptions Options = new() { PropertyNameCaseInsensitive = true, NumberHandling = JsonNumberHandling.AllowReadingFromString };

    public static HookReport Load(string path)
    {
        var r = JsonSerializer.Deserialize<HookReport>(File.ReadAllText(path), Options) ?? throw new InvalidDataException("empty report");
        if (!r.Tool.Equals("HookMap", StringComparison.Ordinal)) throw new InvalidDataException("not a HookMap report");
        r.SourceFile = path;
        return r;
    }

    public static HookReport Parse(string json) =>
        JsonSerializer.Deserialize<HookReport>(json, Options) ?? throw new InvalidDataException("empty report");
}

public sealed class ReportModule
{
    public string Name { get; set; } = "";
    public string Path { get; set; } = "";
    public string Base { get; set; } = "";
    public long Size { get; set; }
    public bool System { get; set; }
    public bool Exe { get; set; }
    public bool Skse { get; set; }
    public string Plugin { get; set; } = "";
    public string Author { get; set; } = "";
    public long PluginVersion { get; set; }
    public int Hooks { get; set; }
}

public sealed class ReportHook
{
    public int Id { get; set; }
    public string Kind { get; set; } = "";
    public string Site { get; set; } = "";
    public bool FuncKnown { get; set; }
    public string Func { get; set; } = "";
    public long FuncSize { get; set; }
    public List<string> Names { get; set; } = [];
    public string Group { get; set; } = "";
    public string Target { get; set; } = "";
    public string Owner { get; set; } = "";
    public string OwnerOffset { get; set; } = "";
    public string How { get; set; } = "";
    public int Hops { get; set; }
    public string Bytes { get; set; } = "";
    public string Original { get; set; } = "";
    public string Note { get; set; } = "";

    public long SiteRva => Hex(Site);
    public long FuncRva => Hex(Func);
    public bool OwnerKnown => Owner != "?" && Owner.Length > 0;

    public static long Hex(string s) => long.TryParse(s, NumberStyles.HexNumber, CultureInfo.InvariantCulture, out var v) ? v : 0;
    public override string ToString() => $"{Kind} @{Site} -> {Owner}";
}

public sealed class ReportOverlap
{
    public string Group { get; set; } = "";
    public string Func { get; set; } = "";
    public List<string> Names { get; set; } = [];
    public List<string> Owners { get; set; } = [];
    public string Severity { get; set; } = "";
    public List<int> Hooks { get; set; } = [];
}
