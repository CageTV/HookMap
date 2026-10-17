using HookMap.Core.Mo2;

namespace HookMap.Core.Bisect;

/// <summary>SKSE mods that a bisect should leave on by default: the crash logger (the test is no use without its log), this tool,
/// and the libraries other plugins and scripts load first. All of it can be changed in the window.</summary>
public static class DefaultKeep
{
    private static readonly string[] DllNames =
    [
        "CrashLogger.dll", "HookMap.dll", "PapyrusUtil.dll", "JContainers64.dll", "po3_PapyrusExtender.dll", "powerofthree's Papyrus Extender.dll", "SKSEMenuFramework.dll",
        "ConsoleUtilSSE.dll", "SkyUI_SE.dll", "MCMHelper.dll", "devbench.dll", "msdia140.dll",
    ];

    public static bool Matches(SkseMod m) =>
        m.Dlls.Any(d => DllNames.Contains(d.FileName, StringComparer.OrdinalIgnoreCase))
        || m.Name.Contains("Crash Logger", StringComparison.OrdinalIgnoreCase) || m.Name.Contains("CrashLogger", StringComparison.OrdinalIgnoreCase)
        || m.Name.StartsWith("Address Library", StringComparison.OrdinalIgnoreCase) || m.Name.Contains("Papyrus Extender", StringComparison.OrdinalIgnoreCase);
}
