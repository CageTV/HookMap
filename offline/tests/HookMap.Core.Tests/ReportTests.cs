using HookMap.Core.Crash;
using HookMap.Core.Pe;
using HookMap.Core.Reports;

namespace HookMap.Core.Tests;

public class ReportTests
{
    private static string Json(params string[] hooks) => $$"""
        {"tool":"HookMap","version":"t","reason":"menu","time":"2026-10-18 10:00:00","exePath":"x","exeVersion":"1.6.1170.0","exeBase":"7FF7520A0000","exeSize":100,
         "diskUsed":true,"diskNote":"","diffBytes":10,"unresolvedCandidates":0,"vtables":1,"namedFunctions":1,"seconds":0.5,
         "modules":[{"name":"A.dll","path":"p","base":"1","size":1,"system":false,"exe":false,"skse":true,"plugin":"A","author":"x","pluginVersion":1,"hooks":1},
                    {"name":"B.dll","path":"p","base":"2","size":1,"system":false,"exe":false,"skse":true,"plugin":"B","author":"y","pluginVersion":1,"hooks":1}],
         "hooks":[{{string.Join(",", hooks)}}],"overlaps":[]}
        """;

    private static string Hook(int id, string site, string owner, string group = "F:14F2700", string kind = "call", string func = "14F2700") =>
        $$"""{"id":{{id}},"kind":"{{kind}}","site":"{{site}}","funcKnown":true,"func":"{{func}}","funcSize":256,"names":["BSBatchRenderer::vfunc[3]"],"group":"{{group}}","target":"1","owner":"{{owner}}","ownerOffset":"10","how":"stub","hops":1,"bytes":"E8","original":"","note":""}""";

    [Fact]
    public void Two_dlls_patching_one_function_are_an_overlap_and_one_dll_twice_is_not()
    {
        var two = HookAnalysis.Build([HookReport.Parse(Json(Hook(0, "14F2710", "A.dll"), Hook(1, "14F2720", "B.dll")))]);
        var o = Assert.Single(two.Overlaps);
        Assert.Equal("two-modules", o.Severity);
        Assert.Equal(["A.dll", "B.dll"], o.Owners);
        Assert.Equal(1, two.Modules.Single(m => m.Module == "A.dll").OverlapGroups);
        Assert.Contains("B.dll", two.Modules.Single(m => m.Module == "A.dll").Partners);

        var one = HookAnalysis.Build([HookReport.Parse(Json(Hook(0, "14F2710", "A.dll"), Hook(1, "14F2720", "A.dll")))]);
        Assert.Empty(one.Overlaps);
    }

    [Fact]
    public void An_unfollowed_patch_next_to_a_known_one_is_only_possible()
    {
        var a = HookAnalysis.Build([HookReport.Parse(Json(Hook(0, "14F2710", "A.dll"), Hook(1, "14F2720", "?", kind: "inline")))]);
        Assert.Equal("possible", Assert.Single(a.Overlaps).Severity);
    }

    [Fact]
    public void A_later_snapshot_adds_late_hooks_and_does_not_repeat_old_ones()
    {
        var menu = HookReport.Parse(Json(Hook(0, "14F2710", "A.dll")));
        var game = HookReport.Parse(Json(Hook(0, "14F2710", "A.dll"), Hook(1, "14F2720", "B.dll")).Replace("\"menu\"", "\"ingame\"").Replace("10:00:00", "10:05:00"));
        var a = HookAnalysis.Build([game, menu]);
        Assert.Equal(2, a.Hooks.Count);
        Assert.False(a.Hooks.Single(h => h.Hook.Owner == "A.dll").Late);
        Assert.True(a.Hooks.Single(h => h.Hook.Owner == "B.dll").Late);
        Assert.Equal(["menu", "ingame"], a.Hooks.Single(h => h.Hook.Owner == "A.dll").SeenIn);
    }

    private const string Crash = """
        CRASH TIME: 2026-10-17 14:23:58
        Skyrim SSE v1.6.1170
        CrashLoggerSSE v1-24-0-0 Jun 28 2026 00:14:22

        Unhandled exception "EXCEPTION_ACCESS_VIOLATION" at 0x7FF753592744 SkyrimSE.exe+14F2744	mov rax, [r14+0x48] |  BSBatchRenderer::sub_SE100843_AE107633_14F2744)
        PROCESS INFO:
        	Process Uptime: 00:03:12 (192013ms)

        THREAD CONTEXT (HEURISTIC):
        	Likely Role: Rendering

        CALL STACK ([P]robable / [S]tack scan):
        	[ 0][P] 0x7FF753592744                SkyrimSE.exe+14F2744	mov rax, [r14+0x48] |  BSBatchRenderer::sub_SE100843_AE107633_14F2744 -> 107633+0x54	mov rax, [r14+0x48]
        	[ 5][P] 0x7FFF04EC99EE        CommunityShaders.dll+04C99EE	mov ecx, 0xFE0 |  D:\a\Skylighting.cpp:653 static void Skylighting::thunk(void)
        	[ 9][P] 0x7FFF21EA7831                cetweaks.dll+0007831	mov byte ptr [0x1], 0x00
        	[18][P] 0x7FFFA2D5DDA7                KERNEL32.DLL+002DDA7
        	[30][S] 0x7FFEB6762C93   gameoverlayrenderer64.dll+00B2C93

        MODULES:
        	SkyrimSE.exe                                     0x7FF7520A0000
        	cetweaks.dll                                     0x7FFF21EA0000

        SKSE PLUGINS:
        	cetweaks.dll v1.2
        """;

    [Fact]
    public void A_crash_log_is_read()
    {
        var log = CrashLog.Parse(Crash.Split('\n').Select(l => l.TrimEnd('\r')).ToArray());
        Assert.Equal("EXCEPTION_ACCESS_VIOLATION", log.Exception);
        Assert.Equal("SkyrimSE.exe+14F2744", log.ExceptionAt);
        Assert.Equal("Rendering", log.ThreadRole);
        Assert.Equal(5, log.Frames.Count);
        Assert.Equal(0x14F2744, log.Frames[0].Offset);
        Assert.Contains("BSBatchRenderer", log.Frames[0].Symbol);
        var dlls = log.DllsOnStack().Select(d => d.Module).ToList();
        Assert.Equal(["CommunityShaders.dll", "cetweaks.dll"], dlls);   // system DLLs are left out
        Assert.Equal(0x7FFF21EA0000UL, log.Modules["cetweaks.dll"]);
    }

    [Fact]
    public void A_crash_frame_inside_a_function_patched_by_two_dlls_raises_both()
    {
        var log = CrashLog.Parse(Crash.Split('\n').Select(l => l.TrimEnd('\r')).ToArray());
        var a = HookAnalysis.Build([HookReport.Parse(Json(Hook(0, "14F2710", "A.dll"), Hook(1, "14F2720", "B.dll")))]);
        var c = a.Correlate(log);
        var hit = Assert.Single(c.Hits);
        Assert.NotNull(hit.Overlap);
        Assert.True(c.Suspicion["A.dll"] >= 10 && c.Suspicion["B.dll"] >= 10);
        Assert.True(c.Suspicion["CommunityShaders.dll"] > 0);
        Assert.False(c.Suspicion.ContainsKey("KERNEL32.DLL"));
    }
}

public class SkseDllInfoTests
{
    private static string? Find(params string[] relative)
    {
        for (var d = new DirectoryInfo(AppContext.BaseDirectory); d is not null; d = d.Parent)
            if (File.Exists(Path.Combine(d.FullName, "VERSION")) && Directory.Exists(Path.Combine(d.FullName, "plugin")))
            {
                var p = Path.Combine([d.FullName, .. relative]);
                return File.Exists(p) ? p : null;
            }
        return null;
    }

    [Fact]
    public void The_plugin_built_by_this_repo_describes_itself()
    {
        var path = Find("plugin", "build", "Release", "HookMap.dll");
        if (path is null) return;   // built by build.ps1; nothing to check on a fresh checkout
        var info = SkseDllInfo.Read(path);
        Assert.True(info.IsSkseDll && info.HasVersionBlock);
        Assert.Equal("HookMap", info.PluginName);
        Assert.Equal("CageTV", info.Author);
        Assert.True(info.HasLoad && info.HasQuery);
        Assert.True(info.VersionIndependent);
        Assert.False(info.UsesAddressLibrary);
    }

    [Fact]
    public void A_file_that_is_no_dll_still_gets_a_row()
    {
        var f = Path.GetTempFileName();
        try
        {
            File.WriteAllBytes(f, [1, 2, 3]);
            var info = SkseDllInfo.Read(f);
            Assert.False(info.IsSkseDll);
            Assert.Equal(Path.GetFileName(f), info.FileName);
        }
        finally { File.Delete(f); }
    }

    [Fact]
    public void Versions_unpack_the_way_skse_packs_them()
    {
        Assert.Equal("1.6.1170", SkseDllInfo.Unpack((1u << 24) | (6u << 16) | (1170u << 4)));
    }
}
