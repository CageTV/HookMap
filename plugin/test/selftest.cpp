// Self-test for the scanner. It patches its own code the way SKSE plugins patch the game and checks the scan finds each patch,
// names the DLL it leads to, and groups two patches in one function. Run for both ways of looking (disk comparison and pattern scan).
#ifndef NOMINMAX
#define NOMINMAX
#endif
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>

#include <cstdio>
#include <cstring>
#include <string>

#include "../src/scanner.h"

static volatile int g_sink = 0;

__declspec(noinline) void Sink(int v) { g_sink = g_sink + v; }

// Plenty of room for patches, and a frame so the function has unwind data like a real game function.
__declspec(noinline) void Victim()
{
    volatile int x = 1;
    for (int i = 0; i < 3; ++i) { __nop(); }
    Sink(x);
    __nop(); __nop(); __nop(); __nop(); __nop(); __nop(); __nop(); __nop(); __nop(); __nop(); __nop(); __nop(); __nop(); __nop(); __nop(); __nop();
    __nop(); __nop(); __nop(); __nop(); __nop(); __nop(); __nop(); __nop(); __nop(); __nop(); __nop(); __nop(); __nop(); __nop(); __nop(); __nop();
    __nop(); __nop(); __nop(); __nop(); __nop(); __nop(); __nop(); __nop(); __nop(); __nop(); __nop(); __nop(); __nop(); __nop(); __nop(); __nop();
    Sink(x + 1);
}

struct SelfTestWidget
{
    virtual ~SelfTestWidget() {}
    virtual int First() { return 1; }
    virtual int Second() { return 2; }
    virtual int Third() { return 3; }
};

static uint8_t* AllocNear(void* where, size_t size)
{
    uintptr_t base = (uintptr_t)where & ~(uintptr_t)0xFFFF;
    for (uintptr_t d = 0x100000; d < 0x70000000; d += 0x10000)
    {
        for (int sign = 0; sign < 2; ++sign)
        {
            uintptr_t hint = sign ? base - d : base + d;
            void* p = VirtualAlloc((LPVOID)hint, size, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
            if (p) return (uint8_t*)p;
        }
    }
    return nullptr;
}

static void Write(void* dst, const void* src, size_t n)
{
    DWORD old;
    VirtualProtect(dst, n, PAGE_EXECUTE_READWRITE, &old);
    memcpy(dst, src, n);
    VirtualProtect(dst, n, old, &old);
}

static int g_fail = 0;
static void Check(bool ok, const char* what)
{
    printf("  %s  %s\n", ok ? "ok  " : "FAIL", what);
    if (!ok) ++g_fail;
}

static bool Has(const hookmap::Report& r, const char* kind, const char* owner)
{
    for (auto& h : r.hooks) if (h.kind == kind && h.owner == owner) return true;
    return false;
}

static void Run(const hookmap::Report& r, const char* label, uint32_t victimRva)
{
    printf("[%s] %zu patches, %zu overlaps, disk %s%s%s\n", label, r.hooks.size(), r.overlaps.size(), r.diskUsed ? "used" : "not used",
           r.diskNote.empty() ? "" : " - ", r.diskNote.c_str());
    for (auto& h : r.hooks)
        printf("    %-9s site %X func %X owner %s (%s, %d hop) %s orig=%s\n", h.kind.c_str(), h.site, h.func, h.owner.c_str(), h.how.c_str(), h.hops,
               h.names.empty() ? "" : h.names[0].c_str(), h.original.c_str());

    Check(Has(r, "jmp", "hm_test_a.dll"), "jump patch leads to hm_test_a.dll");
    Check(Has(r, "call", "hm_test_b.dll"), "call patch leads to hm_test_b.dll");
    bool vt = false;
    for (auto& h : r.hooks)
        if (h.kind == "vtable" && h.owner == "hm_test_b.dll")
            for (auto& n : h.names) if (n.find("SelfTestWidget::vfunc[2]") != std::string::npos) vt = true;
    Check(vt, "vtable slot 2 of SelfTestWidget leads to hm_test_b.dll and is named");

    bool overlap = false;
    for (auto& o : r.overlaps)
    {
        bool a = false, b = false;
        for (auto& w : o.owners) { if (w == "hm_test_a.dll") a = true; if (w == "hm_test_b.dll") b = true; }
        if (a && b && o.severity == "two-modules") overlap = true;
    }
    Check(overlap, "both DLLs patching Victim() are reported as an overlap");

    bool inVictim = false;
    for (auto& h : r.hooks) if ((h.kind == "jmp" || h.kind == "call") && h.funcKnown && h.func == victimRva) inVictim = true;
    Check(inVictim, "patches are placed in the right function (unwind table lookup)");

    uint32_t foreign = 0;
    for (auto& h : r.hooks) if (h.owner != "hm_test_a.dll" && h.owner != "hm_test_b.dll") ++foreign;
    printf("  note: %u patches belong to other modules (the CRT, the OS shims)\n", foreign);
}

// hookmap_selftest.exe --scan-module <dll>: scans a big image that nobody patched, to time the scan and count false alarms.
static int ScanModule(const wchar_t* path)
{
    HMODULE m = LoadLibraryExW(path, nullptr, DONT_RESOLVE_DLL_REFERENCES);
    if (!m) { printf("could not map the module\n"); return 2; }
    hookmap::ScanOptions opt;
    opt.version = "selftest";
    opt.target = m;
    for (int pass = 0; pass < 2; ++pass)
    {
        opt.useDisk = pass == 0;
        auto r = hookmap::Scan("scan-module", opt);
        printf("[%s] %.2f s, %zu patches, %u unresolved, %zu vtables, %u named functions, %zu overlaps, diff %llu bytes %s\n", pass == 0 ? "disk" : "pattern", r.seconds, r.hooks.size(), r.unresolvedCandidates, (size_t)r.vtables, r.namedFunctions, r.overlaps.size(), (unsigned long long)r.diffBytes, r.diskNote.c_str());
        int shown = 0;
        for (auto& h : r.hooks) { if (shown++ >= 10) break; printf("    %-9s +%X owner %s  %s\n", h.kind.c_str(), h.site, h.owner.c_str(), h.bytes.c_str()); }
    }
    return 0;
}

int main(int argc, char** argv)
{
    if (argc >= 3 && std::string(argv[1]) == "--scan-module")
    {
        wchar_t w[1024];
        MultiByteToWideChar(CP_UTF8, 0, argv[2], -1, w, 1024);
        return ScanModule(w);
    }
    HMODULE exe = GetModuleHandleW(nullptr);
    wchar_t dir[MAX_PATH];
    GetModuleFileNameW(nullptr, dir, MAX_PATH);
    std::wstring d = dir;
    d.resize(d.find_last_of(L'\\') + 1);
    HMODULE a = LoadLibraryW((d + L"hm_test_a.dll").c_str());
    HMODULE b = LoadLibraryW((d + L"hm_test_b.dll").c_str());
    if (!a || !b) { printf("could not load the test DLLs next to the exe\n"); return 2; }
    auto* hookA = (uint8_t*)GetProcAddress(a, "hm_hook");
    auto* hookB = (uint8_t*)GetProcAddress(b, "hm_hook");

    // Patching: the function address may be an incremental-link thunk; follow a leading E9.
    uint8_t* victim = (uint8_t*)&Victim;
    if (victim[0] == 0xE9) { int32_t rel; memcpy(&rel, victim + 1, 4); victim = victim + 5 + rel; }
    uint8_t* run = nullptr;
    for (int i = 0; i < 400; ++i)
    {
        int n = 0;
        while (n < 40 && victim[i + n] == 0x90) ++n;
        if (n >= 40) { run = victim + i; break; }
    }
    if (!run) { printf("no room found for patches in Victim()\n"); return 2; }

    uint8_t* stubs = AllocNear(victim, 0x1000);
    if (!stubs) { printf("no memory near the executable for trampolines\n"); return 2; }
    // Trampoline entries like CommonLib / SKSE write: jmp [rip+0] ; dq target
    auto makeStub = [&](uint8_t* at, uint8_t* target) {
        uint8_t s[14] = { 0xFF, 0x25, 0, 0, 0, 0 };
        memcpy(s + 6, &target, 8);
        memcpy(at, s, 14);
    };
    makeStub(stubs, hookA);
    makeStub(stubs + 16, hookB);

    // jmp rel32 at run+4 -> stub A (the first byte E9 is not an original byte: it changes 0x90)
    uint8_t p1[5] = { 0xE9 };
    int32_t rel1 = (int32_t)(stubs - (run + 4 + 5));
    memcpy(p1 + 1, &rel1, 4);
    Write(run + 4, p1, 5);
    // call rel32 at run+24 -> stub B
    uint8_t p2[5] = { 0xE8 };
    int32_t rel2 = (int32_t)((stubs + 16) - (run + 24 + 5));
    memcpy(p2 + 1, &rel2, 4);
    Write(run + 24, p2, 5);

    // vtable hook: SelfTestWidget slot 2 -> DLL B
    auto* w = new SelfTestWidget();
    void** vtable = *(void***)w;
    {
        void* nv = hookB;
        Write(&vtable[2], &nv, 8);
    }
    g_sink = w->First();   // keep the class alive; slot 2 is never called

    uint32_t victimRva = (uint32_t)(victim - (uint8_t*)exe);
    // The unwind table starts at the function, not at a thunk, so look the address up the way a scan does.
    printf("Victim at RVA %X, trampolines at %p, A=%p B=%p\n", victimRva, (void*)stubs, (void*)hookA, (void*)hookB);

    hookmap::ScanOptions opt;
    opt.version = "selftest";
    opt.useDisk = true;
    auto r1 = hookmap::Scan("selftest-disk", opt);
    Run(r1, "disk comparison", victimRva);
    opt.useDisk = false;
    auto r2 = hookmap::Scan("selftest-pattern", opt);
    Run(r2, "pattern scan", victimRva);

    printf("%s (%d failed)\n", g_fail ? "SELF-TEST FAILED" : "SELF-TEST PASSED", g_fail);
    return g_fail ? 1 : 0;
}
