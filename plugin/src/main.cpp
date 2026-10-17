// HookMap: writes a report of every patch other SKSE plugins made to the game's code and pointers.
#ifndef NOMINMAX
#define NOMINMAX
#endif
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>

#include <atomic>
#include <chrono>
#include <cstdio>
#include <filesystem>
#include <fstream>
#include <string>
#include <thread>

#include "scanner.h"
#include "skse_min.h"

#ifndef HOOKMAP_VERSION
#define HOOKMAP_VERSION "0.0.0"
#endif
#ifndef HOOKMAP_VERSION_PACKED
#define HOOKMAP_VERSION_PACKED 0
#endif

namespace
{
    namespace fs = std::filesystem;

    std::atomic<bool> g_scanning{ false };
    std::atomic<bool> g_loadedSnapshotDone{ false };
    fs::path g_dir;   // <plugin folder>\HookMap

    fs::path PluginDir()
    {
        HMODULE self = nullptr;
        GetModuleHandleExW(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS | GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT, (LPCWSTR)&PluginDir, &self);
        wchar_t p[MAX_PATH * 2] = {};
        GetModuleFileNameW(self, p, MAX_PATH * 2);
        return fs::path(p).parent_path() / L"HookMap";
    }

    void Log(const std::string& line)
    {
        std::error_code ec;
        fs::create_directories(g_dir, ec);
        std::ofstream f(g_dir / L"HookMap.log", std::ios::app);
        SYSTEMTIME t;
        GetLocalTime(&t);
        char ts[32];
        snprintf(ts, sizeof ts, "%02u:%02u:%02u ", t.wHour, t.wMinute, t.wSecond);
        f << ts << line << "\n";
    }

    void RunScan(const std::string& reason)
    {
        bool expected = false;
        if (!g_scanning.compare_exchange_strong(expected, true)) return;
        std::thread([reason] {
            try
            {
                hookmap::ScanOptions opt;
                opt.version = HOOKMAP_VERSION;
                auto rep = hookmap::Scan(reason, opt);
                std::error_code ec;
                fs::create_directories(g_dir, ec);
                SYSTEMTIME t;
                GetLocalTime(&t);
                char stamp[40];
                snprintf(stamp, sizeof stamp, "%04u%02u%02u_%02u%02u%02u", t.wYear, t.wMonth, t.wDay, t.wHour, t.wMinute, t.wSecond);
                auto json = hookmap::ToJson(rep);
                fs::path file = g_dir / (std::string("HookMap_") + reason + "_" + stamp + ".json");
                { std::ofstream f(file, std::ios::binary); f << json; }
                { std::ofstream f(g_dir / (std::string("HookMap_") + reason + "_latest.json"), std::ios::binary); f << json; }
                Log("snapshot '" + reason + "': " + std::to_string(rep.hooks.size()) + " patches, " + std::to_string(rep.overlaps.size()) + " functions patched by more than one DLL, "
                    + (rep.diskUsed ? std::string("compared with the file on disk") : "pattern scan (" + rep.diskNote + ")") + ", " + std::to_string((int)(rep.seconds * 1000)) + " ms -> " + file.string());
            }
            catch (const std::exception& e) { Log(std::string("snapshot failed: ") + e.what()); }
            catch (...) { Log("snapshot failed"); }
            g_scanning = false;
        }).detach();
    }

    void OnMessage(skse::Message* m)
    {
        if (!m) return;
        switch (m->type)
        {
        case skse::kMessage_DataLoaded: RunScan("menu"); break;   // every plugin has installed its hooks by the main menu
        case skse::kMessage_PostLoadGame:
            if (!g_loadedSnapshotDone.exchange(true)) RunScan("ingame");   // the first save that is loaded: catches hooks installed late
            break;
        default: break;
        }
    }

    // Dropping HookMap\snapshot_now.txt next to the reports takes one more snapshot, e.g. right before a crash you can reproduce.
    void WatchForRequests()
    {
        std::thread([] {
            for (;;)
            {
                Sleep(2000);
                std::error_code ec;
                auto req = g_dir / L"snapshot_now.txt";
                if (fs::exists(req, ec)) { fs::remove(req, ec); RunScan("manual"); }
            }
        }).detach();
    }
}

namespace
{
    // Built at compile time so the description is in the file itself: HookMap's own offline side (and any tool that reads the DLL) can read it without running it.
    constexpr skse::PluginVersionData MakeVersion()
    {
        skse::PluginVersionData d{};
        d.dataVersion = 1;
        d.pluginVersion = HOOKMAP_VERSION_PACKED;
        const char name[] = "HookMap";
        const char author[] = "CageTV";
        for (size_t i = 0; i < sizeof name; ++i) d.name[i] = name[i];
        for (size_t i = 0; i < sizeof author; ++i) d.author[i] = author[i];
        d.versionIndependenceEx = 1 << 0;   // uses no game structures
        d.versionIndependence = 1 << 1;     // finds nothing by address: works on every runtime
        d.seVersionRequired = 0;
        return d;
    }
}

extern "C" __declspec(dllexport) constinit skse::PluginVersionData SKSEPlugin_Version = MakeVersion();

extern "C" __declspec(dllexport) bool SKSEPlugin_Query(const skse::Interface*, skse::PluginInfo* info)
{
    info->infoVersion = 1;
    info->name = "HookMap";
    info->version = HOOKMAP_VERSION_PACKED;
    return true;
}

extern "C" __declspec(dllexport) bool SKSEPlugin_Load(const skse::Interface* skse)
{
    g_dir = PluginDir();
    Log(std::string("HookMap ") + HOOKMAP_VERSION + " loaded");
    auto* msg = static_cast<skse::MessagingInterface*>(skse->QueryInterface(skse::kInterface_Messaging));
    if (!msg || !msg->RegisterListener(skse->GetPluginHandle(), "SKSE", OnMessage))
    {
        Log("could not register for SKSE messages; the manual request file still works");
    }
    WatchForRequests();
    return true;
}

BOOL APIENTRY DllMain(HMODULE, DWORD, LPVOID) { return TRUE; }
