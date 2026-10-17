// HookMap scanner: finds code and pointer patches that other DLLs wrote into the game executable.
// Win32 only, no SKSE or CommonLib types, so the same code runs in the plugin and in the self-test.
#pragma once
#include <cstdint>
#include <string>
#include <vector>

namespace hookmap
{
    struct ModuleInfo
    {
        std::string name;        // file name, e.g. "EngineFixes.dll"
        std::string path;        // full path (UTF-8)
        uint64_t base = 0;
        uint64_t size = 0;
        bool system = false;     // lives under the Windows folder
        bool isExe = false;
        bool skse = false;       // exports SKSEPlugin_Version
        std::string plugin;      // name the plugin reports
        std::string author;
        uint32_t pluginVersion = 0;
        uint32_t hooks = 0;      // hooks attributed to this module (filled by the scan)
    };

    struct Hook
    {
        std::string kind;        // call, jmp, call-ind, jmp-ind, jmp-abs, mov-jmp, mov-call, vtable, data, iat, inline
        uint32_t site = 0;       // RVA of the patched bytes (the vtable slot or IAT slot for pointer hooks)
        uint32_t func = 0;       // RVA of the game function that was patched
        uint32_t funcSize = 0;
        bool funcKnown = false;
        std::vector<std::string> names;   // virtual-function names that point at the function (from RTTI), if any
        std::string group;       // key used to find hooks on the same function
        uint64_t target = 0;     // first jump target
        std::string owner;       // module that the jump ends up in; "?" when it could not be followed
        std::string how;         // direct, stub, scan, none
        int hops = 0;
        std::string bytes;       // the patched bytes in memory, hex
        std::string original;    // the bytes the file on disk has there, hex (empty when the disk image is unusable)
        std::string note;        // for IAT hooks the imported function
        uint64_t ownerOffset = 0; // where in the owner module the jump ends
    };

    struct Overlap
    {
        std::string group;
        uint32_t func = 0;
        std::vector<std::string> names;
        std::vector<std::string> owners;
        std::vector<int> hooks;       // indexes into Report::hooks
        std::string severity;         // "two-modules" or "possible"
    };

    struct Report
    {
        std::string tool = "HookMap";
        std::string version;
        std::string reason;
        std::string time;
        std::string exePath;
        std::string exeVersion;
        uint64_t exeBase = 0;
        uint64_t exeSize = 0;
        bool diskUsed = false;
        std::string diskNote;
        uint64_t diffBytes = 0;
        uint32_t unresolvedCandidates = 0;
        double seconds = 0;
        std::vector<ModuleInfo> modules;
        std::vector<Hook> hooks;
        std::vector<Overlap> overlaps;
        uint32_t vtables = 0;
        uint32_t namedFunctions = 0;
    };

    struct ScanOptions
    {
        bool useDisk = true;          // compare the code with the executable file when that file is usable
        std::string version;          // tool version for the report
        void* target = nullptr;       // module to scan instead of the running executable (used by the self-test on big images)
    };

    Report Scan(const std::string& reason, const ScanOptions& opt);
    std::string ToJson(const Report& r);
}
