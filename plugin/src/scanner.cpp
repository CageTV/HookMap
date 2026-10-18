#include "scanner.h"

#ifndef NOMINMAX
#define NOMINMAX
#endif
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#include <tlhelp32.h>

#include <algorithm>
#include <chrono>
#include <cstdio>
#include <cstring>
#include <map>
#include <set>
#include <unordered_map>

#pragma comment(lib, "version.lib")

namespace hookmap
{
    namespace
    {
        // ---------------------------------------------------------------- small helpers

        std::string Narrow(const std::wstring& w)
        {
            if (w.empty()) return {};
            int n = WideCharToMultiByte(CP_UTF8, 0, w.data(), (int)w.size(), nullptr, 0, nullptr, nullptr);
            std::string s(n, '\0');
            WideCharToMultiByte(CP_UTF8, 0, w.data(), (int)w.size(), s.data(), n, nullptr, nullptr);
            return s;
        }

        std::string Lower(std::string s)
        {
            for (auto& c : s) if (c >= 'A' && c <= 'Z') c = (char)(c + 32);
            return s;
        }

        std::string Hex(uint64_t v)
        {
            char b[24];
            snprintf(b, sizeof b, "%llX", (unsigned long long)v);
            return b;
        }

        std::string HexBytes(const uint8_t* p, size_t n)
        {
            static const char* d = "0123456789ABCDEF";
            std::string s;
            for (size_t i = 0; i < n; ++i) { s += d[p[i] >> 4]; s += d[p[i] & 15]; }
            return s;
        }

        bool SafeRead(uint64_t addr, void* out, size_t n)
        {
            SIZE_T got = 0;
            return ReadProcessMemory(GetCurrentProcess(), (LPCVOID)addr, out, n, &got) && got == n;
        }

        template <class T> bool Rd(uint64_t a, T& v) { return SafeRead(a, &v, sizeof(T)); }

        // A.B@C@@ style RTTI name -> C::B. Anything else is returned as it is.
        std::string Demangle(const std::string& raw)
        {
            if (raw.size() > 4 && raw[0] == '.' && raw[1] == '?' && raw[2] == 'A' && (raw[3] == 'V' || raw[3] == 'U'))
            {
                std::string s = raw.substr(4);
                while (!s.empty() && s.back() == '@') s.pop_back();
                if (s.find('?') != std::string::npos) return s;       // template: keep the decorated form
                std::vector<std::string> parts;
                size_t st = 0;
                for (;;)
                {
                    size_t e = s.find('@', st);
                    parts.push_back(s.substr(st, e == std::string::npos ? std::string::npos : e - st));
                    if (e == std::string::npos) break;
                    st = e + 1;
                }
                std::string r;
                for (size_t i = parts.size(); i-- > 0;) { r += parts[i]; if (i) r += "::"; }
                return r;
            }
            return raw;
        }

        struct Range { uint64_t b, e; };

        // ---------------------------------------------------------------- process picture

        struct Section
        {
            std::string name;
            uint32_t rva = 0, vsize = 0, rawPtr = 0, rawSize = 0, chars = 0;
            std::vector<uint8_t> mem;           // copy of the section as it is in memory now
            bool exec() const { return (chars & IMAGE_SCN_MEM_EXECUTE) != 0; }
        };

        struct VTable { uint64_t start; uint32_t count; uint32_t cls; };
        struct NameEnt { uint32_t rva; uint32_t cls; uint32_t slot; };

        struct Resolved { std::string owner = "?"; std::string how = "none"; int hops = 0; uint64_t finalTarget = 0; uint64_t ownerOffset = 0; };

        struct Ctx
        {
            std::vector<ModuleInfo> mods;       // sorted by base
            int exeIdx = -1;
            std::vector<Range> priv;            // executable private memory (trampolines)
            uint64_t exeBase = 0, exeSize = 0, preferred = 0;
            std::vector<Section> secs;
            std::vector<RUNTIME_FUNCTION> pdata;
            std::vector<VTable> vts;
            std::vector<NameEnt> ents;
            std::vector<std::string> clsNames;
            std::vector<uint8_t> disk;          // the file on disk, when it is usable
            bool diskOk = false;
            std::vector<uint8_t> hdr;

            int ModAt(uint64_t a) const
            {
                size_t lo = 0, hi = mods.size();
                while (lo < hi)
                {
                    size_t mid = (lo + hi) / 2;
                    if (mods[mid].base + mods[mid].size <= a) lo = mid + 1; else hi = mid;
                }
                if (lo < mods.size() && a >= mods[lo].base && a < mods[lo].base + mods[lo].size) return (int)lo;
                return -1;
            }

            bool InPriv(uint64_t a) const
            {
                size_t lo = 0, hi = priv.size();
                while (lo < hi)
                {
                    size_t mid = (lo + hi) / 2;
                    if (priv[mid].e <= a) lo = mid + 1; else hi = mid;
                }
                return lo < priv.size() && a >= priv[lo].b && a < priv[lo].e;
            }

            bool InExe(uint64_t a) const { return a >= exeBase && a < exeBase + exeSize; }

            const Section* SecAt(uint32_t rva) const
            {
                for (auto& s : secs)
                    if (rva >= s.rva && rva < s.rva + std::max<uint32_t>(s.vsize, 1)) return &s;
                return nullptr;
            }

            // A pointer into the memory copy of the image, or null when the range is not inside one section's copy.
            const uint8_t* Img(uint32_t rva, size_t n) const
            {
                auto* s = SecAt(rva);
                if (!s) return nullptr;
                size_t off = rva - s->rva;
                if (off + n > s->mem.size()) return nullptr;
                return s->mem.data() + off;
            }

            bool IsExecRva(uint32_t rva) const { auto* s = SecAt(rva); return s && s->exec(); }
        };

        bool IsCodeTarget(const Ctx& c, uint64_t v)
        {
            if (v < 0x10000) return false;
            if (c.InExe(v)) return c.IsExecRva((uint32_t)(v - c.exeBase));
            return c.ModAt(v) >= 0 || c.InPriv(v);
        }

        // ---------------------------------------------------------------- modules and memory

        void LoadModules(Ctx& c, HMODULE exe)
        {
            wchar_t win[MAX_PATH] = {};
            GetWindowsDirectoryW(win, MAX_PATH);
            std::string winLower = Lower(Narrow(win));

            HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, GetCurrentProcessId());
            if (snap == INVALID_HANDLE_VALUE) return;
            MODULEENTRY32W me{};
            me.dwSize = sizeof me;
            for (BOOL ok = Module32FirstW(snap, &me); ok; ok = Module32NextW(snap, &me))
            {
                ModuleInfo m;
                m.name = Narrow(me.szModule);
                m.path = Narrow(me.szExePath);
                m.base = (uint64_t)(uintptr_t)me.modBaseAddr;
                m.size = me.modBaseSize;
                m.isExe = (HMODULE)me.modBaseAddr == exe;
                std::string pl = Lower(m.path);
                m.system = !winLower.empty() && pl.compare(0, winLower.size(), winLower) == 0;
                if (!m.isExe && !m.system)
                {
                    // SKSE plugins export their description. Layout: dataVersion, pluginVersion, name[256], author[256].
                    auto* ver = (const uint8_t*)GetProcAddress((HMODULE)me.modBaseAddr, "SKSEPlugin_Version");
                    if (ver)
                    {
                        uint8_t buf[8 + 512] = {};
                        if (SafeRead((uint64_t)(uintptr_t)ver, buf, sizeof buf))
                        {
                            m.skse = true;
                            memcpy(&m.pluginVersion, buf + 4, 4);
                            m.plugin.assign((const char*)buf + 8, strnlen((const char*)buf + 8, 255));
                            m.author.assign((const char*)buf + 264, strnlen((const char*)buf + 264, 255));
                        }
                    }
                    else if (GetProcAddress((HMODULE)me.modBaseAddr, "SKSEPlugin_Load"))
                    {
                        m.skse = true;   // an older plugin that only has the query/load pair
                    }
                }
                c.mods.push_back(std::move(m));
            }
            CloseHandle(snap);
            std::sort(c.mods.begin(), c.mods.end(), [](auto& a, auto& b) { return a.base < b.base; });
            for (size_t i = 0; i < c.mods.size(); ++i) if (c.mods[i].isExe) c.exeIdx = (int)i;
        }

        void LoadExecutablePrivate(Ctx& c)
        {
            MEMORY_BASIC_INFORMATION mbi{};
            uint64_t a = 0x10000;
            while (a < 0x7FFFFFFF0000ull && VirtualQuery((LPCVOID)a, &mbi, sizeof mbi))
            {
                uint64_t b = (uint64_t)(uintptr_t)mbi.BaseAddress;
                uint64_t e = b + mbi.RegionSize;
                const DWORD x = PAGE_EXECUTE | PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY;
                if (mbi.State == MEM_COMMIT && mbi.Type == MEM_PRIVATE && (mbi.Protect & x) && !(mbi.Protect & PAGE_GUARD))
                {
                    if (!c.priv.empty() && c.priv.back().e == b) c.priv.back().e = e;
                    else c.priv.push_back({ b, e });
                }
                if (e <= a) break;
                a = e;
            }
        }

        bool LoadExeImage(Ctx& c)
        {
            if (c.exeIdx < 0) return false;
            c.exeBase = c.mods[c.exeIdx].base;
            c.exeSize = c.mods[c.exeIdx].size;
            std::vector<uint8_t> head(0x1000);
            if (!SafeRead(c.exeBase, head.data(), head.size())) return false;
            auto* dos = (const IMAGE_DOS_HEADER*)head.data();
            if (dos->e_magic != IMAGE_DOS_SIGNATURE || dos->e_lfanew > 0xC00) return false;
            auto* nt = (const IMAGE_NT_HEADERS64*)(head.data() + dos->e_lfanew);
            if (nt->Signature != IMAGE_NT_SIGNATURE || nt->OptionalHeader.Magic != IMAGE_NT_OPTIONAL_HDR64_MAGIC) return false;
            c.preferred = nt->OptionalHeader.ImageBase;
            c.hdr = head;
            auto* sec = IMAGE_FIRST_SECTION(nt);
            for (unsigned i = 0; i < nt->FileHeader.NumberOfSections; ++i)
            {
                Section s;
                s.name.assign((const char*)sec[i].Name, strnlen((const char*)sec[i].Name, 8));
                s.rva = sec[i].VirtualAddress;
                s.vsize = sec[i].Misc.VirtualSize;
                s.rawPtr = sec[i].PointerToRawData;
                s.rawSize = sec[i].SizeOfRawData;
                s.chars = sec[i].Characteristics;
                if ((s.chars & IMAGE_SCN_MEM_DISCARDABLE) || !(s.chars & IMAGE_SCN_MEM_READ) || s.vsize == 0) { c.secs.push_back(std::move(s)); continue; }
                s.mem.resize(s.vsize);
                // Read page by page so one unreadable page does not lose the whole section.
                for (uint32_t off = 0; off < s.vsize; off += 0x10000)
                {
                    uint32_t n = std::min<uint32_t>(0x10000, s.vsize - off);
                    if (!SafeRead(c.exeBase + s.rva + off, s.mem.data() + off, n)) memset(s.mem.data() + off, 0, n);
                }
                c.secs.push_back(std::move(s));
            }
            // Exception directory: one entry per function that has unwind data.
            auto& ex = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXCEPTION];
            if (ex.VirtualAddress && ex.Size)
                if (auto* p = c.Img(ex.VirtualAddress, ex.Size))
                {
                    size_t n = ex.Size / sizeof(RUNTIME_FUNCTION);
                    c.pdata.resize(n);
                    memcpy(c.pdata.data(), p, n * sizeof(RUNTIME_FUNCTION));
                }
            return true;
        }

        // The function that holds an RVA, from the exception directory (follows chained unwind entries to the parent).
        bool FuncOf(const Ctx& c, uint32_t rva, uint32_t& begin, uint32_t& size)
        {
            for (int guard = 0; guard < 4; ++guard)
            {
                size_t lo = 0, hi = c.pdata.size();
                while (lo < hi)
                {
                    size_t mid = (lo + hi) / 2;
                    if (c.pdata[mid].EndAddress <= rva) lo = mid + 1; else hi = mid;
                }
                if (lo >= c.pdata.size() || rva < c.pdata[lo].BeginAddress) return false;
                const auto& rf = c.pdata[lo];
                uint32_t unwind = rf.UnwindData & ~1u;
                const uint8_t* u = c.Img(unwind, 4);
                if (u && ((u[0] >> 3) & 4))   // UNW_FLAG_CHAININFO
                {
                    uint32_t codes = u[2];
                    uint32_t off = unwind + 4 + ((codes + 1) & ~1u) * 2;
                    auto* parent = (const RUNTIME_FUNCTION*)c.Img(off, sizeof(RUNTIME_FUNCTION));
                    if (parent) { rva = parent->BeginAddress; continue; }
                }
                begin = rf.BeginAddress;
                size = rf.EndAddress - rf.BeginAddress;
                return true;
            }
            return false;
        }

        // ---------------------------------------------------------------- RTTI: class names for virtual functions

        void BuildVtables(Ctx& c)
        {
            std::vector<std::pair<uint64_t, uint32_t>> cols;   // vtable start -> class index
            std::unordered_map<uint32_t, uint32_t> colToCls;
            for (auto& s : c.secs)
            {
                if (s.exec() || s.mem.empty()) continue;
                uint64_t secBase = c.exeBase + s.rva;
                for (size_t off = 0; off + 16 <= s.mem.size(); off += 8)
                {
                    uint64_t v;
                    memcpy(&v, s.mem.data() + off, 8);
                    if (v < c.exeBase || v >= c.exeBase + c.exeSize || (v & 3)) continue;
                    uint32_t colRva = (uint32_t)(v - c.exeBase);
                    auto* col = c.Img(colRva, 24);
                    if (!col) continue;
                    uint32_t sig, self, tdRva;
                    memcpy(&sig, col, 4);
                    memcpy(&tdRva, col + 12, 4);
                    memcpy(&self, col + 20, 4);
                    if (sig != 1 || self != colRva) continue;
                    uint32_t cls;
                    auto it = colToCls.find(colRva);
                    if (it != colToCls.end()) cls = it->second;
                    else
                    {
                        auto* nm = c.Img(tdRva + 16, 8);
                        std::string raw;
                        if (nm)
                        {
                            auto* sc = c.SecAt(tdRva + 16);
                            size_t o = tdRva + 16 - sc->rva;
                            size_t e = o;
                            while (e < sc->mem.size() && e - o < 200 && sc->mem[e]) ++e;
                            raw.assign((const char*)sc->mem.data() + o, e - o);
                        }
                        cls = (uint32_t)c.clsNames.size();
                        c.clsNames.push_back(Demangle(raw));
                        colToCls[colRva] = cls;
                    }
                    cols.push_back({ secBase + off + 8, cls });
                }
            }
            std::sort(cols.begin(), cols.end());
            for (auto& [start, cls] : cols)
            {
                VTable vt{ start, 0, cls };
                uint32_t slot = 0;
                for (; slot < 4096; ++slot)
                {
                    uint32_t rva = (uint32_t)(start - c.exeBase) + slot * 8;
                    auto* p = c.Img(rva, 8);
                    if (!p) break;
                    uint64_t e;
                    memcpy(&e, p, 8);
                    if (!IsCodeTarget(c, e)) break;
                    if (c.InExe(e)) c.ents.push_back({ (uint32_t)(e - c.exeBase), cls, slot });
                }
                vt.count = slot;
                c.vts.push_back(vt);
            }
            std::sort(c.ents.begin(), c.ents.end(), [](auto& a, auto& b) { return a.rva < b.rva; });
        }

        std::vector<std::string> NamesOf(const Ctx& c, uint32_t funcRva)
        {
            auto lo = std::lower_bound(c.ents.begin(), c.ents.end(), funcRva, [](const NameEnt& a, uint32_t v) { return a.rva < v; });
            std::vector<std::string> v;
            std::set<std::string> seen;
            for (auto it = lo; it != c.ents.end() && it->rva == funcRva; ++it)
            {
                std::string n = c.clsNames[it->cls] + "::vfunc[" + std::to_string(it->slot) + "]";
                if (seen.insert(n).second) v.push_back(n);
            }
            // Derived tables repeat the function of their base, so the shortest class name is the likeliest owner.
            std::sort(v.begin(), v.end(), [](auto& a, auto& b) { return a.size() != b.size() ? a.size() < b.size() : a < b; });
            if (v.size() > 3) v.resize(3);
            return v;
        }

        bool VtableSlot(const Ctx& c, uint64_t slotAddr, uint32_t& cls, uint32_t& slot)
        {
            size_t lo = 0, hi = c.vts.size();
            while (lo < hi)
            {
                size_t mid = (lo + hi) / 2;
                if (c.vts[mid].start + (uint64_t)c.vts[mid].count * 8 <= slotAddr) lo = mid + 1; else hi = mid;
            }
            if (lo >= c.vts.size() || slotAddr < c.vts[lo].start) return false;
            cls = c.vts[lo].cls;
            slot = (uint32_t)((slotAddr - c.vts[lo].start) / 8);
            return true;
        }

        // ---------------------------------------------------------------- following a hook to the DLL that wrote it

        // One step through a stub that starts with a plain jump.
        bool StubNext(uint64_t a, uint64_t& next)
        {
            uint8_t b[16];
            if (!SafeRead(a, b, sizeof b)) return false;
            int32_t rel;
            if (b[0] == 0xFF && b[1] == 0x25)
            {
                memcpy(&rel, b + 2, 4);
                uint64_t v;
                if (!Rd(a + 6 + (int64_t)rel, v)) return false;
                next = v;
                return true;
            }
            if (b[0] == 0xE9) { memcpy(&rel, b + 1, 4); next = a + 5 + (int64_t)rel; return true; }
            if (b[0] == 0x48 && b[1] == 0xB8 && b[10] == 0xFF && b[11] == 0xE0) { memcpy(&next, b + 2, 8); return true; }
            if (b[0] == 0x49 && b[1] == 0xBB && b[10] == 0x41 && b[11] == 0xFF && b[12] == 0xE3) { memcpy(&next, b + 2, 8); return true; }
            if (b[0] == 0x68 && b[5] == 0xC7 && b[6] == 0x44 && b[7] == 0x24 && b[8] == 0x04 && b[13] == 0xC3)
            {
                uint32_t lo, hi;
                memcpy(&lo, b + 1, 4);
                memcpy(&hi, b + 9, 4);
                next = ((uint64_t)hi << 32) | lo;
                return true;
            }
            return false;
        }

        // A stub that saves registers first: look through its first bytes for the branch that leaves for a module.
        bool StubScan(const Ctx& c, uint64_t a, uint64_t& next)
        {
            uint8_t buf[160];
            size_t len = 0;
            for (size_t want : { sizeof buf, (size_t)96, (size_t)48, (size_t)24 })
                if (SafeRead(a, buf, want)) { len = want; break; }
            for (size_t k = 0; k + 14 <= len; ++k)
            {
                uint64_t t = 0;
                int32_t rel;
                if (buf[k] == 0xE8 || buf[k] == 0xE9) { memcpy(&rel, buf + k + 1, 4); t = a + k + 5 + (int64_t)rel; }
                else if (buf[k] == 0xFF && (buf[k + 1] == 0x15 || buf[k + 1] == 0x25)) { memcpy(&rel, buf + k + 2, 4); if (!Rd(a + k + 6 + (int64_t)rel, t)) continue; }
                else if ((buf[k] == 0x48 && buf[k + 1] == 0xB8) || (buf[k] == 0x49 && buf[k + 1] == 0xBB)) memcpy(&t, buf + k + 2, 8);
                else continue;
                int m = c.ModAt(t);
                if (m >= 0 && !c.mods[m].isExe && !c.mods[m].system) { next = t; return true; }
            }
            return false;
        }

        Resolved Resolve(const Ctx& c, uint64_t target)
        {
            Resolved r;
            uint64_t cur = target;
            for (int hop = 0; hop < 6; ++hop)
            {
                int m = c.ModAt(cur);
                if (m >= 0 && !c.mods[m].isExe)
                {
                    r.owner = c.mods[m].name;
                    r.how = hop == 0 ? "direct" : (r.how == "scan" ? "scan" : "stub");
                    r.hops = hop;
                    r.finalTarget = cur;
                    r.ownerOffset = cur - c.mods[m].base;
                    return r;
                }
                if (m >= 0) return r;                       // jumps back into the executable: nothing to attribute
                if (!c.InPriv(cur)) return r;
                uint64_t next = 0;
                if (StubNext(cur, next)) { r.how = "stub"; }
                else if (StubScan(c, cur, next)) { r.how = "scan"; }
                else return r;
                cur = next;
            }
            return r;
        }

        // ---------------------------------------------------------------- instruction patterns of a patch

        struct Decoded { std::string kind; size_t len = 0; uint64_t target = 0; };

        bool ReadQ(const Ctx& c, uint64_t a, uint64_t& v)
        {
            if (c.InExe(a))
            {
                if (auto* p = c.Img((uint32_t)(a - c.exeBase), 8)) { memcpy(&v, p, 8); return true; }
            }
            return Rd(a, v);
        }

        bool DecodeAt(const Ctx& c, const uint8_t* p, size_t avail, uint64_t addr, Decoded& d)
        {
            if (avail < 5) return false;
            int32_t rel;
            if (p[0] == 0xE8 || p[0] == 0xE9)
            {
                memcpy(&rel, p + 1, 4);
                d = { p[0] == 0xE8 ? "call" : "jmp", 5, addr + 5 + (int64_t)rel };
                return true;
            }
            if (avail >= 6 && p[0] == 0xFF && (p[1] == 0x15 || p[1] == 0x25))
            {
                memcpy(&rel, p + 2, 4);
                bool call = p[1] == 0x15;
                if (!call && rel == 0 && avail >= 14)
                {
                    uint64_t t;
                    memcpy(&t, p + 6, 8);
                    d = { "jmp-abs", 14, t };
                    return true;
                }
                uint64_t t;
                if (!ReadQ(c, addr + 6 + (int64_t)rel, t)) return false;
                d = { call ? "call-ind" : "jmp-ind", 6, t };
                return true;
            }
            if (avail >= 12 && p[0] == 0x48 && p[1] == 0xB8 && p[10] == 0xFF && (p[11] == 0xE0 || p[11] == 0xD0))
            {
                uint64_t t;
                memcpy(&t, p + 2, 8);
                d = { p[11] == 0xE0 ? "mov-jmp" : "mov-call", 12, t };
                return true;
            }
            if (avail >= 13 && p[0] == 0x49 && p[1] == 0xBB && p[10] == 0x41 && p[11] == 0xFF && (p[12] == 0xE3 || p[12] == 0xD3))
            {
                uint64_t t;
                memcpy(&t, p + 2, 8);
                d = { p[12] == 0xE3 ? "mov-jmp" : "mov-call", 13, t };
                return true;
            }
            return false;
        }

        // ---------------------------------------------------------------- the scan

        struct Scanner
        {
            Ctx c;
            Report r;
            HMODULE targetModule = nullptr;
            std::set<uint32_t> sites;

            void Add(Hook h)
            {
                if (!sites.insert(h.site).second) return;
                uint32_t b = 0, sz = 0;
                if (h.func == 0 && h.kind != "vtable" && h.kind != "data" && h.kind != "iat")
                {
                    if (FuncOf(c, h.site, b, sz)) { h.func = b; h.funcSize = sz; h.funcKnown = true; }
                }
                else if (h.func != 0)
                {
                    h.funcKnown = FuncOf(c, h.func, b, sz);
                    if (h.funcKnown) { h.func = b; h.funcSize = sz; }
                }
                if (h.funcKnown)
                {
                    h.names = NamesOf(c, h.func);
                    h.group = "F:" + Hex(h.func);
                }
                else if (h.kind == "inline" || h.kind == "call" || h.kind == "jmp" || h.kind == "call-ind" || h.kind == "jmp-ind" || h.kind == "jmp-abs" || h.kind == "mov-jmp" || h.kind == "mov-call")
                    h.group = "S:" + Hex(h.site & ~0xFFu);   // no unwind entry (small leaf function): same 256-byte neighbourhood
                if (h.group.empty()) h.group = "P:" + Hex(h.site);
                r.hooks.push_back(std::move(h));
            }

            void Own(Hook& h, uint64_t target)
            {
                h.target = target;
                auto res = Resolve(c, target);
                h.owner = res.owner;
                h.how = res.how;
                h.hops = res.hops;
                h.ownerOffset = res.ownerOffset;
            }

            // -------- diff against the file on disk
            bool LoadDisk()
            {
                std::string pathUtf = r.exePath;
                wchar_t wp[MAX_PATH * 2] = {};
                GetModuleFileNameW(targetModule, wp, MAX_PATH * 2);
                HANDLE f = CreateFileW(wp, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, nullptr, OPEN_EXISTING, 0, nullptr);
                if (f == INVALID_HANDLE_VALUE) { r.diskNote = "could not open the executable file"; return false; }
                LARGE_INTEGER sz{};
                GetFileSizeEx(f, &sz);
                if (sz.QuadPart <= 0 || sz.QuadPart > (1ll << 31)) { CloseHandle(f); r.diskNote = "unexpected executable size"; return false; }
                c.disk.resize((size_t)sz.QuadPart);
                size_t done = 0;
                while (done < c.disk.size())
                {
                    DWORD got = 0;
                    if (!ReadFile(f, c.disk.data() + done, (DWORD)std::min<size_t>(c.disk.size() - done, 1u << 24), &got, nullptr) || !got) break;
                    done += got;
                }
                CloseHandle(f);
                if (done != c.disk.size()) { r.diskNote = "could not read the executable file"; return false; }
                // The loader rewrites ImageBase in the headers it maps, so the preferred base has to come from the file.
                auto* dd = (const IMAGE_DOS_HEADER*)c.disk.data();
                if (c.disk.size() > sizeof(IMAGE_DOS_HEADER) && dd->e_magic == IMAGE_DOS_SIGNATURE && (size_t)dd->e_lfanew + sizeof(IMAGE_NT_HEADERS64) <= c.disk.size())
                    c.preferred = ((const IMAGE_NT_HEADERS64*)(c.disk.data() + dd->e_lfanew))->OptionalHeader.ImageBase;
                return true;
            }

            const uint8_t* DiskAt(const Section& s, uint32_t off, size_t n) const
            {
                if (off + n > s.rawSize || (size_t)s.rawPtr + off + n > c.disk.size()) return nullptr;
                return c.disk.data() + s.rawPtr + off;
            }

            void BuildRelocMask(std::vector<uint8_t>& mask)
            {
                mask.assign((c.exeSize + 7) / 8 + 1, 0);
                auto* dos = (const IMAGE_DOS_HEADER*)c.hdr.data();
                auto* nt = (const IMAGE_NT_HEADERS64*)(c.hdr.data() + dos->e_lfanew);
                auto& rd = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC];
                if (!rd.VirtualAddress || !rd.Size) return;
                uint32_t pos = 0;
                while (pos + 8 <= rd.Size)
                {
                    auto* blk = c.Img(rd.VirtualAddress + pos, 8);
                    if (!blk) break;
                    uint32_t page, bsz;
                    memcpy(&page, blk, 4);
                    memcpy(&bsz, blk + 4, 4);
                    if (bsz < 8 || pos + bsz > rd.Size) break;
                    auto* ents = c.Img(rd.VirtualAddress + pos + 8, bsz - 8);
                    if (!ents) break;
                    for (uint32_t i = 0; i < (bsz - 8) / 2; ++i)
                    {
                        uint16_t e;
                        memcpy(&e, ents + i * 2, 2);
                        uint32_t type = e >> 12, off = page + (e & 0xFFF);
                        uint32_t len = type == IMAGE_REL_BASED_DIR64 ? 8 : type == IMAGE_REL_BASED_HIGHLOW ? 4 : 0;
                        for (uint32_t k = 0; k < len && off + k < c.exeSize; ++k) { uint32_t x = off + k; mask[x >> 3] |= (uint8_t)(1u << (x & 7)); }
                    }
                    pos += bsz;
                }
            }

            void DiffCode()
            {
                std::vector<uint8_t> mask;
                BuildRelocMask(mask);
                uint64_t total = 0, execBytes = 0;
                struct Span { uint32_t rva; uint32_t len; const Section* sec; };
                std::vector<Span> spans;
                for (auto& s : c.secs)
                {
                    if (!s.exec() || s.mem.empty()) continue;
                    size_t n = std::min<size_t>(s.mem.size(), s.rawSize);
                    auto* d = DiskAt(s, 0, n);
                    if (!d) continue;
                    execBytes += n;
                    int64_t spanStart = -1, last = -1;
                    for (size_t i = 0; i < n; ++i)
                    {
                        uint32_t rv = s.rva + (uint32_t)i;
                        if (s.mem[i] == d[i] || (mask[rv >> 3] & (1u << (rv & 7)))) continue;
                        ++total;
                        if (spanStart >= 0 && (int64_t)i - last <= 6) { last = (int64_t)i; continue; }
                        if (spanStart >= 0) spans.push_back({ s.rva + (uint32_t)spanStart, (uint32_t)(last - spanStart + 1), &s });
                        spanStart = last = (int64_t)i;
                    }
                    if (spanStart >= 0) spans.push_back({ s.rva + (uint32_t)spanStart, (uint32_t)(last - spanStart + 1), &s });
                }
                r.diffBytes = total;
                if (execBytes == 0) { r.diskNote = "no code to compare"; return; }
                if (total > execBytes / 50)
                {
                    r.diskNote = "the executable on disk differs from memory in " + std::to_string(total) + " bytes (copy protection or a different build); using the pattern scan instead";
                    return;
                }
                r.diskUsed = true;
                c.diskOk = true;
                for (auto& sp : spans) DecodeSpan(sp.rva, sp.len, *sp.sec);
            }

            void DecodeSpan(uint32_t rva, uint32_t len, const Section& s)
            {
                uint32_t off = rva - s.rva;
                // A call/jump patch can keep its opcode byte, so the first changed byte may sit inside the instruction: look back.
                uint32_t back = std::min<uint32_t>(off, 13);
                Decoded best;
                uint32_t bestStart = 0;
                bool found = false;
                for (uint32_t st = off - back; st <= off; ++st)
                {
                    size_t avail = std::min<size_t>(s.mem.size() - st, 16);
                    Decoded d;
                    if (!DecodeAt(c, s.mem.data() + st, avail, c.exeBase + s.rva + st, d)) continue;
                    if (st + d.len <= off) continue;               // ends before the changed bytes
                    if (c.InExe(d.target)) continue;               // an ordinary call that merely overlaps
                    bool owned = Resolve(c, d.target).owner != "?";
                    // The first candidate is kept unless a later one can be followed to a DLL.
                    if (!found || (owned && Resolve(c, best.target).owner == "?")) { best = d; bestStart = st; found = true; }
                }
                Hook h;
                size_t show = std::min<uint32_t>(len + 2, 16);
                if (found)
                {
                    h.kind = best.kind;
                    h.site = s.rva + bestStart;
                    Own(h, best.target);
                    show = std::max<size_t>(best.len, std::min<uint32_t>(len, 16));
                }
                else
                {
                    h.kind = "inline";
                    h.site = rva;
                    h.owner = "?";
                }
                uint32_t so = h.site - s.rva;
                size_t n = std::min<size_t>(show, s.mem.size() - so);
                h.bytes = HexBytes(s.mem.data() + so, n);
                if (auto* d = DiskAt(s, so, n)) h.original = HexBytes(d, n);
                Add(std::move(h));
            }

            // -------- pattern scan, used when the file on disk cannot be compared
            void PatternScan()
            {
                auto* dos = (const IMAGE_DOS_HEADER*)c.hdr.data();
                auto* nt = (const IMAGE_NT_HEADERS64*)(c.hdr.data() + dos->e_lfanew);
                auto& iat = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IAT];
                uint64_t iatB = c.exeBase + iat.VirtualAddress, iatE = iatB + iat.Size;
                for (auto& s : c.secs)
                {
                    if (!s.exec() || s.mem.empty()) continue;
                    size_t n = s.mem.size();
                    for (size_t i = 0; i + 14 <= n; ++i)
                    {
                        uint8_t b = s.mem[i];
                        if (b != 0xE8 && b != 0xE9 && b != 0xFF && b != 0x48 && b != 0x49) continue;
                        uint64_t addr = c.exeBase + s.rva + i;
                        Decoded d;
                        if (!DecodeAt(c, s.mem.data() + i, 14, addr, d)) continue;
                        if (c.InExe(d.target)) continue;
                        if (d.kind == "call-ind" || d.kind == "jmp-ind")
                        {
                            int32_t rel;
                            memcpy(&rel, s.mem.data() + i + 2, 4);
                            uint64_t slot = addr + 6 + (int64_t)rel;
                            if (slot >= iatB && slot < iatE) continue;      // an ordinary call through the import table
                        }
                        if (!IsCodeTarget(c, d.target)) continue;
                        auto res = Resolve(c, d.target);
                        if (res.owner == "?" || c.mods[c.ModAt(res.finalTarget)].system) { ++r.unresolvedCandidates; continue; }
                        Hook h;
                        h.kind = d.kind;
                        h.site = s.rva + (uint32_t)i;
                        h.target = d.target;
                        h.owner = res.owner; h.how = res.how; h.hops = res.hops; h.ownerOffset = res.ownerOffset;
                        h.bytes = HexBytes(s.mem.data() + i, d.len);
                        Add(std::move(h));
                        i += d.len - 1;
                    }
                }
            }

            // -------- pointers: virtual tables and other data that now point outside the executable
            void DataScan()
            {
                auto* dos = (const IMAGE_DOS_HEADER*)c.hdr.data();
                auto* nt = (const IMAGE_NT_HEADERS64*)(c.hdr.data() + dos->e_lfanew);
                auto& iat = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IAT];
                uint32_t iatB = iat.VirtualAddress, iatE = iat.VirtualAddress + iat.Size;
                for (auto& s : c.secs)
                {
                    if (s.exec() || s.mem.empty()) continue;
                    for (size_t off = 0; off + 8 <= s.mem.size(); off += 8)
                    {
                        uint64_t v;
                        memcpy(&v, s.mem.data() + off, 8);
                        if (v < 0x10000 || c.InExe(v)) continue;
                        uint32_t rva = s.rva + (uint32_t)off;
                        if (rva >= iatB && rva < iatE) continue;
                        int m = c.ModAt(v);
                        bool priv = m < 0 && c.InPriv(v);
                        if (!priv && (m < 0 || c.mods[m].system || c.mods[m].isExe)) continue;
                        Hook h;
                        uint32_t cls, slot;
                        uint64_t slotAddr = c.exeBase + rva;
                        bool inVt = VtableSlot(c, slotAddr, cls, slot);
                        h.kind = inVt ? "vtable" : "data";
                        h.site = rva;
                        Own(h, v);
                        if (h.owner == "?" && priv && !inVt) { ++r.unresolvedCandidates; continue; }
                        h.bytes = HexBytes(s.mem.data() + off, 8);
                        // What the slot held before: the file on disk, when it is usable.
                        if (c.diskOk)
                            if (auto* d = DiskAt(s, (uint32_t)off, 8))
                            {
                                uint64_t ov;
                                memcpy(&ov, d, 8);
                                h.original = HexBytes(d, 8);
                                if (ov >= c.preferred && ov - c.preferred < c.exeSize) h.func = (uint32_t)(ov - c.preferred);
                            }
                        Add(std::move(h));
                        auto& back = r.hooks.back();
                        if (inVt)
                        {
                            std::string nm = c.clsNames[cls] + "::vfunc[" + std::to_string(slot) + "]";
                            back.names.insert(back.names.begin(), nm);
                        }
                    }
                }
            }

            // -------- imports that lead somewhere other than the DLL they name
            void ImportScan()
            {
                auto* dos = (const IMAGE_DOS_HEADER*)c.hdr.data();
                auto* nt = (const IMAGE_NT_HEADERS64*)(c.hdr.data() + dos->e_lfanew);
                auto& imp = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
                if (!imp.VirtualAddress) return;
                for (uint32_t pos = 0;; pos += sizeof(IMAGE_IMPORT_DESCRIPTOR))
                {
                    auto* d = (const IMAGE_IMPORT_DESCRIPTOR*)c.Img(imp.VirtualAddress + pos, sizeof(IMAGE_IMPORT_DESCRIPTOR));
                    if (!d || !d->Name) break;
                    auto* sc = c.SecAt(d->Name);
                    if (!sc) continue;
                    std::string dll((const char*)sc->mem.data() + (d->Name - sc->rva), strnlen((const char*)sc->mem.data() + (d->Name - sc->rva), std::min<size_t>(120, sc->mem.size() - (d->Name - sc->rva))));
                    std::string dllL = Lower(dll);
                    for (uint32_t i = 0;; ++i)
                    {
                        auto* th = c.Img(d->FirstThunk + i * 8, 8);
                        if (!th) break;
                        uint64_t v;
                        memcpy(&v, th, 8);
                        if (!v) break;
                        int m = c.ModAt(v);
                        bool priv = m < 0 && c.InPriv(v);
                        if (!priv && (m < 0 || c.mods[m].system || c.mods[m].isExe)) continue;
                        if (m >= 0 && Lower(c.mods[m].name) == dllL) continue;   // a wrapper DLL named like the import
                        Hook h;
                        h.kind = "iat";
                        h.site = d->FirstThunk + i * 8;
                        Own(h, v);
                        h.bytes = HexBytes(th, 8);
                        uint32_t o = d->OriginalFirstThunk ? d->OriginalFirstThunk : d->FirstThunk;
                        if (auto* ot = c.Img(o + i * 8, 8))
                        {
                            uint64_t ov;
                            memcpy(&ov, ot, 8);
                            if (!(ov & (1ull << 63)))
                                if (auto* sn = c.SecAt((uint32_t)ov))
                                {
                                    size_t so = (uint32_t)ov - sn->rva + 2;
                                    if (so < sn->mem.size())
                                        h.note = dll + "!" + std::string((const char*)sn->mem.data() + so, strnlen((const char*)sn->mem.data() + so, std::min<size_t>(100, sn->mem.size() - so)));
                                }
                        }
                        if (h.note.empty()) h.note = dll;
                        Add(std::move(h));
                    }
                }
            }

            void Overlaps()
            {
                std::map<std::string, std::vector<int>> groups;
                for (size_t i = 0; i < r.hooks.size(); ++i) groups[r.hooks[i].group].push_back((int)i);
                for (auto& [g, idx] : groups)
                {
                    if (idx.size() < 2) continue;
                    std::set<std::string> owners;
                    bool unknown = false;
                    for (int i : idx) { if (r.hooks[i].owner == "?") unknown = true; else owners.insert(r.hooks[i].owner); }
                    Overlap o;
                    o.group = g;
                    o.hooks = idx;
                    o.func = r.hooks[idx[0]].func;
                    o.names = r.hooks[idx[0]].names;
                    o.owners.assign(owners.begin(), owners.end());
                    if (owners.size() >= 2) o.severity = "two-modules";
                    else if (owners.size() == 1 && unknown) o.severity = "possible";
                    else continue;
                    r.overlaps.push_back(std::move(o));
                }
            }
        };

        std::string ExeVersion(const wchar_t* path)
        {
            DWORD h = 0, n = GetFileVersionInfoSizeW(path, &h);
            if (!n) return {};
            std::vector<uint8_t> buf(n);
            if (!GetFileVersionInfoW(path, 0, n, buf.data())) return {};
            VS_FIXEDFILEINFO* fi = nullptr;
            UINT len = 0;
            if (!VerQueryValueW(buf.data(), L"\\", (LPVOID*)&fi, &len) || !fi) return {};
            char b[64];
            snprintf(b, sizeof b, "%u.%u.%u.%u", HIWORD(fi->dwFileVersionMS), LOWORD(fi->dwFileVersionMS), HIWORD(fi->dwFileVersionLS), LOWORD(fi->dwFileVersionLS));
            return b;
        }

        std::string Now()
        {
            SYSTEMTIME t;
            GetLocalTime(&t);
            char b[40];
            snprintf(b, sizeof b, "%04u-%02u-%02u %02u:%02u:%02u", t.wYear, t.wMonth, t.wDay, t.wHour, t.wMinute, t.wSecond);
            return b;
        }
    }

    Report Scan(const std::string& reason, const ScanOptions& opt)
    {
        auto t0 = std::chrono::steady_clock::now();
        Scanner s;
        s.r.reason = reason;
        s.r.version = opt.version;
        s.r.time = Now();
        wchar_t wp[MAX_PATH * 2] = {};
        GetModuleFileNameW(opt.target ? (HMODULE)opt.target : nullptr, wp, MAX_PATH * 2);
        s.r.exePath = Narrow(wp);
        s.r.exeVersion = ExeVersion(wp);

        HMODULE exeModule = opt.target ? (HMODULE)opt.target : GetModuleHandleW(nullptr);
        s.targetModule = exeModule;
        LoadModules(s.c, exeModule);
        LoadExecutablePrivate(s.c);
        if (!LoadExeImage(s.c)) { s.r.diskNote = "could not read the executable image"; s.r.modules = s.c.mods; return s.r; }
        s.r.exeBase = s.c.exeBase;
        s.r.exeSize = s.c.exeSize;
        BuildVtables(s.c);
        s.r.vtables = (uint32_t)s.c.vts.size();
        s.r.namedFunctions = (uint32_t)s.c.ents.size();

        if (opt.useDisk && s.LoadDisk()) s.DiffCode();
        else if (!opt.useDisk) s.r.diskNote = "disk comparison switched off";
        if (!s.c.diskOk) s.PatternScan();
        s.DataScan();
        s.ImportScan();

        std::unordered_map<std::string, uint32_t> perModule;
        for (auto& h : s.r.hooks) ++perModule[h.owner];
        for (auto& m : s.c.mods) { auto it = perModule.find(m.name); if (it != perModule.end()) m.hooks = it->second; }
        s.r.modules = s.c.mods;
        std::sort(s.r.hooks.begin(), s.r.hooks.end(), [](auto& a, auto& b) { return a.site < b.site; });
        // The overlaps hold hook indexes, which the sort just moved: build them again.
        s.r.overlaps.clear();
        s.Overlaps();
        s.r.seconds = std::chrono::duration<double>(std::chrono::steady_clock::now() - t0).count();
        return s.r;
    }

    namespace
    {
        void Esc(std::string& o, const std::string& s)
        {
            o += '"';
            for (unsigned char ch : s)
            {
                switch (ch)
                {
                case '"': o += "\\\""; break;
                case '\\': o += "\\\\"; break;
                case '\n': o += "\\n"; break;
                case '\r': o += "\\r"; break;
                case '\t': o += "\\t"; break;
                default:
                    if (ch < 0x20) { char b[8]; snprintf(b, sizeof b, "\\u%04x", ch); o += b; }
                    else o += (char)ch;
                }
            }
            o += '"';
        }

        void Kv(std::string& o, const char* k, const std::string& v, bool comma = true) { Esc(o, k); o += ':'; Esc(o, v); if (comma) o += ','; }
        void Kn(std::string& o, const char* k, uint64_t v, bool comma = true) { Esc(o, k); o += ':'; o += std::to_string(v); if (comma) o += ','; }
        void Kb(std::string& o, const char* k, bool v, bool comma = true) { Esc(o, k); o += ':'; o += v ? "true" : "false"; if (comma) o += ','; }
        void Ka(std::string& o, const char* k, const std::vector<std::string>& v, bool comma = true)
        {
            Esc(o, k); o += ":[";
            for (size_t i = 0; i < v.size(); ++i) { if (i) o += ','; Esc(o, v[i]); }
            o += ']';
            if (comma) o += ',';
        }
    }

    std::string ToJson(const Report& r)
    {
        std::string o;
        o += "{\n";
        Kv(o, "tool", r.tool); Kv(o, "version", r.version); Kv(o, "reason", r.reason); Kv(o, "time", r.time);
        Kv(o, "exePath", r.exePath); Kv(o, "exeVersion", r.exeVersion);
        Kv(o, "exeBase", Hex(r.exeBase)); Kn(o, "exeSize", r.exeSize);
        Kb(o, "diskUsed", r.diskUsed); Kv(o, "diskNote", r.diskNote); Kn(o, "diffBytes", r.diffBytes);
        Kn(o, "unresolvedCandidates", r.unresolvedCandidates); Kn(o, "vtables", r.vtables); Kn(o, "namedFunctions", r.namedFunctions);
        char sec[32];
        snprintf(sec, sizeof sec, "%.3f", r.seconds);
        o += "\"seconds\":"; o += sec; o += ",\n";

        o += "\"modules\":[\n";
        for (size_t i = 0; i < r.modules.size(); ++i)
        {
            auto& m = r.modules[i];
            o += '{';
            Kv(o, "name", m.name); Kv(o, "path", m.path); Kv(o, "base", Hex(m.base)); Kn(o, "size", m.size);
            Kb(o, "system", m.system); Kb(o, "exe", m.isExe); Kb(o, "skse", m.skse);
            Kv(o, "plugin", m.plugin); Kv(o, "author", m.author); Kn(o, "pluginVersion", m.pluginVersion); Kn(o, "hooks", m.hooks, false);
            o += i + 1 < r.modules.size() ? "},\n" : "}\n";
        }
        o += "],\n\"hooks\":[\n";
        for (size_t i = 0; i < r.hooks.size(); ++i)
        {
            auto& h = r.hooks[i];
            o += '{';
            Kn(o, "id", i); Kv(o, "kind", h.kind); Kv(o, "site", Hex(h.site)); Kb(o, "funcKnown", h.funcKnown);
            Kv(o, "func", Hex(h.func)); Kn(o, "funcSize", h.funcSize); Ka(o, "names", h.names); Kv(o, "group", h.group);
            Kv(o, "target", Hex(h.target)); Kv(o, "owner", h.owner); Kv(o, "ownerOffset", Hex(h.ownerOffset)); Kv(o, "how", h.how); Kn(o, "hops", h.hops);
            Kv(o, "bytes", h.bytes); Kv(o, "original", h.original); Kv(o, "note", h.note, false);
            o += i + 1 < r.hooks.size() ? "},\n" : "}\n";
        }
        o += "],\n\"overlaps\":[\n";
        for (size_t i = 0; i < r.overlaps.size(); ++i)
        {
            auto& v = r.overlaps[i];
            o += '{';
            Kv(o, "group", v.group); Kv(o, "func", Hex(v.func)); Ka(o, "names", v.names); Ka(o, "owners", v.owners); Kv(o, "severity", v.severity);
            o += "\"hooks\":[";
            for (size_t k = 0; k < v.hooks.size(); ++k) { if (k) o += ','; o += std::to_string(v.hooks[k]); }
            o += "]";
            o += i + 1 < r.overlaps.size() ? "},\n" : "}\n";
        }
        o += "]\n}\n";
        return o;
    }
}
