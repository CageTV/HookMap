using System.Text;

namespace HookMap.Core.Pe;

/// <summary>What an SKSE plugin DLL says about itself, read from the file (no loading): the SKSEPlugin_Version block, which entry points
/// it exports and which DLLs it imports.</summary>
public sealed record SkseDllInfo(
    string FileName,
    bool IsPe64,
    bool IsSkseDll,
    bool HasVersionBlock,
    string? PluginName,
    string? Author,
    string PluginVersion,
    uint VersionIndependence,
    uint VersionIndependenceEx,
    IReadOnlyList<string> CompatibleVersions,
    bool HasLoad,
    bool HasQuery,
    bool HasPreload,
    IReadOnlyList<string> Imports)
{
    /// <summary>A DLL that cannot be read or is no PE file still gets a row, so it is not silently left out of a list.</summary>
    public static SkseDllInfo Unreadable(string path) => new(Path.GetFileName(path), false, false, false, null, null, "", 0, 0, [], false, false, false, []);

    public bool UsesAddressLibrary => (VersionIndependence & 1) != 0;
    public bool VersionIndependent => (VersionIndependence & 0x6) != 0 || (VersionIndependenceEx & 1) != 0;

    public static SkseDllInfo Read(string path)
    {
        try { return Parse(path, File.ReadAllBytes(path)); }
        catch (Exception e) when (e is IOException or UnauthorizedAccessException) { return Unreadable(path); }
    }

    public static SkseDllInfo Parse(string path, byte[] d)
    {
        var name = Path.GetFileName(path);
        if (d.Length < 0x100 || d[0] != 'M' || d[1] != 'Z') return Unreadable(path);
        int pe = BitConverter.ToInt32(d, 0x3C);
        if (pe < 0 || pe + 0x108 > d.Length || BitConverter.ToUInt32(d, pe) != 0x4550) return Unreadable(path);
        int numSec = BitConverter.ToUInt16(d, pe + 6);
        int optSize = BitConverter.ToUInt16(d, pe + 20);
        int opt = pe + 24;
        bool pe64 = BitConverter.ToUInt16(d, opt) == 0x20B;
        if (!pe64) return new SkseDllInfo(name, false, false, false, null, null, "", 0, 0, [], false, false, false, []);
        int dirs = opt + 112;
        uint exportRva = BitConverter.ToUInt32(d, dirs), exportSize = BitConverter.ToUInt32(d, dirs + 4);
        uint importRva = BitConverter.ToUInt32(d, dirs + 8);
        int secTable = opt + optSize;
        var secs = new List<(uint rva, uint vsize, uint raw, uint rawSize)>();
        for (int i = 0; i < numSec; i++)
        {
            int s = secTable + i * 40;
            if (s + 40 > d.Length) break;
            secs.Add((BitConverter.ToUInt32(d, s + 12), BitConverter.ToUInt32(d, s + 8), BitConverter.ToUInt32(d, s + 20), BitConverter.ToUInt32(d, s + 16)));
        }
        int Off(uint rva)
        {
            foreach (var (r, vs, raw, rs) in secs)
                if (rva >= r && rva < r + Math.Max(vs, rs)) { long o = raw + (rva - r); return o < d.Length ? (int)o : -1; }
            return -1;
        }
        string Str(int o)
        {
            if (o < 0) return "";
            int e = o;
            while (e < d.Length && d[e] != 0 && e - o < 260) e++;
            return Encoding.ASCII.GetString(d, o, e - o);
        }

        bool load = false, query = false, preload = false;
        int versionOff = -1;
        int ex = exportRva != 0 ? Off(exportRva) : -1;
        if (ex >= 0 && ex + 40 <= d.Length)
        {
            uint nNames = BitConverter.ToUInt32(d, ex + 24);
            int funcs = Off(BitConverter.ToUInt32(d, ex + 28)), names = Off(BitConverter.ToUInt32(d, ex + 32)), ords = Off(BitConverter.ToUInt32(d, ex + 36));
            if (funcs >= 0 && names >= 0 && ords >= 0)
                for (uint i = 0; i < nNames && names + i * 4 + 4 <= d.Length; i++)
                {
                    var n = Str(Off(BitConverter.ToUInt32(d, names + (int)i * 4)));
                    if (n.Length == 0 || n[0] != 'S') continue;
                    int ord = BitConverter.ToUInt16(d, ords + (int)i * 2);
                    switch (n)
                    {
                        case "SKSEPlugin_Load": load = true; break;
                        case "SKSEPlugin_Query": query = true; break;
                        case "SKSEPlugin_Preload": preload = true; break;
                        case "SKSEPlugin_Version":
                            if (funcs + ord * 4 + 4 <= d.Length) versionOff = Off(BitConverter.ToUInt32(d, funcs + ord * 4));
                            break;
                    }
                }
        }

        var imports = new List<string>();
        int imp = importRva != 0 ? Off(importRva) : -1;
        if (imp >= 0)
            for (int i = 0; imp + i * 20 + 20 <= d.Length; i++)
            {
                uint nameRva = BitConverter.ToUInt32(d, imp + i * 20 + 12);
                if (nameRva == 0) break;
                imports.Add(Str(Off(nameRva)));
            }

        bool isSkse = load || query || versionOff >= 0;
        if (versionOff >= 0 && versionOff + 848 <= d.Length && BitConverter.ToUInt32(d, versionOff) == 1)
        {
            uint ver = BitConverter.ToUInt32(d, versionOff + 4);
            string Z(int o, int max) { int e = o; while (e < o + max && d[e] != 0) e++; return Encoding.UTF8.GetString(d, o, e - o); }
            var pname = Z(versionOff + 8, 256);
            var author = Z(versionOff + 264, 256);
            uint indepEx = BitConverter.ToUInt32(d, versionOff + 772);
            uint indep = BitConverter.ToUInt32(d, versionOff + 776);
            var compat = new List<string>();
            for (int i = 0; i < 16; i++)
            {
                uint c = BitConverter.ToUInt32(d, versionOff + 780 + i * 4);
                if (c != 0) compat.Add(Unpack(c));
            }
            return new SkseDllInfo(name, true, true, true, pname, author, Unpack(ver), indep, indepEx, compat, load, query, preload, imports);
        }
        return new SkseDllInfo(name, true, isSkse, false, null, null, "", 0, 0, [], load, query, preload, imports);
    }

    /// <summary>SKSE packs a version as major&lt;&lt;24 | minor&lt;&lt;16 | build&lt;&lt;4 | sub.</summary>
    public static string Unpack(uint v) => $"{v >> 24}.{(v >> 16) & 0xFF}.{(v >> 4) & 0xFFF}";
}
