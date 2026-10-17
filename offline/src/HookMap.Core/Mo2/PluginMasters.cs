using System.Text;

namespace HookMap.Core.Mo2;

/// <summary>Reads the master list (MAST entries) from the TES4 header of an esp/esm/esl without loading the plugin.</summary>
public static class PluginMasters
{
    public static IReadOnlyList<string> Read(string path)
    {
        try
        {
            using var fs = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete);
            Span<byte> head = stackalloc byte[24];
            if (fs.Read(head) < 24 || head[0] != 'T' || head[1] != 'E' || head[2] != 'S' || head[3] != '4') return [];
            uint size = BitConverter.ToUInt32(head[4..8]);
            if (size > 4 * 1024 * 1024) return [];
            var data = new byte[size];
            if (fs.Read(data, 0, data.Length) < data.Length) return [];
            return Parse(data);
        }
        catch (IOException) { return []; }
        catch (UnauthorizedAccessException) { return []; }
    }

    public static IReadOnlyList<string> Parse(byte[] data)
    {
        var masters = new List<string>();
        int p = 0;
        uint extra = 0;   // size of an XXXX override for the next subrecord
        while (p + 6 <= data.Length)
        {
            string type = Encoding.ASCII.GetString(data, p, 4);
            uint sz = BitConverter.ToUInt16(data, p + 4);
            p += 6;
            if (type == "XXXX" && sz == 4 && p + 4 <= data.Length) { extra = BitConverter.ToUInt32(data, p); p += 4; continue; }
            if (extra != 0) { sz = extra; extra = 0; }
            if (p + sz > data.Length) break;
            if (type == "MAST")
            {
                int e = p;
                while (e < p + sz && data[e] != 0) e++;
                masters.Add(Encoding.UTF8.GetString(data, p, e - p));
            }
            p += (int)sz;
        }
        return masters;
    }
}
