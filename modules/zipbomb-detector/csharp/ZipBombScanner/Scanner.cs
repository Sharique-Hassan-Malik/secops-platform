// Scanner.cs  —  ZIP Bomb Detection Engine (C# / .NET 8)
// Reads ZIP structure via BinaryReader without extracting any data.

using System.IO.Compression;
using System.Text;
using System.Text.Json;

namespace ZipBombScanner;

public enum ThreatLevel { None, Low, Medium, High, Critical }

public enum DetectionCode {
    Clean, RatioExceeded, SizeExceeded, EntryCountExceeded,
    NestingDepthExceeded, OverlappingDataRegions, HeaderCorruption, IoError
}

public record ThreatFlag(ThreatLevel Level, DetectionCode Code, string Description);

public record EntryInfo(
    string Name, long CompressedSize, long UncompressedSize,
    double Ratio, ushort CompressionMethod, uint LocalHeaderOffset, bool IsNestedArchive
);

public class ScanPolicy
{
    public double  MaxRatio         { get; init; } = 100.0;
    public long    MaxUncompressed  { get; init; } = 4L * 1024 * 1024 * 1024;
    public int     MaxEntries       { get; init; } = 10_000;
    public int     MaxNestingDepth  { get; init; } = 3;
    public bool    CheckOverlaps    { get; init; } = true;

    public static ScanPolicy Default  => new();
    public static ScanPolicy Strict   => new() { MaxRatio=50,  MaxUncompressed=1L<<30, MaxEntries=500,   MaxNestingDepth=2 };
    public static ScanPolicy Paranoid => new() { MaxRatio=10,  MaxUncompressed=1L<<28, MaxEntries=100,   MaxNestingDepth=1 };
    public static ScanPolicy Relaxed  => new() { MaxRatio=500, MaxUncompressed=1L<<36, MaxEntries=50000, MaxNestingDepth=5 };
}

public class ScanResult
{
    public string      FilePath          { get; init; } = string.Empty;
    public bool        IsThreat          { get; set;  }
    public ThreatLevel ThreatLevel       { get; set;  }
    public int         EntryCount        { get; set;  }
    public long        TotalCompressed   { get; set;  }
    public long        TotalUncompressed { get; set;  }
    public double      OverallRatio      { get; set;  }
    public int         NestingDepth      { get; set;  }
    public bool        HasOverlaps       { get; set;  }
    public TimeSpan    ScanDuration      { get; set;  }

    public List<ThreatFlag> Flags   { get; } = new();
    public List<EntryInfo>  Entries { get; } = new();

    public string ToJson() =>
        JsonSerializer.Serialize(this, new JsonSerializerOptions { WriteIndented = true });

    public string ToSummary()
    {
        var sb = new StringBuilder();
        sb.AppendLine($"  File        : {FilePath}");
        sb.AppendLine($"  Threat      : {ThreatLevel}");
        sb.AppendLine($"  Entries     : {EntryCount}");
        sb.AppendLine($"  Compressed  : {TotalCompressed:N0} bytes");
        sb.AppendLine($"  Expanded    : {TotalUncompressed:N0} bytes");
        sb.AppendLine($"  Ratio       : {OverallRatio:F2} : 1");
        sb.AppendLine($"  Overlaps    : {(HasOverlaps ? "YES" : "No")}");
        sb.AppendLine($"  Depth       : {NestingDepth}");
        sb.AppendLine($"  Scan time   : {ScanDuration.TotalMilliseconds:F2} ms");
        foreach (var f in Flags)
            sb.AppendLine($"  [{f.Level}] {f.Code}: {f.Description}");
        return sb.ToString();
    }
}

public class ZipBombDetector
{
    private readonly ScanPolicy _policy;
    public event Action<string, int, int>? OnProgress;

    public ZipBombDetector(ScanPolicy? policy = null) => _policy = policy ?? ScanPolicy.Default;

    public ScanResult Scan(string path, int depth = 0)
    {
        var sw = System.Diagnostics.Stopwatch.StartNew();
        var result = ScanInternal(path, depth);
        result.ScanDuration = sw.Elapsed;
        return result;
    }

    public IEnumerable<ScanResult> ScanDirectory(string dir, bool recursive = false)
    {
        var opts = recursive ? SearchOption.AllDirectories : SearchOption.TopDirectoryOnly;
        foreach (var file in Directory.EnumerateFiles(dir, "*.zip", opts))
            yield return Scan(file);
    }

    private ScanResult ScanInternal(string path, int depth)
    {
        var result = new ScanResult { FilePath = path, NestingDepth = depth };

        if (depth > _policy.MaxNestingDepth)
        {
            AddFlag(result, ThreatLevel.Critical, DetectionCode.NestingDepthExceeded,
                $"Depth {depth} exceeds limit {_policy.MaxNestingDepth}");
            return result;
        }

        if (!File.Exists(path))
        {
            AddFlag(result, ThreatLevel.None, DetectionCode.IoError, $"File not found: {path}");
            return result;
        }

        try
        {
            using var fs     = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.Read);
            using var reader = new BinaryReader(fs, Encoding.UTF8, leaveOpen: false);

            if (!TryFindEocd(fs, out var entryCount, out var cdOffset))
            {
                AddFlag(result, ThreatLevel.None, DetectionCode.HeaderCorruption, "No EOCD record");
                return result;
            }

            if (entryCount > _policy.MaxEntries)
            {
                AddFlag(result, ThreatLevel.High, DetectionCode.EntryCountExceeded,
                    $"{entryCount} entries exceeds limit {_policy.MaxEntries}");
                return result;
            }

            fs.Seek(cdOffset, SeekOrigin.Begin);
            var ranges = new List<(uint S, uint E)>(entryCount);

            for (int i = 0; i < entryCount; i++)
            {
                if (reader.ReadUInt32() != 0x02014b50)
                {
                    AddFlag(result, ThreatLevel.Medium, DetectionCode.HeaderCorruption,
                        $"Bad central dir sig at entry {i}");
                    return result;
                }

                reader.ReadUInt16(); reader.ReadUInt16(); // ver
                reader.ReadUInt16();                      // flags
                ushort method    = reader.ReadUInt16();
                reader.ReadUInt32();                      // mod time
                reader.ReadUInt32();                      // CRC
                uint   compSz    = reader.ReadUInt32();
                uint   uncompSz  = reader.ReadUInt32();
                ushort fnLen     = reader.ReadUInt16();
                ushort exLen     = reader.ReadUInt16();
                ushort cmLen     = reader.ReadUInt16();
                reader.ReadUInt32(); reader.ReadUInt32(); // disk, attrs
                uint   lhOffset  = reader.ReadUInt32();

                string fname = Encoding.UTF8.GetString(reader.ReadBytes(fnLen));
                reader.ReadBytes(exLen + cmLen);

                bool isArchive = fname.EndsWith(".zip", StringComparison.OrdinalIgnoreCase)
                              || fname.EndsWith(".gz",  StringComparison.OrdinalIgnoreCase)
                              || fname.EndsWith(".bz2", StringComparison.OrdinalIgnoreCase);

                double ratio = compSz > 0 ? (double)uncompSz / compSz : 0.0;
                result.Entries.Add(new EntryInfo(fname, compSz, uncompSz, ratio, method, lhOffset, isArchive));

                OnProgress?.Invoke(fname, i, entryCount);

                if (compSz > 0 && ratio > _policy.MaxRatio)
                    AddFlag(result, ThreatLevel.Critical, DetectionCode.RatioExceeded,
                        $"'{fname}' ratio {ratio:F1}:1 exceeds {_policy.MaxRatio}:1");

                result.TotalCompressed   += compSz;
                result.TotalUncompressed += uncompSz;
                result.EntryCount++;

                if (result.TotalUncompressed > _policy.MaxUncompressed)
                {
                    AddFlag(result, ThreatLevel.Critical, DetectionCode.SizeExceeded,
                        $"Cumulative {result.TotalUncompressed:N0} bytes exceeds limit");
                    return result;
                }

                ranges.Add((lhOffset, lhOffset + 30u + fnLen + exLen + compSz));
            }

            result.OverallRatio = result.TotalCompressed > 0
                ? (double)result.TotalUncompressed / result.TotalCompressed : 0.0;

            if (_policy.CheckOverlaps && DetectOverlaps(ranges))
            {
                result.HasOverlaps = true;
                AddFlag(result, ThreatLevel.Critical, DetectionCode.OverlappingDataRegions,
                    "Data regions overlap — Fifield-style non-recursive zip bomb");
            }

            if (!result.IsThreat && result.OverallRatio > 10.0)
            {
                var tl = result.OverallRatio > 50.0 ? ThreatLevel.Medium : ThreatLevel.Low;
                AddFlag(result, tl, DetectionCode.RatioExceeded,
                    $"Elevated overall ratio {result.OverallRatio:F2}:1");
            }
        }
        catch (Exception ex)
        {
            AddFlag(result, ThreatLevel.None, DetectionCode.IoError, ex.Message);
        }

        return result;
    }

    private static bool TryFindEocd(Stream s, out int entryCount, out long cdOffset)
    {
        entryCount = 0; cdOffset = 0;
        long fsize = s.Length;
        var  buf   = new byte[4];

        for (long pos = fsize - 22; pos >= Math.Max(0, fsize - 65557); pos--)
        {
            s.Seek(pos, SeekOrigin.Begin);
            s.ReadExactly(buf, 0, 4);
            if (buf[0]==0x50 && buf[1]==0x4b && buf[2]==0x05 && buf[3]==0x06)
            {
                using var r = new BinaryReader(s, Encoding.UTF8, leaveOpen: true);
                r.ReadUInt16(); r.ReadUInt16(); r.ReadUInt16();
                entryCount = r.ReadUInt16();
                r.ReadUInt32();
                cdOffset   = r.ReadUInt32();
                return true;
            }
        }
        return false;
    }

    private static bool DetectOverlaps(List<(uint S, uint E)> ranges)
    {
        var sorted = ranges.OrderBy(r => r.S).ToList();
        for (int i = 0; i + 1 < sorted.Count; i++)
            if (sorted[i].E > sorted[i+1].S) return true;
        return false;
    }

    private void AddFlag(ScanResult r, ThreatLevel lv, DetectionCode code, string desc)
    {
        r.Flags.Add(new ThreatFlag(lv, code, desc));
        if (lv > r.ThreatLevel) r.ThreatLevel = lv;
        r.IsThreat = r.ThreatLevel > ThreatLevel.None;
    }
}

public static class FormatDetector
{
    private static readonly Dictionary<string,string> ExtMap = new(StringComparer.OrdinalIgnoreCase)
    {
        [".zip"]=  "zip",  [".jar"]= "zip",  [".war"]= "zip",  [".apk"]= "zip",
        [".docx"]= "zip",  [".xlsx"]="zip",  [".pptx"]="zip",
        [".pt"]=   "zip",  [".pth"]= "zip",
        [".gz"]=   "gzip", [".tgz"]= "gzip",
        [".bz2"]=  "bzip2",[".tbz2"]="bzip2",
        [".7z"]=   "7z",   [".xz"]=  "xz",
        [".rar"]=  "rar",  [".zst"]= "zstd", [".zstd"]="zstd",
        [".tar"]=  "tar",
    };

    public static string Detect(string path)
    {
        try
        {
            using var fs    = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.Read);
            var magic = new byte[8];
            fs.ReadExactly(magic, 0, Math.Min(8, (int)fs.Length));

            if (magic[0]==0x50 && magic[1]==0x4b)                                         return "zip";
            if (magic[0]==0x1f && magic[1]==0x8b)                                         return "gzip";
            if (magic[0]==0x42 && magic[1]==0x5a && magic[2]==0x68)                       return "bzip2";
            if (magic[0]==0x37 && magic[1]==0x7a && magic[2]==0xbc && magic[3]==0xaf)     return "7z";
            if (magic[0]==0xfd && magic[1]==0x37 && magic[2]==0x7a)                       return "xz";
            if (magic[0]==0x52 && magic[1]==0x61 && magic[2]==0x72 && magic[3]==0x21)     return "rar";
            if (magic[0]==0x28 && magic[1]==0xb5 && magic[2]==0x2f && magic[3]==0xfd)     return "zstd";

            // TAR: "ustar" at offset 257
            if (fs.Length >= 512)
            {
                fs.Seek(0, SeekOrigin.Begin);
                var buf = new byte[512];
                fs.ReadExactly(buf, 0, 512);
                if (buf[257]=='u'&&buf[258]=='s'&&buf[259]=='t'&&buf[260]=='a'&&buf[261]=='r')
                    return "tar";
            }
        }
        catch { }

        var ext = Path.GetExtension(path);
        return ExtMap.TryGetValue(ext, out var fmt) ? fmt : "unknown";
    }
}
