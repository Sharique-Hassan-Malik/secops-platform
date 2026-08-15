// Program.cs  —  CLI entry point for ZipBombScanner
using ZipBombScanner;

Console.OutputEncoding = System.Text.Encoding.UTF8;

if (args.Length == 0)
{
    Console.Error.WriteLine("Usage: ZipBombScanner <file.zip> [options]");
    Console.Error.WriteLine("Options:");
    Console.Error.WriteLine("  --policy <default|strict|paranoid|relaxed>");
    Console.Error.WriteLine("  --json          Output JSON instead of text");
    Console.Error.WriteLine("  --dir <path>    Scan all ZIPs in directory");
    return 1;
}

ScanPolicy policy   = ScanPolicy.Default;
bool jsonMode       = false;
string? dirScan     = null;
var files           = new List<string>();

for (int i = 0; i < args.Length; i++)
{
    switch (args[i])
    {
        case "--json": jsonMode = true; break;
        case "--policy" when i + 1 < args.Length:
            policy = args[++i] switch {
                "strict"   => ScanPolicy.Strict,
                "paranoid" => ScanPolicy.Paranoid,
                "relaxed"  => ScanPolicy.Relaxed,
                _          => ScanPolicy.Default
            };
            break;
        case "--dir" when i + 1 < args.Length:
            dirScan = args[++i];
            break;
        default:
            if (!args[i].StartsWith("--")) files.Add(args[i]);
            break;
    }
}

var detector = new ZipBombDetector(policy);
detector.OnProgress += (fname, idx, total) =>
    Console.Write($"\r  Scanning entry [{idx+1}/{total}]: {fname,-40}");

int exitCode = 0;

// Directory scan mode
if (dirScan is not null)
{
    Console.WriteLine($"Scanning directory: {dirScan}");
    foreach (var r in detector.ScanDirectory(dirScan))
    {
        Console.WriteLine();
        Console.WriteLine(jsonMode ? r.ToJson() : r.ToSummary());
        if (r.IsThreat) exitCode = 1;
    }
    return exitCode;
}

// Individual file scan
foreach (var file in files)
{
    Console.WriteLine($"Scanning: {file}");
    Console.WriteLine($"Format: {FormatDetector.Detect(file)}");
    var result = detector.Scan(file);
    Console.WriteLine();
    Console.WriteLine(jsonMode ? result.ToJson() : result.ToSummary());
    if (result.IsThreat) exitCode = 1;
}

return exitCode;
