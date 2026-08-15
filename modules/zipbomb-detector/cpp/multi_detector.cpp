// multi_detector.cpp  —  Multi-format archive bomb detector CLI (C++17)
// Build:  make multi_detector
// Usage:  ./multi_detector <file> [--policy strict|relaxed] [--json]

#include "FormatScanner.h"
#include <iostream>

using namespace std;
using namespace ZipBombDetector;

int main(int argc, char *argv[]) {
    if (argc < 2) {
        cerr << "Usage: " << argv[0] << " <file> [--policy strict|relaxed] [--json]\n";
        cerr << "Formats: zip, gzip, bzip2, tar, 7z, xz, rar, zstd, pt/pth\n";
        return 1;
    }

    ScanPolicy policy;
    bool json_out = false;
    for (int i = 2; i < argc; ++i) {
        string a = argv[i];
        if (a == "--policy" && i+1<argc) {
            string p = argv[++i];
            if (p=="strict")  policy = ScanPolicy::strict();
            if (p=="relaxed") policy = ScanPolicy::relaxed();
        } else if (a == "--json") json_out = true;
    }

    int exit_code = 0;
    for (int i = 1; i < argc; ++i) {
        if (argv[i][0] == '-') continue;
        string fmt = detect_format(argv[i]);
        cout << "Scanning: " << argv[i] << "  [" << fmt << "]\n";
        auto result = scan_archive(argv[i], policy);
        cout << (json_out ? result.json() : result.summary()) << "\n";
        if (result.is_threat) exit_code = 1;
    }
    return exit_code;
}
