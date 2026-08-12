#include "ArchiveAnalyzer.h"
#include <iostream>
using namespace std;
using namespace ZipBombDetector;
namespace fs = filesystem;

int main(int argc, char *argv[]) {
    if (argc < 2) {
        cerr << "Usage: " << argv[0] << " <file.zip> [--policy strict|relaxed] [--json]\n";
        return 1;
    }

    ZipBombDetector::ScanPolicy policy;
    bool json_out = false;

    for (int i = 2; i < argc; ++i) {
        string arg = argv[i];
        if (arg == "--policy" && i + 1 < argc) {
            string p = argv[++i];
            if (p == "strict")  policy = ZipBombDetector::ScanPolicy::strict();
            if (p == "relaxed") policy = ZipBombDetector::ScanPolicy::relaxed();
        } else if (arg == "--json") {
            json_out = true;
        }
    }

    ZipBombDetector::ArchiveAnalyzer analyzer(policy);
    analyzer.set_progress_callback([](const string &name, uint32_t i, uint32_t n) {
        cout << "\r  [" << i+1 << "/" << n << "] " << name << string(20, ' ') << flush;
    });

    int exit_code = 0;
    for (int i = 1; i < argc; ++i) {
        if (argv[i][0] == '-') continue;
        cout << "Format: " << detect_format(argv[i]) << "\n";
        auto result = analyzer.scan(argv[i]);
        cout << "\n";
        cout << (json_out ? result.json() : result.summary()) << "\n";
        if (result.is_threat) exit_code = 1;
    }
    return exit_code;
}
