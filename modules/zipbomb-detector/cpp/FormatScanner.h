// FormatScanner.h  —  Multi-format archive bomb detection (C++17)
#pragma once
#include "ArchiveAnalyzer.h"
#include <cstdio>
#include <vector>

namespace ZipBombDetector {

// Dispatch to the right scanner based on magic bytes / extension
ScanResult scan_archive(const std::filesystem::path &path,
                        const ScanPolicy &policy = {});

// Per-format scanner functions
ScanResult scan_gzip (const std::filesystem::path &p, const ScanPolicy &pol);
ScanResult scan_bzip2(const std::filesystem::path &p, const ScanPolicy &pol);
ScanResult scan_tar  (const std::filesystem::path &p, const ScanPolicy &pol);
ScanResult scan_7z   (const std::filesystem::path &p, const ScanPolicy &pol);
ScanResult scan_xz   (const std::filesystem::path &p, const ScanPolicy &pol);
ScanResult scan_rar  (const std::filesystem::path &p, const ScanPolicy &pol);
ScanResult scan_zstd (const std::filesystem::path &p, const ScanPolicy &pol);

} // namespace ZipBombDetector
