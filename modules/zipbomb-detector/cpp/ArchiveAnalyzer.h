#pragma once

#include <cstdint>
#include <string>
#include <vector>
#include <filesystem>
#include <functional>
#include <chrono>

namespace ZipBombDetector {

struct ScanPolicy {
    double   max_ratio         = 100.0;
    uint64_t max_uncompressed  = 4ULL * 1024 * 1024 * 1024;
    uint32_t max_entries       = 10'000;
    int      max_nesting_depth = 3;
    bool     check_overlaps    = true;

    static ScanPolicy strict()  { return {50.0,  1ULL<<30, 1000,  2, true}; }
    static ScanPolicy relaxed() { return {500.0, 1ULL<<34, 50000, 5, true}; }
};

enum class ThreatLevel { None, Low, Medium, High, Critical };

struct ThreatFlag {
    ThreatLevel level;
    std::string code;
    std::string description;
};

struct EntryInfo {
    std::string name;
    uint64_t    compressed_size   = 0;
    uint64_t    uncompressed_size = 0;
    double      ratio             = 0.0;
    uint32_t    local_offset      = 0;
    uint16_t    method            = 0;
    bool        is_archive        = false;
};

struct ScanResult {
    bool        is_threat          = false;
    ThreatLevel threat_level       = ThreatLevel::None;
    std::string path;
    uint32_t    entry_count        = 0;
    uint64_t    total_compressed   = 0;
    uint64_t    total_uncompressed = 0;
    double      overall_ratio      = 0.0;
    int         nesting_depth      = 0;
    bool        has_overlaps       = false;

    std::vector<ThreatFlag>  flags;
    std::vector<EntryInfo>   entries;
    std::vector<ScanResult>  nested_results;
    std::chrono::microseconds scan_duration{0};

    std::string summary() const;
    std::string json()    const;
};

class ArchiveAnalyzer {
public:
    explicit ArchiveAnalyzer(ScanPolicy policy = {});

    ScanResult              scan(const std::filesystem::path &path, int depth = 0) const;
    std::vector<ScanResult> scan_directory(const std::filesystem::path &dir, bool recursive = false) const;

    using ProgressCb = std::function<void(const std::string&, uint32_t, uint32_t)>;
    void set_progress_callback(ProgressCb cb) { progress_cb_ = std::move(cb); }

    static std::string threat_level_name(ThreatLevel l);

private:
    ScanPolicy         policy_;
    mutable ProgressCb progress_cb_;

    ScanResult scan_zip(const std::filesystem::path &path, int depth) const;
    bool find_eocd(FILE *f, long fsize, uint16_t &out_count, uint32_t &out_offset) const;
    bool detect_overlaps(const std::vector<std::pair<uint32_t,uint32_t>> &ranges) const;
    void add_flag(ScanResult &r, ThreatLevel level, const std::string &code, const std::string &desc) const;
    ThreatLevel escalate(ThreatLevel cur, ThreatLevel cand) const;
};

} // namespace ZipBombDetector

// Free function — detect archive format by magic bytes + extension
std::string detect_format(const std::filesystem::path &path);
