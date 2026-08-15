/*
 * ArchiveAnalyzer.cpp  —  C++17 ZIP bomb detector
 * Build:  make
 * Usage:  ./archive_analyzer <file.zip> [--policy strict|relaxed] [--json]
 */

#include "ArchiveAnalyzer.h"
#include <cstdio>
#include <algorithm>
#include <sstream>
#include <iomanip>
#include <iostream>

using namespace std;
using namespace ZipBombDetector;
namespace fs = filesystem;

static constexpr uint32_t SIG_CDIR = 0x02014b50;
static constexpr uint32_t SIG_EOCD = 0x06054b50;

static uint16_t ru16(FILE *f) {
    uint8_t b[2] = {}; if (fread(b, 1, 2, f) < 2) return 0;
    return uint16_t(b[0] | (b[1] << 8));
}
static uint32_t ru32(FILE *f) {
    uint8_t b[4] = {}; if (fread(b, 1, 4, f) < 4) return 0;
    return uint32_t(b[0] | (b[1]<<8) | (b[2]<<16) | (b[3]<<24));
}

ArchiveAnalyzer::ArchiveAnalyzer(ScanPolicy policy) : policy_(move(policy)) {}

string ArchiveAnalyzer::threat_level_name(ThreatLevel l) {
    switch (l) {
        case ThreatLevel::None:     return "NONE";
        case ThreatLevel::Low:      return "LOW";
        case ThreatLevel::Medium:   return "MEDIUM";
        case ThreatLevel::High:     return "HIGH";
        case ThreatLevel::Critical: return "CRITICAL";
    }
    return "UNKNOWN";
}

ThreatLevel ArchiveAnalyzer::escalate(ThreatLevel cur, ThreatLevel cand) const {
    return cand > cur ? cand : cur;
}

void ArchiveAnalyzer::add_flag(ScanResult &r, ThreatLevel level,
                               const string &code, const string &desc) const {
    r.flags.push_back({level, code, desc});
    r.threat_level = escalate(r.threat_level, level);
    r.is_threat    = r.threat_level > ThreatLevel::None;
}

bool ArchiveAnalyzer::find_eocd(FILE *f, long fsize,
                                uint16_t &out_count, uint32_t &out_offset) const {
    long limit = fsize > 65557L ? fsize - 65557L : 0L;
    for (long pos = fsize - 22; pos >= limit; --pos) {
        fseek(f, pos, SEEK_SET);
        if (ru32(f) == SIG_EOCD) {
            ru16(f); ru16(f); ru16(f);
            out_count  = ru16(f);
            ru32(f);
            out_offset = ru32(f);
            return true;
        }
    }
    return false;
}

bool ArchiveAnalyzer::detect_overlaps(const vector<pair<uint32_t,uint32_t>> &ranges) const {
    if (ranges.size() < 2) return false;
    auto sorted = ranges;
    sort(sorted.begin(), sorted.end());
    for (size_t i = 0; i + 1 < sorted.size(); ++i)
        if (sorted[i].second > sorted[i+1].first) return true;
    return false;
}

ScanResult ArchiveAnalyzer::scan_zip(const fs::path &path, int depth) const {
    auto t0 = chrono::high_resolution_clock::now();
    ScanResult result;
    result.path          = path.string();
    result.nesting_depth = depth;

    if (depth > policy_.max_nesting_depth) {
        add_flag(result, ThreatLevel::Critical, "DEPTH_EXCEEDED",
                 "Depth " + to_string(depth) + " exceeds limit " + to_string(policy_.max_nesting_depth));
        return result;
    }

    FILE *f = fopen(path.string().c_str(), "rb");
    if (!f) {
        add_flag(result, ThreatLevel::None, "IO_ERROR", "Cannot open: " + path.string());
        return result;
    }

    fseek(f, 0, SEEK_END);
    long fsize = ftell(f);
    rewind(f);

    uint16_t total_entries = 0;
    uint32_t cd_offset     = 0;
    if (!find_eocd(f, fsize, total_entries, cd_offset)) {
        add_flag(result, ThreatLevel::None, "INVALID_ZIP", "No EOCD record");
        fclose(f); return result;
    }

    if (total_entries > policy_.max_entries) {
        add_flag(result, ThreatLevel::High, "ENTRY_FLOOD",
                 to_string(total_entries) + " entries exceeds limit " + to_string(policy_.max_entries));
        fclose(f); return result;
    }

    vector<pair<uint32_t,uint32_t>> ranges;
    ranges.reserve(total_entries);
    fseek(f, cd_offset, SEEK_SET);

    for (uint16_t i = 0; i < total_entries; ++i) {
        if (ru32(f) != SIG_CDIR) {
            add_flag(result, ThreatLevel::Medium, "HEADER_CORRUPT",
                     "Bad central dir sig at entry " + to_string(i));
            fclose(f); return result;
        }

        ru16(f); ru16(f); ru16(f);          // ver made, ver needed, flags
        uint16_t method    = ru16(f);
        fseek(f, 4, SEEK_CUR);              // mod time/date
        ru32(f);                             // CRC
        uint32_t comp_sz   = ru32(f);
        uint32_t uncomp_sz = ru32(f);
        uint16_t fname_len = ru16(f);
        uint16_t extra_len = ru16(f);
        uint16_t comm_len  = ru16(f);
        fseek(f, 8, SEEK_CUR);              // disk, attrs
        uint32_t lh_offset = ru32(f);

        string fname(fname_len, '\0');
        { size_t _n = fread(fname.data(), 1, fname_len, f); (void)_n; }
        fseek(f, extra_len + comm_len, SEEK_CUR);

        auto lo = fname;
        transform(lo.begin(), lo.end(), lo.begin(), ::tolower);

        EntryInfo entry;
        entry.name              = fname;
        entry.compressed_size   = comp_sz;
        entry.uncompressed_size = uncomp_sz;
        entry.ratio             = comp_sz ? double(uncomp_sz) / comp_sz : 0.0;
        entry.local_offset      = lh_offset;
        entry.method            = method;
        entry.is_archive = lo.size()>3 && (lo.rfind(".zip")==lo.size()-4 || lo.rfind(".gz")==lo.size()-3 || lo.rfind(".bz2")==lo.size()-4);

        if (progress_cb_) progress_cb_(fname, i, total_entries);

        if (comp_sz > 0 && entry.ratio > policy_.max_ratio)
            add_flag(result, ThreatLevel::Critical, "RATIO_EXCEEDED",
                     "Entry '" + fname + "' ratio " + to_string(entry.ratio) + ":1");

        result.total_compressed   += comp_sz;
        result.total_uncompressed += uncomp_sz;
        result.entries.push_back(move(entry));

        if (result.total_uncompressed > policy_.max_uncompressed) {
            add_flag(result, ThreatLevel::Critical, "SIZE_EXCEEDED",
                     "Cumulative size exceeds " + to_string(policy_.max_uncompressed) + " bytes");
            fclose(f); return result;
        }

        ranges.emplace_back(lh_offset, lh_offset + 30 + fname_len + extra_len + comp_sz);
        ++result.entry_count;
    }
    fclose(f);

    result.overall_ratio = result.total_compressed
        ? double(result.total_uncompressed) / result.total_compressed : 0.0;

    if (policy_.check_overlaps && detect_overlaps(ranges)) {
        result.has_overlaps = true;
        add_flag(result, ThreatLevel::Critical, "OVERLAPPING_DATA",
                 "Data regions overlap — non-recursive zip bomb (Fifield) pattern");
    }

    if (!result.is_threat && result.overall_ratio > 10.0) {
        auto tl = result.overall_ratio > 50.0 ? ThreatLevel::Medium : ThreatLevel::Low;
        add_flag(result, tl, "HIGH_RATIO", "Overall ratio " + to_string(result.overall_ratio));
    }

    result.scan_duration = chrono::duration_cast<chrono::microseconds>(
        chrono::high_resolution_clock::now() - t0);
    return result;
}

ScanResult ArchiveAnalyzer::scan(const fs::path &path, int depth) const {
    return scan_zip(path, depth);
}

vector<ScanResult> ArchiveAnalyzer::scan_directory(const fs::path &dir, bool rec) const {
    vector<ScanResult> results;
    for (auto &entry : fs::directory_iterator{dir}) {
        if (entry.path().extension() == ".zip")
            results.push_back(scan(entry.path(), 0));
        else if (rec && entry.is_directory()) {
            auto sub = scan_directory(entry.path(), true);
            results.insert(results.end(), sub.begin(), sub.end());
        }
    }
    return results;
}

string ScanResult::summary() const {
    ostringstream ss;
    ss << "\n  File      : " << path
       << "\n  Threat    : " << ArchiveAnalyzer::threat_level_name(threat_level)
       << "\n  Entries   : " << entry_count
       << fixed << setprecision(2)
       << "\n  Ratio     : " << overall_ratio << " : 1"
       << "\n  Compressed: " << total_compressed   << " bytes"
       << "\n  Expanded  : " << total_uncompressed << " bytes"
       << "\n  Overlaps  : " << (has_overlaps ? "YES" : "No")
       << "\n  Depth     : " << nesting_depth
       << "\n  Scan µs   : " << scan_duration.count() << "\n";
    for (auto &fl : flags)
        ss << "  [" << ArchiveAnalyzer::threat_level_name(fl.level)
           << "] " << fl.code << ": " << fl.description << "\n";
    return ss.str();
}

string ScanResult::json() const {
    ostringstream j;
    j << "{\n"
      << "  \"path\": \""         << path << "\",\n"
      << "  \"is_threat\": "      << (is_threat ? "true" : "false") << ",\n"
      << "  \"threat_level\": \"" << ArchiveAnalyzer::threat_level_name(threat_level) << "\",\n"
      << "  \"entry_count\": "    << entry_count << ",\n"
      << "  \"total_compressed\": "   << total_compressed << ",\n"
      << "  \"total_uncompressed\": " << total_uncompressed << ",\n"
      << fixed << setprecision(4)
      << "  \"overall_ratio\": "  << overall_ratio << ",\n"
      << "  \"has_overlaps\": "   << (has_overlaps ? "true" : "false") << ",\n"
      << "  \"scan_us\": "        << scan_duration.count() << ",\n"
      << "  \"flags\": [\n";
    for (size_t i = 0; i < flags.size(); ++i) {
        j << "    {\"level\":\"" << ArchiveAnalyzer::threat_level_name(flags[i].level)
          << "\",\"code\":\""    << flags[i].code
          << "\",\"desc\":\""    << flags[i].description << "\"}";
        if (i + 1 < flags.size()) j << ",";
        j << "\n";
    }
    j << "  ]\n}";
    return j.str();
}


string detect_format(const fs::path &path) {
    FILE *f = fopen(path.string().c_str(), "rb");
    if (!f) return "unknown";
    uint8_t magic[8] = {};
    { size_t n = fread(magic, 1, 8, f); (void)n; }
    uint8_t tarbuf[512] = {};
    rewind(f);
    bool is_tar = fread(tarbuf, 1, 512, f) == 512 &&
                  tarbuf[257]=='u' && tarbuf[258]=='s' && tarbuf[259]=='t' &&
                  tarbuf[260]=='a' && tarbuf[261]=='r';
    fclose(f);

    if (magic[0]==0x50 && magic[1]==0x4b)                                      return "zip";
    if (magic[0]==0x1f && magic[1]==0x8b)                                      return "gzip";
    if (magic[0]==0x42 && magic[1]==0x5a && magic[2]==0x68)                    return "bzip2";
    if (magic[0]==0x37 && magic[1]==0x7a && magic[2]==0xbc && magic[3]==0xaf)  return "7z";
    if (magic[0]==0xfd && magic[1]==0x37 && magic[2]==0x7a)                    return "xz";
    if (magic[0]==0x52 && magic[1]==0x61 && magic[2]==0x72 && magic[3]==0x21)  return "rar";
    if (magic[0]==0x28 && magic[1]==0xb5 && magic[2]==0x2f && magic[3]==0xfd)  return "zstd";
    if (is_tar) return "tar";

    string ext = path.extension().string();
    transform(ext.begin(), ext.end(), ext.begin(), ::tolower);
    if (ext==".zip"||ext==".jar"||ext==".pt"||ext==".pth") return "zip";
    if (ext==".gz" ||ext==".tgz")   return "gzip";
    if (ext==".bz2"||ext==".tbz2")  return "bzip2";
    if (ext==".7z")  return "7z";
    if (ext==".xz")  return "xz";
    if (ext==".rar") return "rar";
    if (ext==".zst"||ext==".zstd") return "zstd";
    if (ext==".tar") return "tar";
    return "unknown";
}
