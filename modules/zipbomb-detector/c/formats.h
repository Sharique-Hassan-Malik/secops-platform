/*
 * formats.h  —  Multi-format archive bomb detection (C99)
 */
#ifndef FORMATS_H
#define FORMATS_H

#include <stdint.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define MAX_RATIO           100.0
#define MAX_UNCOMPRESSED    (4ULL * 1024 * 1024 * 1024)
#define MAX_ENTRIES         10000
#define MAX_NESTED_DEPTH    3

typedef enum {
    FMT_ZIP, FMT_GZIP, FMT_BZIP2, FMT_TAR,
    FMT_7Z,  FMT_XZ,   FMT_RAR,   FMT_ZSTD,
    FMT_UNKNOWN
} ArchiveFormat;

typedef enum {
    THREAT_NONE, THREAT_LOW, THREAT_MEDIUM, THREAT_HIGH, THREAT_CRITICAL
} ThreatLevel;

#define MAX_FLAGS    16
#define FLAG_MSG_LEN 256

typedef struct {
    ThreatLevel level;
    char        code[32];
    char        message[FLAG_MSG_LEN];
} ThreatFlag;

typedef struct {
    char        path[512];
    char        fmt[16];
    bool        is_threat;
    ThreatLevel threat_level;
    uint64_t    total_compressed;
    uint64_t    total_uncompressed;
    double      overall_ratio;
    uint32_t    entry_count;
    bool        has_overlaps;
    double      scan_ms;
    ThreatFlag  flags[MAX_FLAGS];
    int         flag_count;
} FormatResult;

/* Initialise a result struct */
static inline FormatResult make_result(const char *path, const char *fmt) {
    FormatResult r;
    memset(&r, 0, sizeof(r));
    strncpy(r.path, path, sizeof(r.path)-1);
    strncpy(r.fmt,  fmt,  sizeof(r.fmt)-1);
    return r;
}

/* Add a threat flag */
static inline void add_flag(FormatResult *r, ThreatLevel level,
                             const char *code, const char *msg) {
    if (r->flag_count >= MAX_FLAGS) return;
    ThreatFlag *f = &r->flags[r->flag_count++];
    f->level = level;
    strncpy(f->code, code, sizeof(f->code)-1);
    strncpy(f->message, msg, sizeof(f->message)-1);
    if (level > r->threat_level) r->threat_level = level;
    r->is_threat = r->threat_level > THREAT_NONE;
}

static inline const char *threat_name(ThreatLevel l) {
    switch(l) {
        case THREAT_NONE:     return "NONE";
        case THREAT_LOW:      return "LOW";
        case THREAT_MEDIUM:   return "MEDIUM";
        case THREAT_HIGH:     return "HIGH";
        case THREAT_CRITICAL: return "CRITICAL";
        default:              return "UNKNOWN";
    }
}

/* Format detection and per-format scanners */
ArchiveFormat detect_archive_format(const char *path);
FormatResult  scan_archive(const char *path);
FormatResult  scan_zip(const char *path);
FormatResult  scan_gzip(const char *path);
FormatResult  scan_bzip2(const char *path);
FormatResult  scan_tar(const char *path);
FormatResult  scan_7z(const char *path);
FormatResult  scan_xz(const char *path);
FormatResult  scan_rar(const char *path);
FormatResult  scan_zstd(const char *path);
void          print_format_result(const FormatResult *r);

#endif
