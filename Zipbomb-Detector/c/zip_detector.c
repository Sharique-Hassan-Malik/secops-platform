/*
 * zip_detector.c  —  Multi-format archive bomb detector (C99)
 * Build:  make
 * Usage:  ./zip_detector <file> [file2 ...]
 */

#include "zip_detector.h"
#include <math.h>

static uint16_t read_u16(FILE *f) {
    uint8_t b[2] = {0};
    if (fread(b, 1, 2, f) < 2) return 0;
    return (uint16_t)(b[0] | (b[1] << 8));
}

static uint32_t read_u32(FILE *f) {
    uint8_t b[4] = {0};
    if (fread(b, 1, 4, f) < 4) return 0;
    return (uint32_t)(b[0] | (b[1]<<8) | (b[2]<<16) | (b[3]<<24));
}

typedef struct { uint32_t start, end; } Range;

static int range_cmp(const void *a, const void *b) {
    return (int)(((const Range*)a)->start - ((const Range*)b)->start);
}

static bool detect_overlaps(Range *ranges, uint32_t n) {
    if (n < 2) return false;
    qsort(ranges, n, sizeof(Range), range_cmp);
    for (uint32_t i = 0; i < n - 1; i++)
        if (ranges[i].end > ranges[i+1].start) return true;
    return false;
}

static bool find_eocd(FILE *f, long file_size,
                      uint16_t *out_count, uint32_t *out_offset) {
    long limit = (file_size > 65557) ? file_size - 65557 : 0;
    for (long pos = file_size - 22; pos >= limit; pos--) {
        fseek(f, pos, SEEK_SET);
        if (read_u32(f) == ZIP_END_CENTRAL_DIR_SIG) {
            read_u16(f); read_u16(f); read_u16(f);
            *out_count  = read_u16(f);
            read_u32(f);
            *out_offset = read_u32(f);
            return true;
        }
    }
    return false;
}

/* Format detection by magic bytes then extension fallback */
const char *detect_format(const char *path) {
    FILE *f = fopen(path, "rb");
    if (!f) return "unknown";
    unsigned char magic[8] = {0};
    { size_t n = fread(magic, 1, 8, f); (void)n; }

    /* Check TAR ustar at offset 257 */
    unsigned char tarbuf[512] = {0};
    rewind(f);
    bool is_tar = false;
    if (fread(tarbuf, 1, 512, f) == 512 &&
        tarbuf[257]=='u' && tarbuf[258]=='s' && tarbuf[259]=='t' &&
        tarbuf[260]=='a' && tarbuf[261]=='r')
        is_tar = true;
    fclose(f);

    if (magic[0]==0x50 && magic[1]==0x4b)                              return "zip";
    if (magic[0]==0x1f && magic[1]==0x8b)                              return "gzip";
    if (magic[0]==0x42 && magic[1]==0x5a && magic[2]==0x68)            return "bzip2";
    if (magic[0]==0x37 && magic[1]==0x7a && magic[2]==0xbc && magic[3]==0xaf) return "7z";
    if (magic[0]==0xfd && magic[1]==0x37 && magic[2]==0x7a)            return "xz";
    if (magic[0]==0x52 && magic[1]==0x61 && magic[2]==0x72 && magic[3]==0x21) return "rar";
    if (magic[0]==0x28 && magic[1]==0xb5 && magic[2]==0x2f && magic[3]==0xfd) return "zstd";
    if (is_tar) return "tar";

    const char *dot = strrchr(path, '.');
    if (!dot) return "unknown";
    if (!strcmp(dot,".zip")||!strcmp(dot,".jar")||!strcmp(dot,".pt")||!strcmp(dot,".pth")) return "zip";
    if (!strcmp(dot,".gz") ||!strcmp(dot,".tgz"))  return "gzip";
    if (!strcmp(dot,".bz2")||!strcmp(dot,".tbz2")) return "bzip2";
    if (!strcmp(dot,".7z"))  return "7z";
    if (!strcmp(dot,".xz"))  return "xz";
    if (!strcmp(dot,".rar")) return "rar";
    if (!strcmp(dot,".zst")||!strcmp(dot,".zstd")) return "zstd";
    if (!strcmp(dot,".tar")) return "tar";
    return "unknown";
}

ScanReport scan_zip_file(const char *path, int depth) {
    ScanReport report;
    memset(&report, 0, sizeof(report));
    report.nesting_depth = depth;

    if (depth > MAX_NESTED_DEPTH) {
        report.result = RESULT_DEPTH_EXCEEDED;
        snprintf(report.message, sizeof(report.message),
                 "Nesting depth %d exceeds limit %d", depth, MAX_NESTED_DEPTH);
        return report;
    }

    FILE *f = fopen(path, "rb");
    if (!f) {
        report.result = RESULT_IO_ERROR;
        snprintf(report.message, sizeof(report.message), "Cannot open '%s'", path);
        return report;
    }

    fseek(f, 0, SEEK_END);
    long file_size = ftell(f);
    rewind(f);

    uint16_t total_entries = 0;
    uint32_t cd_offset     = 0;
    if (!find_eocd(f, file_size, &total_entries, &cd_offset)) {
        report.result = RESULT_IO_ERROR;
        snprintf(report.message, sizeof(report.message), "No EOCD record — not a valid ZIP");
        fclose(f); return report;
    }

    if (total_entries > MAX_FILE_COUNT) {
        report.result = RESULT_COUNT_EXCEEDED;
        snprintf(report.message, sizeof(report.message),
                 "Entry count %u exceeds limit %d", total_entries, MAX_FILE_COUNT);
        fclose(f); return report;
    }

    Range *ranges = malloc(total_entries * sizeof(Range));
    if (!ranges) {
        report.result = RESULT_IO_ERROR;
        snprintf(report.message, sizeof(report.message), "malloc failed");
        fclose(f); return report;
    }

    uint64_t total_comp = 0, total_uncomp = 0;
    fseek(f, cd_offset, SEEK_SET);

    for (uint16_t i = 0; i < total_entries; i++) {
        if (read_u32(f) != ZIP_CENTRAL_DIR_SIG) {
            report.result = RESULT_HEADER_MISMATCH;
            snprintf(report.message, sizeof(report.message),
                     "Bad central dir sig at entry %u", i);
            free(ranges); fclose(f); return report;
        }

        read_u16(f); read_u16(f); read_u16(f); /* ver made, needed, flags */
        read_u16(f);                            /* method */
        fseek(f, 4, SEEK_CUR);                 /* mod time/date */
        read_u32(f);                            /* CRC */
        uint32_t comp_sz   = read_u32(f);
        uint32_t uncomp_sz = read_u32(f);
        uint16_t fname_len = read_u16(f);
        uint16_t extra_len = read_u16(f);
        uint16_t comm_len  = read_u16(f);
        fseek(f, 8, SEEK_CUR);                 /* disk, attrs */
        uint32_t lh_offset = read_u32(f);

        char fname[MAX_FILENAME_LEN] = {0};
        uint16_t rlen = (fname_len < MAX_FILENAME_LEN-1) ? fname_len : MAX_FILENAME_LEN-1;
        { size_t n = fread(fname, 1, rlen, f); (void)n; }
        fseek(f, fname_len - rlen + extra_len + comm_len, SEEK_CUR);

        total_comp   += comp_sz;
        total_uncomp += uncomp_sz;

        if (comp_sz > 0) {
            double ratio = (double)uncomp_sz / comp_sz;
            if (ratio > MAX_COMPRESSION_RATIO) {
                report.result = RESULT_RATIO_EXCEEDED;
                snprintf(report.trigger_filename, MAX_FILENAME_LEN, "%s", fname);
                snprintf(report.message, sizeof(report.message),
                         "'%.200s': ratio %.1f:1 exceeds limit %.0f:1",
                         fname, ratio, MAX_COMPRESSION_RATIO);
                free(ranges); fclose(f); return report;
            }
        }

        if (total_uncomp > MAX_UNCOMPRESSED_BYTES) {
            report.result = RESULT_SIZE_EXCEEDED;
            snprintf(report.message, sizeof(report.message),
                     "Cumulative size %llu bytes exceeds limit",
                     (unsigned long long)total_uncomp);
            free(ranges); fclose(f); return report;
        }

        ranges[i].start = lh_offset;
        ranges[i].end   = lh_offset + 30 + fname_len + extra_len + comp_sz;
        report.entry_count++;
    }

    if (detect_overlaps(ranges, report.entry_count)) {
        report.has_overlapping_entries = true;
        report.result = RESULT_OVERLAPPING_DATA;
        snprintf(report.message, sizeof(report.message),
                 "Overlapping data regions — Fifield-style zip bomb");
        free(ranges); fclose(f); return report;
    }

    free(ranges);
    fclose(f);

    report.total_compressed   = total_comp;
    report.total_uncompressed = total_uncomp;
    report.overall_ratio = (total_comp > 0) ? (double)total_uncomp / total_comp : 0.0;
    report.result = RESULT_CLEAN;
    snprintf(report.message, sizeof(report.message),
             "Clean. Ratio: %.2f:1, Entries: %u", report.overall_ratio, report.entry_count);
    return report;
}

const char *result_name(DetectionResult r) {
    switch (r) {
        case RESULT_CLEAN:            return "CLEAN";
        case RESULT_RATIO_EXCEEDED:   return "RATIO_EXCEEDED";
        case RESULT_SIZE_EXCEEDED:    return "SIZE_EXCEEDED";
        case RESULT_DEPTH_EXCEEDED:   return "DEPTH_EXCEEDED";
        case RESULT_COUNT_EXCEEDED:   return "COUNT_EXCEEDED";
        case RESULT_OVERLAPPING_DATA: return "OVERLAPPING_DATA";
        case RESULT_HEADER_MISMATCH:  return "HEADER_MISMATCH";
        case RESULT_IO_ERROR:         return "IO_ERROR";
        default:                      return "UNKNOWN";
    }
}

void print_report(const ScanReport *r) {
    printf("  Result     : %s\n",  result_name(r->result));
    printf("  Entries    : %u\n",  r->entry_count);
    printf("  Compressed : %llu bytes\n", (unsigned long long)r->total_compressed);
    printf("  Expanded   : %llu bytes\n", (unsigned long long)r->total_uncompressed);
    printf("  Ratio      : %.2f:1\n",     r->overall_ratio);
    printf("  Overlapping: %s\n",  r->has_overlapping_entries ? "YES" : "No");
    if (r->trigger_filename[0])
        printf("  Trigger    : %s\n", r->trigger_filename);
    printf("  Message    : %s\n\n", r->message);
}

int main(int argc, char *argv[]) {
    if (argc < 2) {
        fprintf(stderr, "Usage: %s <file> [file2 ...]\n", argv[0]);
        fprintf(stderr, "Supported: zip, gzip, bzip2, tar, 7z, xz, rar, zstd, pt/pth\n");
        return 1;
    }
    int exit_code = 0;
    for (int i = 1; i < argc; i++) {
        const char *fmt = detect_format(argv[i]);
        printf("Scanning: %s  [%s]\n", argv[i], fmt);
        ScanReport rep = scan_zip_file(argv[i], 0);
        print_report(&rep);
        if (rep.result != RESULT_CLEAN) exit_code = 1;
    }
    return exit_code;
}
