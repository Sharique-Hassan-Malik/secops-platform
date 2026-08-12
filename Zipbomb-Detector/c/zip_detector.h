#ifndef ZIP_DETECTOR_H
#define ZIP_DETECTOR_H

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>

#define MAX_COMPRESSION_RATIO   100.0
#define MAX_UNCOMPRESSED_BYTES  (1ULL << 32)
#define MAX_NESTED_DEPTH        3
#define MAX_FILE_COUNT          10000
#define MAX_FILENAME_LEN        260

#define ZIP_LOCAL_HEADER_SIG    0x04034b50
#define ZIP_CENTRAL_DIR_SIG     0x02014b50
#define ZIP_END_CENTRAL_DIR_SIG 0x06054b50

typedef enum {
    RESULT_CLEAN,
    RESULT_RATIO_EXCEEDED,
    RESULT_SIZE_EXCEEDED,
    RESULT_DEPTH_EXCEEDED,
    RESULT_COUNT_EXCEEDED,
    RESULT_OVERLAPPING_DATA,
    RESULT_HEADER_MISMATCH,
    RESULT_IO_ERROR
} DetectionResult;

typedef struct {
    char     filename[MAX_FILENAME_LEN];
    uint32_t compressed_size;
    uint32_t uncompressed_size;
    double   ratio;
    uint16_t compression_method;
    uint32_t local_header_offset;
} ZipEntry;

typedef struct {
    DetectionResult result;
    uint32_t        entry_count;
    uint64_t        total_compressed;
    uint64_t        total_uncompressed;
    double          overall_ratio;
    int             nesting_depth;
    bool            has_overlapping_entries;
    char            trigger_filename[MAX_FILENAME_LEN];
    char            message[512];
} ScanReport;

ScanReport  scan_zip_file(const char *path, int current_depth);
void        print_report(const ScanReport *report);
const char *result_name(DetectionResult r);

#endif
