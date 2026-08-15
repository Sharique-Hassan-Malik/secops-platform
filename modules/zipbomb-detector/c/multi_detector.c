/*
 * multi_detector.c  —  Multi-format archive bomb detector CLI (C99)
 * Build:  make multi_detector
 * Usage:  ./multi_detector <file> [file2 ...]
 */
#include "formats.h"

int main(int argc, char *argv[]) {
    if (argc < 2) {
        fprintf(stderr, "Usage: %s <file> [file2 ...]\n", argv[0]);
        fprintf(stderr, "Formats: zip, gzip, bzip2, tar, 7z, xz, rar, zstd, pt/pth\n");
        return 1;
    }
    int exit_code = 0;
    for (int i = 1; i < argc; i++) {
        printf("Scanning: %s\n", argv[i]);
        FormatResult r = scan_archive(argv[i]);
        print_format_result(&r);
        if (r.is_threat) exit_code = 1;
    }
    return exit_code;
}
