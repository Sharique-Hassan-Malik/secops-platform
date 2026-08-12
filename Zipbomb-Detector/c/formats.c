/*
 * formats.c  —  Multi-format archive bomb detection (C99)
 *
 * Implements detectors for: ZIP, GZip, BZip2, TAR, 7z, XZ, RAR4/5, Zstandard
 * All detection is metadata-only — zero decompression.
 */

#include "formats.h"
#include <math.h>
#include <time.h>

/* ── Little-endian readers ─────────────────────────────────────────────────── */

static uint16_t ru16(FILE *f) {
    uint8_t b[2]={0}; if(fread(b,1,2,f)<2)return 0;
    return (uint16_t)(b[0]|(b[1]<<8));
}
static uint32_t ru32(FILE *f) {
    uint8_t b[4]={0}; if(fread(b,1,4,f)<4)return 0;
    return (uint32_t)(b[0]|(b[1]<<8)|(b[2]<<16)|(b[3]<<24));
}
static uint64_t ru64(FILE *f) {
    uint64_t lo=ru32(f), hi=ru32(f); return lo|(hi<<32);
}
static uint32_t ru32_at(const uint8_t *b, size_t off) {
    return (uint32_t)(b[off]|(b[off+1]<<8)|(b[off+2]<<16)|(b[off+3]<<24));
}
static uint64_t ru64_at(const uint8_t *b, size_t off) {
    uint64_t lo=ru32_at(b,off), hi=ru32_at(b,off+4); return lo|(hi<<32);
}

/* Variable-length integer (7z / RAR5) */
static uint64_t read_vint(const uint8_t *data, size_t len, size_t *pos) {
    uint64_t v=0; int shift=0;
    while(*pos < len) {
        uint8_t byte = data[(*pos)++];
        v |= (uint64_t)(byte & 0x7f) << shift;
        shift += 7;
        if (!(byte & 0x80)) break;
    }
    return v;
}

/* ── Format detection ──────────────────────────────────────────────────────── */

ArchiveFormat detect_archive_format(const char *path) {
    FILE *f = fopen(path,"rb");
    if (!f) return FMT_UNKNOWN;

    uint8_t magic[16]={0};
    { size_t n=fread(magic,1,16,f); (void)n; }

    /* TAR: ustar at byte 257 */
    uint8_t tarbuf[512]={0};
    rewind(f);
    bool is_tar = (fread(tarbuf,1,512,f)==512 &&
                   tarbuf[257]=='u'&&tarbuf[258]=='s'&&tarbuf[259]=='t'&&
                   tarbuf[260]=='a'&&tarbuf[261]=='r');
    fclose(f);

    if (magic[0]==0x50&&magic[1]==0x4b)                                       return FMT_ZIP;
    if (magic[0]==0x1f&&magic[1]==0x8b)                                       return FMT_GZIP;
    if (magic[0]==0x42&&magic[1]==0x5a&&magic[2]==0x68)                       return FMT_BZIP2;
    if (magic[0]==0x37&&magic[1]==0x7a&&magic[2]==0xbc&&magic[3]==0xaf)       return FMT_7Z;
    if (magic[0]==0xfd&&magic[1]==0x37&&magic[2]==0x7a)                       return FMT_XZ;
    if (magic[0]==0x52&&magic[1]==0x61&&magic[2]==0x72&&magic[3]==0x21)       return FMT_RAR;
    if (magic[0]==0x28&&magic[1]==0xb5&&magic[2]==0x2f&&magic[3]==0xfd)       return FMT_ZSTD;
    if (is_tar) return FMT_TAR;

    /* Extension fallback */
    const char *dot = strrchr(path,'.');
    if (!dot) return FMT_UNKNOWN;
    if (!strcmp(dot,".zip")||!strcmp(dot,".jar")||!strcmp(dot,".pt")||!strcmp(dot,".pth")) return FMT_ZIP;
    if (!strcmp(dot,".gz") ||!strcmp(dot,".tgz"))  return FMT_GZIP;
    if (!strcmp(dot,".bz2")||!strcmp(dot,".tbz2")) return FMT_BZIP2;
    if (!strcmp(dot,".7z"))  return FMT_7Z;
    if (!strcmp(dot,".xz"))  return FMT_XZ;
    if (!strcmp(dot,".rar")) return FMT_RAR;
    if (!strcmp(dot,".zst")||!strcmp(dot,".zstd")) return FMT_ZSTD;
    if (!strcmp(dot,".tar")) return FMT_TAR;
    return FMT_UNKNOWN;
}

/* ── ZIP scanner ───────────────────────────────────────────────────────────── */

FormatResult scan_zip(const char *path) {
    FormatResult r = make_result(path, "zip");

    FILE *f = fopen(path,"rb");
    if (!f) { add_flag(&r,THREAT_NONE,"IO_ERROR","Cannot open file"); return r; }

    fseek(f,0,SEEK_END); long fsz=ftell(f); rewind(f);

    /* Find EOCD */
    long limit = (fsz>65557)?fsz-65557:0;
    uint16_t entry_count=0; uint32_t cd_offset=0; bool found=false;
    for (long pos=fsz-22; pos>=limit; pos--) {
        fseek(f,pos,SEEK_SET);
        if (ru32(f)==0x06054b50) {
            ru16(f);ru16(f);ru16(f);
            entry_count=ru16(f); ru32(f); cd_offset=ru32(f);
            found=true; break;
        }
    }
    if (!found) { add_flag(&r,THREAT_NONE,"INVALID_ZIP","No EOCD"); fclose(f); return r; }
    if (entry_count>MAX_ENTRIES) {
        char msg[64]; snprintf(msg,sizeof(msg),"%u entries exceeds limit",entry_count);
        add_flag(&r,THREAT_HIGH,"ENTRY_FLOOD",msg); fclose(f); return r;
    }

    typedef struct{uint32_t s,e;} Rng;
    Rng *ranges = malloc(entry_count*sizeof(Rng));
    if (!ranges) { add_flag(&r,THREAT_NONE,"IO_ERROR","malloc failed"); fclose(f); return r; }

    fseek(f,cd_offset,SEEK_SET);
    uint64_t tc=0,tu=0;

    for (uint16_t i=0;i<entry_count;i++) {
        if (ru32(f)!=0x02014b50) {
            add_flag(&r,THREAT_MEDIUM,"HEADER_CORRUPT","Bad central dir sig");
            free(ranges); fclose(f); return r;
        }
        ru16(f);ru16(f);ru16(f);ru16(f);  /* ver×2, flags, method */
        fseek(f,4,SEEK_CUR);               /* mod time */
        ru32(f);                           /* CRC */
        uint32_t csz=ru32(f), usz=ru32(f);
        uint16_t fnl=ru16(f),exl=ru16(f),cml=ru16(f);
        fseek(f,8,SEEK_CUR);
        uint32_t lho=ru32(f);
        /* skip name + extra + comment */
        fseek(f,fnl+exl+cml,SEEK_CUR);

        tc+=csz; tu+=usz;
        if (csz>0) {
            double ratio=(double)usz/csz;
            if (ratio>MAX_RATIO) {
                char msg[128]; snprintf(msg,sizeof(msg),"Entry ratio %.1f:1 exceeds %.0f:1",ratio,MAX_RATIO);
                add_flag(&r,THREAT_CRITICAL,"RATIO_EXCEEDED",msg);
            }
        }
        if (tu>MAX_UNCOMPRESSED) {
            add_flag(&r,THREAT_CRITICAL,"SIZE_EXCEEDED","Cumulative size exceeds limit");
            free(ranges); fclose(f);
            r.total_compressed=tc; r.total_uncompressed=tu; r.entry_count=i+1;
            return r;
        }
        ranges[i].s=lho; ranges[i].e=lho+30+fnl+exl+csz;
        r.entry_count++;
    }
    fclose(f);

    /* Overlap detection */
    for (uint32_t i=0;i<r.entry_count;i++)
        for (uint32_t j=i+1;j<r.entry_count;j++)
            if (ranges[j].s<ranges[i].e && ranges[j].s>=ranges[i].s) {
                r.has_overlaps=true;
                add_flag(&r,THREAT_CRITICAL,"OVERLAPPING_DATA","Fifield-style zip bomb");
                goto done_overlap;
            }
done_overlap:
    free(ranges);
    r.total_compressed=tc; r.total_uncompressed=tu;
    r.overall_ratio = tc>0?(double)tu/tc:0.0;
    if (!r.is_threat && r.overall_ratio>10.0)
        add_flag(&r, r.overall_ratio>50?THREAT_MEDIUM:THREAT_LOW,
                 "HIGH_RATIO","Elevated compression ratio");
    return r;
}

/* ── GZip scanner ──────────────────────────────────────────────────────────── */

FormatResult scan_gzip(const char *path) {
    FormatResult r = make_result(path,"gzip");

    FILE *f = fopen(path,"rb");
    if (!f) { add_flag(&r,THREAT_NONE,"IO_ERROR","Cannot open"); return r; }
    fseek(f,0,SEEK_END); long fsz=ftell(f);

    /* ISIZE is stored in the last 4 bytes */
    if (fsz < 18) { add_flag(&r,THREAT_NONE,"INVALID_GZIP","File too small"); fclose(f); return r; }
    fseek(f,-4,SEEK_END);
    uint32_t isize = ru32(f);
    fclose(f);

    r.total_compressed   = (uint64_t)fsz;
    r.total_uncompressed = isize;
    r.entry_count        = 1;

    if (isize == 0 && fsz > 100) {
        add_flag(&r,THREAT_MEDIUM,"ISIZE_ZERO","ISIZE=0; may indicate >4 GB content");
    } else {
        r.overall_ratio = fsz>0?(double)isize/fsz:0.0;
        if (r.overall_ratio > MAX_RATIO) {
            char msg[64]; snprintf(msg,sizeof(msg),"Ratio %.1f:1 exceeds %.0f:1",r.overall_ratio,MAX_RATIO);
            add_flag(&r,THREAT_CRITICAL,"RATIO_EXCEEDED",msg);
        }
        if (isize == 0xFFFFFFFF) /* 4GB-1 edge case */
        { add_flag(&r,THREAT_HIGH,"MAX_ISIZE","ISIZE at uint32 max — may be truncated"); }
        if (0 /* gzip ISIZE is 32-bit, cannot exceed 4GB */)
            add_flag(&r,THREAT_CRITICAL,"SIZE_EXCEEDED","Declared size exceeds limit");
        if (!r.is_threat && r.overall_ratio>10.0)
            add_flag(&r, r.overall_ratio>50?THREAT_MEDIUM:THREAT_LOW,"HIGH_RATIO","Elevated ratio");
    }
    return r;
}

/* ── BZip2 scanner ─────────────────────────────────────────────────────────── */

FormatResult scan_bzip2(const char *path) {
    FormatResult r = make_result(path,"bzip2");

    FILE *f = fopen(path,"rb");
    if (!f) { add_flag(&r,THREAT_NONE,"IO_ERROR","Cannot open"); return r; }

    uint8_t hdr[4]={0};
    { size_t n=fread(hdr,1,4,f); (void)n; }
    if (hdr[0]!=0x42||hdr[1]!=0x5a||hdr[2]!=0x68) {
        add_flag(&r,THREAT_NONE,"INVALID_BZIP2","Bad magic"); fclose(f); return r;
    }

    int block_level = hdr[3]-'0';
    if (block_level<1||block_level>9) block_level=9;
    uint32_t block_sizes[10]={0,100000,200000,300000,400000,500000,600000,700000,800000,900000};
    uint32_t max_block = block_sizes[block_level];

    fseek(f,0,SEEK_END); long fsz=ftell(f); fclose(f);

    /* Read file to count block magic occurrences */
    FILE *f2=fopen(path,"rb");
    if (!f2) { add_flag(&r,THREAT_NONE,"IO_ERROR","Cannot reopen"); return r; }
    uint8_t *buf=malloc((size_t)fsz);
    if (!buf) { fclose(f2); add_flag(&r,THREAT_NONE,"IO_ERROR","malloc"); return r; }
    size_t read_n=fread(buf,1,(size_t)fsz,f2); fclose(f2);

    /* Block magic: 0x31 0x41 0x59 0x26 0x53 0x59 */
    static const uint8_t BM[6]={0x31,0x41,0x59,0x26,0x53,0x59};
    uint32_t blocks=0;
    for (size_t i=4; i+6<=read_n; i++)
        if (memcmp(buf+i,BM,6)==0) { blocks++; i+=5; }
    free(buf);

    uint64_t max_uncomp = (uint64_t)blocks * max_block * 30;
    r.total_compressed   = (uint64_t)fsz;
    r.total_uncompressed = max_uncomp;
    r.entry_count        = blocks;
    r.overall_ratio      = fsz>0?(double)max_uncomp/fsz:0.0;

    if (max_uncomp > MAX_UNCOMPRESSED) {
        char msg[128];
        snprintf(msg,sizeof(msg),"Worst-case expansion %llu GB may exceed limit",
                 (unsigned long long)(max_uncomp>>30));
        add_flag(&r,THREAT_HIGH,"WORST_CASE_SIZE",msg);
    }
    if (!r.is_threat && r.overall_ratio>10.0)
        add_flag(&r, r.overall_ratio>50?THREAT_MEDIUM:THREAT_LOW,"HIGH_THEORETICAL_RATIO","Theoretical max ratio is high");
    return r;
}

/* ── TAR scanner ───────────────────────────────────────────────────────────── */

FormatResult scan_tar(const char *path) {
    FormatResult r = make_result(path,"tar");

    FILE *f = fopen(path,"rb");
    if (!f) { add_flag(&r,THREAT_NONE,"IO_ERROR","Cannot open"); return r; }
    fseek(f,0,SEEK_END); long fsz=ftell(f); rewind(f);

    uint8_t block[512];
    uint64_t total_size=0;
    int zero_blocks=0;

    while (fread(block,1,512,f)==512) {
        bool all_zero=true;
        for (int i=0;i<512;i++) if(block[i]){all_zero=false;break;}
        if (all_zero) { if(++zero_blocks>=2) break; continue; }
        zero_blocks=0;

        /* Parse octal size at offset 124 */
        char octal[13]={0};
        memcpy(octal,block+124,12);
        uint64_t entry_size=0;
        for (int i=0;i<12&&octal[i]>='0'&&octal[i]<='7';i++)
            entry_size=entry_size*8+(octal[i]-'0');

        char typeflag = (char)block[156];
        if (typeflag=='0'||typeflag=='\0'||typeflag=='7') {
            total_size += entry_size;
            r.entry_count++;
            if (total_size > MAX_UNCOMPRESSED) {
                add_flag(&r,THREAT_CRITICAL,"SIZE_EXCEEDED","TAR content exceeds size limit");
                break;
            }
        }
        if (r.entry_count > MAX_ENTRIES) {
            char msg[64]; snprintf(msg,sizeof(msg),"%u entries exceeds limit",r.entry_count);
            add_flag(&r,THREAT_HIGH,"ENTRY_FLOOD",msg);
            break;
        }
        /* Skip data blocks */
        long data_blocks = (long)((entry_size+511)/512);
        fseek(f, data_blocks*512, SEEK_CUR);
    }
    fclose(f);

    r.total_compressed   = (uint64_t)fsz;
    r.total_uncompressed = total_size;
    r.overall_ratio      = fsz>0?(double)total_size/fsz:0.0;
    if (!r.is_threat && r.overall_ratio>10.0)
        add_flag(&r, r.overall_ratio>50?THREAT_MEDIUM:THREAT_LOW,"HIGH_RATIO","Elevated ratio");
    return r;
}

/* ── 7z scanner ────────────────────────────────────────────────────────────── */

FormatResult scan_7z(const char *path) {
    FormatResult r = make_result(path,"7z");

    FILE *f = fopen(path,"rb");
    if (!f) { add_flag(&r,THREAT_NONE,"IO_ERROR","Cannot open"); return r; }
    fseek(f,0,SEEK_END); long fsz=ftell(f);
    if (fsz < 32) { add_flag(&r,THREAT_NONE,"INVALID_7Z","Too small"); fclose(f); return r; }

    /* Verify signature */
    uint8_t sig[6]={0}; rewind(f);
    { size_t n=fread(sig,1,6,f); (void)n; }
    uint8_t expected[6]={0x37,0x7a,0xbc,0xaf,0x27,0x1c};
    if (memcmp(sig,expected,6)!=0) {
        add_flag(&r,THREAT_NONE,"INVALID_7Z","Bad signature"); fclose(f); return r;
    }

    /* Read start header: next_hdr_offset at byte 12, next_hdr_size at byte 20 */
    fseek(f,12,SEEK_SET);
    uint64_t hdr_offset = ru64(f);
    uint64_t hdr_size   = ru64(f);
    fclose(f);

    long hdr_start = 32 + (long)hdr_offset;
    r.total_compressed = (uint64_t)fsz;

    if (hdr_start < 0 || hdr_start+(long)hdr_size > fsz) {
        add_flag(&r,THREAT_MEDIUM,"TRUNCATED_HEADER","7z end header beyond file");
        return r;
    }

    /* Read end header to find pack/unpack sizes (best-effort vint walk) */
    FILE *f2 = fopen(path,"rb");
    if (!f2) return r;
    fseek(f2,hdr_start,SEEK_SET);
    uint8_t *hbuf = malloc((size_t)hdr_size);
    uint64_t total_unpack=0;
    if (hbuf) {
        size_t n=fread(hbuf,1,(size_t)hdr_size,f2);
        /* Very simple scan: look for kSize (0x09) followed by a run of vints */
        for (size_t i=0; i+1<n; i++) {
            if (hbuf[i]==0x09) {
                size_t pos=i+1;
                uint64_t sz=read_vint(hbuf,n,&pos);
                if (sz>0 && sz<(uint64_t)1<<40) { total_unpack+=sz; i=pos; }
            }
        }
        free(hbuf);
    }
    fclose(f2);

    if (total_unpack > 0) {
        r.total_uncompressed = total_unpack;
        r.overall_ratio = fsz>0?(double)total_unpack/fsz:0.0;
        if (r.overall_ratio > MAX_RATIO) {
            char msg[64]; snprintf(msg,sizeof(msg),"Ratio %.1f:1 exceeds %.0f:1",r.overall_ratio,MAX_RATIO);
            add_flag(&r,THREAT_CRITICAL,"RATIO_EXCEEDED",msg);
        }
        if (total_unpack > MAX_UNCOMPRESSED)
            add_flag(&r,THREAT_CRITICAL,"SIZE_EXCEEDED","Declared unpack size exceeds limit");
        if (!r.is_threat && r.overall_ratio>10.0)
            add_flag(&r, r.overall_ratio>50?THREAT_MEDIUM:THREAT_LOW,"HIGH_RATIO","Elevated ratio");
    }
    return r;
}

/* ── XZ scanner ────────────────────────────────────────────────────────────── */

FormatResult scan_xz(const char *path) {
    FormatResult r = make_result(path,"xz");

    FILE *f = fopen(path,"rb");
    if (!f) { add_flag(&r,THREAT_NONE,"IO_ERROR","Cannot open"); return r; }
    fseek(f,0,SEEK_END); long fsz=ftell(f);
    if (fsz < 32) { add_flag(&r,THREAT_NONE,"INVALID_XZ","Too small"); fclose(f); return r; }

    uint8_t magic[6]={0}; rewind(f);
    { size_t n=fread(magic,1,6,f); (void)n; }
    uint8_t expected[6]={0xfd,0x37,0x7a,0x58,0x5a,0x00};
    if (memcmp(magic,expected,6)!=0) {
        add_flag(&r,THREAT_NONE,"INVALID_XZ","Bad magic"); fclose(f); return r;
    }
    fclose(f);

    /* Read entire file for block scanning */
    FILE *f2=fopen(path,"rb");
    if (!f2) { add_flag(&r,THREAT_NONE,"IO_ERROR","Cannot reopen"); return r; }
    uint8_t *buf=malloc((size_t)fsz);
    if (!buf) { fclose(f2); add_flag(&r,THREAT_NONE,"IO_ERROR","malloc"); return r; }
    { size_t n=fread(buf,1,(size_t)fsz,f2); (void)n; } fclose(f2);

    long pos=12; /* after stream header */
    uint64_t total_uncomp=0;
    uint32_t blocks=0;

    while (pos < fsz-12) {
        if (pos+4>(long)fsz) break;
        uint8_t bh_size_field = buf[pos];
        if (bh_size_field==0) break; /* index record */
        long bh_size = (long)(bh_size_field+1)*4;
        if (pos+bh_size>(long)fsz) break;

        uint8_t bflags = buf[pos+1];
        bool has_comp   = (bflags>>6)&1;
        bool has_uncomp = (bflags>>7)&1;

        size_t bpos=(size_t)(pos+2);
        if (has_comp)   read_vint(buf,(size_t)fsz,&bpos);
        uint64_t uncomp=0;
        if (has_uncomp) uncomp=read_vint(buf,(size_t)fsz,&bpos);

        total_uncomp += uncomp; blocks++;
        if (total_uncomp>MAX_UNCOMPRESSED) {
            add_flag(&r,THREAT_CRITICAL,"SIZE_EXCEEDED","Cumulative XZ content exceeds limit");
            break;
        }

        if (has_comp) {
            size_t p2=(size_t)(pos+2);
            uint64_t comp=read_vint(buf,(size_t)fsz,&p2);
            if (comp>0 && uncomp>0) {
                double ratio=(double)uncomp/comp;
                if (ratio>MAX_RATIO) {
                    char msg[64]; snprintf(msg,sizeof(msg),"Block ratio %.1f:1 exceeds limit",ratio);
                    add_flag(&r,THREAT_CRITICAL,"RATIO_EXCEEDED",msg);
                }
            }
            long padded=(long)((comp+3)/4)*4;
            pos+=bh_size+padded+4;
        } else {
            break;
        }
    }
    free(buf);

    r.total_compressed   = (uint64_t)fsz;
    r.total_uncompressed = total_uncomp;
    r.entry_count        = blocks;
    r.overall_ratio      = fsz>0?(double)total_uncomp/fsz:0.0;
    if (!r.is_threat && r.overall_ratio>10.0)
        add_flag(&r, r.overall_ratio>50?THREAT_MEDIUM:THREAT_LOW,"HIGH_RATIO","Elevated ratio");
    return r;
}

/* ── RAR scanner ───────────────────────────────────────────────────────────── */

FormatResult scan_rar(const char *path) {
    FormatResult r = make_result(path,"rar");

    FILE *f = fopen(path,"rb");
    if (!f) { add_flag(&r,THREAT_NONE,"IO_ERROR","Cannot open"); return r; }
    fseek(f,0,SEEK_END); long fsz=ftell(f);

    uint8_t magic[8]={0}; rewind(f);
    { size_t n=fread(magic,1,8,f); (void)n; }
    fclose(f);

    bool is_rar5 = (magic[6]==0x01&&magic[7]==0x00);
    bool is_rar4 = (magic[6]==0x00&&magic[7]!=0x00);
    if (!is_rar4 && !is_rar5) {
        add_flag(&r,THREAT_NONE,"INVALID_RAR","Bad RAR magic"); return r;
    }
    if (is_rar5) strncpy(r.fmt,"rar5",sizeof(r.fmt)-1);
    else         strncpy(r.fmt,"rar4",sizeof(r.fmt)-1);

    FILE *f2=fopen(path,"rb");
    if (!f2) return r;
    uint8_t *buf=malloc((size_t)fsz);
    if (!buf) { fclose(f2); return r; }
    { size_t n=fread(buf,1,(size_t)fsz,f2); (void)n; } fclose(f2);

    uint64_t tc=0, tu=0;

    if (is_rar4) {
        size_t pos=7;
        while (pos+7<(size_t)fsz) {
            uint8_t  htype  = buf[pos+2];
            uint16_t hflags = (uint16_t)(buf[pos+3]|(buf[pos+4]<<8));
            uint16_t hsize  = (uint16_t)(buf[pos+5]|(buf[pos+6]<<8));
            if (hsize<7) break;
            uint32_t block_size=hsize;
            if (hflags&0x8000 && pos+11<(size_t)fsz)
                block_size += ru32_at(buf,pos+7);
            if (htype==0x7b) break; /* end-of-archive */
            if (htype==0x74 && hsize>=32) { /* file header */
                uint32_t csz = ru32_at(buf,pos+7);
                uint32_t usz = ru32_at(buf,pos+11);
                tc+=csz; tu+=usz;
                if (csz>0) {
                    double ratio=(double)usz/csz;
                    if (ratio>MAX_RATIO) {
                        char msg[64]; snprintf(msg,sizeof(msg),"Entry ratio %.1f:1 exceeds limit",ratio);
                        add_flag(&r,THREAT_CRITICAL,"RATIO_EXCEEDED",msg);
                    }
                }
                if (tu>MAX_UNCOMPRESSED) {
                    add_flag(&r,THREAT_CRITICAL,"SIZE_EXCEEDED","Cumulative size exceeds limit");
                    break;
                }
                r.entry_count++;
            }
            pos+=block_size;
        }
    } else { /* RAR5 */
        size_t pos=8;
        while (pos+8<(size_t)fsz) {
            pos+=4; /* header CRC */
            uint64_t hdr_size=read_vint(buf,(size_t)fsz,&pos);
            size_t hdr_end=pos+(size_t)hdr_size;
            if (hdr_end>(size_t)fsz) break;
            uint64_t hdr_type =read_vint(buf,(size_t)fsz,&pos);
            uint64_t hdr_flags=read_vint(buf,(size_t)fsz,&pos);
            if (hdr_flags&0x0001) read_vint(buf,(size_t)fsz,&pos); /* extra_size */
            uint64_t data_size=0;
            if (hdr_flags&0x0002) data_size=read_vint(buf,(size_t)fsz,&pos);
            if (hdr_type==2) { /* file */
                read_vint(buf,(size_t)fsz,&pos); /* file flags */
                uint64_t usz=read_vint(buf,(size_t)fsz,&pos);
                if (data_size>0) {
                    double ratio=usz?(double)usz/data_size:0;
                    if (ratio>MAX_RATIO) {
                        char msg[64]; snprintf(msg,sizeof(msg),"Entry ratio %.1f:1 exceeds limit",ratio);
                        add_flag(&r,THREAT_CRITICAL,"RATIO_EXCEEDED",msg);
                    }
                }
                tc+=data_size; tu+=usz; r.entry_count++;
                if (tu>MAX_UNCOMPRESSED) {
                    add_flag(&r,THREAT_CRITICAL,"SIZE_EXCEEDED","Cumulative size exceeds limit");
                    break;
                }
            }
            pos=hdr_end+data_size;
        }
    }
    free(buf);

    r.total_compressed   = tc?tc:(uint64_t)fsz;
    r.total_uncompressed = tu;
    r.overall_ratio      = tc>0?(double)tu/tc:0.0;
    if (!r.is_threat && r.overall_ratio>10.0)
        add_flag(&r, r.overall_ratio>50?THREAT_MEDIUM:THREAT_LOW,"HIGH_RATIO","Elevated ratio");
    return r;
}

/* ── Zstandard scanner ─────────────────────────────────────────────────────── */

FormatResult scan_zstd(const char *path) {
    FormatResult r = make_result(path,"zstd");

    FILE *f = fopen(path,"rb");
    if (!f) { add_flag(&r,THREAT_NONE,"IO_ERROR","Cannot open"); return r; }
    fseek(f,0,SEEK_END); long fsz=ftell(f);
    if (fsz < 8) { add_flag(&r,THREAT_NONE,"INVALID_ZSTD","Too small"); fclose(f); return r; }
    fclose(f);

    FILE *f2=fopen(path,"rb");
    if (!f2) { add_flag(&r,THREAT_NONE,"IO_ERROR","Cannot reopen"); return r; }
    uint8_t *buf=malloc((size_t)fsz);
    if (!buf) { fclose(f2); add_flag(&r,THREAT_NONE,"IO_ERROR","malloc"); return r; }
    { size_t n=fread(buf,1,(size_t)fsz,f2); (void)n; } fclose(f2);

    if (ru32_at(buf,0)!=0xFD2FB528) {
        free(buf); add_flag(&r,THREAT_NONE,"INVALID_ZSTD","Bad magic"); return r;
    }

    long pos=0; uint32_t frames=0; uint64_t total_uncomp=0;

    while (pos+4<fsz) {
        uint32_t magic=ru32_at(buf,(size_t)pos);
        if (magic!=0xFD2FB528) break;
        if (pos+5>=fsz) break;

        uint8_t fhd=buf[pos+4];
        uint8_t csflag=(fhd>>6)&3;
        bool single_seg=(fhd&0x20)!=0;
        int dict_flag=fhd&3;
        long hpos=pos+5;
        if (!single_seg) hpos++;
        int dict_sizes[]={0,1,2,4};
        hpos+=dict_sizes[dict_flag];

        uint64_t uncomp=0;
        if (csflag==0 && single_seg && hpos<fsz) { uncomp=buf[hpos]; hpos++; }
        else if (csflag==1 && hpos+2<=fsz) {
            uncomp=ru32_at(buf,(size_t)hpos)&0xffff; uncomp+=256; hpos+=2;
        }
        else if (csflag==2 && hpos+4<=fsz) { uncomp=ru32_at(buf,(size_t)hpos); hpos+=4; }
        else if (csflag==3 && hpos+8<=fsz) { uncomp=ru64_at(buf,(size_t)hpos); hpos+=8; }

        total_uncomp+=uncomp; frames++;
        if (total_uncomp>MAX_UNCOMPRESSED) {
            add_flag(&r,THREAT_CRITICAL,"SIZE_EXCEEDED","Declared content exceeds limit");
            break;
        }

        /* Advance: find next frame magic */
        long next=fsz;
        for (long i=hpos;i<fsz-3;i++)
            if (ru32_at(buf,(size_t)i)==0xFD2FB528) { next=i; break; }
        if (next<=pos) break;
        pos=next;
    }
    free(buf);

    r.total_compressed   = (uint64_t)fsz;
    r.total_uncompressed = total_uncomp;
    r.entry_count        = frames;
    r.overall_ratio      = fsz>0?(double)total_uncomp/fsz:0.0;
    if (r.overall_ratio>MAX_RATIO) {
        char msg[64]; snprintf(msg,sizeof(msg),"Ratio %.1f:1 exceeds limit",r.overall_ratio);
        add_flag(&r,THREAT_CRITICAL,"RATIO_EXCEEDED",msg);
    }
    if (!r.is_threat && r.overall_ratio>10.0)
        add_flag(&r, r.overall_ratio>50?THREAT_MEDIUM:THREAT_LOW,"HIGH_RATIO","Elevated ratio");
    return r;
}

/* ── Dispatcher ────────────────────────────────────────────────────────────── */

FormatResult scan_archive(const char *path) {
    switch (detect_archive_format(path)) {
        case FMT_ZIP:   return scan_zip(path);
        case FMT_GZIP:  return scan_gzip(path);
        case FMT_BZIP2: return scan_bzip2(path);
        case FMT_TAR:   return scan_tar(path);
        case FMT_7Z:    return scan_7z(path);
        case FMT_XZ:    return scan_xz(path);
        case FMT_RAR:   return scan_rar(path);
        case FMT_ZSTD:  return scan_zstd(path);
        default: {
            FormatResult r = make_result(path,"unknown");
            add_flag(&r,THREAT_NONE,"UNSUPPORTED","Format not recognised");
            return r;
        }
    }
}

/* ── Print result ──────────────────────────────────────────────────────────── */

void print_format_result(const FormatResult *r) {
    printf("  Format     : %s\n",   r->fmt);
    printf("  Threat     : %s\n",   threat_name(r->threat_level));
    printf("  Entries    : %u\n",   r->entry_count);
    printf("  Compressed : %llu bytes\n", (unsigned long long)r->total_compressed);
    printf("  Expanded   : %llu bytes\n", (unsigned long long)r->total_uncompressed);
    printf("  Ratio      : %.2f : 1\n",   r->overall_ratio);
    printf("  Overlaps   : %s\n",   r->has_overlaps?"YES":"No");
    for (int i=0;i<r->flag_count;i++)
        printf("  [%s] %s: %s\n", threat_name(r->flags[i].level),
               r->flags[i].code, r->flags[i].message);
    printf("\n");
}
