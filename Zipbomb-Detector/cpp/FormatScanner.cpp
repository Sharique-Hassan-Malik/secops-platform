// FormatScanner.cpp  —  Multi-format archive bomb detection (C++17)
// Build:  make (see Makefile)

#include "FormatScanner.h"
#include <fstream>
#include <algorithm>
#include <cstring>
#include <sstream>
#include <iomanip>

using namespace std;
using namespace ZipBombDetector;
namespace fs = filesystem;

// ── Utility readers ──────────────────────────────────────────────────────────

static uint16_t u16le(const uint8_t *b) { return uint16_t(b[0]|(b[1]<<8)); }
static uint32_t u32le(const uint8_t *b) { return uint32_t(b[0]|(b[1]<<8)|(b[2]<<16)|(b[3]<<24)); }
static uint64_t u64le(const uint8_t *b) { return uint64_t(u32le(b))|(uint64_t(u32le(b+4))<<32); }

static uint64_t read_vint(const vector<uint8_t> &d, size_t &pos) {
    uint64_t v=0; int shift=0;
    while (pos<d.size()) {
        uint8_t byte=d[pos++]; v|=uint64_t(byte&0x7f)<<shift; shift+=7;
        if (!(byte&0x80)) break;
    }
    return v;
}

static vector<uint8_t> read_file(const fs::path &p) {
    ifstream f(p, ios::binary);
    return vector<uint8_t>(istreambuf_iterator<char>(f), {});
}

static ScanResult make_result(const fs::path &p, const string &fmt) {
    ScanResult r; r.path = p.string();
    // Store fmt in details via a workaround — ScanResult has no fmt field
    // We add a flag note instead which appears in summary
    (void)fmt;
    return r;
}

static void add(ScanResult &r, ThreatLevel lv, const string &code, const string &desc,
                const ScanPolicy &) {
    r.flags.push_back({lv, code, desc});
    if (lv > r.threat_level) r.threat_level = lv;
    r.is_threat = r.threat_level > ThreatLevel::None;
}

static void soft_ratio(ScanResult &r, const ScanPolicy &pol) {
    if (!r.is_threat && r.overall_ratio > 10.0) {
        auto lv = r.overall_ratio > 50.0 ? ThreatLevel::Medium : ThreatLevel::Low;
        add(r, lv, "HIGH_RATIO", "Overall ratio " + to_string(r.overall_ratio), pol);
    }
}

// ── GZip ─────────────────────────────────────────────────────────────────────

ScanResult ZipBombDetector::scan_gzip(const fs::path &p, const ScanPolicy &pol) {
    ScanResult r = make_result(p, "gzip");
    auto data = read_file(p);
    if (data.size() < 18) { add(r,ThreatLevel::None,"INVALID_GZIP","Too small",pol); return r; }
    if (data[0]!=0x1f||data[1]!=0x8b) { add(r,ThreatLevel::None,"INVALID_GZIP","Bad magic",pol); return r; }

    uint32_t isize = u32le(data.data()+data.size()-4);
    uint64_t fsz   = data.size();
    r.total_compressed   = fsz;
    r.total_uncompressed = isize;
    r.entry_count        = 1;

    if (isize==0 && fsz>100) {
        add(r,ThreatLevel::Medium,"ISIZE_ZERO","ISIZE=0; may indicate >4 GB content",pol);
    } else {
        r.overall_ratio = fsz>0?(double)isize/fsz:0.0;
        if (r.overall_ratio > pol.max_ratio)
            add(r,ThreatLevel::Critical,"RATIO_EXCEEDED",
                "Ratio "+to_string(r.overall_ratio)+":1 exceeds "+to_string(pol.max_ratio),pol);
        if (isize==0xFFFFFFFF)
            add(r,ThreatLevel::High,"MAX_ISIZE","ISIZE at max (4 GB-1); possible truncation",pol);
        soft_ratio(r,pol);
    }
    return r;
}

// ── BZip2 ────────────────────────────────────────────────────────────────────

ScanResult ZipBombDetector::scan_bzip2(const fs::path &p, const ScanPolicy &pol) {
    ScanResult r = make_result(p,"bzip2");
    auto data = read_file(p);
    if (data.size()<4) { add(r,ThreatLevel::None,"INVALID_BZIP2","Too small",pol); return r; }
    if (data[0]!=0x42||data[1]!=0x5a||data[2]!=0x68) {
        add(r,ThreatLevel::None,"INVALID_BZIP2","Bad magic",pol); return r;
    }

    int level = data[3]-'0';
    if (level<1||level>9) level=9;
    static const uint32_t bsz[10]={0,100000,200000,300000,400000,500000,600000,700000,800000,900000};

    static const uint8_t BM[6]={0x31,0x41,0x59,0x26,0x53,0x59};
    uint32_t blocks=0;
    for (size_t i=4; i+6<=data.size(); i++)
        if (memcmp(data.data()+i,BM,6)==0) { blocks++; i+=5; }

    uint64_t max_uncomp = uint64_t(blocks)*bsz[level]*30;
    r.total_compressed   = data.size();
    r.total_uncompressed = max_uncomp;
    r.entry_count        = blocks;
    r.overall_ratio      = data.size()>0?(double)max_uncomp/data.size():0.0;

    if (max_uncomp > pol.max_uncompressed)
        add(r,ThreatLevel::High,"WORST_CASE_SIZE",
            "Worst-case expansion "+to_string(max_uncomp>>30)+" GB may exceed limit",pol);
    soft_ratio(r,pol);
    return r;
}

// ── TAR ──────────────────────────────────────────────────────────────────────

ScanResult ZipBombDetector::scan_tar(const fs::path &p, const ScanPolicy &pol) {
    ScanResult r = make_result(p,"tar");
    ifstream f(p, ios::binary);
    if (!f) { add(r,ThreatLevel::None,"IO_ERROR","Cannot open",pol); return r; }
    uint64_t fsz = fs::file_size(p);

    uint8_t block[512];
    uint64_t total=0;
    int zero_blocks=0;

    while (f.read(reinterpret_cast<char*>(block),512)) {
        bool all_zero = all_of(block,block+512,[](uint8_t b){return b==0;});
        if (all_zero) { if(++zero_blocks>=2) break; continue; }
        zero_blocks=0;

        char octal[13]={};
        memcpy(octal,block+124,12);
        uint64_t sz=0;
        for (int i=0;i<12&&octal[i]>='0'&&octal[i]<='7';i++) sz=sz*8+(octal[i]-'0');

        char tf=char(block[156]);
        if (tf=='0'||tf=='\0'||tf=='7') {
            total+=sz; r.entry_count++;
            if (total>pol.max_uncompressed) {
                add(r,ThreatLevel::Critical,"SIZE_EXCEEDED","TAR content exceeds size limit",pol);
                break;
            }
        }
        if (r.entry_count>pol.max_entries) {
            add(r,ThreatLevel::High,"ENTRY_FLOOD",
                to_string(r.entry_count)+" entries exceeds limit",pol);
            break;
        }
        long skip=(long)((sz+511)/512)*512;
        f.seekg(skip,ios::cur);
    }

    r.total_compressed   = fsz;
    r.total_uncompressed = total;
    r.overall_ratio      = fsz>0?(double)total/fsz:0.0;
    soft_ratio(r,pol);
    return r;
}

// ── 7z ───────────────────────────────────────────────────────────────────────

ScanResult ZipBombDetector::scan_7z(const fs::path &p, const ScanPolicy &pol) {
    ScanResult r = make_result(p,"7z");
    auto data = read_file(p);
    if (data.size()<32) { add(r,ThreatLevel::None,"INVALID_7Z","Too small",pol); return r; }

    static const uint8_t SIG[6]={0x37,0x7a,0xbc,0xaf,0x27,0x1c};
    if (memcmp(data.data(),SIG,6)!=0) {
        add(r,ThreatLevel::None,"INVALID_7Z","Bad signature",pol); return r;
    }

    uint64_t hdr_off  = u64le(data.data()+12);
    uint64_t hdr_size = u64le(data.data()+20);
    size_t   hdr_start= 32+(size_t)hdr_off;
    r.total_compressed = data.size();

    if (hdr_start+hdr_size > data.size()) {
        add(r,ThreatLevel::Medium,"TRUNCATED_HEADER","End header beyond file boundary",pol);
        return r;
    }

    // Walk end header: scan for kSize (0x09) property tags and sum vints
    uint64_t total_unpack=0;
    for (size_t i=hdr_start; i+1<hdr_start+hdr_size; i++) {
        if (data[i]==0x09) {
            size_t pos=i+1;
            uint64_t sz=read_vint(data,pos);
            if (sz>0 && sz<(uint64_t(1)<<40)) { total_unpack+=sz; i=pos; }
        }
    }

    if (total_unpack>0) {
        r.total_uncompressed = total_unpack;
        r.overall_ratio = data.size()>0?(double)total_unpack/data.size():0.0;
        if (r.overall_ratio>pol.max_ratio)
            add(r,ThreatLevel::Critical,"RATIO_EXCEEDED",
                "Ratio "+to_string(r.overall_ratio)+":1 exceeds limit",pol);
        if (total_unpack>pol.max_uncompressed)
            add(r,ThreatLevel::Critical,"SIZE_EXCEEDED","Declared unpack size exceeds limit",pol);
        soft_ratio(r,pol);
    }
    return r;
}

// ── XZ ───────────────────────────────────────────────────────────────────────

ScanResult ZipBombDetector::scan_xz(const fs::path &p, const ScanPolicy &pol) {
    ScanResult r = make_result(p,"xz");
    auto data = read_file(p);
    if (data.size()<32) { add(r,ThreatLevel::None,"INVALID_XZ","Too small",pol); return r; }

    static const uint8_t XZ_SIG[6]={0xfd,0x37,0x7a,0x58,0x5a,0x00};
    if (memcmp(data.data(),XZ_SIG,6)!=0) {
        add(r,ThreatLevel::None,"INVALID_XZ","Bad magic",pol); return r;
    }

    size_t pos=12; uint64_t total_uncomp=0; uint32_t blocks=0;
    while (pos+4<data.size()) {
        if (data[pos]==0) break;
        long bh_size=(long(data[pos])+1)*4;
        if (pos+(size_t)bh_size>data.size()) break;

        uint8_t bflags=data[pos+1];
        bool has_comp  =(bflags>>6)&1;
        bool has_uncomp=(bflags>>7)&1;
        size_t bpos=pos+2;
        if (has_comp)   read_vint(data,bpos);
        uint64_t uncomp=has_uncomp?read_vint(data,bpos):0;

        total_uncomp+=uncomp; blocks++;
        if (total_uncomp>pol.max_uncompressed) {
            add(r,ThreatLevel::Critical,"SIZE_EXCEEDED","Cumulative XZ content exceeds limit",pol);
            break;
        }
        if (has_comp) {
            size_t p2=pos+2;
            uint64_t comp=read_vint(data,p2);
            if (comp>0&&uncomp>0) {
                double ratio=(double)uncomp/comp;
                if (ratio>pol.max_ratio)
                    add(r,ThreatLevel::Critical,"RATIO_EXCEEDED",
                        "Block ratio "+to_string(ratio)+":1 exceeds limit",pol);
            }
            long padded=(long((comp+3)/4))*4;
            pos+=bh_size+padded+4;
        } else break;
    }
    r.total_compressed   = data.size();
    r.total_uncompressed = total_uncomp;
    r.entry_count        = blocks;
    r.overall_ratio      = data.size()>0?(double)total_uncomp/data.size():0.0;
    soft_ratio(r,pol);
    return r;
}

// ── RAR ──────────────────────────────────────────────────────────────────────

ScanResult ZipBombDetector::scan_rar(const fs::path &p, const ScanPolicy &pol) {
    ScanResult r = make_result(p,"rar");
    auto data = read_file(p);
    if (data.size()<8) { add(r,ThreatLevel::None,"INVALID_RAR","Too small",pol); return r; }

    bool is5=(data[6]==0x01&&data[7]==0x00);
    bool is4=(data[6]==0x00);
    if (!is4&&!is5) { add(r,ThreatLevel::None,"INVALID_RAR","Bad magic",pol); return r; }

    uint64_t tc=0,tu=0;

    if (is4) {
        size_t pos=7;
        while (pos+7<data.size()) {
            uint8_t  htype  = data[pos+2];
            uint16_t hflags = u16le(data.data()+pos+3);
            uint16_t hsize  = u16le(data.data()+pos+5);
            if (!hsize) break;
            uint32_t bsz=hsize;
            if ((hflags&0x8000)&&pos+11<data.size()) bsz+=u32le(data.data()+pos+7);
            if (htype==0x7b) break;
            if (htype==0x74&&hsize>=32) {
                uint32_t csz=u32le(data.data()+pos+7);
                uint32_t usz=u32le(data.data()+pos+11);
                tc+=csz; tu+=usz; r.entry_count++;
                if (csz&&usz&&(double)usz/csz>pol.max_ratio)
                    add(r,ThreatLevel::Critical,"RATIO_EXCEEDED","Entry exceeds ratio limit",pol);
                if (tu>pol.max_uncompressed) {
                    add(r,ThreatLevel::Critical,"SIZE_EXCEEDED","Cumulative size exceeds limit",pol); break;
                }
            }
            pos+=bsz;
        }
    } else {
        size_t pos=8;
        while (pos+8<data.size()) {
            pos+=4;
            uint64_t hsz  =read_vint(data,pos);
            size_t   hend =pos+(size_t)hsz;
            uint64_t htype=read_vint(data,pos);
            uint64_t hflags=read_vint(data,pos);
            if (hflags&1) read_vint(data,pos);
            uint64_t dsz=0;
            if (hflags&2) dsz=read_vint(data,pos);
            if (htype==2) {
                read_vint(data,pos);
                uint64_t usz=read_vint(data,pos);
                tc+=dsz; tu+=usz; r.entry_count++;
                if (dsz&&usz&&(double)usz/dsz>pol.max_ratio)
                    add(r,ThreatLevel::Critical,"RATIO_EXCEEDED","Entry exceeds ratio limit",pol);
                if (tu>pol.max_uncompressed) {
                    add(r,ThreatLevel::Critical,"SIZE_EXCEEDED","Cumulative size exceeds limit",pol); break;
                }
            }
            pos=hend+(size_t)dsz;
        }
    }

    r.total_compressed   = tc?tc:data.size();
    r.total_uncompressed = tu;
    r.overall_ratio      = tc>0?(double)tu/tc:0.0;
    soft_ratio(r,pol);
    return r;
}

// ── Zstandard ────────────────────────────────────────────────────────────────

ScanResult ZipBombDetector::scan_zstd(const fs::path &p, const ScanPolicy &pol) {
    ScanResult r = make_result(p,"zstd");
    auto data = read_file(p);
    if (data.size()<8) { add(r,ThreatLevel::None,"INVALID_ZSTD","Too small",pol); return r; }
    if (u32le(data.data())!=0xFD2FB528) {
        add(r,ThreatLevel::None,"INVALID_ZSTD","Bad magic",pol); return r;
    }

    size_t pos=0; uint32_t frames=0; uint64_t total=0;
    while (pos+4<data.size()) {
        if (u32le(data.data()+pos)!=0xFD2FB528) break;
        if (pos+5>=data.size()) break;
        uint8_t fhd=data[pos+4];
        uint8_t csflag=(fhd>>6)&3;
        bool single_seg=(fhd&0x20)!=0;
        int dict_sizes[]={0,1,2,4};
        size_t hpos=pos+5;
        if (!single_seg) hpos++;
        hpos+=dict_sizes[fhd&3];

        uint64_t uncomp=0;
        if (csflag==0&&single_seg&&hpos<data.size()) { uncomp=data[hpos]; hpos++; }
        else if (csflag==1&&hpos+2<=data.size()) { uncomp=u16le(data.data()+hpos)+256; hpos+=2; }
        else if (csflag==2&&hpos+4<=data.size()) { uncomp=u32le(data.data()+hpos); hpos+=4; }
        else if (csflag==3&&hpos+8<=data.size()) { uncomp=u64le(data.data()+hpos); hpos+=8; }

        total+=uncomp; frames++;
        if (total>pol.max_uncompressed) {
            add(r,ThreatLevel::Critical,"SIZE_EXCEEDED","Declared content exceeds limit",pol); break;
        }

        size_t next=data.size();
        for (size_t i=hpos;i+3<data.size();i++)
            if (u32le(data.data()+i)==0xFD2FB528) { next=i; break; }
        if (next<=pos) break;
        pos=next;
    }

    r.total_compressed   = data.size();
    r.total_uncompressed = total;
    r.entry_count        = frames;
    r.overall_ratio      = data.size()>0?(double)total/data.size():0.0;
    if (r.overall_ratio>pol.max_ratio)
        add(r,ThreatLevel::Critical,"RATIO_EXCEEDED",
            "Ratio "+to_string(r.overall_ratio)+":1 exceeds limit",pol);
    soft_ratio(r,pol);
    return r;
}

// ── Dispatcher ───────────────────────────────────────────────────────────────

ScanResult ZipBombDetector::scan_archive(const fs::path &p, const ScanPolicy &pol) {
    string fmt = detect_format(p);

    if (fmt=="zip"||fmt=="jar"||fmt=="war"||fmt=="apk"||
        fmt=="docx"||fmt=="xlsx"||fmt=="pptx"||fmt=="pytorch") {
        ArchiveAnalyzer az(pol);
        return az.scan(p);
    }
    if (fmt=="gzip")  return scan_gzip(p, pol);
    if (fmt=="bzip2") return scan_bzip2(p,pol);
    if (fmt=="tar"||fmt=="tar.gz"||fmt=="tar.bzip2"||fmt=="tar.xz")
                      return scan_tar(p,pol);
    if (fmt=="7z")    return scan_7z(p,  pol);
    if (fmt=="xz")    return scan_xz(p,  pol);
    if (fmt=="rar4"||fmt=="rar5"||fmt=="rar")
                      return scan_rar(p,  pol);
    if (fmt=="zstd")  return scan_zstd(p, pol);

    ScanResult r; r.path=p.string();
    r.flags.push_back({ThreatLevel::None,"UNSUPPORTED","Format '"+fmt+"' not supported"});
    return r;
}
