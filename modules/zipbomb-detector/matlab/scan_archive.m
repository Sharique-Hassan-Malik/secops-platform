% scan_archive.m  —  Multi-format archive bomb detection dispatcher (MATLAB)
%
% Detects format by magic bytes, dispatches to the correct scanner.
% Supported: ZIP, GZip, BZip2, TAR, 7z, XZ, RAR, Zstandard
%
% Usage:
%   result = scan_archive('suspicious.7z')
%   result = scan_archive('file.tar.gz', 'policy', 'strict')

function result = scan_archive(path, varargin)
    p = inputParser;
    addRequired(p,  'path',   @ischar);
    addParameter(p, 'policy', 'default', @ischar);
    addParameter(p, 'plot',   false,     @islogical);
    parse(p, path, varargin{:});

    fmt = detect_format(p.Results.path);
    switch fmt
        case 'zip'
            result = analyze_compression(path, 'policy', p.Results.policy, 'plot', p.Results.plot);
            result.fmt = 'zip';
        case 'gzip'
            result = scan_gzip_m(path, p.Results.policy);
        case 'bzip2'
            result = scan_bzip2_m(path, p.Results.policy);
        case 'tar'
            result = scan_tar_m(path, p.Results.policy);
        case '7z'
            result = scan_7z_m(path, p.Results.policy);
        case 'xz'
            result = scan_xz_m(path, p.Results.policy);
        case 'rar'
            result = scan_rar_m(path, p.Results.policy);
        case 'zstd'
            result = scan_zstd_m(path, p.Results.policy);
        otherwise
            result = make_result(path, fmt);
            result = add_flag(result, 'NONE', sprintf('UNSUPPORTED: format "%s" not recognised', fmt));
    end

    % Print summary
    print_result(result);
end

% ── Format detection ──────────────────────────────────────────────────────────

function fmt = detect_format(path)
    fid = fopen(path, 'rb');
    if fid < 0; fmt = 'unknown'; return; end
    magic = fread(fid, 16, 'uint8')';
    fclose(fid);

    % ZIP
    if numel(magic)>=2 && magic(1)==0x50 && magic(2)==0x4b
        fmt = 'zip'; return; end
    % GZip
    if numel(magic)>=2 && magic(1)==0x1f && magic(2)==0x8b
        fmt = 'gzip'; return; end
    % BZip2
    if numel(magic)>=3 && magic(1)==0x42 && magic(2)==0x5a && magic(3)==0x68
        fmt = 'bzip2'; return; end
    % 7z
    if numel(magic)>=6 && magic(1)==0x37 && magic(2)==0x7a && ...
       magic(3)==0xbc && magic(4)==0xaf && magic(5)==0x27 && magic(6)==0x1c
        fmt = '7z'; return; end
    % XZ
    if numel(magic)>=6 && magic(1)==0xfd && magic(2)==0x37 && magic(3)==0x7a
        fmt = 'xz'; return; end
    % RAR
    if numel(magic)>=4 && magic(1)==0x52 && magic(2)==0x61 && ...
       magic(3)==0x72 && magic(4)==0x21
        fmt = 'rar'; return; end
    % Zstandard
    if numel(magic)>=4 && magic(1)==0x28 && magic(2)==0xb5 && ...
       magic(3)==0x2f && magic(4)==0xfd
        fmt = 'zstd'; return; end
    % TAR: ustar at offset 257
    fid = fopen(path,'rb');
    if fid >= 0
        fread(fid, 257, 'uint8');
        ustar = fread(fid, 5, 'uint8')';
        fclose(fid);
        if isequal(ustar, double('ustar'))
            fmt = 'tar'; return; end
    end
    % Extension fallback
    [~,~,ext] = fileparts(path);
    ext = lower(ext);
    switch ext
        case {'.zip','.jar','.pt','.pth'}; fmt='zip';
        case {'.gz','.tgz'};               fmt='gzip';
        case {'.bz2','.tbz2'};             fmt='bzip2';
        case '.7z';                        fmt='7z';
        case '.xz';                        fmt='xz';
        case '.rar';                       fmt='rar';
        case {'.zst','.zstd'};             fmt='zstd';
        case '.tar';                       fmt='tar';
        otherwise;                         fmt='unknown';
    end
end

% ── Policy helper ─────────────────────────────────────────────────────────────

function pol = get_policy(name)
    switch lower(name)
        case 'strict'
            pol = struct('max_ratio',50, 'max_uncomp',1e9, 'max_entries',500);
        case 'paranoid'
            pol = struct('max_ratio',10, 'max_uncomp',2.5e8, 'max_entries',100);
        case 'relaxed'
            pol = struct('max_ratio',500,'max_uncomp',4e10, 'max_entries',50000);
        otherwise
            pol = struct('max_ratio',100,'max_uncomp',4e9, 'max_entries',10000);
    end
end

% ── Result helpers ────────────────────────────────────────────────────────────

function r = make_result(path, fmt)
    r = struct('path',path, 'fmt',fmt, 'is_threat',false, ...
               'threat_level','NONE', 'total_compressed',0, ...
               'total_uncompressed',0, 'overall_ratio',0, ...
               'entry_count',0, 'has_overlaps',false, 'flags',{{}});
end

function r = add_flag(r, level, msg)
    r.flags{end+1} = sprintf('[%s] %s', level, msg);
    order = {'NONE','LOW','MEDIUM','HIGH','CRITICAL'};
    cur = find(strcmp(r.threat_level, order));
    nw  = find(strcmp(level, order));
    if ~isempty(nw) && (isempty(cur) || nw > cur)
        r.threat_level = level;
        r.is_threat = nw > 1;
    end
end

function print_result(r)
    fprintf('  Format     : %s\n', r.fmt);
    fprintf('  Threat     : %s\n', r.threat_level);
    fprintf('  Compressed : %.2f MB\n', r.total_compressed/1e6);
    fprintf('  Expanded   : %.2f MB\n', r.total_uncompressed/1e6);
    fprintf('  Ratio      : %.2f : 1\n', r.overall_ratio);
    fprintf('  Entries    : %d\n', r.entry_count);
    for i = 1:numel(r.flags)
        fprintf('  %s\n', r.flags{i});
    end
    fprintf('\n');
end

function r = soft_ratio(r, pol)
    if ~r.is_threat && r.overall_ratio > 10
        lv = 'LOW';
        if r.overall_ratio > 50; lv = 'MEDIUM'; end
        r = add_flag(r, lv, sprintf('HIGH_RATIO: overall ratio %.1f:1', r.overall_ratio));
    end
end

% ── GZip scanner ─────────────────────────────────────────────────────────────

function r = scan_gzip_m(path, policy_name)
    pol = get_policy(policy_name);
    info = dir(path);
    r = make_result(path, 'gzip');
    if isempty(info); r = add_flag(r,'NONE','IO_ERROR: file not found'); return; end

    fid = fopen(path,'rb');
    magic = fread(fid,2,'uint8')';
    fclose(fid);
    if ~isequal(magic,[0x1f,0x8b])
        r = add_flag(r,'NONE','INVALID_GZIP: bad magic'); return; end

    % ISIZE: last 4 bytes of file (little-endian)
    fid = fopen(path,'rb');
    fseek(fid,-4,'eof');
    isize = double(fread(fid,1,'uint32','l'));
    fclose(fid);

    fsz = info.bytes;
    r.total_compressed   = fsz;
    r.total_uncompressed = isize;
    r.entry_count        = 1;

    if isize == 0 && fsz > 100
        r = add_flag(r,'MEDIUM','ISIZE_ZERO: ISIZE=0, may indicate >4 GB content');
    else
        r.overall_ratio = fsz > 0 ? isize/fsz : 0;
        if r.overall_ratio > pol.max_ratio
            r = add_flag(r,'CRITICAL',sprintf('RATIO_EXCEEDED: %.1f:1 exceeds limit',r.overall_ratio));
        end
        if isize == 2^32-1
            r = add_flag(r,'HIGH','MAX_ISIZE: ISIZE at maximum (4 GB-1)');
        end
        r = soft_ratio(r, pol);
    end
end

% ── BZip2 scanner ────────────────────────────────────────────────────────────

function r = scan_bzip2_m(path, policy_name)
    pol  = get_policy(policy_name);
    info = dir(path);
    r    = make_result(path,'bzip2');
    if isempty(info); r = add_flag(r,'NONE','IO_ERROR: file not found'); return; end

    fid = fopen(path,'rb'); hdr = fread(fid,4,'uint8')'; fclose(fid);
    if ~(hdr(1)==0x42&&hdr(2)==0x5a&&hdr(3)==0x68)
        r = add_flag(r,'NONE','INVALID_BZIP2: bad magic'); return; end

    block_level = hdr(4)-double('0');
    if block_level<1||block_level>9; block_level=9; end
    bsz_table   = [0,1,2,3,4,5,6,7,8,9]*1e5;
    max_block   = bsz_table(block_level+1);

    % Count block magic occurrences
    fid  = fopen(path,'rb');
    data = fread(fid,'uint8')';
    fclose(fid);
    bm   = [0x31,0x41,0x59,0x26,0x53,0x59];
    blocks = 0; i = 5;
    while i+5 <= numel(data)
        if isequal(data(i:i+5), bm); blocks=blocks+1; i=i+6;
        else; i=i+1; end
    end

    max_uncomp = blocks * max_block * 30;
    r.total_compressed   = info.bytes;
    r.total_uncompressed = max_uncomp;
    r.entry_count        = blocks;
    r.overall_ratio      = info.bytes>0 ? max_uncomp/info.bytes : 0;

    if max_uncomp > pol.max_uncomp
        r = add_flag(r,'HIGH',sprintf('WORST_CASE_SIZE: %.1f GB worst-case', max_uncomp/1e9));
    end
    r = soft_ratio(r,pol);
end

% ── TAR scanner ──────────────────────────────────────────────────────────────

function r = scan_tar_m(path, policy_name)
    pol  = get_policy(policy_name);
    info = dir(path);
    r    = make_result(path,'tar');
    if isempty(info); r = add_flag(r,'NONE','IO_ERROR: file not found'); return; end

    fid        = fopen(path,'rb');
    total      = 0;
    entries    = 0;
    zero_count = 0;

    while ~feof(fid)
        block = fread(fid, 512, 'uint8');
        if numel(block) < 512; break; end
        if all(block==0)
            zero_count = zero_count+1;
            if zero_count >= 2; break; end
            continue;
        end
        zero_count = 0;

        % Size field: bytes 125-136 (1-indexed), octal ASCII
        size_bytes = block(125:136);
        size_str   = char(size_bytes(size_bytes>=48 & size_bytes<=55)');
        if isempty(size_str); sz=0;
        else; sz = base2dec(size_str,8); end

        typeflag = block(157);
        if typeflag==48||typeflag==0||typeflag==55  % '0', '\0', '7'
            total   = total + sz;
            entries = entries + 1;
            if total > pol.max_uncomp
                r = add_flag(r,'CRITICAL','SIZE_EXCEEDED: TAR content exceeds limit');
                break;
            end
        end
        if entries > pol.max_entries
            r = add_flag(r,'HIGH',sprintf('ENTRY_FLOOD: %d entries exceeds limit',entries));
            break;
        end
        skip_blocks = ceil(sz/512);
        fread(fid, skip_blocks*512, 'uint8');
    end
    fclose(fid);

    r.total_compressed   = info.bytes;
    r.total_uncompressed = total;
    r.entry_count        = entries;
    r.overall_ratio      = info.bytes>0 ? total/info.bytes : 0;
    r = soft_ratio(r,pol);
end

% ── 7z scanner ───────────────────────────────────────────────────────────────

function r = scan_7z_m(path, policy_name)
    pol  = get_policy(policy_name);
    info = dir(path);
    r    = make_result(path,'7z');
    if isempty(info)||info.bytes<32; r=add_flag(r,'NONE','INVALID_7Z: too small'); return; end

    fid   = fopen(path,'rb');
    magic = fread(fid,6,'uint8')';
    fclose(fid);
    if ~isequal(magic,[0x37,0x7a,0xbc,0xaf,0x27,0x1c])
        r = add_flag(r,'NONE','INVALID_7Z: bad signature'); return; end

    fid      = fopen(path,'rb');
    fseek(fid,12,'bof');
    hdr_off  = fread(fid,1,'uint64','l');
    hdr_size = fread(fid,1,'uint64','l');
    fclose(fid);

    hdr_start = 32 + hdr_off + 1;  % MATLAB is 1-indexed
    r.total_compressed = info.bytes;

    if hdr_start + hdr_size - 1 > info.bytes
        r = add_flag(r,'MEDIUM','TRUNCATED_HEADER: end header beyond file'); return; end

    fid  = fopen(path,'rb');
    fseek(fid, hdr_start-1, 'bof');
    hdr  = fread(fid, hdr_size, 'uint8')';
    fclose(fid);

    % Scan for kSize property (0x09) and sum vints
    total_unpack = 0;
    i = 1;
    while i < numel(hdr)
        if hdr(i)==0x09
            [sz, consumed] = read_vint_m(hdr, i+1);
            if sz>0 && sz<2^40; total_unpack=total_unpack+sz; i=i+consumed; continue; end
        end
        i = i+1;
    end

    if total_unpack > 0
        r.total_uncompressed = total_unpack;
        r.overall_ratio      = info.bytes>0 ? total_unpack/info.bytes : 0;
        if r.overall_ratio > pol.max_ratio
            r = add_flag(r,'CRITICAL',sprintf('RATIO_EXCEEDED: %.1f:1 exceeds limit',r.overall_ratio));
        end
        if total_unpack > pol.max_uncomp
            r = add_flag(r,'CRITICAL','SIZE_EXCEEDED: declared unpack size exceeds limit');
        end
        r = soft_ratio(r,pol);
    end
end

% ── XZ scanner ───────────────────────────────────────────────────────────────

function r = scan_xz_m(path, policy_name)
    pol  = get_policy(policy_name);
    info = dir(path);
    r    = make_result(path,'xz');
    if isempty(info)||info.bytes<32; r=add_flag(r,'NONE','INVALID_XZ: too small'); return; end

    fid   = fopen(path,'rb');
    magic = fread(fid,6,'uint8')';
    fclose(fid);
    if ~isequal(magic,[0xfd,0x37,0x7a,0x58,0x5a,0x00])
        r = add_flag(r,'NONE','INVALID_XZ: bad magic'); return; end

    fid  = fopen(path,'rb');
    data = fread(fid,'uint8')';
    fclose(fid);

    pos = 13; total_uncomp = 0; blocks = 0; % 1-indexed
    while pos+3 <= numel(data)
        if data(pos)==0; break; end
        bh_size = (double(data(pos))+1)*4;
        if pos+bh_size-1 > numel(data); break; end
        bflags = data(pos+1);
        has_comp   = bitand(bflags,64)  ~= 0;
        has_uncomp = bitand(bflags,128) ~= 0;
        bpos = pos+2;
        if has_comp;   [comp,  n]=read_vint_m(data,bpos); bpos=bpos+n; else; comp=0; end
        if has_uncomp; [uncomp,n]=read_vint_m(data,bpos); bpos=bpos+n; else; uncomp=0; end

        total_uncomp = total_uncomp + uncomp;
        blocks       = blocks + 1;
        if total_uncomp > pol.max_uncomp
            r = add_flag(r,'CRITICAL','SIZE_EXCEEDED: XZ content exceeds limit'); break; end
        if comp>0 && uncomp>0 && uncomp/comp>pol.max_ratio
            r = add_flag(r,'CRITICAL',sprintf('RATIO_EXCEEDED: block ratio %.1f:1',uncomp/comp));
        end
        if has_comp; padded=ceil(comp/4)*4; pos=pos+bh_size+padded+4;
        else; break; end
    end

    r.total_compressed   = info.bytes;
    r.total_uncompressed = total_uncomp;
    r.entry_count        = blocks;
    r.overall_ratio      = info.bytes>0 ? total_uncomp/info.bytes : 0;
    r = soft_ratio(r,pol);
end

% ── RAR scanner ──────────────────────────────────────────────────────────────

function r = scan_rar_m(path, policy_name)
    pol  = get_policy(policy_name);
    info = dir(path);
    r    = make_result(path,'rar');
    if isempty(info)||info.bytes<8; r=add_flag(r,'NONE','INVALID_RAR: too small'); return; end

    fid   = fopen(path,'rb');
    magic = fread(fid,8,'uint8')';
    fclose(fid);
    is5 = (magic(7)==0x01 && magic(8)==0x00);
    is4 = (magic(7)==0x00 && ~is5);
    if ~is4 && ~is5; r=add_flag(r,'NONE','INVALID_RAR: bad magic'); return; end

    fid  = fopen(path,'rb');
    data = fread(fid,'uint8')';
    fclose(fid);

    tc=0; tu=0;
    if is4
        pos = 8; % 1-indexed
        while pos+6 < numel(data)
            htype  = data(pos+2);
            hflags = data(pos+3) + data(pos+4)*256;
            hsize  = data(pos+5) + data(pos+6)*256;
            if hsize==0; break; end
            bsz = hsize;
            if bitand(hflags,0x8000)~=0 && pos+10<numel(data)
                bsz = bsz + typecast(uint8(data(pos+7:pos+10)),'uint32'); end
            if htype==0x7b; break; end
            if htype==0x74 && hsize>=32
                csz = typecast(uint8(data(pos+7:pos+10)),'uint32');
                usz = typecast(uint8(data(pos+11:pos+14)),'uint32');
                tc=tc+double(csz); tu=tu+double(usz);
                if csz>0 && double(usz)/double(csz)>pol.max_ratio
                    r=add_flag(r,'CRITICAL','RATIO_EXCEEDED: entry exceeds ratio limit'); end
                if tu>pol.max_uncomp
                    r=add_flag(r,'CRITICAL','SIZE_EXCEEDED: cumulative size exceeds limit'); break; end
            end
            pos = pos+bsz;
        end
    else
        pos = 9;
        while pos+7 < numel(data)
            pos=pos+4; % skip CRC
            [hsz,n]=read_vint_m(data,pos); pos=pos+n; hend=pos+hsz;
            [htype,n]=read_vint_m(data,pos); pos=pos+n;
            [hflags,n]=read_vint_m(data,pos); pos=pos+n;
            if bitand(hflags,1); [~,n]=read_vint_m(data,pos); pos=pos+n; end
            dsz=0;
            if bitand(hflags,2); [dsz,n]=read_vint_m(data,pos); pos=pos+n; end
            if htype==2
                [~,n]=read_vint_m(data,pos); pos=pos+n;
                [usz,n]=read_vint_m(data,pos); pos=pos+n;
                tc=tc+dsz; tu=tu+usz;
                if dsz>0 && usz/dsz>pol.max_ratio
                    r=add_flag(r,'CRITICAL','RATIO_EXCEEDED: entry exceeds ratio limit'); end
                if tu>pol.max_uncomp
                    r=add_flag(r,'CRITICAL','SIZE_EXCEEDED: cumulative size exceeds limit'); break; end
            end
            if hend+dsz > numel(data); break; end
            pos = hend+dsz;
        end
    end

    r.total_compressed   = max(tc, info.bytes);
    r.total_uncompressed = tu;
    r.overall_ratio      = tc>0 ? tu/tc : 0;
    r.entry_count        = 0;
    r = soft_ratio(r,pol);
end

% ── Zstandard scanner ────────────────────────────────────────────────────────

function r = scan_zstd_m(path, policy_name)
    pol  = get_policy(policy_name);
    info = dir(path);
    r    = make_result(path,'zstd');
    if isempty(info)||info.bytes<8; r=add_flag(r,'NONE','INVALID_ZSTD: too small'); return; end

    fid  = fopen(path,'rb');
    data = fread(fid,'uint8')';
    fclose(fid);

    magic_val = typecast(uint8(data(1:4)),'uint32');
    if magic_val ~= 0xFD2FB528
        r = add_flag(r,'NONE','INVALID_ZSTD: bad magic'); return; end

    pos=1; frames=0; total=0;
    while pos+3 <= numel(data)
        m = typecast(uint8(data(pos:pos+3)),'uint32');
        if m ~= 0xFD2FB528; break; end
        if pos+4 > numel(data); break; end
        fhd     = data(pos+4);
        csflag  = bitshift(fhd,-6);
        single  = bitand(fhd,0x20)~=0;
        dict_sz = [0,1,2,4];
        dict_bytes = dict_sz(bitand(fhd,3)+1);
        hpos = pos+5 + ~single + dict_bytes;  % skip window desc if not single

        uncomp = 0;
        if csflag==0 && single && hpos<=numel(data)
            uncomp=data(hpos); hpos=hpos+1;
        elseif csflag==1 && hpos+1<=numel(data)
            uncomp=double(typecast(uint8(data(hpos:hpos+1)),'uint16'))+256; hpos=hpos+2;
        elseif csflag==2 && hpos+3<=numel(data)
            uncomp=double(typecast(uint8(data(hpos:hpos+3)),'uint32')); hpos=hpos+4;
        elseif csflag==3 && hpos+7<=numel(data)
            uncomp=double(typecast(uint8(data(hpos:hpos+7)),'uint64')); hpos=hpos+8;
        end

        total=total+uncomp; frames=frames+1;
        if total>pol.max_uncomp
            r=add_flag(r,'CRITICAL','SIZE_EXCEEDED: declared content exceeds limit'); break; end

        % Find next frame
        next = numel(data)+1;
        for i=hpos:numel(data)-3
            if typecast(uint8(data(i:i+3)),'uint32')==0xFD2FB528
                next=i; break; end
        end
        if next<=pos; break; end
        pos=next;
    end

    r.total_compressed   = info.bytes;
    r.total_uncompressed = total;
    r.entry_count        = frames;
    r.overall_ratio      = info.bytes>0 ? total/info.bytes : 0;
    if r.overall_ratio>pol.max_ratio
        r=add_flag(r,'CRITICAL',sprintf('RATIO_EXCEEDED: %.1f:1 exceeds limit',r.overall_ratio));
    end
    r = soft_ratio(r,pol);
end

% ── Variable-length integer helper ───────────────────────────────────────────

function [value, consumed] = read_vint_m(data, start)
    value=0; shift=0; pos=start;
    while pos<=numel(data)
        b=data(pos); pos=pos+1;
        value=value+bitand(b,127)*2^shift;
        shift=shift+7;
        if bitand(b,128)==0; break; end
    end
    consumed = pos-start;
end
