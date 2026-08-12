% analyze_compression.m
% ─────────────────────────────────────────────────────────────────────────────
% ZIP Bomb Statistical Analyzer (MATLAB)
%
% Reads ZIP file metadata via Java's java.util.zip.ZipFile (available in
% all MATLAB installations) without extracting any content.
% Performs statistical analysis and anomaly detection on compression ratios.
%
% Usage:
%   analyze_compression('path/to/file.zip')
%   analyze_compression('path/to/file.zip', 'policy', 'strict')
%   results = analyze_compression('path/to/file.zip', 'plot', true)
%
% Returns a struct with fields:
%   .is_threat, .threat_level, .flags, .entries, .stats
%
% Requires: MATLAB R2019b+ (uses Java zip API, no toolbox required)
% ─────────────────────────────────────────────────────────────────────────────

function results = analyze_compression(zip_path, varargin)

    %% ── Parse optional arguments ──────────────────────────────────────────
    p = inputParser;
    addRequired(p,  'zip_path', @ischar);
    addParameter(p, 'policy',   'default', @ischar);
    addParameter(p, 'plot',     false,     @islogical);
    addParameter(p, 'verbose',  true,      @islogical);
    parse(p, zip_path, varargin{:});

    opt = p.Results;

    %% ── Policy thresholds ─────────────────────────────────────────────────
    switch lower(opt.policy)
        case 'strict'
            max_ratio    = 50;
            max_uncomp   = 1e9;   % 1 GB
            max_entries  = 500;
        case 'paranoid'
            max_ratio    = 10;
            max_uncomp   = 2.5e8; % 250 MB
            max_entries  = 100;
        case 'relaxed'
            max_ratio    = 500;
            max_uncomp   = 4e10;
            max_entries  = 50000;
        otherwise % default
            max_ratio    = 100;
            max_uncomp   = 4e9;   % 4 GB
            max_entries  = 10000;
    end

    %% ── Read ZIP metadata via Java ────────────────────────────────────────
    results = struct();
    results.path        = zip_path;
    results.is_threat   = false;
    results.threat_level = 'NONE';   % NONE / LOW / MEDIUM / HIGH / CRITICAL
    results.flags       = {};
    results.entries     = struct('name', {}, 'comp', {}, 'uncomp', {}, 'ratio', {});

    try
        jzip = java.util.zip.ZipFile(zip_path);
    catch e
        results.flags{end+1} = sprintf('IO_ERROR: %s', e.message);
        results.threat_level = 'NONE';
        return;
    end

    entries_java = jzip.entries();
    names        = {};
    comp_sizes   = [];
    uncomp_sizes = [];

    while entries_java.hasMoreElements()
        entry        = entries_java.nextElement();
        comp_sz      = entry.getCompressedSize();
        uncomp_sz    = entry.getSize();
        name         = char(entry.getName());

        % Negative sizes mean "unknown" (streaming entries) — skip
        if comp_sz < 0 || uncomp_sz < 0
            continue
        end

        names{end+1}        = name;      %#ok<AGROW>
        comp_sizes(end+1)   = comp_sz;   %#ok<AGROW>
        uncomp_sizes(end+1) = uncomp_sz; %#ok<AGROW>
    end
    jzip.close();

    n = length(names);

    %% ── Entry count check ─────────────────────────────────────────────────
    if n > max_entries
        results = add_flag(results, 'HIGH', ...
            sprintf('ENTRY_FLOOD: %d entries exceeds limit %d', n, max_entries));
    end

    %% ── Compute ratios ────────────────────────────────────────────────────
    ratios = zeros(1, n);
    for i = 1:n
        if comp_sizes(i) > 0
            ratios(i) = uncomp_sizes(i) / comp_sizes(i);
        else
            ratios(i) = 0;
        end
        results.entries(i).name   = names{i};
        results.entries(i).comp   = comp_sizes(i);
        results.entries(i).uncomp = uncomp_sizes(i);
        results.entries(i).ratio  = ratios(i);

        % Per-entry ratio check
        if ratios(i) > max_ratio
            results = add_flag(results, 'CRITICAL', ...
                sprintf('RATIO_EXCEEDED: "%s" ratio=%.1f:1 (limit %.0f:1)', ...
                        names{i}, ratios(i), max_ratio));
        end
    end

    %% ── Aggregate size check ──────────────────────────────────────────────
    total_uncomp = sum(uncomp_sizes);
    total_comp   = sum(comp_sizes);
    overall_ratio = total_comp > 0 ? total_uncomp / total_comp : 0;

    if total_uncomp > max_uncomp
        results = add_flag(results, 'CRITICAL', ...
            sprintf('SIZE_EXCEEDED: %.2f GB exceeds %.2f GB limit', ...
                    total_uncomp/1e9, max_uncomp/1e9));
    end

    %% ── Statistical analysis ──────────────────────────────────────────────
    stats = struct();
    stats.n             = n;
    stats.total_comp    = total_comp;
    stats.total_uncomp  = total_uncomp;
    stats.overall_ratio = overall_ratio;

    if n > 0
        stats.ratio_mean   = mean(ratios);
        stats.ratio_median = median(ratios);
        stats.ratio_std    = std(ratios);
        stats.ratio_max    = max(ratios);
        stats.ratio_cv     = (stats.ratio_std / stats.ratio_mean) ...
                              * (stats.ratio_mean > 0);

        % Kolmogorov-Smirnov normality test (requires Stats Toolbox)
        try
            [h, p_val] = kstest((ratios - stats.ratio_mean) / max(stats.ratio_std, 1));
            stats.ks_h   = h;
            stats.ks_p   = p_val;
        catch
            stats.ks_h = NaN;
            stats.ks_p = NaN;
        end

        % Interquartile range outlier detection
        q1 = prctile(ratios, 25);
        q3 = prctile(ratios, 75);
        iqr_val = q3 - q1;
        outliers = ratios > (q3 + 3 * iqr_val);
        stats.outlier_count = sum(outliers);
        stats.outlier_names = names(outliers);

        % Uniformity suspicion heuristic
        % High mean + low CV = all entries compress similarly = suspicious
        if stats.ratio_mean > 20 && stats.ratio_cv < 0.1 && n > 5
            results = add_flag(results, 'HIGH', ...
                sprintf('ENTROPY_ANOMALY: High mean ratio (%.1f) with low CV (%.3f) — '...
                        'possible shared data block', ...
                        stats.ratio_mean, stats.ratio_cv));
        end
    else
        stats.ratio_mean   = 0;
        stats.ratio_median = 0;
        stats.ratio_std    = 0;
        stats.ratio_max    = 0;
        stats.ratio_cv     = 0;
        stats.ks_h         = NaN;
        stats.ks_p         = NaN;
        stats.outlier_count = 0;
        stats.outlier_names = {};
    end

    results.stats = stats;

    %% ── Mild ratio warning ────────────────────────────────────────────────
    if ~results.is_threat && overall_ratio > 10
        if overall_ratio > 50
            lv = 'MEDIUM';
        else
            lv = 'LOW';
        end
        results = add_flag(results, lv, ...
            sprintf('HIGH_RATIO: Overall ratio %.2f:1', overall_ratio));
    end

    %% ── Console report ────────────────────────────────────────────────────
    if opt.verbose
        fprintf('\n╔══════════════════════════════════════════╗\n');
        fprintf('║   ZIP Bomb Analyzer  (MATLAB)            ║\n');
        fprintf('╠══════════════════════════════════════════╣\n');
        fprintf('  File          : %s\n', zip_path);
        fprintf('  Threat level  : %s\n', results.threat_level);
        fprintf('  Entries       : %d\n', n);
        fprintf('  Total comp.   : %.2f MB\n', total_comp/1e6);
        fprintf('  Total uncomp. : %.2f MB\n', total_uncomp/1e6);
        fprintf('  Overall ratio : %.2f : 1\n', overall_ratio);
        fprintf('  Ratio mean    : %.2f\n', stats.ratio_mean);
        fprintf('  Ratio median  : %.2f\n', stats.ratio_median);
        fprintf('  Ratio std     : %.2f\n', stats.ratio_std);
        fprintf('  Ratio CV      : %.4f\n', stats.ratio_cv);
        fprintf('  Outliers      : %d\n',   stats.outlier_count);
        if ~isempty(results.flags)
            fprintf('  Flags:\n');
            for i = 1:length(results.flags)
                fprintf('    ⚑  %s\n', results.flags{i});
            end
        end
        fprintf('\n');
    end

    %% ── Optional plot ─────────────────────────────────────────────────────
    if opt.plot && n > 0
        plot_ratios(ratios, names, results.threat_level, zip_path, max_ratio);
    end
end


%% ── Helper: add a threat flag ─────────────────────────────────────────────
function results = add_flag(results, level, message)
    level_order = {'NONE','LOW','MEDIUM','HIGH','CRITICAL'};
    results.flags{end+1} = sprintf('[%s] %s', level, message);

    curr_idx = find(strcmp(results.threat_level, level_order));
    new_idx  = find(strcmp(level,                level_order));
    if new_idx > curr_idx
        results.threat_level = level;
        results.is_threat    = new_idx > 1;
    end
end
