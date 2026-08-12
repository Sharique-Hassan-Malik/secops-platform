function plot_ratios(ratios, names, threat_level, zip_path, max_ratio)
% plot_ratios  —  Visualize per-entry compression ratios
%
% Called automatically by analyze_compression when 'plot' = true.
% Produces a 2x2 dashboard:
%   1. Bar chart of per-entry ratios
%   2. Histogram of ratio distribution
%   3. Box plot with outlier annotation
%   4. Cumulative uncompressed size curve

    n = length(ratios);
    if n == 0, return; end

    % Colour scheme
    danger_color  = [0.85, 0.20, 0.20];
    safe_color    = [0.20, 0.60, 0.35];
    warn_color    = [0.95, 0.65, 0.10];
    bg_color      = [0.97, 0.97, 0.97];

    switch upper(threat_level)
        case 'CRITICAL', title_color = danger_color;
        case {'HIGH','MEDIUM'}, title_color = warn_color;
        otherwise, title_color = safe_color;
    end

    fig = figure('Name', 'ZIP Bomb Analyzer', ...
                 'Color', bg_color, ...
                 'Position', [100, 100, 1200, 800]);

    sgtitle(sprintf('ZIP Bomb Analysis: %s  [%s]', ...
            fileparts(zip_path), threat_level), ...
            'Color', title_color, 'FontSize', 14, 'FontWeight', 'bold');

    %% Panel 1 — Bar chart ─────────────────────────────────────────────────
    ax1 = subplot(2, 2, 1);
    bar_colors = repmat(safe_color, n, 1);
    bar_colors(ratios > max_ratio, :) = repmat(danger_color, ...
        sum(ratios > max_ratio), 1);
    bar_colors(ratios > max_ratio*0.5 & ratios <= max_ratio, :) = ...
        repmat(warn_color, sum(ratios > max_ratio*0.5 & ratios <= max_ratio), 1);

    b = bar(ax1, 1:n, ratios, 'FaceColor', 'flat');
    b.CData = bar_colors;
    hold(ax1, 'on');
    yline(ax1, max_ratio, '--', 'Color', danger_color, 'LineWidth', 1.5, ...
          'Label', sprintf('Limit (%.0f:1)', max_ratio));
    hold(ax1, 'off');
    xlabel(ax1, 'Entry index');
    ylabel(ax1, 'Compression ratio');
    title(ax1, 'Per-Entry Compression Ratio');
    grid(ax1, 'on'); ax1.Color = bg_color;

    %% Panel 2 — Histogram ─────────────────────────────────────────────────
    ax2 = subplot(2, 2, 2);
    histogram(ax2, ratios, min(max(n, 5), 50), ...
              'FaceColor', [0.30, 0.55, 0.85], 'EdgeColor', 'white');
    hold(ax2, 'on');
    xline(ax2, max_ratio, '--', 'Color', danger_color, 'LineWidth', 1.5);
    hold(ax2, 'off');
    xlabel(ax2, 'Compression ratio');
    ylabel(ax2, 'Count');
    title(ax2, 'Ratio Distribution');
    grid(ax2, 'on'); ax2.Color = bg_color;

    %% Panel 3 — Box plot ──────────────────────────────────────────────────
    ax3 = subplot(2, 2, 3);
    boxplot(ax3, ratios, 'Symbol', 'r+', 'Widths', 0.5);
    hold(ax3, 'on');
    yline(ax3, max_ratio, '--', 'Color', danger_color, 'LineWidth', 1.5);
    hold(ax3, 'off');
    ylabel(ax3, 'Compression ratio');
    title(ax3, 'Box Plot with Outliers');
    grid(ax3, 'on'); ax3.Color = bg_color;

    % Annotate top outliers
    [sorted_r, idx] = sort(ratios, 'descend');
    for k = 1:min(3, n)
        if sorted_r(k) > max_ratio
            text(ax3, 1.1, sorted_r(k), ...
                 strtrim(names{idx(k)}(max(1,end-20):end)), ...
                 'FontSize', 7, 'Color', danger_color);
        end
    end

    %% Panel 4 — Cumulative uncompressed size ──────────────────────────────
    ax4 = subplot(2, 2, 4);
    % We only have ratios here; use ratio * 1 as proxy for relative size
    cum_size = cumsum(ratios) / sum(ratios) * 100;
    plot(ax4, 1:n, cum_size, 'Color', [0.30, 0.55, 0.85], 'LineWidth', 2);
    xlabel(ax4, 'Entry index');
    ylabel(ax4, 'Cumulative size contribution (%)');
    title(ax4, 'Cumulative Ratio Distribution');
    grid(ax4, 'on'); ax4.Color = bg_color;

    % Mark 80% Pareto line
    hold(ax4, 'on');
    yline(ax4, 80, ':', 'Color', warn_color, 'LineWidth', 1.2, 'Label', '80%');
    hold(ax4, 'off');

    % Save figure
    [fdir, fname] = fileparts(zip_path);
    outfile = fullfile(fdir, [fname '_analysis.png']);
    try
        exportgraphics(fig, outfile, 'Resolution', 150);
        fprintf('  Plot saved: %s\n', outfile);
    catch
        % exportgraphics not available in older MATLAB — skip silently
    end
end
