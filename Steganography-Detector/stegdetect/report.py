"""
Report formatter for steganography detection results.

Converts the structured dict returned by detector.detect() into
human-readable plain text suitable for terminal output or file logging.
"""

from __future__ import annotations

_VERDICT_LABELS = {
    "clean": "CLEAN",
    "suspicious": "SUSPICIOUS",
    "likely_stego": "LIKELY STEGANOGRAPHY",
}


def _bar(value: float, width: int = 30) -> str:
    filled = int(round(value * width))
    return "[" + "#" * filled + "-" * (width - filled) + "]"


def _pct(value: float) -> str:
    return f"{value * 100:.1f}%"


def format_report(results: dict, verbose: bool = False) -> str:
    lines: list[str] = []
    append = lines.append

    append("=" * 60)
    append(f"  File   : {results.get('file', 'unknown')}")
    append(f"  Type   : {results.get('file_type', 'unknown')}")

    if "error" in results:
        append(f"  Error  : {results['error']}")
        append("=" * 60)
        return "\n".join(lines)

    verdict_key = results.get("verdict", "clean")
    verdict_label = _VERDICT_LABELS.get(verdict_key, verdict_key.upper())
    score = results.get("score", 0.0)

    append(f"  Verdict: {verdict_label}")
    append(f"  Score  : {_pct(score)}  {_bar(score)}")
    append(f"  ({results.get('n_detected', 0)}/{results.get('n_methods', 0)} methods flagged)")
    append("-" * 60)

    methods = results.get("methods", {})
    for name, result in methods.items():
        flag = "  [!]" if result.get("detection", False) else "   - "
        label = name.replace("_", " ").title()
        append(f"{flag} {label}")

        if "error" in result:
            append(f"       Error: {result['error']}")
            continue

        if name == "chi_square":
            append(f"       Chi2      : {result.get('chi2', 0.0):.2f}  (df={result.get('df', 0)})")
            append(f"       Stego prob: {_pct(result.get('stego_probability', 0.0))}")
            if verbose:
                per = result.get("per_channel", {})
                for ch, cr in per.items():
                    if "error" not in cr:
                        append(f"         {ch:6s}: {_pct(cr.get('stego_probability', 0.0))}")

        elif name == "rs_analysis":
            append(f"       Est. rate : {_pct(result.get('estimated_rate', 0.0))}")
            append(f"       RS ratio  : {result.get('rs_ratio', 0.0):.4f}")
            if verbose:
                append(f"       RM={result.get('RM', 0):.4f}  SM={result.get('SM', 0):.4f}  RN={result.get('RN', 0):.4f}  SN={result.get('SN', 0):.4f}")

        elif name == "spa":
            append(f"       Est. rate : {_pct(result.get('estimated_rate', 0.0))}")
            append(f"       W={result.get('W', 0):.4f}  X={result.get('X', 0):.4f}")

        elif name == "dct":
            append(f"       Stego prob: {_pct(result.get('stego_probability', 0.0))}")
            append(f"       Calibrated: {result.get('calibrated', False)}")
            append(f"       N coeffs  : {result.get('n_coefficients', 0):,}")

        elif name == "palette":
            append(f"       Colors    : {result.get('n_used_colors', 0)} used / {result.get('n_colors', 0)} total")
            append(f"       Order score: {result.get('ordering_score', 0.0):.3f}")
            append(f"       Duplicates: {result.get('duplicates', 0)}")

    append("=" * 60)
    return "\n".join(lines)


def format_batch_summary(results: list[dict]) -> str:
    lines = ["", f"{'File':<40} {'Verdict':<20} {'Score':>6}", "-" * 70]
    for r in results:
        fname = r.get("file", "?")
        if len(fname) > 39:
            fname = "..." + fname[-36:]
        verdict = _VERDICT_LABELS.get(r.get("verdict", "clean"), "?")
        score = f"{r.get('score', 0.0) * 100:.0f}%"
        lines.append(f"{fname:<40} {verdict:<20} {score:>6}")
    lines.append("")
    return "\n".join(lines)
