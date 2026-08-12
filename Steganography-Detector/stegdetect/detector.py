"""
Unified steganography detector.

Runs all applicable detection methods for a given file and combines their
results into a single risk score and verdict. Each method returns an independent
detection decision. The overall verdict is based on a weighted vote.
"""

from __future__ import annotations

from pathlib import Path
from typing import Union

IMAGE_EXTENSIONS = {".png", ".bmp", ".tif", ".tiff", ".jpg", ".jpeg", ".gif", ".webp"}
AUDIO_EXTENSIONS = {".wav", ".flac", ".aif", ".aiff"}

# Methods that are only applied to JPEG images.
_JPEG_ONLY = {"dct"}

# Methods that only apply to palette-mode images.
_PALETTE_ONLY = {"palette"}


def detect(path: Union[str, Path], channels: list[str] | None = None) -> dict:
    """Analyze a file for steganographic content.

    Args:
        path:     Path to the file to analyze.
        channels: For multi-channel images, list of color channels to test
                  ('red', 'green', 'blue'). Defaults to all three for RGB images.

    Returns:
        Dictionary with keys:
            file          -- original path
            file_type     -- 'image' or 'audio'
            methods       -- dict of method_name -> result_dict
            detections    -- list of method names that flagged the file
            n_detected    -- number of methods that detected steganography
            n_methods     -- total number of methods applied
            score         -- fraction of methods that detected (0..1)
            verdict       -- 'clean', 'suspicious', or 'likely_stego'
            error         -- set if the file could not be analyzed
    """
    path = Path(path)
    if not path.exists():
        return {"file": str(path), "error": "File not found"}

    suffix = path.suffix.lower()

    if suffix in IMAGE_EXTENSIONS:
        return _detect_image(path, channels)
    if suffix in AUDIO_EXTENSIONS:
        return _detect_audio(path)

    return {"file": str(path), "error": f"Unsupported file type: {suffix}"}


def _detect_image(path: Path, channels: list[str] | None) -> dict:
    from stegdetect.image import chi_square, rs_analysis, spa, dct_analysis, palette

    if channels is None:
        channels = ["red", "green", "blue"]

    methods: dict[str, dict] = {}

    # Chi-square: one result per channel, report the max probability.
    chi_results = {}
    for ch in channels:
        try:
            chi_results[ch] = chi_square.analyze(path, channel=ch)
        except Exception as exc:
            chi_results[ch] = {"error": str(exc), "detection": False, "stego_probability": 0.0}

    best_chi = max(chi_results.values(), key=lambda r: r.get("stego_probability", 0.0))
    methods["chi_square"] = {**best_chi, "per_channel": chi_results}

    # RS analysis: run on each channel.
    rs_results = {}
    for ch in channels:
        try:
            rs_results[ch] = rs_analysis.analyze(path, channel=ch)
        except Exception as exc:
            rs_results[ch] = {"error": str(exc), "detection": False, "estimated_rate": 0.0}

    best_rs = max(rs_results.values(), key=lambda r: r.get("estimated_rate", 0.0))
    methods["rs_analysis"] = {**best_rs, "per_channel": rs_results}

    # SPA: horizontal+vertical average.
    try:
        methods["spa"] = spa.analyze_rows_and_cols(path)
    except Exception as exc:
        methods["spa"] = {"error": str(exc), "detection": False, "estimated_rate": 0.0}

    # DCT analysis: only for JPEG.
    if path.suffix.lower() in (".jpg", ".jpeg"):
        try:
            methods["dct"] = dct_analysis.analyze(path)
        except Exception as exc:
            methods["dct"] = {"error": str(exc), "detection": False}

    # Palette analysis: only for palette-mode images.
    try:
        pal_result = palette.analyze(path)
        if pal_result.get("is_palette_image", False):
            methods["palette"] = pal_result
    except Exception:
        pass

    return _build_report(path, "image", methods)


def _detect_audio(path: Path) -> dict:
    from stegdetect.audio import chi_square, spa

    methods: dict[str, dict] = {}

    channels = ["left", "right"]
    chi_results = {}
    for ch in channels:
        try:
            chi_results[ch] = chi_square.analyze(path, channel=ch)
        except Exception as exc:
            chi_results[ch] = {"error": str(exc), "detection": False, "stego_probability": 0.0}

    best_chi = max(chi_results.values(), key=lambda r: r.get("stego_probability", 0.0))
    methods["chi_square"] = {**best_chi, "per_channel": chi_results}

    spa_results = {}
    for ch in channels:
        try:
            spa_results[ch] = spa.analyze(path, channel=ch)
        except Exception as exc:
            spa_results[ch] = {"error": str(exc), "detection": False, "estimated_rate": 0.0}

    best_spa = max(spa_results.values(), key=lambda r: r.get("estimated_rate", 0.0))
    methods["spa"] = {**best_spa, "per_channel": spa_results}

    return _build_report(path, "audio", methods)


def _build_report(path: Path, file_type: str, methods: dict) -> dict:
    detections = [name for name, result in methods.items() if result.get("detection", False)]
    n_detected = len(detections)
    n_methods = len(methods)
    score = n_detected / n_methods if n_methods > 0 else 0.0

    if score >= 0.67:
        verdict = "likely_stego"
    elif score >= 0.34:
        verdict = "suspicious"
    else:
        verdict = "clean"

    return {
        "file": str(path),
        "file_type": file_type,
        "methods": methods,
        "detections": detections,
        "n_detected": n_detected,
        "n_methods": n_methods,
        "score": round(score, 3),
        "verdict": verdict,
    }
