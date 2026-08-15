from __future__ import annotations

import hashlib
import json
from datetime import datetime
from typing import Any

from .database import Fingerprint


def ingest(raw: dict) -> Fingerprint:
    """
    Flatten a raw fingerprint dict into a Fingerprint ORM object ready for
    insertion. The raw JSON is also stored verbatim for ad-hoc analysis.
    """
    canvas  = raw.get("canvas",  {}) or {}
    webgl   = raw.get("webgl",   {}) or {}
    audio   = raw.get("audio",   {}) or {}
    fonts   = raw.get("fonts",   {}) or {}
    timing  = raw.get("timing",  {}) or {}
    network = raw.get("network", {}) or {}

    wgl_params = webgl.get("parameters", {}) or {}
    net_counts = (network.get("mediaDeviceCounts") or {})

    ice_types = ",".join(sorted(network.get("iceCandidateTypes") or []))
    langs     = ",".join(timing.get("languages") or [])
    fonts_list = json.dumps(sorted(fonts.get("detected") or []))

    composite_hash = _composite_hash(canvas, webgl, audio, timing)

    try:
        collected_at = datetime.fromisoformat(raw.get("collected_at", "").replace("Z", "+00:00"))
    except (ValueError, AttributeError):
        collected_at = datetime.utcnow()

    return Fingerprint(
        collected_at    = collected_at,
        collection_ms   = raw.get("collection_ms"),

        canvas_hash     = canvas.get("hash"),
        canvas_supported = int(bool(canvas.get("supported"))),

        webgl_vendor            = _str(webgl.get("vendor")),
        webgl_renderer          = _str(webgl.get("renderer")),
        webgl_unmasked_vendor   = _str(webgl.get("unmaskedVendor")),
        webgl_unmasked_renderer = _str(webgl.get("unmaskedRenderer")),
        webgl_version           = _str(webgl.get("version")),
        webgl_extensions_count  = len(webgl.get("extensions") or []),
        webgl_image_hash        = webgl.get("imageHash"),

        audio_hash       = audio.get("hash"),
        audio_sample_sum = audio.get("sampleSum"),

        font_count      = len(fonts.get("detected") or []),
        fonts_detected  = fonts_list,

        timezone         = _str(timing.get("timezone")),
        timezone_offset  = timing.get("timezoneOffset"),
        platform         = _str(timing.get("platform")),
        user_agent       = _str(timing.get("userAgent")),
        language         = _str(timing.get("language")),
        languages        = langs,
        hardware_concurrency = timing.get("hardwareConcurrency"),
        device_memory_gb = timing.get("deviceMemoryGB"),
        screen_width     = timing.get("screenWidth"),
        screen_height    = timing.get("screenHeight"),
        screen_depth     = timing.get("screenDepth"),
        pixel_ratio      = timing.get("screenPixelRatio"),
        max_touch_points = timing.get("maxTouchPoints"),
        clock_resolution = timing.get("clockResolution"),
        math_timing_hash = timing.get("mathTimingHash"),

        connection_type     = _str(network.get("connectionType")),
        effective_type      = _str(network.get("effectiveType")),
        audio_input_count   = net_counts.get("audioinput"),
        audio_output_count  = net_counts.get("audiooutput"),
        video_input_count   = net_counts.get("videoinput"),
        ice_types           = ice_types,

        raw_json         = json.dumps(raw),
        composite_hash   = composite_hash,
    )


def _composite_hash(canvas: dict, webgl: dict, audio: dict, timing: dict) -> str:
    parts = [
        canvas.get("hash") or "",
        webgl.get("imageHash") or "",
        webgl.get("unmaskedRenderer") or webgl.get("renderer") or "",
        audio.get("hash") or "",
        timing.get("timezone") or "",
        str(timing.get("screenWidth") or ""),
        str(timing.get("screenHeight") or ""),
        str(timing.get("hardwareConcurrency") or ""),
    ]
    raw = "|".join(parts).encode()
    return hashlib.md5(raw).hexdigest()


def _str(v: Any) -> str | None:
    if v is None:
        return None
    s = str(v).strip()
    return s[:512] if s else None
