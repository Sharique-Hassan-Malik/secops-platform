"""
Generate synthetic browser fingerprint rows for testing.

Each generated row matches the schema used by the Fingerprint ORM model.
The distributions are calibrated to approximate real-world browser populations
so that entropy values and classifier accuracy are meaningful.
"""

from __future__ import annotations

import hashlib
import json
import random
from datetime import datetime, timedelta, timezone


_BROWSER_PROFILES = [
    # (browser, os, weight, screen_w, screen_h, hw_concurrency, memory, canvas_group, audio_group)
    ("Chrome",  "Windows", 0.32, [1920, 1366, 2560, 1280], [1080, 768, 1440, 800], [8, 12, 16, 4], [8, 16, 4, 32], "A", "A"),
    ("Chrome",  "macOS",   0.12, [2560, 1920, 2880, 1440], [1440, 1080, 1800, 900], [10, 14, 8, 6], [16, 8, 32, 4], "B", "B"),
    ("Chrome",  "Android", 0.10, [1080, 1440, 720, 2160],  [2340, 3040, 1560, 3840], [8, 4, 6, 8], [4, 3, 6, 8],  "C", "C"),
    ("Firefox", "Windows", 0.09, [1920, 1366, 2560, 1280], [1080, 768, 1440, 800],  [8, 12, 16, 4], [8, 16, 4, 32], "D", "D"),
    ("Firefox", "Linux",   0.06, [1920, 2560, 1280, 3840], [1080, 1440, 800, 2160],  [16, 8, 12, 4], [16, 8, 4, 32], "E", "E"),
    ("Safari",  "macOS",   0.10, [2560, 1920, 2880, 1440], [1440, 1080, 1800, 900], [10, 14, 8, 6], [16, 8, 32, 4], "F", "F"),
    ("Safari",  "iOS",     0.08, [390, 414, 428, 375],     [844, 896, 926, 812],     [6, 4, 8, 6],  [4, 3, 6, 4],  "G", "G"),
    ("Edge",    "Windows", 0.07, [1920, 1366, 2560, 1280], [1080, 768, 1440, 800],   [8, 12, 16, 4], [8, 16, 4, 32], "H", "H"),
    ("Opera",   "Windows", 0.04, [1920, 1366, 2560],       [1080, 768, 1440],        [8, 12, 4],    [8, 4, 16],    "I", "I"),
    ("Chrome",  "Linux",   0.02, [1920, 2560, 1280, 1600], [1080, 1440, 800, 900],   [8, 16, 4, 12], [8, 16, 4],   "J", "J"),
]

_WEIGHTS = [p[2] for p in _BROWSER_PROFILES]

_TIMEZONES = [
    ("America/New_York", -300), ("America/Los_Angeles", -480), ("America/Chicago", -360),
    ("Europe/London", 0), ("Europe/Berlin", -60), ("Europe/Paris", -60),
    ("Asia/Tokyo", -540), ("Asia/Shanghai", -480), ("Asia/Kolkata", -330),
    ("Australia/Sydney", -660), ("America/Sao_Paulo", 180), ("Africa/Cairo", -120),
]

_GPU_RENDERERS_WIN  = ["ANGLE (NVIDIA GeForce RTX 3070)", "ANGLE (Intel UHD 630)", "ANGLE (AMD Radeon RX 6800)"]
_GPU_RENDERERS_MAC  = ["Apple M1", "Apple M2", "Intel Iris Pro", "AMD Radeon Pro 5500M"]
_GPU_RENDERERS_LIN  = ["Mesa Intel(R) UHD 630", "llvmpipe (LLVM 12)", "NVIDIA GeForce GTX 1660"]
_GPU_RENDERERS_AND  = ["Adreno (TM) 640", "Mali-G78 MC14", "PowerVR GE8320"]
_GPU_RENDERERS_IOS  = ["Apple A15", "Apple A14", "Apple A13"]

_GPU_BY_OS = {
    "Windows": _GPU_RENDERERS_WIN,
    "macOS":   _GPU_RENDERERS_MAC,
    "Linux":   _GPU_RENDERERS_LIN,
    "Android": _GPU_RENDERERS_AND,
    "iOS":     _GPU_RENDERERS_IOS,
}


def _stable_hash(s: str) -> str:
    return hashlib.md5(s.encode()).hexdigest()[:8]


def _canvas_hash(browser: str, os: str, group: str) -> str:
    return _stable_hash(f"canvas:{browser}:{os}:{group}")


def _audio_hash(browser: str, os: str, group: str) -> str:
    return _stable_hash(f"audio:{browser}:{os}:{group}")


def _webgl_hash(renderer: str) -> str:
    return _stable_hash(f"webgl:{renderer}")


def _ua(browser: str, os: str) -> str:
    templates = {
        ("Chrome",  "Windows"): "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
        ("Chrome",  "macOS"):   "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
        ("Chrome",  "Android"): "Mozilla/5.0 (Linux; Android 13; Pixel 7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Mobile Safari/537.36",
        ("Chrome",  "Linux"):   "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
        ("Firefox", "Windows"): "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:121.0) Gecko/20100101 Firefox/121.0",
        ("Firefox", "Linux"):   "Mozilla/5.0 (X11; Linux x86_64; rv:121.0) Gecko/20100101 Firefox/121.0",
        ("Safari",  "macOS"):   "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Safari/605.1.15",
        ("Safari",  "iOS"):     "Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Mobile/15E148 Safari/604.1",
        ("Edge",    "Windows"): "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36 Edg/120.0.0.0",
        ("Opera",   "Windows"): "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36 OPR/106.0.0.0",
    }
    return templates.get((browser, os), f"Mozilla/5.0 ({os}) {browser}/1.0")


def generate(n: int = 1000, seed: int = 42) -> list[dict]:
    """Generate n synthetic fingerprint rows."""
    random.seed(seed)
    rows = []
    now  = datetime.now(timezone.utc).replace(tzinfo=None)

    for i in range(n):
        profile = random.choices(_BROWSER_PROFILES, weights=_WEIGHTS, k=1)[0]
        browser, os_name, _, sw_list, sh_list, hw_list, mem_list, can_grp, aud_grp = profile

        tz_name, tz_off = random.choice(_TIMEZONES)
        renderer        = random.choice(_GPU_BY_OS.get(os_name, _GPU_RENDERERS_WIN))
        screen_w        = random.choice(sw_list)
        screen_h        = random.choice(sh_list)
        hw_conc         = random.choice(hw_list)
        mem             = random.choice(mem_list)
        font_count      = random.randint(12, 35) if os_name in ("Windows", "macOS") else random.randint(5, 18)
        ext_count       = random.randint(12, 38)

        collected_at = now - timedelta(seconds=random.randint(0, 7 * 86400))

        rows.append({
            "id":                   i + 1,
            "collected_at":         collected_at.isoformat(),
            "collection_ms":        round(random.uniform(80, 600), 1),
            "canvas_hash":          _canvas_hash(browser, os_name, can_grp),
            "canvas_supported":     1,
            "webgl_vendor":         "WebKit" if browser == "Safari" else "Google Inc.",
            "webgl_renderer":       renderer,
            "webgl_unmasked_vendor":    renderer.split("(")[0].strip() if "(" in renderer else renderer[:20],
            "webgl_unmasked_renderer":  renderer,
            "webgl_version":        "WebGL 1.0",
            "webgl_extensions_count": ext_count,
            "webgl_image_hash":     _webgl_hash(renderer),
            "audio_hash":           _audio_hash(browser, os_name, aud_grp),
            "audio_sample_sum":     round(random.gauss(120.5, 3.2), 6),
            "font_count":           font_count,
            "fonts_detected":       json.dumps([f"Font{j}" for j in range(font_count)]),
            "timezone":             tz_name,
            "timezone_offset":      tz_off,
            "platform":             {"Windows": "Win32", "macOS": "MacIntel",
                                     "Linux": "Linux x86_64", "Android": "Linux armv8l",
                                     "iOS": "iPhone"}.get(os_name, "Other"),
            "user_agent":           _ua(browser, os_name),
            "language":             random.choices(["en-US", "en-GB", "de", "fr", "zh-CN", "ja"], weights=[40,8,8,7,10,5])[0],
            "languages":            "en-US,en",
            "hardware_concurrency": hw_conc,
            "device_memory_gb":     mem,
            "screen_width":         screen_w,
            "screen_height":        screen_h,
            "screen_depth":         24,
            "pixel_ratio":          2.0 if os_name in ("macOS", "iOS") else 1.0,
            "max_touch_points":     5 if os_name in ("Android", "iOS") else 0,
            "clock_resolution":     random.choice([0.1, 1.0, 5.0]),
            "math_timing_hash":     random.randint(10000, 99999),
            "connection_type":      random.choice(["wifi", "ethernet", None]),
            "effective_type":       random.choice(["4g", "3g", None]),
            "audio_input_count":    random.randint(1, 3),
            "audio_output_count":   random.randint(1, 2),
            "video_input_count":    random.randint(0, 2),
            "ice_types":            "host,srflx",
            "composite_hash":       _stable_hash(f"{browser}{os_name}{renderer}{screen_w}{screen_h}{hw_conc}"),
        })

    return rows
