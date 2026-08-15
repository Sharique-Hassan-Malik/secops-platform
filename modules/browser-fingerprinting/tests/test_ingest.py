import json
import pytest

from server.ingest import ingest, _composite_hash, _str


# ── Minimal raw fingerprint dict used across tests ────────────────────────────

def _raw(**overrides):
    base = {
        "collected_at":  "2024-03-22T10:00:00Z",
        "collection_ms": 234.5,
        "canvas": {
            "supported": True,
            "hash":      "deadbeef",
            "dataUrl":   None,
            "error":     None,
        },
        "webgl": {
            "supported":        True,
            "vendor":           "Google Inc.",
            "renderer":         "ANGLE (Intel)",
            "unmaskedVendor":   "Intel",
            "unmaskedRenderer": "Intel UHD 630",
            "version":          "WebGL 1.0",
            "extensions":       ["EXT_texture_filter_anisotropic"] * 20,
            "imageHash":        "cafe1234",
        },
        "audio": {
            "supported":  True,
            "hash":       "a1b2c3d4e5f60708",
            "sampleSum":  123.456,
            "error":      None,
        },
        "fonts": {
            "detected": ["Arial", "Verdana", "Tahoma"],
            "tested":   37,
            "error":    None,
        },
        "timing": {
            "timezoneOffset":    -300,
            "timezone":          "America/New_York",
            "clockResolution":   0.1,
            "mathTimingHash":    54321,
            "hardwareConcurrency": 8,
            "deviceMemoryGB":    16,
            "platform":          "Win32",
            "userAgent":         "Mozilla/5.0 (Windows NT 10.0) Chrome/120",
            "language":          "en-US",
            "languages":         ["en-US", "en"],
            "screenWidth":       1920,
            "screenHeight":      1080,
            "screenDepth":       24,
            "screenPixelRatio":  1.0,
            "maxTouchPoints":    0,
            "cookieEnabled":     True,
        },
        "network": {
            "connectionType":      "wifi",
            "effectiveType":       "4g",
            "iceCandidateTypes":   ["host", "srflx"],
            "mediaDeviceCounts":   {"audioinput": 1, "audiooutput": 1, "videoinput": 1},
            "mediaDeviceGroupIds": [],
            "batteryCharging":     True,
            "batteryLevel":        0.95,
        },
    }
    base.update(overrides)
    return base


class TestIngest:
    def test_returns_fingerprint_object(self):
        from server.database import Fingerprint
        fp = ingest(_raw())
        assert isinstance(fp, Fingerprint)

    def test_canvas_hash_extracted(self):
        fp = ingest(_raw())
        assert fp.canvas_hash == "deadbeef"

    def test_canvas_supported_as_int(self):
        fp = ingest(_raw())
        assert fp.canvas_supported == 1

    def test_webgl_renderer(self):
        fp = ingest(_raw())
        assert fp.webgl_renderer == "ANGLE (Intel)"
        assert fp.webgl_unmasked_renderer == "Intel UHD 630"

    def test_webgl_extension_count(self):
        fp = ingest(_raw())
        assert fp.webgl_extensions_count == 20

    def test_audio_hash(self):
        fp = ingest(_raw())
        assert fp.audio_hash == "a1b2c3d4e5f60708"

    def test_audio_sample_sum(self):
        fp = ingest(_raw())
        assert abs(fp.audio_sample_sum - 123.456) < 1e-6

    def test_font_count(self):
        fp = ingest(_raw())
        assert fp.font_count == 3

    def test_fonts_detected_json(self):
        fp = ingest(_raw())
        parsed = json.loads(fp.fonts_detected)
        assert set(parsed) == {"Arial", "Verdana", "Tahoma"}

    def test_timezone(self):
        fp = ingest(_raw())
        assert fp.timezone == "America/New_York"

    def test_timezone_offset(self):
        fp = ingest(_raw())
        assert fp.timezone_offset == -300

    def test_screen_dimensions(self):
        fp = ingest(_raw())
        assert fp.screen_width  == 1920
        assert fp.screen_height == 1080

    def test_hardware_concurrency(self):
        fp = ingest(_raw())
        assert fp.hardware_concurrency == 8

    def test_ice_types_sorted_and_joined(self):
        fp = ingest(_raw())
        assert fp.ice_types == "host,srflx"

    def test_media_device_counts(self):
        fp = ingest(_raw())
        assert fp.audio_input_count  == 1
        assert fp.audio_output_count == 1
        assert fp.video_input_count  == 1

    def test_connection_type(self):
        fp = ingest(_raw())
        assert fp.connection_type == "wifi"

    def test_raw_json_stored(self):
        fp = ingest(_raw())
        assert fp.raw_json is not None
        data = json.loads(fp.raw_json)
        assert "canvas" in data

    def test_composite_hash_is_string(self):
        fp = ingest(_raw())
        assert isinstance(fp.composite_hash, str)
        assert len(fp.composite_hash) == 32

    def test_composite_hash_deterministic(self):
        fp1 = ingest(_raw())
        fp2 = ingest(_raw())
        assert fp1.composite_hash == fp2.composite_hash

    def test_different_canvas_hashes_yield_different_composites(self):
        fp1 = ingest(_raw())
        fp2 = ingest(_raw(canvas={"supported": True, "hash": "ffffffff", "dataUrl": None, "error": None}))
        assert fp1.composite_hash != fp2.composite_hash

    def test_missing_sections_do_not_raise(self):
        fp = ingest({"collected_at": "2024-03-22T10:00:00Z", "collection_ms": 10})
        assert fp.canvas_hash is None
        assert fp.composite_hash is not None

    def test_invalid_collected_at_falls_back_to_now(self):
        fp = ingest(_raw(collected_at="not-a-date"))
        from datetime import datetime
        assert isinstance(fp.collected_at, datetime)


class TestHelpers:
    def test_str_truncates_long_string(self):
        long = "x" * 600
        result = _str(long)
        assert len(result) == 512

    def test_str_returns_none_for_none(self):
        assert _str(None) is None

    def test_str_returns_none_for_empty(self):
        assert _str("") is None
        assert _str("   ") is None

    def test_composite_hash_changes_with_renderer(self):
        canvas  = {"hash": "abc"}
        webgl_a = {"imageHash": "111", "unmaskedRenderer": "GPU-A"}
        webgl_b = {"imageHash": "111", "unmaskedRenderer": "GPU-B"}
        audio   = {"hash": "xyz"}
        timing  = {"timezone": "UTC", "screenWidth": 1920, "screenHeight": 1080, "hardwareConcurrency": 8}
        assert _composite_hash(canvas, webgl_a, audio, timing) != _composite_hash(canvas, webgl_b, audio, timing)

    def test_composite_hash_length(self):
        h = _composite_hash({}, {}, {}, {})
        assert len(h) == 32
