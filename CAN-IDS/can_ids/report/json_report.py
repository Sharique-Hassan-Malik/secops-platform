"""JSON serializer for AnalysisResult."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from can_ids.analyzer import AnalysisResult


def _alert_to_dict(a: Any) -> dict:
    return {
        "timestamp": round(a.timestamp, 6),
        "can_id": a.id_str,
        "detector": a.detector,
        "severity": a.severity,
        "score": round(a.score, 4),
        "message": a.message,
        "frame_data": a.frame_data.hex().upper() if a.frame_data else "",
        "extra": a.extra,
    }


def _baseline_to_dict(bl: Any) -> dict:
    profiles = []
    for p in sorted(bl.profiles.values(), key=lambda x: x.can_id):
        dlc = (max(p.byte_stats.keys()) + 1) if p.byte_stats else 0
        profiles.append({
            "can_id": f"{p.can_id:03X}" if p.can_id <= 0x7FF else f"{p.can_id:08X}",
            "frame_count": p.count,
            "mean_rate": round(p.mean_rate, 4),
            "iat_mean_ms": round(p.iat_mean * 1000, 3) if p.iat_count > 0 else None,
            "iat_std_ms":  round(p.iat_std * 1000, 3) if p.iat_count > 1 else None,
            "dlc": dlc,
        })
    return {
        "total_frames": bl.total_frames,
        "duration_s": round(bl.duration, 4),
        "known_id_count": len(bl.profiles),
        "profiles": profiles,
    }


def to_dict(result: AnalysisResult) -> dict:
    sev = result.by_severity
    return {
        "source": result.source,
        "test_frame_count": result.test_frame_count,
        "analysis_time_s": round(result.analysis_time, 4),
        "alert_summary": {
            "total": len(result.alerts),
            "critical": len(sev.get("critical", [])),
            "high":     len(sev.get("high", [])),
            "medium":   len(sev.get("medium", [])),
            "low":      len(sev.get("low", [])),
        },
        "alerts": [_alert_to_dict(a) for a in result.alerts],
        "baseline": _baseline_to_dict(result.baseline),
    }


def to_json(result: AnalysisResult, indent: int = 2) -> str:
    return json.dumps(to_dict(result), indent=indent)


def save(result: AnalysisResult, path: str) -> None:
    Path(path).write_text(to_json(result), encoding="utf-8")
