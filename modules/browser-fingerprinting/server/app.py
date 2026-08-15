from __future__ import annotations

import json
import os
from pathlib import Path

from fastapi import Depends, FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles
from sqlalchemy.orm import Session

from .database import Fingerprint, get_db_factory, init_db, make_engine
from .ingest import ingest

_DB_URL = os.getenv("FP_DATABASE_URL", "sqlite:///./fingerprints.db")
_engine = make_engine(_DB_URL)
init_db(_engine)
get_db = get_db_factory(_engine)

app = FastAPI(title="Browser Fingerprinting Research Tool", version="1.0.0")
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

_STATIC = Path(__file__).parent.parent / "dashboard" / "static"


@app.post("/api/collect")
def collect(raw: dict, db: Session = Depends(get_db)):
    fp = ingest(raw)
    db.add(fp)
    db.commit()
    db.refresh(fp)
    return {"fingerprint_id": fp.id, "composite_hash": fp.composite_hash}


@app.get("/api/fingerprints")
def list_fingerprints(limit: int = 100, offset: int = 0, db: Session = Depends(get_db)):
    rows = db.query(Fingerprint).order_by(Fingerprint.id.desc()).offset(offset).limit(limit).all()
    total = db.query(Fingerprint).count()
    return {
        "total": total,
        "fingerprints": [_fp_dict(r) for r in rows],
    }


@app.get("/api/fingerprints/{fp_id}")
def get_fingerprint(fp_id: int, db: Session = Depends(get_db)):
    fp = db.query(Fingerprint).filter(Fingerprint.id == fp_id).first()
    if not fp:
        raise HTTPException(404, "Fingerprint not found")
    return _fp_dict(fp, include_raw=True)


@app.get("/api/entropy")
def entropy_analysis(db: Session = Depends(get_db)):
    from analysis.entropy import entropy_summary
    rows = [_fp_dict(fp) for fp in db.query(Fingerprint).all()]
    if not rows:
        return {"error": "No fingerprints collected yet"}
    return entropy_summary(rows)


@app.get("/api/classifier")
def classifier_analysis(db: Session = Depends(get_db)):
    from analysis.classifier import FingerprintClassifier
    from sklearn.model_selection import train_test_split

    rows = [_fp_dict(fp, include_raw=True) for fp in db.query(Fingerprint).all()]
    if len(rows) < 10:
        return {"error": f"Need at least 10 fingerprints, have {len(rows)}"}

    train, test = train_test_split(rows, test_size=0.3, random_state=42)
    clf = FingerprintClassifier()
    clf.fit(train)
    return clf.evaluate(test)


@app.get("/api/stats")
def stats(db: Session = Depends(get_db)):
    from sqlalchemy import func
    total         = db.query(func.count(Fingerprint.id)).scalar()
    unique_canvas = db.query(func.count(func.distinct(Fingerprint.canvas_hash))).scalar()
    unique_webgl  = db.query(func.count(func.distinct(Fingerprint.webgl_unmasked_renderer))).scalar()
    unique_audio  = db.query(func.count(func.distinct(Fingerprint.audio_hash))).scalar()
    unique_composite = db.query(func.count(func.distinct(Fingerprint.composite_hash))).scalar()
    return {
        "total_fingerprints": total,
        "unique_canvas":      unique_canvas,
        "unique_webgl":       unique_webgl,
        "unique_audio":       unique_audio,
        "unique_composite":   unique_composite,
        "uniqueness_rate":    round(unique_composite / total, 4) if total else 0,
    }


@app.get("/", include_in_schema=False)
def index():
    return FileResponse(_STATIC / "index.html")


@app.get("/collect", include_in_schema=False)
def collect_page():
    return FileResponse(_STATIC / "collect.html")


if _STATIC.exists():
    app.mount("/static", StaticFiles(directory=str(_STATIC)), name="static")


def _fp_dict(fp: Fingerprint, include_raw: bool = False) -> dict:
    d = {
        "id":                    fp.id,
        "collected_at":          fp.collected_at.isoformat() if fp.collected_at else None,
        "canvas_hash":           fp.canvas_hash,
        "canvas_supported":      fp.canvas_supported,
        "webgl_vendor":          fp.webgl_vendor,
        "webgl_renderer":        fp.webgl_renderer,
        "webgl_unmasked_vendor":   fp.webgl_unmasked_vendor,
        "webgl_unmasked_renderer": fp.webgl_unmasked_renderer,
        "webgl_version":         fp.webgl_version,
        "webgl_extensions_count": fp.webgl_extensions_count,
        "webgl_image_hash":      fp.webgl_image_hash,
        "audio_hash":            fp.audio_hash,
        "audio_sample_sum":      fp.audio_sample_sum,
        "font_count":            fp.font_count,
        "fonts_detected":        fp.fonts_detected,
        "timezone":              fp.timezone,
        "timezone_offset":       fp.timezone_offset,
        "platform":              fp.platform,
        "user_agent":            fp.user_agent,
        "language":              fp.language,
        "languages":             fp.languages,
        "hardware_concurrency":  fp.hardware_concurrency,
        "device_memory_gb":      fp.device_memory_gb,
        "screen_width":          fp.screen_width,
        "screen_height":         fp.screen_height,
        "screen_depth":          fp.screen_depth,
        "pixel_ratio":           fp.pixel_ratio,
        "max_touch_points":      fp.max_touch_points,
        "clock_resolution":      fp.clock_resolution,
        "math_timing_hash":      fp.math_timing_hash,
        "connection_type":       fp.connection_type,
        "effective_type":        fp.effective_type,
        "audio_input_count":     fp.audio_input_count,
        "audio_output_count":    fp.audio_output_count,
        "video_input_count":     fp.video_input_count,
        "ice_types":             fp.ice_types,
        "composite_hash":        fp.composite_hash,
    }
    if include_raw and fp.raw_json:
        try:
            d["raw"] = json.loads(fp.raw_json)
        except Exception:
            pass
    return d
