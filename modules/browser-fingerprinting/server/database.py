from __future__ import annotations

import json
from datetime import datetime

from sqlalchemy import Column, DateTime, Float, Integer, String, Text, create_engine
from sqlalchemy.orm import declarative_base, sessionmaker

Base = declarative_base()


class Fingerprint(Base):
    __tablename__ = "fingerprints"

    id              = Column(Integer, primary_key=True, index=True)
    collected_at    = Column(DateTime, default=datetime.utcnow, index=True)
    collection_ms   = Column(Float)

    # Canvas
    canvas_hash     = Column(String(16), index=True)
    canvas_supported = Column(Integer)  # boolean as int for SQLite

    # WebGL
    webgl_vendor        = Column(String(256))
    webgl_renderer      = Column(String(256))
    webgl_unmasked_vendor   = Column(String(256))
    webgl_unmasked_renderer = Column(String(256))
    webgl_version       = Column(String(128))
    webgl_extensions_count = Column(Integer)
    webgl_image_hash    = Column(String(16))

    # Audio
    audio_hash       = Column(String(32))
    audio_sample_sum = Column(Float)

    # Fonts
    font_count       = Column(Integer)
    fonts_detected   = Column(Text)    # JSON list

    # Timing
    timezone         = Column(String(64))
    timezone_offset  = Column(Integer)
    platform         = Column(String(64))
    user_agent       = Column(Text)
    language         = Column(String(16))
    languages        = Column(String(256))
    hardware_concurrency = Column(Integer)
    device_memory_gb = Column(Float)
    screen_width     = Column(Integer)
    screen_height    = Column(Integer)
    screen_depth     = Column(Integer)
    pixel_ratio      = Column(Float)
    max_touch_points = Column(Integer)
    clock_resolution = Column(Float)
    math_timing_hash = Column(Integer)

    # Network
    connection_type  = Column(String(32))
    effective_type   = Column(String(16))
    audio_input_count  = Column(Integer)
    audio_output_count = Column(Integer)
    video_input_count  = Column(Integer)
    ice_types        = Column(String(128))  # comma-separated

    # Full raw JSON for ad-hoc analysis
    raw_json         = Column(Text)

    # Computed composite fingerprint hash
    composite_hash   = Column(String(32), index=True)


def make_engine(url: str = "sqlite:///./fingerprints.db"):
    return create_engine(url, connect_args={"check_same_thread": False})


def make_session(engine):
    return sessionmaker(bind=engine)


def init_db(engine):
    Base.metadata.create_all(bind=engine)


def get_db_factory(engine):
    Session = make_session(engine)

    def get_db():
        db = Session()
        try:
            yield db
        finally:
            db.close()

    return get_db
