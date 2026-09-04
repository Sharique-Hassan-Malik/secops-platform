import json
from datetime import datetime, timezone


from sqlalchemy import Column, DateTime, Float, Integer, String, Text, create_engine
from sqlalchemy.orm import declarative_base, sessionmaker

from siem_config import DB_URL


def _utcnow():
    """Naive UTC, matching the naive `DateTime` columns below."""
    return datetime.now(timezone.utc).replace(tzinfo=None)


engine = create_engine(DB_URL, connect_args={"check_same_thread": False})
SessionLocal = sessionmaker(bind=engine)
Base = declarative_base()


class LogEvent(Base):
    __tablename__ = "log_events"

    id          = Column(Integer, primary_key=True, index=True)
    timestamp   = Column(DateTime, index=True)
    source_type = Column(String(32), index=True)
    source_ip   = Column(String(45), index=True)
    method      = Column(String(16))
    path        = Column(String(512))
    status_code = Column(Integer)
    user_agent  = Column(String(512))
    severity    = Column(String(16), default="info")
    raw         = Column(Text)


class Alert(Base):
    __tablename__ = "alerts"

    id          = Column(Integer, primary_key=True, index=True)
    created_at  = Column(DateTime, default=_utcnow, index=True)
    rule_name   = Column(String(64))
    severity    = Column(String(16))
    description = Column(Text)
    source_ip   = Column(String(45))
    event_count = Column(Integer, default=1)
    status      = Column(String(16), default="open")


class Detection(Base):
    """An event from one of the platform's sensors.

    Separate from `LogEvent` because the two are genuinely different shapes.
    A log event is a parsed HTTP or syslog line and is described by method,
    path and status. A detection is a sensor's judgement about an entity — a
    file, a CAN identifier, an origin — and forcing it into the log schema
    would mean six null columns and a `path` holding a filename.
    """

    __tablename__ = "detections"

    id        = Column(Integer, primary_key=True, index=True)
    timestamp = Column(DateTime, index=True, default=_utcnow)
    sensor    = Column(String(64), index=True)
    category  = Column(String(32), index=True)
    severity  = Column(String(16), index=True)
    title     = Column(String(128))
    entity    = Column(String(512), index=True)
    message   = Column(Text, default="")
    score     = Column(Float, nullable=True)
    fields    = Column(Text, default="{}")      # JSON, sensor-specific

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "timestamp": self.timestamp.isoformat() if self.timestamp else None,
            "sensor": self.sensor,
            "category": self.category,
            "severity": self.severity,
            "title": self.title,
            "entity": self.entity,
            "message": self.message,
            "score": self.score,
            "fields": json.loads(self.fields or "{}"),
        }


def init_db():
    Base.metadata.create_all(bind=engine)


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
