from datetime import datetime

from sqlalchemy import Column, DateTime, Integer, String, Text, create_engine
from sqlalchemy.orm import declarative_base, sessionmaker

from config import DB_URL

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
    created_at  = Column(DateTime, default=datetime.utcnow, index=True)
    rule_name   = Column(String(64))
    severity    = Column(String(16))
    description = Column(Text)
    source_ip   = Column(String(45))
    event_count = Column(Integer, default=1)
    status      = Column(String(16), default="open")


def init_db():
    Base.metadata.create_all(bind=engine)


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
