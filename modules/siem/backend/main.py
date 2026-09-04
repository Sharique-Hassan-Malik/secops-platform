import asyncio
import queue as queue_module
from contextlib import asynccontextmanager
from datetime import datetime, timedelta, timezone

from fastapi import Depends, FastAPI, HTTPException, Query, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy import desc, func
from sqlalchemy.orm import Session

from anomaly.detector import AnomalyDetector
from api.websocket import manager
from siem_config import PARSERS
from correlation.engine import CorrelationEngine
from database import Alert, Detection, LogEvent, SessionLocal, get_db, init_db
from ingestion.watcher import LogWatcher
from parsers import REGISTRY

_correlation = CorrelationEngine()
_anomaly     = AnomalyDetector()
_watcher     = None


async def _handle_line(source_type: str, line: str) -> None:
    parser = REGISTRY.get(source_type)
    if not parser:
        return
    data = parser(line)
    if not data:
        return

    db = SessionLocal()
    try:
        event = LogEvent(**data)
        db.add(event)
        db.commit()
        db.refresh(event)

        await manager.broadcast({"type": "event", "data": _event_dict(event)})

        pending = _correlation.process(event)
        anom    = _anomaly.feed(event)
        if anom:
            pending.append(anom)

        for ad in pending:
            alert = Alert(**ad)
            db.add(alert)
            db.commit()
            db.refresh(alert)
            await manager.broadcast({"type": "alert", "data": _alert_dict(alert)})
    finally:
        db.close()


async def _ingestion_loop() -> None:
    while True:
        processed = 0
        while processed < 50:
            try:
                source_type, line = _watcher.queue.get_nowait()
                await _handle_line(source_type, line)
                processed += 1
            except queue_module.Empty:
                break
        await asyncio.sleep(0.05)


@asynccontextmanager
async def lifespan(app: FastAPI):
    global _watcher
    init_db()
    _watcher = LogWatcher(PARSERS)
    _watcher.start()
    task = asyncio.create_task(_ingestion_loop())
    yield
    task.cancel()
    _watcher.stop()


app = FastAPI(title="SIEM Dashboard", version="1.0.0", lifespan=lifespan)
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.websocket("/ws")
async def ws_endpoint(ws: WebSocket):
    await manager.connect(ws)
    try:
        while True:
            await ws.receive_text()
    except WebSocketDisconnect:
        manager.disconnect(ws)


@app.get("/api/events")
def get_events(
    limit:       int = Query(100, le=500),
    offset:      int = 0,
    source_type: str = None,
    severity:    str = None,
    db: Session = Depends(get_db),
):
    q = db.query(LogEvent).order_by(desc(LogEvent.timestamp))
    if source_type:
        q = q.filter(LogEvent.source_type == source_type)
    if severity:
        q = q.filter(LogEvent.severity == severity)
    total  = q.count()
    events = q.offset(offset).limit(limit).all()
    return {"total": total, "events": [_event_dict(e) for e in events]}


@app.get("/api/alerts")
def get_alerts(
    limit:  int = Query(50, le=200),
    status: str = None,
    db: Session = Depends(get_db),
):
    q = db.query(Alert).order_by(desc(Alert.created_at))
    if status:
        q = q.filter(Alert.status == status)
    return [_alert_dict(a) for a in q.limit(limit).all()]


@app.patch("/api/alerts/{alert_id}")
def update_alert(alert_id: int, body: dict, db: Session = Depends(get_db)):
    alert = db.query(Alert).filter(Alert.id == alert_id).first()
    if not alert:
        raise HTTPException(404, "Alert not found")
    if "status" in body:
        alert.status = body["status"]
    db.commit()
    return _alert_dict(alert)


@app.get("/api/detections")
def get_detections(
    limit:    int = Query(100, le=1000),
    sensor:   str = None,
    severity: str = None,
    entity:   str = None,
    db: Session = Depends(get_db),
):
    """Sensor detections, newest first.

    Populated by `secops ingest`; empty until a scan has been pushed here.
    """
    q = db.query(Detection)
    if sensor:
        q = q.filter(Detection.sensor == sensor)
    if severity:
        q = q.filter(Detection.severity == severity)
    if entity:
        q = q.filter(Detection.entity.like(f"%{entity}%"))
    rows = q.order_by(desc(Detection.timestamp)).limit(limit).all()
    return [d.to_dict() for d in rows]


@app.get("/api/stats")
def get_stats(db: Session = Depends(get_db)):
    now      = datetime.now(timezone.utc).replace(tzinfo=None)
    last_24h = now - timedelta(hours=24)

    total_events    = db.query(func.count(LogEvent.id)).scalar()
    events_24h      = db.query(func.count(LogEvent.id)).filter(LogEvent.timestamp >= last_24h).scalar()
    open_alerts     = db.query(func.count(Alert.id)).filter(Alert.status == "open").scalar()
    critical_alerts = db.query(func.count(Alert.id)).filter(
        Alert.severity == "critical", Alert.status == "open"
    ).scalar()

    by_source = dict(
        db.query(LogEvent.source_type, func.count(LogEvent.id))
        .group_by(LogEvent.source_type).all()
    )
    by_severity = dict(
        db.query(LogEvent.severity, func.count(LogEvent.id))
        .filter(LogEvent.timestamp >= last_24h)
        .group_by(LogEvent.severity).all()
    )
    top_ips = [
        {"ip": ip, "count": c}
        for ip, c in db.query(LogEvent.source_ip, func.count(LogEvent.id).label("c"))
        .filter(LogEvent.timestamp >= last_24h)
        .group_by(LogEvent.source_ip)
        .order_by(desc("c"))
        .limit(10).all()
    ]
    timeline = [
        {"hour": h, "count": c}
        for h, c in db.query(
            func.strftime("%Y-%m-%dT%H:00:00", LogEvent.timestamp).label("h"),
            func.count(LogEvent.id).label("c"),
        )
        .filter(LogEvent.timestamp >= last_24h)
        .group_by("h").all()
    ]

    return {
        "total_events":    total_events,
        "events_24h":      events_24h,
        "open_alerts":     open_alerts,
        "critical_alerts": critical_alerts,
        "by_source":       by_source,
        "by_severity":     by_severity,
        "top_ips":         top_ips,
        "timeline":        timeline,
    }


def _event_dict(e: LogEvent) -> dict:
    return {
        "id":          e.id,
        "timestamp":   e.timestamp.isoformat() if e.timestamp else None,
        "source_type": e.source_type,
        "source_ip":   e.source_ip,
        "method":      e.method,
        "path":        e.path,
        "status_code": e.status_code,
        "severity":    e.severity,
        "raw":         e.raw,
    }


def _alert_dict(a: Alert) -> dict:
    return {
        "id":          a.id,
        "created_at":  a.created_at.isoformat() if a.created_at else None,
        "rule_name":   a.rule_name,
        "severity":    a.severity,
        "description": a.description,
        "source_ip":   a.source_ip,
        "event_count": a.event_count,
        "status":      a.status,
    }
