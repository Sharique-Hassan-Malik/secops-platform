# SIEM Dashboard

A full-stack Security Information and Event Management dashboard that ingests log data from Apache, Nginx, syslog and iptables firewall sources in real time, correlates events against detection rules, runs statistical anomaly detection and surfaces alerts to a React frontend over WebSocket.

## The Hard Parts

**Real-time pipeline without a message broker.** The log tailing layer uses one daemon thread per file with a `queue.Queue` bridge to the asyncio event loop. This keeps blocking file I/O off the event loop while letting WebSocket broadcasts happen in async context — no Redis and no Kafka required.

**Sliding-window correlation engine.** Each source IP maintains its own `deque` of recent events. On every new event, all detection rules evaluate the current window and a 5-minute per-(IP, rule) cooldown prevents alert floods. The design mirrors industrial SIEM correlation engines at a fraction of the complexity.

**Z-score anomaly detection.** Request rates are bucketed into 10-second intervals. A rolling baseline of 30 buckets (5 minutes) produces a mean and standard deviation; a current-bucket z-score above 3.5 fires a "Traffic Anomaly" alert without any pre-configured static threshold.

**Live UI without polling.** The React frontend maintains a persistent WebSocket connection and updates the event stream and alert panel in-place. Incoming event rows flash green for 2 seconds on arrival. Aggregate stats refresh via REST every 30 seconds.

## Detection Rules

| Rule             | Trigger                                      | Window  | Severity |
|------------------|----------------------------------------------|---------|----------|
| SSH Brute Force  | ≥ 10 failed auth events from one IP          | 60 s    | Critical |
| HTTP Brute Force | ≥ 20 HTTP 4xx responses from one IP          | 60 s    | High     |
| Port Scan        | ≥ 15 distinct destination ports from one IP  | 30 s    | High     |
| Request Flood    | ≥ 100 HTTP requests from one IP              | 10 s    | Critical |
| Web Scanner      | ≥ 30 HTTP 404s or known scanner user-agent   | 120 s   | Medium   |
| Traffic Anomaly  | Request rate z-score > 3.5 (statistical)     | rolling | Medium   |

## Tech Stack

- **Backend**: Python 3.11, FastAPI, SQLAlchemy, SQLite, uvicorn
- **Frontend**: React 18, Vite, Recharts
- **Transport**: WebSocket (FastAPI native) and REST
- **Log sources**: Apache combined log, Nginx combined log, syslog RFC 3164 and iptables/ufw firewall log

## Setup

### Backend

```bash
cd backend
pip install -r requirements.txt
uvicorn main:app --reload --port 8000
```

The backend starts the log watcher and ingestion loop automatically on startup. Log files are created in `./logs/` if they do not already exist.

### Frontend

```bash
cd frontend
npm install
npm run dev
```

Open `http://localhost:5173`. The Vite dev server proxies `/api` and `/ws` to the backend.

### Generating Test Data

Write 500 historical entries and exit:

```bash
python scripts/generate_test_logs.py --backfill --count 500
```

Start a live stream with periodic attack injections in a separate terminal:

```bash
python scripts/generate_test_logs.py --stream
```

The stream injects attack bursts on a rotating schedule so you can watch correlation alerts fire in real time:

- SSH brute-force burst every 60 s
- Port-scan burst every 120 s
- Web-scanner sweep every 90 s
- Nikto scan every 180 s

### Running Tests

```bash
cd tests
pip install pytest
pytest -v
```

## File Map

| Path | Description |
|------|-------------|
| `backend/main.py` | FastAPI application, ingestion loop, REST and WebSocket endpoints |
| `backend/config.py` | Environment-driven configuration for DB URL and log file paths |
| `backend/database.py` | SQLAlchemy ORM models for LogEvent and Alert |
| `backend/parsers/apache.py` | Apache combined log format parser |
| `backend/parsers/nginx.py` | Nginx combined log format parser |
| `backend/parsers/syslog.py` | Syslog RFC 3164 parser with keyword-based severity classification |
| `backend/parsers/firewall.py` | iptables/ufw firewall log parser |
| `backend/ingestion/watcher.py` | Daemon-thread log tailer with thread-safe queue bridge |
| `backend/correlation/rules.py` | Detection rule definitions and check functions |
| `backend/correlation/engine.py` | Sliding-window correlation engine with per-(IP, rule) cooldown |
| `backend/anomaly/detector.py` | Z-score per-IP request-rate anomaly detector |
| `backend/api/websocket.py` | WebSocket connection manager and broadcast helper |
| `frontend/src/App.jsx` | Root component — WebSocket client, data fetching and state |
| `frontend/src/components/Header.jsx` | Top bar with live connection indicator |
| `frontend/src/components/StatsCards.jsx` | Four summary metric cards |
| `frontend/src/components/TimelineChart.jsx` | 24-hour event volume area chart |
| `frontend/src/components/SourceChart.jsx` | Events-by-source bar chart |
| `frontend/src/components/AlertPanel.jsx` | Alert list with severity badges and ACK button |
| `frontend/src/components/EventStream.jsx` | Scrollable live event table with flash animation |
| `scripts/generate_test_logs.py` | Backfill and live-stream test log generator with attack injection |
| `tests/test_parsers.py` | Unit tests for all four log parsers |
| `tests/test_correlation.py` | Unit tests for correlation rules and cooldown logic |
| `logs/` | Watched log files, created automatically on first run |
