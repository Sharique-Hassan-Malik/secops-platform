# SIEM Dashboard — Architecture

## System Overview

Three layers: a file-tailing ingestion layer, a Python/FastAPI processing backend and a React frontend. All real-time communication uses WebSocket push; historical queries use REST.

```
Log file (apache/nginx/syslog/firewall)
        │
        ▼
  LogWatcher thread   ─── queue.Queue ───►  asyncio ingestion loop
  (one per source)                                    │
                                           ┌──────────┴──────────┐
                                           ▼                     ▼
                                        parser             CorrelationEngine
                                           │               AnomalyDetector
                                           ▼                     │
                                       SQLite DB ◄───────────────┘
                                           │
                                   WebSocket broadcast
                                           │
                                   React frontend
```

## Component Details

### Log Ingestion — `ingestion/watcher.py`

`LogWatcher` spawns one daemon thread per configured log source. Each thread opens its file, seeks to the end (so only new lines are processed on startup) and blocks in a 100 ms polling loop. New lines are pushed into a standard-library `queue.Queue`.

This avoids inotify/kqueue platform differences and works on Linux, macOS and WSL without additional dependencies. The async `_ingestion_loop` task in `main.py` drains the queue in batches of up to 50 events per 50 ms cycle, giving average end-to-end latency under 150 ms while preventing the event loop from blocking on traffic bursts.

### Parsing Pipeline — `parsers/`

Each parser module exports a single function `parse(line: str) -> Optional[dict]`. Parsers use precompiled regex patterns to extract fields and normalize them to a shared schema:

```
{timestamp, source_type, source_ip, method, path, status_code, user_agent, severity, raw}
```

Severity assignment is parser-specific:
- HTTP parsers (Apache, Nginx): derived from status code ranges (5xx → high, 4xx → low)
- Syslog: keyword scan of the message field against a priority-ordered table
- Firewall: action word (DROP/REJECT/BLOCK → high, ACCEPT → info)

### Correlation Engine — `correlation/`

`CorrelationEngine` maintains a per-IP `deque` of recent events. On each new event, every registered rule evaluates the current slice of that window corresponding to its configured time span.

Each rule is a plain function that receives the event list and returns `(triggered: bool, description: str)`. Rules have no state — all windowing is handled by the engine. Adding a new rule requires only a new function and a `Rule(...)` entry in `RULES`.

A 5-minute per-(IP, rule-name) cooldown dictionary prevents alert storms while an attack is ongoing. Window entries older than the longest configured rule window are pruned after each evaluation cycle.

### Anomaly Detector — `anomaly/detector.py`

Request events are bucketed into 10-second intervals per source IP. When a bucket boundary is crossed the completed bucket joins a rolling baseline deque capped at 30 entries (5 minutes of history).

On every event the z-score of the current open bucket against the baseline is computed:

```
z = (current_count - mean(baseline)) / pstdev(baseline)
```

A z-score above 3.5 generates a "Traffic Anomaly" alert. The detector requires no training data, adapts automatically to each IP's own traffic pattern and produces human-readable alert descriptions with the exact z-score and baseline mean.

Baseline warm-up requires at least 5 closed buckets (50 seconds) to avoid false positives immediately after startup.

### Storage — `database.py`

Two SQLite tables managed through the SQLAlchemy ORM:

**`log_events`** — one row per parsed log line. Indexed on `timestamp`, `source_type` and `source_ip` to support the stats queries and filtered event listings efficiently.

**`alerts`** — one row per triggered alert with a status lifecycle: `open` → `acknowledged` → `closed`. The `created_at` and `source_ip` columns are indexed.

SQLite with the default WAL mode handles the single-writer / multiple-reader access pattern. Switching to PostgreSQL requires only changing `DATABASE_URL` in the environment; the ORM layer is unchanged.

### API Layer — `main.py` and `api/websocket.py`

**REST endpoints:**

| Method | Path | Description |
|--------|------|-------------|
| GET    | `/api/events` | Paginated event query; filters: `source_type`, `severity` |
| GET    | `/api/alerts` | Alert list; filter: `status` |
| PATCH  | `/api/alerts/{id}` | Update alert status (acknowledge or close) |
| GET    | `/api/stats` | Aggregate counts, 24-hour timeline and top-IP data |

**WebSocket endpoint:** `/ws`

`ConnectionManager` maintains a list of active `WebSocket` objects. On each `broadcast()` call it attempts `send_json()` to every connection and silently removes any that raise an exception. This handles client disconnections without requiring a heartbeat protocol.

Two message types are pushed:
- `{"type": "event", "data": {...}}` — on every successfully parsed log line
- `{"type": "alert", "data": {...}}` — on every triggered alert

### Frontend — `frontend/src/`

React 18 with Vite. State management is plain `useState` in `App.jsx`; no external store is needed. Recharts provides chart primitives.

On mount the app:
1. Fetches the 100 most recent events and 50 most recent alerts via REST to pre-populate the UI
2. Fetches aggregate stats for the cards and charts
3. Opens a WebSocket connection to `/ws`

WebSocket messages prepend to the in-memory event and alert lists (capped at 200 and 100 entries respectively). New event row IDs are tracked in a `useRef Set`; matching rows receive a 2-second CSS flash animation via class toggle. Stats refresh every 30 seconds via a `setInterval` REST call.

## Data Flow — Single Log Line

1. LogWatcher thread reads a new line from the file descriptor
2. Line is pushed to `queue.Queue` with its source type tag
3. Ingestion loop dequeues it (up to 50 per 50 ms cycle)
4. The matching parser converts the raw string to a normalized dict
5. A `LogEvent` row is inserted into SQLite and committed
6. The event is broadcast as JSON to all connected WebSocket clients
7. `CorrelationEngine.process()` appends the event to the per-IP window, evaluates all rules and returns any triggered alert dicts
8. `AnomalyDetector.feed()` updates the rate bucket and computes the z-score
9. Each alert dict is inserted as an `Alert` row and committed
10. Each alert is broadcast as JSON to all connected WebSocket clients

## Extending the System

**Adding a log source:** add a parser module to `parsers/` following the existing interface, register it in `parsers/__init__.py` and add an entry to `PARSERS` in `config.py`.

**Adding a detection rule:** add a check function and a `Rule(...)` entry to `correlation/rules.py`. No other files need to change.

**Switching to a real database:** set `DATABASE_URL` to a PostgreSQL connection string. For high-throughput use replace the synchronous SQLAlchemy session with an async engine (`asyncpg` + `sqlalchemy[asyncio]`) to keep all I/O on the event loop.
