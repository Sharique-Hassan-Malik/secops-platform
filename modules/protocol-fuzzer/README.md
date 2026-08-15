# Network Protocol Fuzzer

> Part of the [Security Operations Platform](../../README.md). Runs standalone
> from this folder, and reports into the shared event pipeline via `secops`.

A mutation-based fuzzer for HTTP, DNS and MQTT.  Generates malformed packets
from valid seeds, transmits them over raw TCP or UDP, classifies responses and
logs crashes with reproducible payloads — built entirely on the Python standard
library (no Scapy required at runtime).

---

## Features

- Eight mutation strategies: bitflip, byteflip, boundary, insert, delete, repeat, splice, havoc
- Weighted random strategy selection with configurable weights
- Boundary-value table (33 known-dangerous integers in multiple encodings)
- Grammar-aware generators for HTTP/1.1, DNS (RFC 1035) and MQTT v3.1.1
- Protocol-specific crash classifiers (HTTP 5xx, DNS malformed response, MQTT CONNACK)
- On-disk corpus with seed persistence and splice cross-pollination
- Crash deduplication and per-crash `.bin` + `.json` storage
- Deterministic replay via fixed seed
- TLS support for HTTPS targets
- Colour-coded terminal progress and JSON crash report output
- Intentionally crashable test HTTP server for local validation
- 50+ offline pytest tests — no network required

---

## Requirements

Python 3.11+ — no runtime dependencies.

```bash
pip install pytest   # for running tests only
```

---

## Usage

### HTTP

```bash
python fuzz.py http --host 127.0.0.1 --port 8080 --iterations 2000
```

### DNS

```bash
python fuzz.py dns --host 127.0.0.1 --port 5353 --iterations 500
```

### MQTT

```bash
python fuzz.py mqtt --host 127.0.0.1 --port 1883 --iterations 1000
```

### Options

```
--host              Target host (default: 127.0.0.1)
--port              Target port (default: 80/53/1883)
--tls               Enable TLS for TCP protocols
--iterations N      Number of test cases (default: 1000)
--seed N            RNG seed for reproducibility (default: 42)
--timeout SECS      Socket timeout (default: 3.0)
--mutation-rate F   Fraction of bytes mutated per packet (default: 0.05)
--generation-ratio F Fraction of inputs generated from grammar (default: 0.2)
--delay SECS        Delay between test cases
--corpus-dir PATH   Seed corpus directory (default: corpus/)
--crash-dir PATH    Crash output directory (default: crashes/)
--json PATH         Write JSON crash report to this file
--no-colour         Disable ANSI colour output
--replay PATH       Replay a saved crash payload and exit
```

---

## Local Testing

Start the intentionally crashable HTTP test server:

```bash
python scripts/test_server_http.py
```

Then fuzz it:

```bash
python fuzz.py http --port 8080 --iterations 500 --timeout 2.0
```

The test server exposes:
- `GET /` → 200 OK
- `GET /crash` → 500 Internal Server Error
- `GET /slow` → waits 5 s (triggers timeout)
- `GET /close` → immediately closes connection

---

## Replaying a Crash

Saved crash payloads can be replayed against the target:

```bash
python fuzz.py http --host 127.0.0.1 --port 8080 \
    --replay crashes/00000042_SERVER_ERROR_boundary.bin
```

---

## Example Output

```
Fuzzing HTTP on 127.0.0.1:8080 (1000 iterations, seed=42)
Corpus: corpus  Crashes: crashes

[CRASH #1] iter=17 mut=boundary kind=SERVER_ERROR
  detail  : HTTP/1.1 500 Internal Server Error
  payload : b'GET /\x80\x00\x00\x00\xff HTTP/1.1\r\nHost: localhos...'
  response: b'HTTP/1.1 500 Internal Server Error\r\n...'
  elapsed : 0.2s

● iter=   100  sent=   100  crashes=1  rate=142/s  elapsed=1s

── Fuzz Session Summary
  Protocol     : http
  Target       : 127.0.0.1:8080
  Iterations   : 1000
  Sent         : 1000
  Rate         : 138 pkt/s
  Elapsed      : 7.3s
  Unique crashes: 3
```

---

## Running Tests

```bash
python -m pytest tests/ -v
```

All tests run entirely offline — no network connections are made.

---

## Architecture Summary

```
Corpus (seeds) ──► FuzzEngine ──► Mutator (8 strategies)
                       │
                       ▼
                  PacketSender (TCP/UDP)
                       │
                       ▼
                  Classifier (per-protocol)
                       │
                       ▼
                  CrashRecord → .bin + .json
```

See [ARCHITECTURE.md](ARCHITECTURE.md) for full documentation of the mutation
strategies, protocol wire-format generators, crash classification rules and
the deduplication algorithm.

---

## Project Structure

```
protocol_fuzzer/
├── fuzz.py
├── config.py
├── fuzzer/
│   ├── mutator.py
│   ├── corpus.py
│   ├── sender.py
│   ├── engine.py
│   └── reporter.py
├── protocols/
│   ├── __init__.py
│   ├── http_gen.py
│   ├── dns_gen.py
│   └── mqtt_gen.py
├── tests/
│   └── test_fuzzer.py
└── scripts/
    └── test_server_http.py
```
