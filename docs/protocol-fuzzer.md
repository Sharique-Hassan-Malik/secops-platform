# Architecture — Network Protocol Fuzzer

## Overview

A mutation-based network protocol fuzzer targeting HTTP, DNS and MQTT.
It generates malformed packets from valid seeds, transmits them over raw
TCP or UDP, classifies responses and logs crashes with reproducible payloads.

---

## Pipeline

```
Corpus (seeds on disk)
    │
    ▼
FuzzEngine
    │  pick seed / generate from grammar
    ▼
Mutator ──── 8 strategies ────────────────────────────────────┐
    │        bitflip, byteflip, boundary, insert, delete,     │
    │        repeat, splice, havoc                            │
    ▼                                                         │
PacketSender                          (weighted random pick) ─┘
    │  TCP (HTTP, MQTT) or UDP (DNS)
    ▼
SendResult (response bytes, elapsed, crash_kind)
    │
    ▼
Classifier (per-protocol)
    │  HTTP: 5xx detection, empty response, transport errors
    │  DNS:  response too short, transport errors
    │  MQTT: malformed CONNACK, transport errors
    ▼
CrashRecord → deduplicate → save .bin + .json
```

---

## Mutation Strategies

Each strategy is a pure function `bytes → bytes`.  The engine selects one
per iteration using weighted random choice.

| Strategy  | Description | Weight |
|-----------|-------------|--------|
| `bitflip` | Flip random bits at mutation_rate density | 1.0 |
| `byteflip` | Replace bytes with random values | 1.0 |
| `boundary` | Overwrite a region with a known boundary integer encoding | 2.0 |
| `insert` | Insert random bytes at a random position | 0.5 |
| `delete` | Remove a random byte slice | 0.5 |
| `repeat` | Duplicate a random chunk within the buffer | 0.5 |
| `splice` | Cross two corpus entries at a random cut point | 0.5 |
| `havoc` | Apply 2–8 random mutations in sequence | 1.0 |

The boundary strategy uses a table of 33 known-dangerous values encoded in
multiple integer widths (1, 2, 4, 8 bytes, both byte orders):

```
0, 1, 127, 128, 255, 256, 0xFFFF, 0x8000, 0x7FFFFFFF, 0xFFFFFFFF, …
```

These values commonly trigger off-by-one errors, integer overflows and
length-field mismatches.

---

## Protocol Generators

Each generator provides two methods:

**`seeds()`** — a static list of packets covering common valid operations
and known edge cases (request smuggling, oversized fields, binary garbage).

**`generate(rng)`** — produces a single randomly generated packet from a
grammar-aware model, exercising cases that pure mutation would take many
iterations to reach (e.g. DNS compression pointer loops, MQTT QoS=3).

### HTTP

Seeds include: all 9 HTTP methods, long URIs, oversized headers, CL.TE
and TE.CL request smuggling, chunked encoding, HTTP/2 preface, null bytes
in headers and binary garbage.

Generator: random method + path + version + header set + body.  The version
string and path are drawn from tables that include deliberately invalid values
(`HTTP/9.9`, `/../../etc/passwd`, etc.).

### DNS

Wire format implemented from scratch (no external library).

Seeds: A/AAAA/MX/ANY queries, compression pointer loop, oversized labels
(>63 bytes), huge QDCOUNT, EDNS OPT record, empty packet.

Generator: modes include valid queries, mangled label lengths, bad header
fields, compression pointer loops and names longer than 255 bytes.

### MQTT v3.1.1

Wire format implemented from scratch.  Variable-length remaining-length
encoding handles all 4-byte continuation cases.

Seeds: CONNECT variants (empty/oversized/binary client ID), PUBLISH at
QoS 0/1/2 (empty/oversized topic and payload, null in topic), SUBSCRIBE,
PINGREQ, DISCONNECT, truncated packets, reserved packet types.

Generator: selects from connect/publish/subscribe/ping/disconnect/garbage
modes with random field values including invalid QoS (3), negative remaining
length (-1 → 0xFF), and reserved packet types (0, 15, 16).

---

## Crash Classification

Crashes are classified by protocol-specific rules, not just transport errors.

### HTTP

| Condition | CrashKind |
|-----------|-----------|
| HTTP 5xx status code | SERVER_ERROR |
| Empty response to non-trivial request | MALFORMED_RESPONSE |
| Socket timeout | TIMEOUT |
| Connection reset / broken pipe | UNEXPECTED_CLOSE |
| SSL error | MALFORMED_RESPONSE |
| Any other OS error | EXCEPTION |
| Connection refused | ignored |

### DNS

| Condition | CrashKind |
|-----------|-----------|
| Response < 4 bytes | MALFORMED_RESPONSE |
| Socket timeout | TIMEOUT |
| Other transport error | respective kind |
| Connection refused | ignored |

### MQTT

| Condition | CrashKind |
|-----------|-----------|
| CONNACK (type 2) not exactly 4 bytes | MALFORMED_RESPONSE |
| Transport errors | respective kind |
| Connection refused | ignored |

---

## Deduplication

Crashes are deduplicated on `(CrashKind, hash(detail[:120]))`.
This prevents thousands of timeout entries from flooding the crash log
when a server goes down, while still recording semantically different
crashes with the same kind.

---

## Crash Storage

Each unique crash is saved as two files:

```
crashes/
    00000042_SERVER_ERROR_boundary.bin    — raw payload bytes
    00000042_SERVER_ERROR_boundary.json   — metadata
```

JSON metadata includes:
- iteration, kind, mutation strategy
- `payload_hex` — full payload as hex
- `response_hex` — first 256 bytes of response as hex

---

## Files

```
protocol_fuzzer/
├── fuzz.py                     — CLI entry point
├── config.py                   — dataclasses: FuzzTarget, FuzzerConfig, CrashRecord, FuzzSession
├── fuzzer/
│   ├── mutator.py              — 8 mutation strategies with weighted selection
│   ├── corpus.py               — on-disk seed corpus management
│   ├── sender.py               — TCP/UDP sender with crash kind classification
│   ├── engine.py               — main fuzzing loop, crash saving, session tracking
│   └── reporter.py             — terminal progress and JSON crash report
├── protocols/
│   ├── __init__.py             — ProtocolGenerator base class
│   ├── http_gen.py             — HTTP/1.1 seeds and generator
│   ├── dns_gen.py              — DNS wire-format seeds and generator
│   └── mqtt_gen.py             — MQTT v3.1.1 seeds and generator
├── tests/
│   └── test_fuzzer.py          — offline pytest suite (50+ tests)
└── scripts/
    └── test_server_http.py     — intentionally crashable HTTP test server
```
