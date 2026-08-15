# Security Operations Platform

Ten security tools — file scanners, traffic monitors, and red-team simulators —
reporting into one event pipeline, one correlation engine, and one SIEM.

The point is not that each tool works. Each worked before. The point is that a
finding from the bytecode analyser and a finding from the steganography
detector are now the same kind of object, keyed to the same entity, so a rule
can say *these two together mean something* — which no individual tool can do,
because no individual tool sees the others' output.

```
secops sensors                        # what is here and what each one needs
secops scan uploads/ --recursive      # every scanner that claims each file
secops scan uploads/ --ingest         # …and push the results into the SIEM
secops probe side-channel-aes         # run a red-team simulator
secops rules                          # the correlation rules, and why each exists
```

```
$ secops probe side-channel-aes --traces 300

  side-channel-aes  (simulator)
    unprotected_bytes_recovered 16
    masked_bytes_recovered 0
    ✖ CRITICAL cpa_unprotected  aes-device:unprotected
               16/16 key bytes recovered from 300 power traces against the
               unprotected device (peak correlation 0.955).

  correlated alerts
    ▲ MEDIUM   simulated-attack-went-undetected  [aes-device:unprotected]
               side-channel-aes recovered data through a side channel and no
               monitoring sensor raised anything. The gap is in the detection
               coverage, not in the target.
```

## The ten modules

**Scanners** — handed an artifact, answer offline.

| Module | What it does |
|---|---|
| [`zipbomb-detector`](modules/zipbomb-detector) | Reads archive metadata to find compression ratios, nesting depth and overlapping entries that would exhaust a host — **without extracting anything**. Python, C, C++, C#, MATLAB and a browser extension. |
| [`steganography-detector`](modules/steganography-detector) | Chi-square, RS analysis, sample-pair and DCT tests for payloads hidden in image LSBs. |
| [`bytecode-analyzer`](modules/bytecode-analyzer) | Parses and disassembles `.pyc` **without importing it**, reconstructs control flow, and flags obfuscation and dynamic-execution patterns. |

**Monitors** — consume a stream and judge it.

| Module | What it does |
|---|---|
| [`can-ids`](modules/can-ids) | Frequency, timing, replay and payload analysis over CAN bus captures. |
| [`waf`](modules/waf) | A rule engine and a learned classifier over HTTP requests — both verdicts reported, because a request only the model objects to is a different decision. |
| [`browser-fingerprinting`](modules/browser-fingerprinting) | Measures how identifying a fingerprint surface is, in bits of entropy, and which features do the identifying. |

**Simulators** — red team, so the detection can be tested rather than assumed.

| Module | What it does |
|---|---|
| [`side-channel-aes`](modules/side-channel-aes) | Correlation power analysis recovering an AES key byte by byte, against a vulnerable device and a masked one. |
| [`acoustic-keylogger`](modules/acoustic-keylogger) | Recovers typed characters from keystroke audio — live from the capture hardware, or offline from a recording. |
| [`protocol-fuzzer`](modules/protocol-fuzzer) | Generates malformed HTTP, DNS and MQTT and reports what the target did with it. |

**The sink.**

| Module | What it does |
|---|---|
| [`siem`](modules/siem) | Log ingestion, parsers, correlation rules, anomaly detection, a WebSocket API and a React dashboard. Sensor events land in its `detections` table via `--ingest`. |

## What the integration actually buys

**Correlation across sensors.** Rules live in [`secops/correlate.py`](secops/correlate.py)
and every one of them needs either two independent sensors to agree, or one
sensor to repeat itself in a way a single observation cannot express. A rule
that restated what one sensor already said would just be that sensor's severity
with extra steps — so `hidden-payload-in-hostile-artifact` explicitly refuses to
fire when both halves came from the same sensor.

**One severity ladder.** These tools between them used `"warn"`, `"critical"`,
a float in [0,1], an `IntEnum` and an exit code. Findings could not be compared,
so no aggregate verdict was possible. Now there is one ordered `Severity` and
`Severity.parse` accepts every spelling they used.

**One place events go.** A scan that prints to a terminal has told one person
once. `--ingest` writes the same events to the SIEM's `detections` table, where
they are queryable and sit alongside the log stream already flowing in.

**One report.** Ten reporters became one renderer: terminal, JSON and a
self-contained HTML page. Severity never travels as colour alone — every level
carries a distinct glyph and its written name, so the output survives a
colour-blind analyst, a printed incident report, and a CI log with the ANSI
codes stripped.

## Using one module on its own

Each module folder is a self-contained source root with its own CLI, tests and
README:

```bash
cd modules/zipbomb-detector/python && python zipbomb_detector.py scan suspect.zip
cd modules/steganography-detector  && python -m stegdetect photo.png
cd modules/bytecode-analyzer       && python analyze.py suspect.pyc
cd modules/can-ids                 && python -m can_ids.cli detect capture.log
cd modules/side-channel-aes        && python demo.py --traces 500
cd modules/siem/backend            && uvicorn main:app --reload
```

They import the event schema from `secops/core`, which is stdlib-only, so
sharing the vocabulary costs a standalone tool no dependencies.

## Install

```bash
pip install -e .                  # the platform and the stdlib-only sensors
pip install -e ".[full]"          # everything: numpy, Pillow, SQLAlchemy, FastAPI
```

Nothing under `modules/` is imported until a sensor is selected to run, so
`secops sensors` and a scan of a zip file work with none of it installed. A
sensor whose dependencies are missing is listed as `needs numpy` rather than
crashing the process.

## Tests

```bash
pytest                            # everything, 250+ tests
pytest modules/can-ids            # one module
```

## Licence

MIT — see [LICENSE](LICENSE).
