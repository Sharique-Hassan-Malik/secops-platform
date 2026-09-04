# Architecture

Ten tools, one event, one correlation pass, one sink. Each tool's own analysis
is documented in [`docs/`](docs); this is about what holds them together.

```
   modules/<sensor>/integration.py          ← the only file that knows both sides
                    │
              secops/pipeline.py            runs sensors, gathers events
                    │
              secops/correlate.py           rules that need ≥2 sensors
                    │
        ┌───────────┴───────────┐
   secops/core/render.py    secops/sink.py
   terminal / JSON / HTML   → the SIEM's detections table
```

Sensors never render, never write to a database, and never know another sensor
exists. They return a `SensorResult` full of `Event`s. Everything downstream is
computed from that.

## Why an event and not a finding

The vocabulary is deliberately SIEM-shaped: a timestamp, which sensor saw it,
what kind of thing it was, and — critically — **the entity it was about**.

`entity` is the join key. A file path, a source IP, a CAN arbitration ID. It is
the only reason correlation is possible: two sensors examining different
properties of the same thing can only be compared if they both name the thing
the same way. Left to themselves, one tool calls it `path`, another `source_ip`,
and a third prints it in a table header and nowhere else.

`fields` carries whatever else that sensor knows. Nothing downstream needs to
understand it, and forcing every sensor into a fixed column set would have
meant either losing detail or a schema with forty nullable columns.

## Three kinds, because they are driven differently

- **Scanner** — handed an artifact, answers offline. Never executes it: the
  bytecode analyser parses `.pyc` rather than importing it, and the archive
  scanner reads metadata rather than extracting.
- **Monitor** — consumes a stream: a capture file, a request, a corpus.
- **Simulator** — red team. It *produces* the activity the monitors are meant
  to catch, which is the only way to find out whether they do.

The simulators are in the same manifest as the detectors on purpose. A rule —
`simulated-attack-went-undetected` — fires when a simulator succeeds and no
monitor raised anything, and reports it as a gap in coverage rather than as a
clean result.

## Correlation rules earn their place

Every rule needs **two independent sensors**, or one sensor repeating itself in
a way a single observation cannot express. This is enforced, not just intended:
`hidden-payload-in-hostile-artifact` explicitly returns nothing when both
halves came from the same sensor, because one tool reporting concealment *and*
hostility has simply given its own verdict twice, and restating it as a
correlation would be that verdict with a higher severity attached.

`sustained-intrusion` is the deliberate exception and the reason the rule is
phrased that way: one injected CAN frame is noise, forty against one
arbitration ID is an attack in progress, and volume is information no
per-event severity can carry.

Every alert carries the events it fired on, so an analyst can disagree with it.

## Nothing is imported until it is needed

`secops/core/sensor.py` holds a static `MANIFEST`. It is data, not the result
of importing anything, so `secops sensors` and a scan of a zip file run on a
host with no numpy, no Pillow and no FastAPI. A sensor whose dependencies are
absent is listed as `needs numpy` rather than crashing the process at import.

Loading is by file path: each module folder is its own source root, put on
`sys.path`, with its `integration.py` imported under a unique key. That is the
same import path the sensor gets when run standalone from its own directory, so
"works alone" and "works in the platform" cannot drift apart.

## The top-level `config.py` collision

Three of these modules carry a top-level `config.py`. Run alone that is fine.
In one process, whichever imports first wins `sys.modules["config"]` and the
others silently receive the wrong settings — the SIEM reading `DB_URL` out of
the bytecode analyser's configuration.

Each now has a name of its own (`siem_config`, `fuzzer_config`,
`bytecode_config`), and a test walks `modules/` asserting no two top-level
module names collide, so the next one is caught before it ships.

## Ingestion

`secops/sink.py` writes events to the SIEM's `detections` table and correlated
alerts to its existing `alerts` table. Reusing the alerts table rather than
adding a parallel one is deliberate: an analyst triaging alerts should see
correlation output and the SIEM's own rule output in one queue.

`detections` is a new table rather than an extension of `log_events`, because
the two are genuinely different shapes. A log event is a parsed HTTP or syslog
line described by method, path and status. A detection is a judgement about an
entity. Merging them would have meant six null columns and a `path` holding a
filename.

The dependency runs one way. Sensors do not know the SIEM exists.

## Rendering

One renderer replaced ten. Severity never travels as colour alone: every level
ships a distinct glyph and its written name.

That is the required mitigation for a status palette — two of the fixed status
hexes sit below 3:1 contrast on a light surface by design — and it is also what
keeps the output readable in a printed incident report and in a CI log that has
stripped the ANSI codes. Chart series take the eight categorical slots in fixed
order, never cycled, and every bar is labelled with its own value so nothing
depends on reading a length against an axis.

## Known trade-offs

- **The CAN IDS learns its baseline from the capture** when no separate
  baseline is supplied. It is honest but weaker: an attack present throughout
  the recording becomes the norm. Pass `baseline=` for a clean profile.
- **The acoustic keylogger's offline path is new.** The firmware segments
  keystrokes and streams fixed windows, which left the host side unable to
  analyse a recording at all. `host/offline.py` adds energy-onset segmentation
  producing the same windows. Without a reference text there is nothing to
  score against, so the model's confidence is reported — labelled as
  confidence, never as accuracy.
- **The WAF's classifier is optional.** An untrained model is absent, not zero,
  so the sensor reports rule matches alone rather than implying the model
  agreed.
- **The fuzzer needs a live target.** Without `host`/`port` it skips and says
  so rather than reporting that nothing crashed.
