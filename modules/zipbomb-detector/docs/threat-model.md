# Threat Model

## What Is a Zip Bomb?

A zip bomb is a malicious archive designed to exhaust resources
(memory, disk space, CPU time) in a system that attempts to decompress it.
It is a denial-of-service attack against archive-processing software.

---

## Attack Taxonomy

### Type 1 — Nested / Recursive Bomb (Classic)
**Technique:** Archives nested inside archives, each containing many large files.

```
bomb.zip
└── a.zip (×10)
    └── b.zip (×10)
        └── large_file.txt (1 GB) (×10)
```

**Expansion factor:** Multiplies per layer. 10 × 10 × 10 × 1 GB = 1 TB.

**Modern resilience:** Most current antivirus tools detect recursive nesting
and impose depth limits. This technique is well-known and widely mitigated.

**Detection:** Nesting depth limit (implemented in all components).

---

### Type 2 — Non-Recursive / Overlapping Data (Fifield, 2019)

**Technique:** A single-layer ZIP where many central directory entries all
point to the same (or overlapping) compressed data region.

```
Central Directory:
  Entry 1 → offset 100 → compressed_size 1000 → "expands to" 4 GB
  Entry 2 → offset 100 → compressed_size 1000 → "expands to" 4 GB
  ...
  Entry 1000 → offset 100 → (same data reused)
```

A naive decompressor sees 1000 entries of 4 GB each = 4 TB.
The actual file is ~45 KB.

**Why it's effective:** Many AV scanners skip recursive nesting detection
but will still attempt to decompress a "flat" single-layer archive.

**Detection:** Overlap detection — checking that no two entries reference
the same byte ranges in the file.

**Reference:** David Fifield, *"A better zip bomb"* (2019)
https://www.bamsoftware.com/hacks/zipbomb/

---

### Type 3 — Quine / Self-Reproducing Archives
An archive that contains itself as an entry. Causes infinite loops in
recursive scanners that follow nested archives.

**Detection:** Nesting depth limit; file hash deduplication.

---

### Type 4 — Header-Only Lies (Metadata Spoofing)
The ZIP specification allows the declared uncompressed size in headers
to differ from the actual decompressed output. Some decompressors allocate
memory based on declared sizes before decompressing.

**Detection:** Ratio check on declared metadata values (implemented here).
Note: a scanner that only reads declared sizes and never decompresses
is immune to the actual resource exhaustion, but can still detect the
declared-size attack.

---

## Threat Actors & Scenarios

| Scenario | Vector | Impact |
|---|---|---|
| Malicious file upload to web app | HTTP POST | Server-side disk/memory DoS |
| Email attachment to gateway scanner | SMTP | Mail server crash, scanning bypass |
| Archive in cloud storage sync | File system event | Sync client hang/crash |
| Supply chain (malicious package) | npm/pip/Maven | CI/CD pipeline disruption |
| IDS/IPS evasion | Malformed archive | Scanner crash while real payload passes |

---

## What This Project Detects

| Attack Type | Detected | Method |
|---|---|---|
| Nested recursive bomb | ✓ | Depth limit |
| Non-recursive overlapping (Fifield) | ✓ | Overlap detection |
| Ratio-based (declared sizes) | ✓ | Per-entry + overall ratio check |
| Entry count flood | ✓ | Entry count limit |
| Cumulative size overflow | ✓ | Running sum guard |
| Quine / self-referencing | Partial | Depth limit mitigates |
| Header metadata spoofing | ✓ | Declared-size ratio check |

---

## Limitations

1. **Does not detect encrypted bombs.** Encrypted ZIP entries have
   size fields that may be unavailable or unreliable before decryption.

2. **Does not detect all quines.** A cycle across different files
   (A contains B, B contains A) requires full graph traversal — not
   implemented in this version.

3. **Relies on declared metadata.** A file with honest headers
   but malicious intent might have correct metadata and only reveal
   itself upon decompression. This scanner cannot detect that case
   without actually decompressing.

4. **Gzip/bzip2/7z/tar.** The current implementation focuses on ZIP.
   Other formats require their own parsers.

---

## Responsible Use

This project is a **defensive tool**. It is designed to:
- Validate file uploads in web applications
- Pre-screen archives before cloud storage ingestion
- Protect CI/CD pipelines from malicious packages
- Serve as educational material for cybersecurity coursework

It does not generate malicious archives and should not be modified to do so.
