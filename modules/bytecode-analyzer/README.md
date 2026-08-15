# Python Bytecode Obfuscation Analyzer

> Part of the [Security Operations Platform](../../README.md). Runs standalone
> from this folder, and reports into the shared event pipeline via `secops`.

Decompiles `.pyc` files, detects obfuscation patterns and reconstructs
readable Python source — without executing any user-controlled code.

Covers CPython protocols 0–5 (Python 2.7 through 3.13), with 15 independent
obfuscation detectors and a stack-based source decompiler.

---

## Features

- `.pyc` header parser — magic number, Python version, timestamp, flags
- Full bytecode disassembler with EXTENDED_ARG chaining and wordcode support
- Recursive descent into nested code objects (functions, classes, lambdas)
- Stack-based decompiler — reconstructs readable Python source
- 15 obfuscation detectors: junk bytecode, dead code, opaque predicates, control-flow flattening, mangled names, chr() chains, exec/eval, dynamic imports, base64 decoding, XOR encoding and more
- Weighted obfuscation score [0, 1]
- Colour-coded terminal output or JSON for pipelines
- 30+ pytest tests, no runtime dependencies beyond the standard library

---

## Requirements

Python 3.11+ — no third-party dependencies.

```bash
pip install pytest   # for running tests only
```

---

## Usage

Analyse a `.pyc` file:

```bash
python analyze.py target.pyc
```

Show disassembly:

```bash
python analyze.py target.pyc --disassemble
```

Reconstruct source:

```bash
python analyze.py obfuscated.pyc --decompile
```

Scan a directory recursively, output JSON:

```bash
python analyze.py build/ --recursive --json
```

Show all findings including low-confidence:

```bash
python analyze.py target.pyc --verbose --min-confidence 0.3
```

---

## Example Output

```
── obfuscated.pyc
  Python version : 3.11
  Source file    : payload.py
  Code objects   : 7
  Obfuscation    : 89%
  Findings       : 5

  [<module>]
    EXEC_EVAL_USE                      95%  Call to 'exec' — code string executed at runtime
    DYNAMIC_IMPORT                     90%  Dynamic import via '__import__'
    CHR_CHAIN                          83%  11 chr() calls — string reconstructed character by character
    MANGLED_NAMES                      72%  8/10 names appear randomly generated
    OPAQUE_PREDICATE                   65%  3 constant-vs-constant comparisons detected
```

---

## Running Tests

```bash
python -m pytest tests/ -v
```

Tests compile Python source fixtures in-memory and run the full analysis
pipeline on each — no pre-built `.pyc` files needed.

---

## Compile Test Fixtures

```bash
python scripts/make_fixtures.py
```

Writes `.pyc` versions of 8 obfuscation-pattern examples to `tests/fixtures/`.

---

## Architecture Summary

```
.pyc file
    │
    ▼
PycParser         — magic → version, marshal → CodeType
    │
    ▼
Disassembler      — bytecode bytes → Instruction tree
    │
    ├──► ObfuscationDetector  — 15 pattern detectors → findings
    └──► Decompiler           — symbolic stack → Python source
    │
    ▼
Reporter          — terminal or JSON output
```

See [ARCHITECTURE.md](ARCHITECTURE.md) for full component documentation
including the `.pyc` header layout, EXTENDED_ARG handling, decompiler
stack emulation and the complete detector reference table.

---

## Project Structure

```
bytecode_analyzer/
├── analyze.py
├── config.py
├── analyzer/
│   ├── __init__.py
│   ├── pyc_parser.py
│   ├── disassembler.py
│   ├── decompiler.py
│   ├── obfuscation.py
│   └── reporter.py
├── tests/
│   └── test_analyzer.py
└── scripts/
    └── make_fixtures.py
```
