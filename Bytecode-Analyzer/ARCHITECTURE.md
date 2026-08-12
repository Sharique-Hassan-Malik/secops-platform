# Architecture — Python Bytecode Obfuscation Analyzer

## Overview

The analyzer performs static analysis of CPython `.pyc` files to detect
obfuscation patterns and produce readable reconstructed source.  It operates
entirely through the standard library (`marshal`, `dis`, `opcode`) and never
executes user-controlled code.

---

## Pipeline

```
.pyc file on disk
    │
    ▼
PycParser (analyzer/pyc_parser.py)
    Reads magic number → Python version
    Reads header flags, timestamp, source size
    Calls marshal.loads on the code payload
    → PycFile (metadata + raw CodeType)
    │
    ▼
Disassembler (analyzer/disassembler.py)
    Walks co_code bytes
    Handles EXTENDED_ARG chaining
    Resolves arguments against co_consts, co_names, co_varnames
    Recurses into nested CodeType objects in co_consts
    → CodeObject tree with Instruction lists
    │
    ├──► ObfuscationDetector (analyzer/obfuscation.py)
    │        15 independent detectors (see below)
    │        → ObfuscationFinding list in AnalysisResult
    │
    └──► Decompiler (analyzer/decompiler.py)
             Symbolic stack emulation
             → reconstructed Python source string
    │
    ▼
Reporter (analyzer/reporter.py)
    Colour-coded terminal output or JSON
```

---

## .pyc Header Layout

### Python 3.8+

```
[0:2]   magic uint16 LE     — encodes Python minor version
[2:4]   0x0d 0x0a           — canonical suffix
[4:8]   flags uint32 LE     — bit 0: hash-based validation
[8:12]  mtime or hash_lo    — uint32 LE
[12:16] source_size or hash_hi
[16:]   marshal'd code object
```

### Python 3.7 and earlier

```
[0:4]   magic (4 bytes)
[4:8]   mtime uint32 LE
[8:12]  source size uint32 LE
[12:]   marshal'd code object
```

---

## Disassembler Design

### EXTENDED_ARG chaining

Before Python 3.6, instructions can span up to 4 bytes by chaining EXTENDED_ARG
prefixes.  Each EXTENDED_ARG shifts the accumulated value left by 8 bits before
ORing in the next byte.  The disassembler handles arbitrary chains:

```
EXTENDED_ARG  0x01     accumulated = 0x01 << 8 = 0x0100
EXTENDED_ARG  0x02     accumulated = (0x0100 | 0x02) << 8 = 0x010200
LOAD_CONST    0x03     final_arg   =  0x010200 | 0x03 = 0x010203
```

### Wordcode (Python 3.6+)

Every instruction is exactly 2 bytes: opcode then argument.  Instructions with
no meaningful argument use arg=0.  The disassembler detects this by checking
`sys.version_info >= (3, 6)`.

### Argument resolution

Raw integer arguments are resolved against the code object's attribute arrays:

| Opcode class | Resolved against |
|---|---|
| `hasconst` | `co_consts[arg]` |
| `hasname` | `co_names[arg]` |
| `haslocal` | `co_varnames[arg]` |
| `hasfree` | `co_cellvars + co_freevars[arg]` |
| `hasjabs`, `hasjrel` | raw target offset |
| `hascompare` | comparison operator string table |

---

## Decompiler Design

The decompiler emulates the CPython value stack symbolically.  Each element
of the symbolic stack is a `SymVal` — a string of Python source text plus an
optional known constant value.

For each instruction the decompiler:
1. Pops operands from the symbolic stack
2. Combines them into a Python expression string
3. Pushes the result back (for intermediate expressions)
4. Or emits a statement line (for stores, calls with side effects, returns)

This produces readable Python for most patterns.  For constructs the
decompiler does not handle (try/except, decorators, async, comprehensions)
it emits a `# <OPNAME>` placeholder comment so the output remains valid
human-readable context.

---

## Obfuscation Detectors

Each detector is an independent method examining one aspect of the code
tree.  Findings are independent — a false positive in one detector does not
suppress others.

| Detector | What it finds | Key heuristic |
|----------|---------------|---------------|
| `_detect_junk_bytecode` | NOP/EXTENDED_ARG padding | >20% instructions are padding |
| `_detect_dead_code` | Unreachable instructions | Code after RETURN/JUMP not a jump target |
| `_detect_opaque_predicates` | Always-true/false branches | LOAD_CONST + LOAD_CONST + COMPARE_OP |
| `_detect_excessive_jumps` | Control-flow scattering | >30% instructions are jumps |
| `_detect_control_flow_flattening` | Dispatcher loop | ≥3 back-edges + ≥5 COMPARE_OPs |
| `_detect_mangled_names` | Random variable names | >50% names match hex/l1l/random patterns |
| `_detect_single_char_names` | Renamed variables | >40% names are one character |
| `_detect_chr_chains` | char-by-char string | ≥4 `chr()` calls in one code object |
| `_detect_string_encoding` | Encoded string constants | >30% non-printable bytes in constants |
| `_detect_dynamic_import` | Hidden module imports | `__import__` / `importlib` name load |
| `_detect_exec_eval` | Second-stage payload | `exec` / `eval` / `compile` name load |
| `_detect_base64` | Encoded payload decode | b64decode/decompress + large constant |
| `_detect_large_const_pool` | Data hidden in constants | co_consts length ≥ 200 |
| `_detect_constant_folding` | XOR-encoded integers | ≥8 ints, >80% in printable ASCII range |
| `_detect_unusual_flags` | Patched code objects | co_flags bits above 0xFFF |

### Obfuscation Score

A weighted sum of finding confidences, normalised to [0, 1]:

```
score = min(Σ weight(kind) × confidence / 4.0, 1.0)
```

High-weight findings: `EXEC_EVAL_USE` (2.0), `DYNAMIC_IMPORT` (1.5),
`CONTROL_FLOW_FLATTEN` (1.5), `JUNK_BYTECODE` (1.5).

---

## Files

```
bytecode_analyzer/
├── analyze.py                    — CLI entry point
├── config.py                     — version tables, finding dataclasses, ObfuscationKind
├── analyzer/
│   ├── __init__.py
│   ├── pyc_parser.py             — .pyc header parsing and marshal extraction
│   ├── disassembler.py           — bytecode decoding, EXTENDED_ARG, recursive descent
│   ├── decompiler.py             — symbolic stack decompiler
│   ├── obfuscation.py            — 15 obfuscation pattern detectors
│   └── reporter.py               — terminal and JSON output
├── tests/
│   └── test_analyzer.py          — pytest suite (30+ tests)
└── scripts/
    └── make_fixtures.py          — compiles Python source fixtures to .pyc
```
