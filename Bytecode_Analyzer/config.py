from __future__ import annotations

import sys
from dataclasses import dataclass, field
from enum import Enum


# ---------------------------------------------------------------------------
# Supported Python versions and their .pyc magic numbers
# ---------------------------------------------------------------------------

# Maps magic number (first 2 bytes of .pyc, little-endian uint16) to a
# human-readable version string.  Generated from CPython source:
# Lib/importlib/_bootstrap_external.py — MAGIC_NUMBER history.
MAGIC_TO_VERSION: dict[int, str] = {
    3000: "3.0",  3010: "3.0",  3020: "3.0",  3030: "3.0",  3040: "3.0",
    3050: "3.0",  3060: "3.0",  3061: "3.0",  3071: "3.0",
    3081: "3.1",  3091: "3.1",  3101: "3.1",  3103: "3.1",
    3111: "3.2",  3131: "3.2",
    3141: "3.3",  3151: "3.3",
    3160: "3.4",  3170: "3.4",  3180: "3.4",
    3190: "3.5",  3200: "3.5",  3210: "3.5",  3220: "3.5",  3230: "3.5",
    3250: "3.6",  3260: "3.6",  3270: "3.6",  3280: "3.6",  3290: "3.6",
    3300: "3.6",  3310: "3.6",
    3320: "3.7",  3330: "3.7",  3340: "3.7",  3350: "3.7",  3360: "3.7",
    3361: "3.7",  3370: "3.7",  3371: "3.7",  3372: "3.7",  3373: "3.7",
    3374: "3.7",  3375: "3.7",  3376: "3.7",  3377: "3.7",  3378: "3.7",
    3379: "3.7",
    3390: "3.8",  3391: "3.8",  3392: "3.8",  3393: "3.8",  3394: "3.8",
    3400: "3.9",  3401: "3.9",  3410: "3.9",  3411: "3.9",  3412: "3.9",
    3413: "3.9",
    3420: "3.10", 3421: "3.10", 3422: "3.10", 3423: "3.10", 3424: "3.10",
    3425: "3.10",
    3430: "3.11", 3431: "3.11", 3432: "3.11", 3433: "3.11", 3434: "3.11",
    3435: "3.11", 3436: "3.11", 3437: "3.11", 3438: "3.11", 3439: "3.11",
    3440: "3.11", 3441: "3.11",
    3450: "3.12", 3451: "3.12", 3460: "3.12", 3461: "3.12", 3471: "3.12",
    3480: "3.12", 3490: "3.12", 3500: "3.12", 3510: "3.12", 3511: "3.12",
    3512: "3.12",
    3530: "3.12", 3531: "3.12",
    3520: "3.13", 3521: "3.13", 3522: "3.13", 3523: "3.13", 3524: "3.13",
    3525: "3.13", 3526: "3.13", 3527: "3.13", 3528: "3.13",
}

# Python 3.6+ uses "wordcode" (2 bytes per instruction: opcode + arg).
# Earlier versions use variable-width encoding.
WORDCODE_MIN_VERSION = "3.6"

# Python 3.11+ uses "adaptive" interpreter with 2-byte instructions and
# a distinct set of specialised opcodes.  We fall back to the base opcode.
ADAPTIVE_MIN_VERSION = "3.11"

# Python 3.12+ uses a different .pyc header layout (no mtime/hash flags).
PYC_HEADER_V2_MIN = "3.8"   # bit-field byte added


# ---------------------------------------------------------------------------
# Obfuscation finding
# ---------------------------------------------------------------------------

class ObfuscationKind(Enum):
    # Code structure
    JUNK_BYTECODE          = "JUNK_BYTECODE"
    DEAD_CODE              = "DEAD_CODE"
    OPAQUE_PREDICATE       = "OPAQUE_PREDICATE"
    CONTROL_FLOW_FLATTEN   = "CONTROL_FLOW_FLATTEN"
    EXCESSIVE_JUMPS        = "EXCESSIVE_JUMPS"

    # Naming
    MANGLED_NAMES          = "MANGLED_NAMES"
    SINGLE_CHAR_NAMES      = "SINGLE_CHAR_NAMES"

    # String / constant hiding
    STRING_ENCODING        = "STRING_ENCODING"
    CHR_CHAIN              = "CHR_CHAIN"
    DYNAMIC_IMPORT         = "DYNAMIC_IMPORT"
    EXEC_EVAL_USE          = "EXEC_EVAL_USE"
    BASE64_ENCODED         = "BASE64_ENCODED"
    CONSTANT_FOLDING       = "CONSTANT_FOLDING"

    # Code object anomalies
    NESTED_CODE_OBJECTS    = "NESTED_CODE_OBJECTS"
    SELF_MODIFYING         = "SELF_MODIFYING"
    LARGE_CONST_POOL       = "LARGE_CONST_POOL"
    MISSING_DOCSTRING      = "MISSING_DOCSTRING"
    UNUSUAL_FLAG_BITS      = "UNUSUAL_FLAG_BITS"


@dataclass
class ObfuscationFinding:
    kind:        ObfuscationKind
    description: str
    detail:      str      = ""
    code_name:   str      = "<module>"
    offset:      int | None = None
    confidence:  float    = 1.0     # 0.0–1.0

    def __str__(self) -> str:
        loc = f" @0x{self.offset:04x}" if self.offset is not None else ""
        conf = f" (conf {self.confidence:.0%})"
        det  = f"\n    {self.detail}" if self.detail else ""
        return f"[{self.kind.value}]{loc}{conf}  {self.description}{det}"


@dataclass
class AnalysisResult:
    path:         str
    python_version: str         = "unknown"
    source_file:  str           = ""
    timestamp:    int           = 0
    flags:        int           = 0
    findings:     list[ObfuscationFinding] = field(default_factory=list)
    code_objects: int           = 0
    error:        str           = ""

    @property
    def obfuscated(self) -> bool:
        return any(
            f.confidence >= 0.6
            for f in self.findings
            if f.kind not in (
                ObfuscationKind.MISSING_DOCSTRING,
                ObfuscationKind.NESTED_CODE_OBJECTS,
            )
        )

    @property
    def obfuscation_score(self) -> float:
        """Weighted sum of finding confidences, capped at 1.0."""
        if not self.findings:
            return 0.0
        weights = {
            ObfuscationKind.EXEC_EVAL_USE:         2.0,
            ObfuscationKind.DYNAMIC_IMPORT:        1.5,
            ObfuscationKind.CONTROL_FLOW_FLATTEN:  1.5,
            ObfuscationKind.JUNK_BYTECODE:         1.5,
            ObfuscationKind.STRING_ENCODING:       1.2,
            ObfuscationKind.CHR_CHAIN:             1.2,
            ObfuscationKind.OPAQUE_PREDICATE:      1.0,
            ObfuscationKind.MANGLED_NAMES:         0.8,
        }
        total = sum(
            weights.get(f.kind, 0.5) * f.confidence
            for f in self.findings
        )
        return min(total / 4.0, 1.0)
