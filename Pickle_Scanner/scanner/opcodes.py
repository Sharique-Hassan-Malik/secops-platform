from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum, auto
from typing import Any


# ---------------------------------------------------------------------------
# Severity
# ---------------------------------------------------------------------------

class Severity(Enum):
    SAFE    = "SAFE"
    INFO    = "INFO"
    LOW     = "LOW"
    MEDIUM  = "MEDIUM"
    HIGH    = "HIGH"
    CRITICAL = "CRITICAL"

    def __lt__(self, other: "Severity") -> bool:
        order = list(Severity)
        return order.index(self) < order.index(other)

    def __le__(self, other: "Severity") -> bool:
        return self == other or self < other


# ---------------------------------------------------------------------------
# Finding
# ---------------------------------------------------------------------------

@dataclass
class Finding:
    opcode:      str
    offset:      int
    severity:    Severity
    description: str
    detail:      str = ""

    def __str__(self) -> str:
        loc = f"offset 0x{self.offset:04x}"
        det = f" — {self.detail}" if self.detail else ""
        return f"[{self.severity.value:<8}] {loc}  {self.opcode:<20} {self.description}{det}"


@dataclass
class ScanResult:
    path:       str
    findings:   list[Finding] = field(default_factory=list)
    safe:       bool = True
    error:      str  = ""
    proto:      int  = 0           # pickle protocol version
    n_opcodes:  int  = 0

    @property
    def max_severity(self) -> Severity:
        if not self.findings:
            return Severity.SAFE
        return max(
            (f.severity for f in self.findings),
            key=lambda s: list(Severity).index(s),
        )

    def add(self, finding: Finding):
        self.findings.append(finding)
        if finding.severity >= Severity.HIGH:
            self.safe = False


# ---------------------------------------------------------------------------
# Dangerous opcode registry
# ---------------------------------------------------------------------------

# Each entry: opcode_name → (Severity, short description, detail template)
# Detail template may reference {arg} which is filled in at scan time.
DANGEROUS_OPCODES: dict[str, tuple[Severity, str, str]] = {
    # ── Arbitrary code execution ──────────────────────────────────────────
    "GLOBAL": (
        Severity.CRITICAL,
        "Imports an arbitrary module attribute",
        "Calls __import__('{module}') then getattr(module, '{name}'). "
        "Enables import of os, subprocess, builtins, etc.",
    ),
    "INST": (
        Severity.CRITICAL,
        "Instantiates a class by module/classname string",
        "Equivalent to GLOBAL + REDUCE; fully arbitrary instantiation.",
    ),
    "REDUCE": (
        Severity.HIGH,
        "Calls a callable with a tuple of arguments",
        "Invokes any previously pushed callable. Combined with GLOBAL or "
        "INST this executes arbitrary code.",
    ),
    "BUILD": (
        Severity.HIGH,
        "Calls __setstate__ or updates __dict__",
        "Can trigger custom __setstate__ methods on deserialized objects.",
    ),
    "NEWOBJ": (
        Severity.MEDIUM,
        "Calls cls.__new__(cls, *args)",
        "Constructs an object via __new__; less dangerous than REDUCE but "
        "can still invoke custom __new__ implementations.",
    ),
    "NEWOBJ_EX": (
        Severity.MEDIUM,
        "Calls cls.__new__(cls, *args, **kwargs) — protocol 4+",
        "Extended NEWOBJ with keyword arguments.",
    ),
    "STACK_GLOBAL": (
        Severity.CRITICAL,
        "Imports module attribute from stack strings — protocol 4+",
        "Pushes __import__(module).__getattr__(name); same risk as GLOBAL.",
    ),
    # ── Potentially dangerous depending on target ─────────────────────────
    "OBJ": (
        Severity.HIGH,
        "Instantiates an object using the top of the stack as class",
        "Class is resolved at runtime from the stack.",
    ),
    # ── Protocol / framing ────────────────────────────────────────────────
    "PROTO": (
        Severity.INFO,
        "Declares pickle protocol version",
        "",
    ),
    "FRAME": (
        Severity.INFO,
        "Protocol 4 framing opcode",
        "",
    ),
    # ── Persistent ID (hook for custom object loading) ────────────────────
    "PERSID": (
        Severity.LOW,
        "Loads a persistent object by string ID",
        "Invokes PersistentUnpickler.persistent_load(); safe only if the "
        "unpickler's persistent_load is trusted.",
    ),
    "BINPERSID": (
        Severity.LOW,
        "Loads a persistent object by ID from stack",
        "Same risk as PERSID.",
    ),
    # ── Memo manipulation ─────────────────────────────────────────────────
    "DUP": (
        Severity.INFO,
        "Duplicates top of stack",
        "",
    ),
}

# Opcodes considered safe data primitives — logged only at INFO level when
# verbose mode is active, never flagged as a finding.
SAFE_OPCODES = frozenset({
    "INT", "LONG", "LONG1", "LONG4",
    "FLOAT", "BINFLOAT",
    "STRING", "BINSTRING", "SHORT_BINSTRING",
    "UNICODE", "BINUNICODE", "SHORT_BINUNICODE", "BINUNICODE8",
    "NONE", "NEWTRUE", "NEWFALSE",
    "EMPTY_LIST", "EMPTY_TUPLE", "EMPTY_DICT", "EMPTY_SET",
    "LIST", "TUPLE", "TUPLE1", "TUPLE2", "TUPLE3",
    "DICT", "FROZENSET",
    "APPEND", "APPENDS", "SETITEM", "SETITEMS",
    "ADD_ITEMS",
    "PUT", "BINPUT", "LONG_BINPUT",
    "GET", "BINGET", "LONG_BINGET",
    "MEMOIZE",
    "MARK", "POP", "POP_MARK",
    "STOP",
    "BYTEARRAY8", "NEXT_BUFFER", "READONLY_BUFFER",
})

# Known-safe (module, name) pairs that are commonly used in ML workflows.
# A GLOBAL/STACK_GLOBAL importing one of these is downgraded from CRITICAL
# to LOW as it is a normal serialisation pattern.
KNOWN_SAFE_GLOBALS: frozenset[tuple[str, str]] = frozenset({
    ("collections", "OrderedDict"),
    ("collections", "defaultdict"),
    ("torch", "Tensor"),
    ("torch._utils", "_rebuild_tensor_v2"),
    ("torch._utils", "_rebuild_parameter"),
    ("torch._tensor", "_rebuild_from_type_v2"),
    ("torch.storage", "_load_from_bytes"),
    ("numpy", "ndarray"),
    ("numpy", "dtype"),
    ("numpy.core.multiarray", "_reconstruct"),
    ("numpy.core.multiarray", "scalar"),
    ("_codecs", "encode"),
    ("builtins", "bytearray"),
    ("builtins", "bytes"),
    ("builtins", "set"),
    ("builtins", "frozenset"),
    ("builtins", "complex"),
    ("builtins", "slice"),
    ("builtins", "range"),
})

# High-risk module prefixes — any GLOBAL targeting these should always remain
# CRITICAL regardless of the exact name.
DANGEROUS_MODULES = frozenset({
    "os", "subprocess", "sys", "socket", "shutil", "pathlib",
    "importlib", "ctypes", "multiprocessing", "threading",
    "pty", "atexit", "signal", "gc", "tempfile",
    "builtins",   # exec, eval, open, __import__, compile, etc.
    "posix", "nt",
    "pickle", "pickletools",
    "_pickle",
})
