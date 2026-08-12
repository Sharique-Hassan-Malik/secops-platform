"""
Disassembles CPython bytecode from a code object into a flat list of
Instruction objects, handling:

    - EXTENDED_ARG chaining (any number of prefixes)
    - Wordcode (2 bytes/instruction, Python 3.6+)
    - Classic variable-width encoding (Python 3.5 and earlier)
    - Recursive descent into nested code objects (functions, classes,
      comprehensions, lambdas)

No instructions are executed.  The disassembler operates purely on the
co_code bytes and the co_consts / co_varnames / co_names arrays.
"""

from __future__ import annotations

import dis
import opcode as _opcode_module
import sys
from dataclasses import dataclass, field
from types import CodeType


# ---------------------------------------------------------------------------
# Data structures
# ---------------------------------------------------------------------------

@dataclass
class Instruction:
    offset:      int
    opcode:      int
    opname:      str
    arg:         int          # raw integer argument (after EXTENDED_ARG expansion)
    argval:      object       # resolved argument value (name, constant, etc.)
    argrepr:     str          # human-readable argument string
    starts_line: int | None   # source line number if this starts a new line

    def __str__(self) -> str:
        line = f"L{self.starts_line:<4}" if self.starts_line else "     "
        return f"{line} {self.offset:>6}  {self.opname:<30} {self.argrepr}"


@dataclass
class CodeObject:
    """Wrapper around a types.CodeType with pre-computed instruction list."""
    code:         CodeType
    name:         str
    filename:     str
    firstlineno:  int
    instructions: list[Instruction]
    children:     list["CodeObject"] = field(default_factory=list)

    @property
    def argcount(self) -> int:
        return self.code.co_argcount

    @property
    def flags(self) -> int:
        return self.code.co_flags

    @property
    def consts(self) -> tuple:
        return self.code.co_consts

    @property
    def names(self) -> tuple:
        return self.code.co_names

    @property
    def varnames(self) -> tuple:
        return self.code.co_varnames

    @property
    def nlocals(self) -> int:
        return self.code.co_nlocals


# ---------------------------------------------------------------------------
# Disassembler
# ---------------------------------------------------------------------------

HAVE_ARGUMENT = _opcode_module.HAVE_ARGUMENT
EXTENDED_ARG  = _opcode_module.opmap.get("EXTENDED_ARG", 144)


class Disassembler:
    """
    Converts a raw types.CodeType (from marshal) into a tree of CodeObject
    instances, each containing a fully decoded instruction list.
    """

    def disassemble(self, code: CodeType) -> CodeObject:
        """Entry point — disassemble code and all nested code objects."""
        instructions = self._decode_instructions(code)
        children     = self._collect_children(code)
        return CodeObject(
            code=code,
            name=code.co_name,
            filename=getattr(code, "co_filename", "<unknown>"),
            firstlineno=getattr(code, "co_firstlineno", 0),
            instructions=instructions,
            children=children,
        )

    # ── Instruction decoding ─────────────────────────────────────────────

    def _decode_instructions(self, code: CodeType) -> list[Instruction]:
        raw          = bytes(code.co_code)
        lnotab       = self._build_lineno_table(code)
        instructions = []
        i            = 0
        extended_arg = 0

        while i < len(raw):
            offset = i
            op     = raw[i]
            i     += 1

            if op == EXTENDED_ARG:
                # Accumulate: each EXTENDED_ARG shifts argument left by 8 bits
                arg_byte  = raw[i] if i < len(raw) else 0
                i        += 1
                extended_arg = (extended_arg | arg_byte) << 8
                # Emit EXTENDED_ARG as its own instruction for analysis
                instructions.append(Instruction(
                    offset=offset, opcode=op, opname="EXTENDED_ARG",
                    arg=extended_arg >> 8, argval=None, argrepr="",
                    starts_line=lnotab.get(offset),
                ))
                continue

            if op >= HAVE_ARGUMENT:
                arg_byte    = raw[i] if i < len(raw) else 0
                i          += 1
                arg         = extended_arg | arg_byte
                extended_arg = 0
            else:
                arg          = 0
                extended_arg = 0
                if i < len(raw) and _is_wordcode(code):
                    i += 1   # skip the padding byte in wordcode format

            argval, argrepr = self._resolve_arg(code, op, arg)
            opname          = _opcode_module.opname[op] if op < len(_opcode_module.opname) else f"<{op}>"

            instructions.append(Instruction(
                offset=offset, opcode=op, opname=opname,
                arg=arg, argval=argval, argrepr=argrepr,
                starts_line=lnotab.get(offset),
            ))

        return instructions

    def _resolve_arg(self, code: CodeType, op: int, arg: int) -> tuple[object, str]:
        """Map a raw integer argument to its semantic value."""
        if op in _opcode_module.hasconst:
            if arg < len(code.co_consts):
                val = code.co_consts[arg]
                return val, repr(val)
            return None, f"<const {arg}>"

        if op in _opcode_module.hasname:
            # Python 3.11+ encodes a flag in arg bit 0 for LOAD_GLOBAL (push-NULL)
            # and 3.12+ for LOAD_ATTR (method-load). In both cases the real name
            # index is arg >> 1. Missing the LOAD_GLOBAL shift misresolves every
            # function-scoped global name (e.g. reading 'os' where 'exec' was meant).
            _op = _opcode_module
            load_attr   = _op.opmap.get("LOAD_ATTR", -1)
            load_global = _op.opmap.get("LOAD_GLOBAL", -1)
            if op == load_attr and sys.version_info >= (3, 12):
                name_idx = arg >> 1
            elif op == load_global and sys.version_info >= (3, 11):
                name_idx = arg >> 1
            else:
                name_idx = arg
            if name_idx < len(code.co_names):
                name = code.co_names[name_idx]
                return name, name
            elif arg < len(code.co_names):
                name = code.co_names[arg]
                return name, name
            return None, f"<name {arg}>"

        if op in _opcode_module.haslocal:
            if arg < len(code.co_varnames):
                name = code.co_varnames[arg]
                return name, name
            return None, f"<local {arg}>"

        if op in _opcode_module.hasfree:
            free  = getattr(code, "co_freevars",  ())
            cell  = getattr(code, "co_cellvars",  ())
            combined = cell + free
            if arg < len(combined):
                name = combined[arg]
                return name, name
            return None, f"<free {arg}>"

        if op in _opcode_module.hasjabs or op in _opcode_module.hasjrel:
            return arg, f"to {arg}"

        if op in _opcode_module.hascompare:
            cmp_ops = ["<", "<=", "==", "!=", ">", ">=", "in", "not in", "is", "is not", "exception match", "BAD"]
            label = cmp_ops[arg] if arg < len(cmp_ops) else str(arg)
            return label, label

        return arg, str(arg) if arg else ""

    # ── Line number table ─────────────────────────────────────────────────

    @staticmethod
    def _build_lineno_table(code: CodeType) -> dict[int, int]:
        """Returns offset → line_number for the first instruction on each line."""
        result: dict[int, int] = {}
        try:
            # Python 3.10+ provides co_linetable; use the stdlib helper
            for offset, end_offset, lineno in code.co_lines():
                if lineno is not None and offset not in result:
                    result[offset] = lineno
        except AttributeError:
            # Older Python — walk co_lnotab manually
            line    = code.co_firstlineno
            offset  = 0
            lnotab  = bytes(code.co_lnotab)
            result[0] = line
            for j in range(0, len(lnotab), 2):
                offset_delta = lnotab[j]
                line_delta   = lnotab[j + 1]
                if offset_delta:
                    offset += offset_delta
                    result[offset] = line
                line += line_delta
        return result

    # ── Nested code objects ───────────────────────────────────────────────

    def _collect_children(self, code: CodeType) -> list[CodeObject]:
        children = []
        for const in code.co_consts:
            if isinstance(const, CodeType):
                children.append(self.disassemble(const))
        return children


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _is_wordcode(code: CodeType) -> bool:
    """
    Python 3.6+ uses wordcode (every instruction is exactly 2 bytes).
    We detect this by checking the Python version via sys rather than
    the code object itself.
    """
    import sys
    return sys.version_info >= (3, 6)


def walk_code_objects(root: CodeObject):
    """Depth-first generator over a code object tree."""
    yield root
    for child in root.children:
        yield from walk_code_objects(child)
