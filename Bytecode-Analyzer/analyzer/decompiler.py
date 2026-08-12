"""
Reconstructs readable Python source from a disassembled code object.

This is a best-effort decompiler that handles the most common bytecode
patterns emitted by CPython.  It uses a symbolic value stack to track
what each LOAD/BINARY/CALL/etc. sequence is building, then emits Python
source text for each completed statement.

Supported constructs:
    - Variable assignments (simple and augmented)
    - Function calls (positional and keyword arguments)
    - Binary and unary operations
    - Comparisons and boolean short-circuits
    - if / elif / else
    - while and for loops
    - Function definitions (signature only; body decompiled recursively)
    - Import statements (import X, from X import Y)
    - Return statements
    - Attribute access and subscript
    - List, dict, tuple, set literals
    - String constants and f-strings (basic)

Complex constructs (nested comprehensions, decorators, try/except,
context managers, async) are emitted as # DECOMPILE_UNSUPPORTED comments.
"""

from __future__ import annotations

import ast
import textwrap
from dataclasses import dataclass, field
from types import CodeType

from analyzer.disassembler import CodeObject, Instruction, walk_code_objects


# ---------------------------------------------------------------------------
# Symbolic value stack
# ---------------------------------------------------------------------------

@dataclass
class SymVal:
    """A symbolic value on the emulated stack."""
    text:  str          # Python source representation
    const: object = None   # actual constant value if known
    is_const: bool = False


def _sval(text: str, const=None, is_const=False) -> SymVal:
    return SymVal(text=text, const=const, is_const=is_const)


# ---------------------------------------------------------------------------
# Decompiler
# ---------------------------------------------------------------------------

class Decompiler:
    """
    Produces a best-effort Python source reconstruction from a CodeObject.

    The output is indented Python that can be read and understood by a human.
    It is not guaranteed to be syntactically valid for all inputs, particularly
    heavily obfuscated ones — in that case it serves as an annotated dump.
    """

    def decompile(self, co: CodeObject, indent: int = 0) -> str:
        lines: list[str] = []
        pad   = "    " * indent
        stack: list[SymVal] = []
        instrs = co.instructions
        i      = 0

        # Build a jump-target set for forward-jump detection
        jump_targets = self._collect_jump_targets(instrs)

        while i < len(instrs):
            instr = instrs[i]
            op    = instr.opname
            i    += 1

            # ── Loads ──────────────────────────────────────────────────
            if op in ("LOAD_CONST",):
                val = instr.argval
                stack.append(_sval(repr(val), const=val, is_const=True))

            elif op in ("LOAD_NAME", "LOAD_GLOBAL", "LOAD_FAST", "LOAD_DEREF",
                        "LOAD_CLASSDEREF", "LOAD_CLOSURE"):
                stack.append(_sval(str(instr.argval or instr.argrepr)))

            elif op == "LOAD_ATTR":
                obj = stack.pop() if stack else _sval("?")
                stack.append(_sval(f"{obj.text}.{instr.argrepr}"))

            elif op in ("LOAD_METHOD",):
                obj = stack.pop() if stack else _sval("?")
                stack.append(_sval(f"{obj.text}.{instr.argrepr}"))

            elif op == "LOAD_SUBSCR":
                idx = stack.pop() if stack else _sval("?")
                obj = stack.pop() if stack else _sval("?")
                stack.append(_sval(f"{obj.text}[{idx.text}]"))

            # ── Stores ─────────────────────────────────────────────────
            elif op in ("STORE_NAME", "STORE_GLOBAL", "STORE_FAST", "STORE_DEREF"):
                val  = stack.pop() if stack else _sval("?")
                name = str(instr.argval or instr.argrepr)
                lines.append(f"{pad}{name} = {val.text}")

            elif op == "STORE_ATTR":
                val = stack.pop() if stack else _sval("?")
                obj = stack.pop() if stack else _sval("?")
                lines.append(f"{pad}{obj.text}.{instr.argrepr} = {val.text}")

            elif op == "STORE_SUBSCR":
                idx = stack.pop() if stack else _sval("?")
                obj = stack.pop() if stack else _sval("?")
                val = stack.pop() if stack else _sval("?")
                lines.append(f"{pad}{obj.text}[{idx.text}] = {val.text}")

            # ── Binary ops ─────────────────────────────────────────────
            elif op in _BINARY_OPS:
                rhs = stack.pop() if stack else _sval("?")
                lhs = stack.pop() if stack else _sval("?")
                sym = _BINARY_OPS[op]
                stack.append(_sval(f"({lhs.text} {sym} {rhs.text})"))

            elif op in _INPLACE_OPS:
                rhs = stack.pop() if stack else _sval("?")
                lhs = stack.pop() if stack else _sval("?")
                sym = _INPLACE_OPS[op]
                stack.append(_sval(f"({lhs.text} {sym} {rhs.text})"))

            # ── Unary ops ──────────────────────────────────────────────
            elif op in _UNARY_OPS:
                val = stack.pop() if stack else _sval("?")
                sym = _UNARY_OPS[op]
                stack.append(_sval(f"({sym}{val.text})"))

            # ── Comparisons ────────────────────────────────────────────
            elif op == "COMPARE_OP":
                rhs = stack.pop() if stack else _sval("?")
                lhs = stack.pop() if stack else _sval("?")
                stack.append(_sval(f"({lhs.text} {instr.argrepr} {rhs.text})"))

            # ── Calls ──────────────────────────────────────────────────
            elif op == "CALL_FUNCTION":
                nargs = instr.arg
                args  = [stack.pop() if stack else _sval("?") for _ in range(nargs)]
                args.reverse()
                fn = stack.pop() if stack else _sval("?")
                stack.append(_sval(f"{fn.text}({', '.join(a.text for a in args)})"))

            elif op == "CALL_FUNCTION_KW":
                keys_tuple = stack.pop() if stack else _sval("?")
                nargs      = instr.arg
                args       = [stack.pop() if stack else _sval("?") for _ in range(nargs)]
                args.reverse()
                fn = stack.pop() if stack else _sval("?")
                stack.append(_sval(f"{fn.text}({', '.join(a.text for a in args)})"))

            elif op in ("CALL_FUNCTION_EX",):
                kwargs = stack.pop() if instr.arg & 1 and stack else None
                args   = stack.pop() if stack else _sval("?")
                fn     = stack.pop() if stack else _sval("?")
                kw_str = f", **{kwargs.text}" if kwargs else ""
                stack.append(_sval(f"{fn.text}(*{args.text}{kw_str})"))

            elif op in ("CALL_METHOD",):
                nargs = instr.arg
                args  = [stack.pop() if stack else _sval("?") for _ in range(nargs)]
                args.reverse()
                fn = stack.pop() if stack else _sval("?")
                # discard implicit self already baked in by LOAD_METHOD
                if stack:
                    stack.pop()
                stack.append(_sval(f"{fn.text}({', '.join(a.text for a in args)})"))

            # Python 3.11+ CALL opcode
            elif op == "CALL":
                nargs = instr.arg
                args  = [stack.pop() if stack else _sval("?") for _ in range(nargs)]
                args.reverse()
                fn = stack.pop() if stack else _sval("?")
                if stack:
                    stack.pop()  # discard NULL sentinel
                stack.append(_sval(f"{fn.text}({', '.join(a.text for a in args)})"))

            # ── Import ─────────────────────────────────────────────────
            elif op == "IMPORT_NAME":
                from_list = stack.pop() if stack else _sval("None")
                level     = stack.pop() if stack else _sval("0")
                name      = str(instr.argval or instr.argrepr)
                if from_list.text not in ("None", "0", "()"):
                    stack.append(_sval(f"__import_sentinel_{name}__"))
                    lines.append(f"{pad}import {name}")
                else:
                    stack.append(_sval(name))
                    lines.append(f"{pad}import {name}")

            elif op == "IMPORT_FROM":
                name = str(instr.argval or instr.argrepr)
                stack.append(_sval(name))

            # ── Return ─────────────────────────────────────────────────
            elif op == "RETURN_VALUE":
                val = stack.pop() if stack else _sval("None")
                if val.text != "None" or co.name != "<module>":
                    lines.append(f"{pad}return {val.text}")

            elif op == "RETURN_CONST":
                val = instr.argval
                if val is not None or co.name != "<module>":
                    lines.append(f"{pad}return {repr(val)}")

            # ── Pop / dup ──────────────────────────────────────────────
            elif op in ("POP_TOP",):
                val = stack.pop() if stack else None
                if val and not val.text.startswith("(") and "(" in val.text:
                    lines.append(f"{pad}{val.text}")

            elif op in ("DUP_TOP",):
                if stack:
                    stack.append(stack[-1])

            elif op in ("ROT_TWO",):
                if len(stack) >= 2:
                    stack[-1], stack[-2] = stack[-2], stack[-1]

            elif op in ("ROT_THREE",):
                if len(stack) >= 3:
                    top = stack.pop()
                    stack.insert(-2, top)

            # ── Collection builders ────────────────────────────────────
            elif op == "BUILD_TUPLE":
                n    = instr.arg
                elts = [stack.pop() if stack else _sval("?") for _ in range(n)]
                elts.reverse()
                stack.append(_sval(f"({', '.join(e.text for e in elts)},)" if n != 1
                                   else f"({elts[0].text},)"))

            elif op == "BUILD_LIST":
                n    = instr.arg
                elts = [stack.pop() if stack else _sval("?") for _ in range(n)]
                elts.reverse()
                stack.append(_sval(f"[{', '.join(e.text for e in elts)}]"))

            elif op == "BUILD_SET":
                n    = instr.arg
                elts = [stack.pop() if stack else _sval("?") for _ in range(n)]
                elts.reverse()
                stack.append(_sval(f"{{{', '.join(e.text for e in elts)}}}"))

            elif op == "BUILD_MAP":
                n    = instr.arg
                pairs = []
                for _ in range(n):
                    v = stack.pop() if stack else _sval("?")
                    k = stack.pop() if stack else _sval("?")
                    pairs.append(f"{k.text}: {v.text}")
                pairs.reverse()
                stack.append(_sval("{" + ", ".join(pairs) + "}"))

            elif op == "BUILD_STRING":
                n    = instr.arg
                parts = [stack.pop() if stack else _sval("?") for _ in range(n)]
                parts.reverse()
                stack.append(_sval(f"({''.join(p.text for p in parts)})"))

            # ── Functions ──────────────────────────────────────────────
            elif op in ("MAKE_FUNCTION", "MAKE_CLOSURE"):
                from types import CodeType as _CodeType
                flags = instr.arg if op == "MAKE_FUNCTION" else 0
                top   = stack.pop() if stack else _sval("?")

                # Python 3.12+: only the code object is pushed before MAKE_FUNCTION.
                # Python <=3.10: qualname string is pushed after the code object.
                if isinstance(top.const, _CodeType):
                    code_obj = top.const
                    fn_name  = code_obj.co_qualname.split(".")[-1] if hasattr(code_obj, "co_qualname") else code_obj.co_name
                else:
                    fn_name  = top.text.strip("'\"")
                    stack.pop() if stack else None  # discard code object

                if flags & 0x08:
                    stack.pop() if stack else None
                if flags & 0x04:
                    stack.pop() if stack else None
                if flags & 0x02:
                    stack.pop() if stack else None
                if flags & 0x01:
                    stack.pop() if stack else None

                lines.append(f"{pad}def {fn_name}(...):")
                child = self._find_child(co, fn_name)
                if child:
                    body = self.decompile(child, indent + 1)
                    lines.append(body if body.strip() else f"{pad}    pass")
                else:
                    lines.append(f"{pad}    ...")
                stack.append(_sval(fn_name))

            # ── Jumps / conditionals (simplified) ──────────────────────
            elif op in ("POP_JUMP_IF_FALSE", "POP_JUMP_IF_TRUE",
                        "JUMP_IF_FALSE_OR_POP", "JUMP_IF_TRUE_OR_POP"):
                cond = stack.pop() if stack else _sval("?")
                neg  = "not " if "FALSE" in op else ""
                lines.append(f"{pad}if {neg}{cond.text}:")
                lines.append(f"{pad}    ...")

            elif op in ("JUMP_FORWARD", "JUMP_ABSOLUTE",
                        "JUMP_BACKWARD", "JUMP_NO_INTERRUPT"):
                pass   # control flow handled by jump target markers

            # ── For loop ───────────────────────────────────────────────
            elif op == "GET_ITER":
                val = stack.pop() if stack else _sval("?")
                stack.append(_sval(f"iter({val.text})"))

            elif op in ("FOR_ITER",):
                iter_val = stack.pop() if stack else _sval("?")
                lines.append(f"{pad}for _item in {iter_val.text.replace('iter(', '').rstrip(')')}:")
                lines.append(f"{pad}    ...")
                stack.append(_sval("_item"))

            # ── Exception handling ─────────────────────────────────────
            elif op in ("SETUP_EXCEPT", "SETUP_FINALLY", "SETUP_WITH",
                        "BEGIN_FINALLY", "END_FINALLY", "POP_EXCEPT",
                        "PUSH_EXC_INFO", "POP_BLOCK"):
                lines.append(f"{pad}# <exception/context handling>")

            # ── Yield ──────────────────────────────────────────────────
            elif op in ("YIELD_VALUE", "YIELD_FROM", "SEND"):
                val = stack.pop() if stack else _sval("None")
                lines.append(f"{pad}yield {val.text}")

            # ── Augmented assignment ────────────────────────────────────
            elif op in ("INPLACE_ADD", "INPLACE_SUBTRACT", "INPLACE_MULTIPLY",
                        "INPLACE_TRUE_DIVIDE", "INPLACE_FLOOR_DIVIDE",
                        "INPLACE_MODULO", "INPLACE_POWER"):
                rhs = stack.pop() if stack else _sval("?")
                lhs = stack.pop() if stack else _sval("?")
                sym = _INPLACE_OPS.get(op, "+=")
                stack.append(_sval(f"({lhs.text} {sym} {rhs.text})"))

            # ── Anything else: leave on stack as placeholder ───────────
            else:
                if not stack or stack[-1].text != f"<{op}>":
                    stack.append(_sval(f"<{op}>"))

        # Flush any remaining unemitted stack items as comments
        for sv in stack:
            if sv.text and not sv.text.startswith("<"):
                lines.append(f"{pad}# expr: {sv.text}")

        return "\n".join(lines)

    # ── Helpers ───────────────────────────────────────────────────────────

    def _find_child(self, co: CodeObject, name: str) -> CodeObject | None:
        for child in co.children:
            bare = child.name.split(".")[-1]
            if bare == name or child.name == name:
                return child
        return None

    @staticmethod
    def _collect_jump_targets(instrs: list[Instruction]) -> set[int]:
        import opcode as _op
        targets: set[int] = set()
        for instr in instrs:
            if instr.opcode in _op.hasjabs or instr.opcode in _op.hasjrel:
                targets.add(instr.arg)
        return targets


# ---------------------------------------------------------------------------
# Operator lookup tables
# ---------------------------------------------------------------------------

_BINARY_OPS: dict[str, str] = {
    "BINARY_ADD": "+", "BINARY_SUBTRACT": "-", "BINARY_MULTIPLY": "*",
    "BINARY_TRUE_DIVIDE": "/", "BINARY_FLOOR_DIVIDE": "//",
    "BINARY_MODULO": "%", "BINARY_POWER": "**",
    "BINARY_LSHIFT": "<<", "BINARY_RSHIFT": ">>",
    "BINARY_AND": "&", "BINARY_OR": "|", "BINARY_XOR": "^",
    "BINARY_MATRIX_MULTIPLY": "@",
    # Python 3.11+ unified BINARY_OP
    "BINARY_OP": "op",
}

_INPLACE_OPS: dict[str, str] = {
    "INPLACE_ADD": "+=", "INPLACE_SUBTRACT": "-=", "INPLACE_MULTIPLY": "*=",
    "INPLACE_TRUE_DIVIDE": "/=", "INPLACE_FLOOR_DIVIDE": "//=",
    "INPLACE_MODULO": "%=", "INPLACE_POWER": "**=",
    "INPLACE_LSHIFT": "<<=", "INPLACE_RSHIFT": ">>=",
    "INPLACE_AND": "&=", "INPLACE_OR": "|=", "INPLACE_XOR": "^=",
}

_UNARY_OPS: dict[str, str] = {
    "UNARY_NEGATIVE": "-", "UNARY_POSITIVE": "+",
    "UNARY_NOT": "not ", "UNARY_INVERT": "~",
}
