"""
Detects obfuscation patterns in disassembled bytecode.

Each detector is an independent method that examines one aspect of the
code object tree and appends ObfuscationFinding objects to the result list.
Detectors are intentionally kept simple and independent so that false
positives in one do not affect others.
"""

from __future__ import annotations

import re
import string
from collections import Counter

from analyzer.disassembler import CodeObject, Instruction, walk_code_objects
from config import ObfuscationFinding, ObfuscationKind, AnalysisResult


# Threshold constants — tuned against a corpus of normal Python code
_JUNK_JUMP_RATIO        = 0.30   # jumps as a fraction of total instructions
_MANGLED_NAME_RATIO     = 0.50   # fraction of names that look mangled
_SINGLE_CHAR_NAME_RATIO = 0.40   # fraction of names that are single characters
_CHR_CHAIN_MIN          = 4      # minimum chr() calls in a single chain
_LARGE_CONST_POOL       = 200    # co_consts count threshold
_DEEP_NESTING_LEVEL     = 4      # nested code object depth threshold
_OPAQUE_PREDICATE_RATIO = 0.15   # fraction of comparisons that are constant


class ObfuscationDetector:
    """
    Runs all detectors against a code object tree and populates the
    findings list of an AnalysisResult.
    """

    def analyse(self, root: CodeObject, result: AnalysisResult):
        result.code_objects = sum(1 for _ in walk_code_objects(root))

        for co in walk_code_objects(root):
            self._detect_junk_bytecode(co, result)
            self._detect_dead_code(co, result)
            self._detect_opaque_predicates(co, result)
            self._detect_excessive_jumps(co, result)
            self._detect_mangled_names(co, result)
            self._detect_single_char_names(co, result)
            self._detect_chr_chains(co, result)
            self._detect_string_encoding(co, result)
            self._detect_dynamic_import(co, result)
            self._detect_exec_eval(co, result)
            self._detect_base64(co, result)
            self._detect_large_const_pool(co, result)
            self._detect_unusual_flags(co, result)
            self._detect_constant_folding(co, result)

        self._detect_control_flow_flattening(root, result)
        self._detect_deep_nesting(root, result, depth=0)

    # ── Structural detectors ─────────────────────────────────────────────

    def _detect_junk_bytecode(self, co: CodeObject, result: AnalysisResult):
        """
        Flags code with a suspiciously high ratio of EXTENDED_ARG and
        NOP instructions, which are a common way to pad bytecode and
        confuse disassemblers.
        """
        instrs = co.instructions
        if len(instrs) < 10:
            return
        junk = sum(
            1 for i in instrs
            if i.opname in ("EXTENDED_ARG", "NOP", "JUMP_FORWARD")
            and i.arg == 0
        )
        ratio = junk / len(instrs)
        if ratio > 0.20:
            result.findings.append(ObfuscationFinding(
                kind=ObfuscationKind.JUNK_BYTECODE,
                code_name=co.name,
                description=f"High proportion of NOP/EXTENDED_ARG/zero-jump opcodes ({junk}/{len(instrs)}, {ratio:.0%})",
                detail="Padding opcodes are commonly inserted to confuse static disassemblers.",
                confidence=min(ratio / 0.4, 1.0),
            ))

    def _detect_dead_code(self, co: CodeObject, result: AnalysisResult):
        """
        Detects unreachable instructions after unconditional jumps or returns
        that are not jump targets.
        """
        instrs = co.instructions
        if len(instrs) < 5:
            return

        import opcode as _op
        jump_targets = {i.arg for i in instrs
                        if i.opcode in _op.hasjabs or i.opcode in _op.hasjrel}
        line_starts  = {i.offset for i in instrs if i.starts_line}

        dead_count = 0
        prev_was_terminal = False
        for instr in instrs:
            if instr.offset in jump_targets or instr.offset in line_starts:
                prev_was_terminal = False
            if prev_was_terminal and instr.opname not in ("NOP", "EXTENDED_ARG"):
                dead_count += 1
            prev_was_terminal = instr.opname in (
                "RETURN_VALUE", "RAISE_VARARGS", "JUMP_ABSOLUTE",
                "JUMP_FORWARD", "JUMP_BACKWARD",
            )

        if dead_count >= 3:
            result.findings.append(ObfuscationFinding(
                kind=ObfuscationKind.DEAD_CODE,
                code_name=co.name,
                description=f"Unreachable instructions after unconditional jumps ({dead_count} dead opcodes)",
                confidence=min(dead_count / 10.0, 0.9),
            ))

    def _detect_opaque_predicates(self, co: CodeObject, result: AnalysisResult):
        """
        Detects comparisons where both operands are compile-time constants —
        an opaque predicate always evaluates the same way and exists purely
        to obscure control flow.
        """
        instrs = co.instructions
        const_compare = 0
        total_compare = 0

        for j, instr in enumerate(instrs):
            if instr.opname != "COMPARE_OP":
                continue
            total_compare += 1
            # Check if both preceding instructions are LOAD_CONST
            if j >= 2:
                a = instrs[j - 2].opname
                b = instrs[j - 1].opname
                if a == "LOAD_CONST" and b == "LOAD_CONST":
                    const_compare += 1

        if total_compare > 0 and const_compare / total_compare >= _OPAQUE_PREDICATE_RATIO:
            result.findings.append(ObfuscationFinding(
                kind=ObfuscationKind.OPAQUE_PREDICATE,
                code_name=co.name,
                description=f"{const_compare} constant-vs-constant comparisons detected",
                detail="Comparisons with both operands known at compile time always produce the same result.",
                confidence=min(const_compare / 5.0, 0.95),
            ))

    def _detect_excessive_jumps(self, co: CodeObject, result: AnalysisResult):
        """High jump-to-instruction ratio indicates control flow obfuscation."""
        instrs = co.instructions
        if len(instrs) < 20:
            return
        import opcode as _op
        n_jumps = sum(
            1 for i in instrs
            if i.opcode in _op.hasjabs or i.opcode in _op.hasjrel
        )
        ratio = n_jumps / len(instrs)
        if ratio > _JUNK_JUMP_RATIO:
            result.findings.append(ObfuscationFinding(
                kind=ObfuscationKind.EXCESSIVE_JUMPS,
                code_name=co.name,
                description=f"High jump density: {n_jumps}/{len(instrs)} ({ratio:.0%}) instructions are jumps",
                confidence=min((ratio - _JUNK_JUMP_RATIO) / 0.3 + 0.5, 0.95),
            ))

    def _detect_control_flow_flattening(self, root: CodeObject, result: AnalysisResult):
        """
        Control-flow flattening replaces structured control flow with a
        dispatcher loop.  Signature: a loop containing a single large
        COMPARE_OP dispatch chain and many JUMP_ABSOLUTE instructions
        targeting a single back-edge.
        """
        for co in walk_code_objects(root):
            instrs = co.instructions
            if len(instrs) < 30:
                continue
            import opcode as _op
            back_edges = [
                i for i in instrs
                if (i.opcode in _op.hasjabs or i.opcode in _op.hasjrel)
                and i.opname in ("JUMP_ABSOLUTE", "JUMP_BACKWARD",
                                 "JUMP_BACKWARD_NO_INTERRUPT", "JUMP_NO_INTERRUPT")
            ]
            compares   = [i for i in instrs if "COMPARE" in i.opname]
            if len(back_edges) >= 1 and len(compares) >= 5:
                result.findings.append(ObfuscationFinding(
                    kind=ObfuscationKind.CONTROL_FLOW_FLATTEN,
                    code_name=co.name,
                    description=f"Dispatcher loop pattern: {len(back_edges)} back-edges, {len(compares)} compare ops",
                    detail="Control-flow flattening replaces structured if/while/for with a loop over a state variable.",
                    confidence=0.75,
                ))
                break

    def _detect_deep_nesting(self, co: CodeObject, result: AnalysisResult, depth: int):
        """Unusually deep code object nesting hides logic inside lambdas or classes."""
        if depth >= _DEEP_NESTING_LEVEL:
            result.findings.append(ObfuscationFinding(
                kind=ObfuscationKind.NESTED_CODE_OBJECTS,
                code_name=co.name,
                description=f"Code object nested {depth} levels deep",
                confidence=0.5,
            ))
            return
        for child in co.children:
            self._detect_deep_nesting(child, result, depth + 1)

    # ── Naming detectors ─────────────────────────────────────────────────

    def _detect_mangled_names(self, co: CodeObject, result: AnalysisResult):
        """
        Detects names that look randomly generated: hex-like strings,
        very long names with no vowels, or names matching /^[_l]{6,}$/.
        """
        all_names = list(co.names) + list(co.varnames)
        if len(all_names) < 4:
            return

        def looks_mangled(name: str) -> bool:
            if len(name) < 4:
                return False
            # Pure hex string
            if re.fullmatch(r"[0-9a-fA-F]{8,}", name):
                return True
            # Looks like base64 identifier
            if re.fullmatch(r"[A-Za-z0-9_]{12,}", name) and not re.search(r"[aeiou]", name, re.I):
                return True
            # Underscore/l confusion pattern (common in pyobfuscate-style tools)
            if re.fullmatch(r"[_lI1O0]{5,}", name):
                return True
            return False

        mangled = [n for n in all_names if looks_mangled(n)]
        ratio   = len(mangled) / len(all_names)
        if ratio >= _MANGLED_NAME_RATIO:
            result.findings.append(ObfuscationFinding(
                kind=ObfuscationKind.MANGLED_NAMES,
                code_name=co.name,
                description=f"{len(mangled)}/{len(all_names)} names appear randomly generated",
                detail=f"Examples: {', '.join(mangled[:5])}",
                confidence=min(ratio / 0.7 + 0.3, 0.95),
            ))

    def _detect_single_char_names(self, co: CodeObject, result: AnalysisResult):
        """A high ratio of single-character names suggests variable renaming."""
        all_names = [
            n for n in list(co.names) + list(co.varnames)
            if n not in ("_", "__", "i", "j", "k", "x", "y", "n", "s", "e", "f")
        ]
        if len(all_names) < 6:
            return
        single = [n for n in all_names if len(n) == 1]
        ratio  = len(single) / len(all_names)
        if ratio >= _SINGLE_CHAR_NAME_RATIO:
            result.findings.append(ObfuscationFinding(
                kind=ObfuscationKind.SINGLE_CHAR_NAMES,
                code_name=co.name,
                description=f"{len(single)}/{len(all_names)} non-conventional single-character names",
                confidence=min(ratio / 0.7 + 0.2, 0.85),
            ))

    # ── String / constant detectors ──────────────────────────────────────

    def _detect_chr_chains(self, co: CodeObject, result: AnalysisResult):
        """
        Detects patterns like chr(104)+chr(101)+chr(108)+chr(108)+chr(111)
        which reconstruct strings character by character to avoid them
        appearing as literals.
        """
        instrs   = co.instructions
        chr_calls = 0
        for j, instr in enumerate(instrs):
            if instr.opname in ("CALL_FUNCTION", "CALL") and instr.arg == 1:
                # Check the callee was 'chr'
                k = j - 1
                while k >= 0 and instrs[k].opname in ("LOAD_CONST", "EXTENDED_ARG"):
                    k -= 1
                if k >= 0 and instrs[k].argrepr == "chr":
                    chr_calls += 1

        if chr_calls >= _CHR_CHAIN_MIN:
            result.findings.append(ObfuscationFinding(
                kind=ObfuscationKind.CHR_CHAIN,
                code_name=co.name,
                description=f"{chr_calls} chr() calls — string reconstructed character by character",
                detail="Obfuscators split string literals into individual chr() calls to hide them from grep.",
                confidence=min(chr_calls / 12.0 + 0.5, 0.99),
            ))

    def _detect_string_encoding(self, co: CodeObject, result: AnalysisResult):
        """
        Checks string constants for patterns associated with encoding:
        - Very high ratio of non-printable or escape characters
        - Strings that are entirely hex digits
        - Reversed strings (heuristic: no spaces, high consonant ratio)
        """
        encoded_count = 0
        for const in co.consts:
            if not isinstance(const, (str, bytes)):
                continue
            s = const if isinstance(const, str) else const.decode("latin-1")
            if len(s) < 6:
                continue
            # Mostly non-printable
            non_print = sum(1 for c in s if c not in string.printable)
            if non_print / len(s) > 0.3:
                encoded_count += 1
                continue
            # Pure hex string constant
            if re.fullmatch(r"[0-9a-fA-F]{16,}", s):
                encoded_count += 1
                continue
            # High escape density in bytes repr
            if isinstance(const, bytes):
                esc = sum(1 for b in const if b < 0x20 or b > 0x7e)
                if esc / len(const) > 0.5:
                    encoded_count += 1

        if encoded_count >= 2:
            result.findings.append(ObfuscationFinding(
                kind=ObfuscationKind.STRING_ENCODING,
                code_name=co.name,
                description=f"{encoded_count} string/bytes constants appear encoded or binary-packed",
                confidence=min(encoded_count / 5.0 + 0.4, 0.9),
            ))

    def _detect_dynamic_import(self, co: CodeObject, result: AnalysisResult):
        """
        Detects __import__() calls and importlib usage which hide what
        modules the code loads from static analysis.
        """
        for instr in co.instructions:
            if instr.argrepr in ("__import__", "importlib", "import_module"):
                result.findings.append(ObfuscationFinding(
                    kind=ObfuscationKind.DYNAMIC_IMPORT,
                    code_name=co.name,
                    offset=instr.offset,
                    description=f"Dynamic import via {instr.argrepr!r} — module name hidden from static analysis",
                    confidence=0.9,
                ))
                return  # one finding per code object is enough

    def _detect_exec_eval(self, co: CodeObject, result: AnalysisResult):
        """exec() and eval() are classic vehicles for second-stage payloads."""
        for instr in co.instructions:
            if instr.argrepr in ("exec", "eval", "compile"):
                result.findings.append(ObfuscationFinding(
                    kind=ObfuscationKind.EXEC_EVAL_USE,
                    code_name=co.name,
                    offset=instr.offset,
                    description=f"Call to {instr.argrepr!r} — code string executed at runtime",
                    detail="exec/eval enable a second stage of code that does not appear in this bytecode.",
                    confidence=0.95,
                ))
                return

    def _detect_base64(self, co: CodeObject, result: AnalysisResult):
        """Detects base64/zlib/codecs decode patterns on string constants."""
        decode_names = {"b64decode", "b64encode", "decodebytes",
                        "decompress", "decode", "codecs"}
        # Check both instruction argrepr and co_names (LOAD_ATTR in 3.12 uses co_names)
        has_decode_call = (
            any(i.argrepr in decode_names for i in co.instructions)
            or any(n in decode_names for n in co.names)
        )
        if has_decode_call:
            for const in co.consts:
                if isinstance(const, (str, bytes)) and len(const) > 40:
                    name = next(
                        (i.argrepr for i in co.instructions if i.argrepr in decode_names),
                        next((n for n in co.names if n in decode_names), "decode"),
                    )
                    result.findings.append(ObfuscationFinding(
                        kind=ObfuscationKind.BASE64_ENCODED,
                        code_name=co.name,
                        description=f"Encoded payload decoded via {name!r} at runtime",
                        confidence=0.85,
                    ))
                    return

    def _detect_large_const_pool(self, co: CodeObject, result: AnalysisResult):
        """An unusually large constant pool often stores encoded payloads."""
        n = len(co.consts)
        if n >= _LARGE_CONST_POOL:
            result.findings.append(ObfuscationFinding(
                kind=ObfuscationKind.LARGE_CONST_POOL,
                code_name=co.name,
                description=f"Constant pool contains {n} entries (threshold: {_LARGE_CONST_POOL})",
                confidence=min((n - _LARGE_CONST_POOL) / 300.0 + 0.5, 0.85),
            ))

    def _detect_unusual_flags(self, co: CodeObject, result: AnalysisResult):
        """
        Detects unusual co_flags combinations that may indicate manually
        crafted or manipulated code objects.
        """
        flags = co.flags
        # CO_OPTIMIZED=0x01, CO_NEWLOCALS=0x02, CO_VARARGS=0x04, CO_VARKEYWORDS=0x08
        # CO_NESTED=0x10, CO_GENERATOR=0x20, CO_NOFREE=0x40
        # Bits above 0x800 are unusual in legitimate code
        if flags & ~0xFFF:
            result.findings.append(ObfuscationFinding(
                kind=ObfuscationKind.UNUSUAL_FLAG_BITS,
                code_name=co.name,
                description=f"Unusual co_flags bits set: 0x{flags:04x}",
                detail="High flag bits may indicate a manually constructed or patched code object.",
                confidence=0.7,
            ))

    def _detect_constant_folding(self, co: CodeObject, result: AnalysisResult):
        """
        Detects intentional constant-folding abuse: very long arithmetic
        expressions compiled into a single constant to hide the original value.
        For example `0x41^0x03` appearing as the integer 66 in co_consts.
        We detect this by checking if a large fraction of integer constants
        fall into ranges commonly produced by XOR-based encoding.
        """
        ints = [c for c in co.consts if isinstance(c, int) and 0 <= c <= 127]
        if len(ints) < 8:
            return
        # XOR'd printable ASCII: most values should be in [32, 126]
        printable = sum(1 for v in ints if 32 <= v <= 126)
        if printable / len(ints) > 0.80 and len(ints) >= 8:
            result.findings.append(ObfuscationFinding(
                kind=ObfuscationKind.CONSTANT_FOLDING,
                code_name=co.name,
                description=f"{len(ints)} integer constants in printable ASCII range — possible XOR encoding",
                detail="Constants may encode a string as individual ASCII/XOR'd integers.",
                confidence=0.65,
            ))
