from __future__ import annotations

import json
import sys

from config import AnalysisResult, ObfuscationKind


_RESET = "\033[0m"
_BOLD  = "\033[1m"
_CYAN  = "\033[36m"
_GREEN = "\033[32m"
_YELLOW = "\033[33m"
_RED   = "\033[31m"
_MAGENTA = "\033[35m"


def _c(text: str, code: str, use_colour: bool) -> str:
    return f"{code}{text}{_RESET}" if use_colour else text


class Reporter:

    def print_result(
        self,
        result: AnalysisResult,
        verbose: bool = False,
        use_colour: bool | None = None,
    ):
        if use_colour is None:
            use_colour = sys.stdout.isatty()

        print()
        print(_c(f"── {result.path}", _BOLD, use_colour))

        if result.error:
            print(f"  ERROR: {result.error}")
            return

        print(f"  Python version : {result.python_version}")
        if result.source_file:
            print(f"  Source file    : {result.source_file}")
        if result.timestamp:
            from analyzer.pyc_parser import PycParser
            print(f"  Timestamp      : {PycParser.timestamp_str(result.timestamp)}")
        print(f"  Code objects   : {result.code_objects}")
        score = result.obfuscation_score
        score_str = f"{score:.0%}"
        if score > 0.6:
            score_str = _c(score_str, _RED, use_colour)
        elif score > 0.3:
            score_str = _c(score_str, _YELLOW, use_colour)
        else:
            score_str = _c(score_str, _GREEN, use_colour)
        print(f"  Obfuscation    : {score_str}")

        findings = result.findings
        if not verbose:
            findings = [f for f in findings if f.confidence >= 0.5]

        if not findings:
            print(f"  Status         : {_c('CLEAN', _GREEN, use_colour)}")
            return

        print(f"  Findings       : {len(findings)}")
        print()

        by_code: dict[str, list] = {}
        for f in sorted(findings, key=lambda x: -x.confidence):
            by_code.setdefault(f.code_name, []).append(f)

        for code_name, fs in by_code.items():
            print(_c(f"  [{code_name}]", _CYAN, use_colour))
            for f in fs:
                loc  = f" @0x{f.offset:04x}" if f.offset is not None else ""
                conf = f"{f.confidence:.0%}"
                kind = _c(f.kind.value, _MAGENTA if f.confidence >= 0.8 else _YELLOW, use_colour)
                print(f"    {kind:<35} {conf:>4}  {f.description}{loc}")
                if f.detail and verbose:
                    print(f"    {'':35}       {f.detail}")
            print()

    def print_disassembly(
        self,
        co,           # CodeObject
        max_instructions: int = 200,
        use_colour: bool | None = None,
    ):
        if use_colour is None:
            use_colour = sys.stdout.isatty()
        from analyzer.disassembler import walk_code_objects
        for code_obj in walk_code_objects(co):
            print()
            header = f"  Code object: {code_obj.name}  (line {code_obj.firstlineno})"
            print(_c(header, _CYAN, use_colour))
            print(f"  {'offset':>6}  {'opname':<30} {'arg'}")
            print("  " + "─" * 60)
            for instr in code_obj.instructions[:max_instructions]:
                line_marker = f"L{instr.starts_line}" if instr.starts_line else ""
                print(f"  {line_marker:<4} {instr.offset:>6}  {instr.opname:<30} {instr.argrepr}")
            if len(code_obj.instructions) > max_instructions:
                print(f"  ... ({len(code_obj.instructions) - max_instructions} more instructions)")

    def result_to_dict(self, result: AnalysisResult) -> dict:
        return {
            "path":             result.path,
            "python_version":   result.python_version,
            "source_file":      result.source_file,
            "timestamp":        result.timestamp,
            "code_objects":     result.code_objects,
            "obfuscated":       result.obfuscated,
            "obfuscation_score": result.obfuscation_score,
            "error":            result.error,
            "findings": [
                {
                    "kind":        f.kind.value,
                    "code_name":   f.code_name,
                    "offset":      f.offset,
                    "confidence":  round(f.confidence, 3),
                    "description": f.description,
                    "detail":      f.detail,
                }
                for f in result.findings
            ],
        }

    def results_to_json(self, results: list[AnalysisResult]) -> str:
        return json.dumps([self.result_to_dict(r) for r in results], indent=2)
