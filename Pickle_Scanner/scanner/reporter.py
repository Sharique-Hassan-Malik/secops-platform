from __future__ import annotations

import sys
from scanner.opcodes import Severity, ScanResult


# ANSI colour codes — automatically disabled when stdout is not a tty
_RESET  = "\033[0m"
_BOLD   = "\033[1m"
_COLOURS: dict[Severity, str] = {
    Severity.SAFE:     "\033[32m",   # green
    Severity.INFO:     "\033[36m",   # cyan
    Severity.LOW:      "\033[34m",   # blue
    Severity.MEDIUM:   "\033[33m",   # yellow
    Severity.HIGH:     "\033[31m",   # red
    Severity.CRITICAL: "\033[35m",   # magenta
}


def _colour(text: str, sev: Severity, use_colour: bool) -> str:
    if not use_colour:
        return text
    return f"{_COLOURS[sev]}{text}{_RESET}"


def _bold(text: str, use_colour: bool) -> str:
    return f"{_BOLD}{text}{_RESET}" if use_colour else text


def print_result(result: ScanResult, verbose: bool = False, use_colour: bool | None = None):
    """Print a single ScanResult to stdout."""
    if use_colour is None:
        use_colour = sys.stdout.isatty()

    print()
    header = f"── {result.path}"
    print(_bold(header, use_colour))

    if result.error:
        print(f"  ERROR: {result.error}")
        return

    print(f"  Protocol : {result.proto}")
    print(f"  Opcodes  : {result.n_opcodes}")

    findings = result.findings if verbose else [
        f for f in result.findings
        if f.severity >= Severity.LOW
    ]

    if not findings:
        label = _colour("CLEAN", Severity.SAFE, use_colour)
        print(f"  Status   : {label} — no dangerous opcodes found")
        return

    max_sev = result.max_severity
    status  = _colour(max_sev.value, max_sev, use_colour)
    print(f"  Status   : {status}")
    print(f"  Findings : {len(result.findings)}")
    print()

    for f in sorted(findings, key=lambda x: x.offset):
        sev_str = _colour(f"[{f.severity.value:<8}]", f.severity, use_colour)
        loc     = f"0x{f.offset:04x}"
        line    = f"  {sev_str}  {loc}  {f.opcode:<20}  {f.description}"
        if f.detail:
            line += f"\n{'':38}{f.detail}"
        print(line)


def print_summary(results: list[ScanResult], use_colour: bool | None = None):
    """Print a multi-file summary table."""
    if use_colour is None:
        use_colour = sys.stdout.isatty()

    from scanner.opcodes import Severity as S
    counts = {s: 0 for s in S}
    n_error = 0

    print()
    print(_bold("── Summary ─────────────────────────────────────────────", use_colour))
    for r in results:
        if r.error:
            n_error += 1
            status = "ERROR"
        else:
            ms     = r.max_severity
            status = _colour(ms.value, ms, use_colour)
            counts[ms] += 1
        short = r.path if len(r.path) <= 60 else "..." + r.path[-57:]
        print(f"  {status:<20}  {short}")

    print()
    for sev in [S.CRITICAL, S.HIGH, S.MEDIUM, S.LOW, S.INFO, S.SAFE]:
        if counts[sev]:
            label = _colour(sev.value, sev, use_colour)
            print(f"  {label:<20} {counts[sev]} file(s)")
    if n_error:
        print(f"  {'ERROR':<20} {n_error} file(s)")
    print()
