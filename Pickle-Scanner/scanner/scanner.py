from __future__ import annotations

from scanner.analyser import Analyser
from scanner.extractor import extract_payloads
from scanner.opcodes import Severity, ScanResult
from scanner.parser import PickleParser, ParseError


def scan_file(path: str, strict: bool = False) -> list[ScanResult]:
    """
    Scan a file for dangerous pickle opcodes.

    Returns one ScanResult per pickle payload found in the file.
    A single PyTorch .pt may contain multiple payloads (one per tensor).

    Args:
        path:   path to the file to scan
        strict: if True, private C-extension modules raise severity to HIGH
    """
    try:
        payloads = extract_payloads(path)
    except (OSError, PermissionError) as exc:
        result = ScanResult(path=path, safe=False, error=str(exc))
        return [result]

    results = []
    parser  = PickleParser()

    for payload in payloads:
        result = ScanResult(path=payload.source)

        if not payload.data:
            result.error = "No pickle payload (non-pickle format or empty file)"
            results.append(result)
            continue

        analyser = Analyser(result, strict=strict)
        try:
            for instr in parser.parse(payload.data):
                analyser.feed(instr)
        except ParseError as exc:
            result.error = f"Parse error: {exc}"
            result.safe  = False

        results.append(result)

    return results


def scan_bytes(data: bytes, label: str = "<bytes>", strict: bool = False) -> ScanResult:
    """
    Scan raw pickle bytes directly — useful for testing and embedding in
    other tools.
    """
    result   = ScanResult(path=label)
    parser   = PickleParser()
    analyser = Analyser(result, strict=strict)

    try:
        for instr in parser.parse(data):
            analyser.feed(instr)
    except ParseError as exc:
        result.error = f"Parse error: {exc}"
        result.safe  = False

    return result
