"""Joins the bytecode analyzer to the platform as a scanner.

`.pyc` files are analysed statically — parsed and disassembled, never imported,
because importing a hostile module is executing it.

Findings carry their own confidence, which becomes the event score. Severity
comes from the *kind* of obfuscation, not the confidence: a confidently
detected missing docstring is still not interesting, and a low-confidence
`exec` of a decoded string very much is.
"""

from __future__ import annotations

import sys
from pathlib import Path
from typing import Any

_HERE = Path(__file__).resolve().parent
for _path in (_HERE, _HERE.parents[1]):
    if str(_path) not in sys.path:
        sys.path.insert(0, str(_path))

from analyze import analyse_file  # noqa: E402
from bytecode_config import ObfuscationKind  # noqa: E402
from secops.core.event import Category, Event, SensorResult, Severity  # noqa: E402
from secops.core.sensor import Sensor, spec  # noqa: E402

# Dynamic execution of decoded data is the pattern worth waking someone for;
# structural obfuscation is evidence, not the payload.
_HIGH = {
    ObfuscationKind.EXEC_EVAL_USE,
    ObfuscationKind.DYNAMIC_IMPORT,
    ObfuscationKind.BASE64_ENCODED,
    ObfuscationKind.SELF_MODIFYING,
}
_LOW = {
    ObfuscationKind.MISSING_DOCSTRING,
    ObfuscationKind.NESTED_CODE_OBJECTS,
    ObfuscationKind.SINGLE_CHAR_NAMES,
}


def _severity(kind: ObfuscationKind, confidence: float) -> Severity:
    if kind in _HIGH:
        return Severity.HIGH
    if kind in _LOW:
        return Severity.INFO
    return Severity.MEDIUM if confidence >= 0.6 else Severity.LOW


class BytecodeSensor(Sensor):
    def observe(self, target: Any, **options: Any) -> SensorResult:
        path = Path(str(target))
        result = self.result(str(path))

        analysis, _ = analyse_file(str(path))
        if analysis.error:
            result.error = analysis.error
            return result

        for finding in analysis.findings:
            result.emit(
                Event(
                    sensor=self.name,
                    category=Category.EVASION,
                    severity=_severity(finding.kind, finding.confidence),
                    title=finding.kind.value,
                    message=finding.description,
                    entity=str(path),
                    score=finding.confidence,
                    fields={
                        "code_object": finding.code_name,
                        "offset": finding.offset,
                        "detail": finding.detail,
                    },
                )
            )

        if analysis.obfuscated:
            result.emit(
                Event(
                    sensor=self.name,
                    category=Category.MALWARE,
                    severity=Severity.HIGH,
                    title="obfuscated_bytecode",
                    message=(
                        f"Weighted obfuscation score {analysis.obfuscation_score:.2f} "
                        f"across {analysis.code_objects} code objects. Obfuscation is "
                        f"not itself malicious, but it is deliberate."
                    ),
                    entity=str(path),
                    score=analysis.obfuscation_score,
                    fields={"python_version": analysis.python_version},
                )
            )

        result.metrics.update({
            "python_version": analysis.python_version,
            "code_objects": analysis.code_objects,
            "findings": len(analysis.findings),
            "obfuscation_score": round(analysis.obfuscation_score, 3),
        })
        return result


SENSOR = BytecodeSensor(spec("bytecode-analyzer"))
