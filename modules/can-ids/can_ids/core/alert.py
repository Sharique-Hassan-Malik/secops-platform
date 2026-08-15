"""
Alert dataclass shared across all detectors.

Every detector emits zero or more Alert objects.  The analyzer collects them
all and passes them to the report layer.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional


SEVERITY_RANK = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}


@dataclass
class Alert:
    timestamp: float          # timestamp of the triggering frame (or window end)
    can_id: int               # offending CAN identifier
    detector: str             # "frequency" | "timing" | "replay" | "payload" | "unknown_id"
    severity: str             # "critical" | "high" | "medium" | "low" | "info"
    message: str              # human-readable description
    score: float = 0.0        # numeric anomaly score (detector-specific units)
    frame_data: bytes = b""   # raw payload bytes of the triggering frame
    extra: dict = field(default_factory=dict)   # detector-specific metadata

    @property
    def id_str(self) -> str:
        return f"{self.can_id:03X}" if self.can_id <= 0x7FF else f"{self.can_id:08X}"

    @property
    def severity_rank(self) -> int:
        return SEVERITY_RANK.get(self.severity, 99)
