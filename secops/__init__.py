"""secops — ten security tools that report into one pipeline.

    from secops import pipeline
    report = pipeline.scan(["uploads/"], recursive=True)

Scanners, monitors and red-team simulators, each usable on its own from its own
folder under `modules/`, emitting one `Event` type so that correlation across
them is possible at all.
"""

from .core.event import Alert, Category, Event, Kind, Report, SensorResult, Severity
from .core.sensor import Sensor, SensorSpec

__version__ = "1.0.0"
__all__ = [
    "Alert", "Category", "Event", "Kind", "Report", "SensorResult", "Severity",
    "Sensor", "SensorSpec",
]
