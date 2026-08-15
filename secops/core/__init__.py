"""The shared contract: events, alerts, the sensor base class and rendering.

Stdlib-only, so a sensor run on its own from its own folder gets the schema
without the platform's dependency set coming with it.
"""

from .event import Alert, Category, Event, Kind, Report, SensorResult, Severity
from .sensor import Sensor, SensorSpec, SensorUnavailable

__all__ = [
    "Alert", "Category", "Event", "Kind", "Report", "SensorResult", "Severity",
    "Sensor", "SensorSpec", "SensorUnavailable",
]
