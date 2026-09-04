import statistics
from collections import defaultdict, deque
from datetime import datetime, timezone
from typing import Optional


class AnomalyDetector:
    """
    Per-IP request-rate anomaly detection using z-score over a rolling baseline.
    Events are bucketed into 10-second intervals. When the current bucket's rate
    deviates more than 3.5 standard deviations from the rolling mean an alert
    is returned.
    """

    BUCKET_SECONDS   = 10
    BASELINE_BUCKETS = 30
    Z_THRESHOLD      = 3.5

    def __init__(self):
        self._buckets: dict[str, deque] = defaultdict(
            lambda: deque(maxlen=self.BASELINE_BUCKETS + 2)
        )
        self._current: dict[str, tuple] = {}

    def feed(self, event) -> Optional[dict]:
        ip = event.source_ip
        if not ip or event.source_type not in ("apache", "nginx"):
            return None
        now = event.timestamp or datetime.now(timezone.utc).replace(tzinfo=None)
        bucket_ts = datetime(
            now.year, now.month, now.day,
            now.hour, now.minute,
            (now.second // self.BUCKET_SECONDS) * self.BUCKET_SECONDS,
        )

        cur = self._current.get(ip)
        if cur is None or cur[0] != bucket_ts:
            if cur is not None:
                self._buckets[ip].append(cur)
            self._current[ip] = (bucket_ts, 1)
        else:
            self._current[ip] = (cur[0], cur[1] + 1)

        counts = [c for _, c in self._buckets[ip]]
        if len(counts) < 5:
            return None

        mean  = statistics.mean(counts)
        stdev = statistics.pstdev(counts)
        if stdev < 1:
            return None

        current_count = self._current[ip][1]
        z = (current_count - mean) / stdev
        if z > self.Z_THRESHOLD:
            return {
                "rule_name":   "Traffic Anomaly",
                "severity":    "medium",
                "description": (
                    f"Request rate z-score {z:.1f} — {current_count} requests in 10 s "
                    f"(baseline mean {mean:.1f})"
                ),
                "source_ip":   ip,
                "event_count": current_count,
            }
        return None
