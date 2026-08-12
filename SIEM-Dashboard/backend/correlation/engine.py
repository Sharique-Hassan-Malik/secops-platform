from collections import defaultdict, deque
from datetime import datetime, timedelta

from .rules import RULES


class CorrelationEngine:
    """
    Maintains a per-source-IP sliding window. On each new event all registered
    rules evaluate the current window. A cooldown prevents alert flooding.
    """

    _COOLDOWN = timedelta(seconds=300)

    def __init__(self):
        self._windows: dict[str, deque] = defaultdict(deque)
        self._last_alert: dict[tuple, datetime] = {}

    def process(self, event) -> list[dict]:
        ip = event.source_ip
        if not ip:
            return []
        now = event.timestamp or datetime.utcnow()
        self._windows[ip].append(event)

        alerts = []
        for rule in RULES:
            cutoff = now - timedelta(seconds=rule.window_seconds)
            window = [e for e in self._windows[ip] if (e.timestamp or now) >= cutoff]
            triggered, detail = rule.check(window)
            if not triggered:
                continue
            key = (ip, rule.name)
            last = self._last_alert.get(key)
            if last and (now - last) < self._COOLDOWN:
                continue
            self._last_alert[key] = now
            alerts.append({
                "rule_name":   rule.name,
                "severity":    rule.severity,
                "description": detail,
                "source_ip":   ip,
                "event_count": len(window),
            })

        max_window = max(r.window_seconds for r in RULES)
        cutoff = now - timedelta(seconds=max_window)
        while self._windows[ip] and (self._windows[ip][0].timestamp or now) < cutoff:
            self._windows[ip].popleft()

        return alerts
