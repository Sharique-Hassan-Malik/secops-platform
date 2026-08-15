from datetime import datetime
from types import SimpleNamespace

from correlation.engine import CorrelationEngine


def _event(source_type, source_ip, status_code=200, path=None, user_agent=None, raw="", ts=None):
    return SimpleNamespace(
        source_type=source_type,
        source_ip=source_ip,
        status_code=status_code,
        path=path,
        user_agent=user_agent,
        raw=raw,
        timestamp=ts or datetime.utcnow(),
    )


class TestSSHBruteForce:
    def test_triggers_after_threshold(self):
        engine = CorrelationEngine()
        alerts = []
        for _ in range(12):
            e = _event("syslog", "1.1.1.1", raw="Failed password for root from 1.1.1.1")
            alerts.extend(engine.process(e))
        assert any(a["rule_name"] == "SSH Brute Force" for a in alerts)

    def test_no_trigger_below_threshold(self):
        engine = CorrelationEngine()
        alerts = []
        for _ in range(5):
            e = _event("syslog", "2.2.2.2", raw="Failed password for root from 2.2.2.2")
            alerts.extend(engine.process(e))
        assert not any(a["rule_name"] == "SSH Brute Force" for a in alerts)


class TestHTTPBruteForce:
    def test_triggers_after_threshold(self):
        engine = CorrelationEngine()
        alerts = []
        for _ in range(25):
            alerts.extend(engine.process(_event("nginx", "3.3.3.3", status_code=401)))
        assert any(a["rule_name"] == "HTTP Brute Force" for a in alerts)


class TestPortScan:
    def test_triggers_after_threshold(self):
        engine = CorrelationEngine()
        alerts = []
        for port in range(1, 20):
            alerts.extend(engine.process(_event("firewall", "4.4.4.4", path=f":{port}")))
        assert any(a["rule_name"] == "Port Scan" for a in alerts)


class TestRequestFlood:
    def test_triggers_after_threshold(self):
        engine = CorrelationEngine()
        alerts = []
        for _ in range(105):
            alerts.extend(engine.process(_event("nginx", "5.5.5.5", status_code=200)))
        assert any(a["rule_name"] == "Request Flood" for a in alerts)


class TestWebScanner:
    def test_triggers_on_scanner_ua(self):
        engine = CorrelationEngine()
        alerts = engine.process(_event("nginx", "6.6.6.6", status_code=200, user_agent="Nikto/2.1.6"))
        assert any(a["rule_name"] == "Web Scanner" for a in alerts)

    def test_triggers_on_404_flood(self):
        engine = CorrelationEngine()
        alerts = []
        for _ in range(32):
            alerts.extend(engine.process(_event("nginx", "7.7.7.7", status_code=404)))
        assert any(a["rule_name"] == "Web Scanner" for a in alerts)


class TestCooldown:
    def test_no_duplicate_alert_within_cooldown(self):
        engine = CorrelationEngine()
        alerts = []
        for _ in range(50):
            alerts.extend(engine.process(_event("nginx", "8.8.8.8", status_code=401)))
        ssh_alerts = [a for a in alerts if a["rule_name"] == "HTTP Brute Force"]
        assert len(ssh_alerts) == 1
