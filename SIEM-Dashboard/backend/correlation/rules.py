class Rule:
    __slots__ = ("name", "severity", "check", "window_seconds")

    def __init__(self, name, severity, check, window_seconds):
        self.name           = name
        self.severity       = severity
        self.check          = check
        self.window_seconds = window_seconds


def _brute_force_ssh(events: list) -> tuple[bool, str]:
    failed = [
        e for e in events
        if e.source_type == "syslog"
        and (
            "authentication failure" in (e.raw or "").lower()
            or "failed password" in (e.raw or "").lower()
        )
    ]
    if len(failed) >= 10:
        return True, f"{len(failed)} failed SSH authentication attempts"
    return False, ""


def _http_brute_force(events: list) -> tuple[bool, str]:
    errors = [e for e in events if e.status_code and 400 <= e.status_code < 500]
    if len(errors) >= 20:
        return True, f"{len(errors)} HTTP 4xx responses"
    return False, ""


def _port_scan(events: list) -> tuple[bool, str]:
    ports: set[int] = set()
    for e in events:
        if e.source_type == "firewall" and e.path:
            try:
                ports.add(int(e.path.lstrip(":")))
            except ValueError:
                pass
    if len(ports) >= 15:
        return True, f"Connections to {len(ports)} distinct ports"
    return False, ""


def _request_flood(events: list) -> tuple[bool, str]:
    http = [e for e in events if e.source_type in ("apache", "nginx")]
    if len(http) >= 100:
        return True, f"{len(http)} requests in 10 seconds"
    return False, ""


_SCANNER_AGENTS = ["nikto", "sqlmap", "nmap", "masscan", "zgrab", "dirbuster", "gobuster"]


def _web_scanner(events: list) -> tuple[bool, str]:
    not_found = [e for e in events if e.status_code == 404]
    agent_hit = any(
        any(s in (e.user_agent or "").lower() for s in _SCANNER_AGENTS)
        for e in events
    )
    if agent_hit:
        return True, "Known web scanner user-agent detected"
    if len(not_found) >= 30:
        return True, f"Web scanner activity — {len(not_found)} 404 responses"
    return False, ""


RULES = [
    Rule("SSH Brute Force",  "critical", _brute_force_ssh,  60),
    Rule("HTTP Brute Force", "high",     _http_brute_force, 60),
    Rule("Port Scan",        "high",     _port_scan,        30),
    Rule("Request Flood",    "critical", _request_flood,    10),
    Rule("Web Scanner",      "medium",   _web_scanner,      120),
]
