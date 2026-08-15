import os
from pathlib import Path

DB_URL = os.getenv("DATABASE_URL", "sqlite:///./siem.db")
LOG_DIR = Path(os.getenv("LOG_DIR", "./logs"))

PARSERS = {
    "apache":   LOG_DIR / "apache_access.log",
    "nginx":    LOG_DIR / "nginx_access.log",
    "syslog":   LOG_DIR / "syslog.log",
    "firewall": LOG_DIR / "firewall.log",
}
