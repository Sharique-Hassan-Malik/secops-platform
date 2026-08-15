"""
Generate realistic test log data for the SIEM dashboard.

Modes:
  --backfill   Write N historical entries to each log file and exit.
  --stream     Continuously append new entries, including periodic attack bursts.
"""

import argparse
import random
import time
from datetime import datetime, timedelta
from pathlib import Path

GOOD_IPS    = [f"192.168.1.{i}" for i in range(10, 40)]
BOT_IPS     = ["10.0.0.50", "10.0.0.51", "185.220.101.12", "45.33.32.156"]
ATTACKER_IP = "172.16.0.99"

PATHS = [
    "/", "/index.html", "/about", "/contact", "/api/v1/users",
    "/api/v1/products", "/static/app.js", "/static/style.css",
    "/favicon.ico", "/robots.txt",
]
SCAN_PATHS = [
    "/.env", "/admin", "/wp-login.php", "/phpmyadmin", "/.git/config",
    "/config.php", "/backup.zip", "/api/admin", "/manager/html",
    "/actuator/env", "/console", "/.htaccess",
]
UAS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15",
    "curl/7.88.1",
    "python-requests/2.31.0",
]

_MONTHS = ["Jan","Feb","Mar","Apr","May","Jun","Jul","Aug","Sep","Oct","Nov","Dec"]


def _apache_line(ts, ip, method, path, status, ua):
    t = ts.strftime("%d/") + _MONTHS[ts.month - 1] + ts.strftime("/%Y:%H:%M:%S +0000")
    return f'{ip} - - [{t}] "{method} {path} HTTP/1.1" {status} {random.randint(200, 8192)} "-" "{ua}"'


def _nginx_line(ts, ip, method, path, status, ua):
    t = ts.strftime("%d/") + _MONTHS[ts.month - 1] + ts.strftime("/%Y:%H:%M:%S +0000")
    return f'{ip} - - [{t}] "{method} {path} HTTP/1.1" {status} {random.randint(200, 8192)} "-" "{ua}"'


def _syslog_line(ts, msg):
    t = ts.strftime("%H:%M:%S")
    d = f"{_MONTHS[ts.month - 1]} {ts.day:2d}"
    return f"<86>{d} {t} server1 {msg}"


def _fw_line(ts, action, src, dst, proto, dpt):
    t = ts.strftime("%H:%M:%S")
    d = f"{_MONTHS[ts.month - 1]} {ts.day:2d}"
    return (
        f"{d} {t} server1 kernel: [12345.678] {action} IN=eth0 OUT= "
        f"SRC={src} DST={dst} LEN=40 TTL=64 ID=0 PROTO={proto} SPT=54321 DPT={dpt} WINDOW=0"
    )


SYSLOG_INFO = [
    "sshd[1234]: Accepted publickey for deploy from 192.168.1.10 port 48222",
    "cron[5678]: (root) CMD (/usr/lib/cron/run-crons)",
    "systemd[1]: Started Daily apt download activities.",
    "kernel: [UFW ALLOW] IN=eth0 SRC=192.168.1.5 DST=10.0.0.1 PROTO=TCP DPT=80",
]
_SSH_FAIL = "sshd[1234]: Failed password for root from {ip} port {port} ssh2"


def _normal_apache(ts):
    ip     = random.choice(GOOD_IPS)
    method = random.choices(["GET", "POST", "GET", "GET"], weights=[6, 2, 1, 1])[0]
    path   = random.choice(PATHS)
    status = random.choices([200, 304, 404, 500], weights=[80, 10, 8, 2])[0]
    return ("apache", _apache_line(ts, ip, method, path, status, random.choice(UAS)))


def _normal_nginx(ts):
    ip     = random.choice(GOOD_IPS)
    status = random.choices([200, 301, 400, 404], weights=[75, 10, 8, 7])[0]
    return ("nginx", _nginx_line(ts, ip, "GET", random.choice(PATHS), status, random.choice(UAS)))


def _normal_syslog(ts):
    return ("syslog", _syslog_line(ts, random.choice(SYSLOG_INFO)))


def _normal_fw(ts):
    ip  = random.choice(GOOD_IPS)
    dpt = random.choice([80, 443, 22, 8080])
    return ("firewall", _fw_line(ts, "ACCEPT", ip, "10.0.0.1", "TCP", dpt))


def _ssh_brute_burst(ts, n=15):
    lines = []
    for i in range(n):
        t    = ts + timedelta(seconds=i * 3)
        port = random.randint(30000, 60000)
        lines.append(("syslog", _syslog_line(t, _SSH_FAIL.format(ip=ATTACKER_IP, port=port))))
    return lines


def _port_scan_burst(ts, n=20):
    lines = []
    for i, dpt in enumerate(random.sample(range(1, 65535), n)):
        t = ts + timedelta(seconds=i)
        lines.append(("firewall", _fw_line(t, "DROP", ATTACKER_IP, "10.0.0.1", "TCP", dpt)))
    return lines


def _web_scan_burst(ts, n=35):
    lines = []
    gobuster = "gobuster/3.6"
    for i in range(n):
        t    = ts + timedelta(seconds=i * 2)
        path = random.choice(SCAN_PATHS)
        lines.append(("nginx", _nginx_line(t, ATTACKER_IP, "GET", path, 404, gobuster)))
    return lines


def _nikto_scan(ts):
    lines = []
    nikto = "Nikto/2.1.6"
    for i, path in enumerate(SCAN_PATHS):
        t = ts + timedelta(seconds=i)
        lines.append(("apache", _apache_line(t, ATTACKER_IP, "GET", path, 404, nikto)))
    return lines


def backfill(log_dir: Path, count: int) -> None:
    files = {
        src: open(log_dir / f"{src}_access.log" if src in ("apache", "nginx") else log_dir / f"{src}.log", "a")
        for src in ("apache", "nginx", "syslog", "firewall")
    }
    # fix filenames to match config
    files = {
        "apache":   open(log_dir / "apache_access.log", "a"),
        "nginx":    open(log_dir / "nginx_access.log",  "a"),
        "syslog":   open(log_dir / "syslog.log",        "a"),
        "firewall": open(log_dir / "firewall.log",      "a"),
    }
    generators = [_normal_apache, _normal_nginx, _normal_syslog, _normal_fw]
    now = datetime.utcnow()
    for i in range(count):
        ts       = now - timedelta(seconds=(count - i) * 10)
        src, line = random.choice(generators)(ts)
        files[src].write(line + "\n")
    for f in files.values():
        f.close()
    print(f"Wrote {count} historical entries to {log_dir}")


def stream(log_dir: Path) -> None:
    files = {
        "apache":   open(log_dir / "apache_access.log", "a"),
        "nginx":    open(log_dir / "nginx_access.log",  "a"),
        "syslog":   open(log_dir / "syslog.log",        "a"),
        "firewall": open(log_dir / "firewall.log",      "a"),
    }
    print("Streaming log data — Ctrl+C to stop")
    tick = 0
    try:
        while True:
            ts = datetime.utcnow()
            for _ in range(random.randint(1, 3)):
                src, line = random.choice([_normal_apache, _normal_nginx, _normal_syslog, _normal_fw])(ts)
                files[src].write(line + "\n")
                files[src].flush()

            if tick % 60 == 30:
                print("[+] Injecting SSH brute-force burst")
                for src, line in _ssh_brute_burst(ts):
                    files[src].write(line + "\n")
                    files[src].flush()

            if tick % 120 == 90:
                print("[+] Injecting port-scan burst")
                for src, line in _port_scan_burst(ts):
                    files[src].write(line + "\n")
                    files[src].flush()

            if tick % 90 == 0 and tick > 0:
                print("[+] Injecting web-scanner burst")
                for src, line in _web_scan_burst(ts):
                    files[src].write(line + "\n")
                    files[src].flush()

            if tick % 180 == 150:
                print("[+] Injecting Nikto scan")
                for src, line in _nikto_scan(ts):
                    files[src].write(line + "\n")
                    files[src].flush()

            tick += 1
            time.sleep(0.5)
    except KeyboardInterrupt:
        print("Stopped.")
    finally:
        for f in files.values():
            f.close()


def main() -> None:
    ap = argparse.ArgumentParser(
        description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    ap.add_argument("--log-dir",  default="./logs", help="Directory containing log files")
    ap.add_argument("--backfill", action="store_true", help="Write historical entries and exit")
    ap.add_argument("--stream",   action="store_true", help="Continuously append new entries")
    ap.add_argument("--count",    type=int, default=500, help="Number of entries for --backfill")
    args = ap.parse_args()

    log_dir = Path(args.log_dir)
    log_dir.mkdir(parents=True, exist_ok=True)

    if args.backfill:
        backfill(log_dir, args.count)
    elif args.stream:
        stream(log_dir)
    else:
        ap.print_help()


if __name__ == "__main__":
    main()
