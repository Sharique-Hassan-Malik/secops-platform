from . import apache, firewall, nginx, syslog

REGISTRY = {
    "apache":   apache.parse,
    "nginx":    nginx.parse,
    "syslog":   syslog.parse,
    "firewall": firewall.parse,
}
