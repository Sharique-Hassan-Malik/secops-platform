from parsers import apache, firewall, nginx, syslog


class TestApache:
    SAMPLE = '1.2.3.4 - - [22/Mar/2024:10:00:01 +0000] "GET /index.html HTTP/1.1" 200 1024 "-" "Mozilla/5.0"'

    def test_parse_200(self):
        r = apache.parse(self.SAMPLE)
        assert r is not None
        assert r["source_ip"]   == "1.2.3.4"
        assert r["method"]      == "GET"
        assert r["path"]        == "/index.html"
        assert r["status_code"] == 200
        assert r["severity"]    == "info"
        assert r["source_type"] == "apache"

    def test_severity_404(self):
        line = self.SAMPLE.replace('" 200', '" 404')
        assert apache.parse(line)["severity"] == "low"

    def test_severity_500(self):
        line = self.SAMPLE.replace('" 200', '" 500')
        assert apache.parse(line)["severity"] == "high"

    def test_invalid_returns_none(self):
        assert apache.parse("not a log line") is None


class TestNginx:
    SAMPLE = '10.0.0.1 - - [22/Mar/2024:10:00:02 +0000] "POST /login HTTP/1.1" 401 512 "-" "curl/7.68"'

    def test_parse_401(self):
        r = nginx.parse(self.SAMPLE)
        assert r is not None
        assert r["source_ip"]   == "10.0.0.1"
        assert r["method"]      == "POST"
        assert r["status_code"] == 401
        assert r["severity"]    == "low"
        assert r["source_type"] == "nginx"

    def test_invalid_returns_none(self):
        assert nginx.parse("") is None


class TestSyslog:
    SAMPLE = "<86>Mar 22 10:00:03 server1 sshd[1234]: Failed password for root from 10.0.0.50 port 22222 ssh2"

    def test_parse(self):
        r = syslog.parse(self.SAMPLE)
        assert r is not None
        assert r["source_ip"]   == "server1"
        assert r["severity"]    == "high"
        assert r["source_type"] == "syslog"

    def test_warning_severity(self):
        r = syslog.parse("<86>Mar 22 10:00:03 host1 kernel: warning disk usage high")
        assert r is not None
        assert r["severity"] == "medium"

    def test_invalid_returns_none(self):
        assert syslog.parse("plain text") is None


class TestFirewall:
    SAMPLE = (
        "Mar 22 10:00:04 server1 kernel: [12345.678] DROP IN=eth0 OUT= "
        "SRC=10.0.0.200 DST=192.168.1.1 LEN=40 TTL=64 ID=0 PROTO=TCP SPT=54321 DPT=22 WINDOW=0"
    )

    def test_parse_drop(self):
        r = firewall.parse(self.SAMPLE)
        assert r is not None
        assert r["source_ip"]   == "10.0.0.200"
        assert r["severity"]    == "high"
        assert r["method"]      == "TCP"
        assert r["path"]        == ":22"
        assert r["source_type"] == "firewall"

    def test_accept_is_info(self):
        line = self.SAMPLE.replace("DROP", "ACCEPT")
        assert firewall.parse(line)["severity"] == "info"

    def test_no_kernel_returns_none(self):
        assert firewall.parse("Mar 22 10:00:04 server1 sshd: something") is None
