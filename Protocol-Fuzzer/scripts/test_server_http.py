#!/usr/bin/env python3
"""
Start a minimal HTTP server on localhost:8080 for live fuzzing tests.

The server intentionally implements several crash-triggering behaviours to
validate that the fuzzer detects them:

    /crash           — returns HTTP 500
    /slow            — waits 5 seconds before responding (triggers timeout)
    /close           — immediately closes the connection (unexpected close)
    /                — returns 200 OK

Usage:
    python scripts/test_server_http.py
    # In another terminal:
    python fuzz.py http --port 8080 --iterations 200 --timeout 2.0
"""

import sys
import time
from http.server import BaseHTTPRequestHandler, HTTPServer


class FuzzTarget(BaseHTTPRequestHandler):

    def log_message(self, fmt, *args):
        pass   # suppress default access log

    def do_GET(self):
        self._handle()

    def do_POST(self):
        n = int(self.headers.get("Content-Length", 0))
        self.rfile.read(min(n, 65536))
        self._handle()

    def _handle(self):
        path = self.path.split("?")[0]
        if path == "/crash":
            self.send_response(500)
            self.end_headers()
            self.wfile.write(b"Internal Server Error")
        elif path == "/slow":
            time.sleep(5)
            self.send_response(200)
            self.end_headers()
        elif path == "/close":
            self.connection.close()
        else:
            self.send_response(200)
            self.send_header("Content-Type", "text/plain")
            self.end_headers()
            self.wfile.write(b"OK")


def main():
    host, port = "127.0.0.1", 8080
    server = HTTPServer((host, port), FuzzTarget)
    print(f"HTTP test server on {host}:{port}")
    print("  GET /        → 200 OK")
    print("  GET /crash   → 500 Internal Server Error")
    print("  GET /slow    → 200 (after 5s delay — triggers timeout)")
    print("  GET /close   → connection closed immediately")
    print("\nPress Ctrl-C to stop.")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    main()
