"""
HTTP/1.1 protocol generator.

Seeds cover:
    - GET, POST, HEAD, PUT, DELETE, OPTIONS, TRACE, CONNECT, PATCH
    - Long URIs and query strings
    - Unusual header values (empty, very long, repeated)
    - HTTP/0.9, HTTP/1.0, HTTP/1.1, HTTP/2.0 version strings
    - Chunked transfer encoding
    - Content-Length mismatches
    - Request smuggling variants (CL.TE, TE.CL)
    - Null bytes and binary data in headers
    - CRLF injection attempts
"""

from __future__ import annotations

import random
import string

from protocols import ProtocolGenerator


_METHODS = [
    "GET", "POST", "HEAD", "PUT", "DELETE",
    "OPTIONS", "TRACE", "CONNECT", "PATCH",
    "INVALID", "", "G\x00T", "GET\r\nGET",
]

_VERSIONS = [
    "HTTP/1.1", "HTTP/1.0", "HTTP/0.9", "HTTP/2.0",
    "HTTP/9.9", "HTTP/", "http/1.1", "HTTP/ 1.1",
    "HTTP/1.1\r\nX-Injected: yes",
]

_PATHS = [
    "/", "/index.html", "/admin", "/../../etc/passwd",
    "/.git/HEAD", "/cgi-bin/test.cgi",
    "/" + "A" * 8192,
    "/%00", "/%0d%0a", "/?q=" + "A" * 4096,
]

_HEADERS_STATIC = [
    b"Host: localhost\r\n",
    b"Host: localhost\r\nHost: evil.com\r\n",       # duplicate Host
    b"Content-Length: 0\r\n",
    b"Transfer-Encoding: chunked\r\nContent-Length: 5\r\n",  # CL.TE smuggling
    b"Content-Length: 5\r\nTransfer-Encoding: chunked\r\n",  # TE.CL smuggling
    b"Connection: keep-alive\r\n",
    b"X-Forwarded-For: 127.0.0.1\r\n",
    b"User-Agent: \x00\r\n",           # null in User-Agent
    b"" ,                               # no host at all
]

_CHUNK_BODIES = [
    b"5\r\nhello\r\n0\r\n\r\n",
    b"0\r\n\r\n",
    b"FFFFFFFF\r\n" + b"X" * 16 + b"\r\n0\r\n\r\n",   # huge chunk size
    b"-1\r\nhello\r\n0\r\n\r\n",                        # negative chunk size
    b"\r\n\r\n",
]


class HTTPGenerator(ProtocolGenerator):

    def seeds(self) -> list[bytes]:
        seeds = []
        # Core valid requests
        for method in ("GET", "POST", "HEAD", "DELETE", "OPTIONS"):
            seeds.append(
                f"{method} / HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n"
                .encode()
            )
        # Malformed requests
        seeds.append(b"GET HTTP/1.1\r\n\r\n")                     # missing path
        seeds.append(b"GET / \r\n\r\n")                            # missing version
        seeds.append(b"\r\n\r\n")                                  # empty
        seeds.append(b"GET / HTTP/1.1\r\n" + b"X: " + b"A" * 8000 + b"\r\n\r\n")   # huge header
        seeds.append(b"POST / HTTP/1.1\r\nContent-Length: 999\r\n\r\nhello")         # CL > body
        seeds.append(b"POST / HTTP/1.1\r\nTransfer-Encoding: chunked\r\n\r\n" + _CHUNK_BODIES[0])
        seeds.append(b"\x00\x01\x02\x03")                          # binary garbage
        # HTTP/2 preface
        seeds.append(b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n")
        return seeds

    def generate(self, rng: random.Random) -> bytes:
        method  = rng.choice(_METHODS)
        path    = rng.choice(_PATHS)
        version = rng.choice(_VERSIONS)
        header  = rng.choice(_HEADERS_STATIC)

        request_line = f"{method} {path} {version}\r\n".encode("latin-1", errors="replace")

        # Random extra headers
        n_extra = rng.randint(0, 5)
        extra   = b""
        for _ in range(n_extra):
            name  = _rand_token(rng, 1, 40)
            value = _rand_value(rng)
            extra += f"{name}: {value}\r\n".encode("latin-1", errors="replace")

        # Body for methods that typically have one
        body = b""
        if method in ("POST", "PUT", "PATCH"):
            body_len = rng.choice([0, 1, 4, 128, 4096, 65536])
            body     = bytes(rng.randint(0, 255) for _ in range(body_len))
            cl_hdr   = f"Content-Length: {body_len}\r\n".encode()
            extra   += cl_hdr

        return request_line + header + extra + b"\r\n" + body


def _rand_token(rng: random.Random, min_len: int, max_len: int) -> str:
    alphabet = string.ascii_letters + string.digits + "-_"
    n = rng.randint(min_len, max_len)
    return "".join(rng.choice(alphabet) for _ in range(n))


def _rand_value(rng: random.Random) -> str:
    choices = [
        "value",
        "A" * rng.randint(100, 8000),
        "\r\nX-Injected: yes",
        "\x00\x01\x02",
        "",
        "9" * 20,
        str(rng.randint(-(2**31), 2**32)),
    ]
    return rng.choice(choices)
