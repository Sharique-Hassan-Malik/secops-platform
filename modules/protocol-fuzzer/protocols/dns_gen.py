"""
DNS protocol generator.

Wire format (RFC 1035):
    [0:2]   Transaction ID  (uint16)
    [2:4]   Flags           (uint16)
    [4:6]   QDCOUNT         (uint16) — number of questions
    [6:8]   ANCOUNT         (uint16)
    [8:10]  NSCOUNT         (uint16)
    [10:12] ARCOUNT         (uint16)
    [12:]   Questions section, then answers, etc.

Each question:
    QNAME   — sequence of labels, each prefixed by length byte, ending with 0x00
    QTYPE   — uint16 (1=A, 2=NS, 5=CNAME, 15=MX, 16=TXT, 28=AAAA, 255=ANY)
    QCLASS  — uint16 (1=IN)

Seeds cover:
    - Standard A/AAAA/MX/TXT/ANY queries for several hostnames
    - Oversized labels (>63 bytes, violating RFC)
    - Compression pointer loops
    - Zero QDCOUNT with data in the questions section
    - Extremely long names (>255 bytes total)
    - Binary garbage
    - EDNS OPT records
"""

from __future__ import annotations

import random
import struct

from protocols import ProtocolGenerator


_QTYPES  = [1, 2, 5, 15, 16, 28, 33, 255, 0, 0xFFFF]  # A NS CNAME MX TXT AAAA SRV ANY
_QCLASS  = [1, 255, 0, 0xFFFF]                           # IN ANY NONE *
_NAMES   = [
    "example.com", "localhost", "google.com",
    "a" * 63 + ".com",               # max label length
    "a." * 127 + "com",              # near max total name length
    "\x00evil.com",                  # null byte in label
]


def _encode_name(name: str) -> bytes:
    """Encode a dotted domain name as DNS wire format labels."""
    if not name:
        return b"\x00"
    out = b""
    for label in name.split("."):
        enc = label.encode("ascii", errors="replace")
        out += bytes([len(enc)]) + enc
    return out + b"\x00"


def _make_query(
    txid:   int,
    name:   str,
    qtype:  int = 1,
    qclass: int = 1,
    flags:  int = 0x0100,   # standard query, recursion desired
) -> bytes:
    header = struct.pack(">HHHHHH", txid, flags, 1, 0, 0, 0)
    qname  = _encode_name(name)
    q      = struct.pack(">HH", qtype, qclass)
    return header + qname + q


class DNSGenerator(ProtocolGenerator):

    def seeds(self) -> list[bytes]:
        seeds = []
        # Standard queries
        for name in ("example.com", "localhost", "google.com"):
            for qtype in (1, 28, 15, 255):
                seeds.append(_make_query(0x1234, name, qtype))

        # Malformed packets
        seeds.append(b"\x00" * 12)                           # all-zero header
        seeds.append(b"\xff\xff\xff\xff" * 3)                # garbage header
        seeds.append(struct.pack(">HHHHHH", 1, 0x0100, 0xFFFF, 0, 0, 0) + b"\x00\x00\x01\x00\x01")  # huge QDCOUNT
        seeds.append(b"\x12\x34\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00"
                     + b"\xc0\x0c"    # compression pointer back to offset 0 (loop)
                     + b"\x00\x01\x00\x01")
        # Oversized label
        seeds.append(_make_query(0xABCD, "A" * 64 + ".com"))
        # Empty packet
        seeds.append(b"")
        seeds.append(b"\x00")
        # EDNS OPT (additional section)
        edns_opt = struct.pack(">HHHHHH", 0x5678, 0x0100, 1, 0, 0, 1) \
                 + _encode_name("example.com") + struct.pack(">HH", 1, 1) \
                 + b"\x00\x00\x29\x10\x00\x00\x00\x00\x00\x00\x00"
        seeds.append(edns_opt)
        return seeds

    def generate(self, rng: random.Random) -> bytes:
        mode = rng.choice(["valid", "mangled_name", "bad_header", "garbage",
                            "compression_loop", "long_name"])

        if mode == "valid":
            name   = rng.choice(_NAMES[:3])
            qtype  = rng.choice(_QTYPES)
            qclass = rng.choice(_QCLASS)
            txid   = rng.randint(0, 0xFFFF)
            return _make_query(txid, name, qtype, qclass)

        if mode == "mangled_name":
            # Random label lengths including 0, > 63, 255
            txid   = rng.randint(0, 0xFFFF)
            flags  = rng.randint(0, 0xFFFF)
            name   = _mangled_name(rng)
            qtype  = rng.choice(_QTYPES)
            qclass = rng.choice(_QCLASS)
            header = struct.pack(">HHHHHH", txid, flags, 1, 0, 0, 0)
            q      = struct.pack(">HH", qtype, qclass)
            return header + name + q

        if mode == "bad_header":
            # Random flags / counts
            txid   = rng.randint(0, 0xFFFF)
            flags  = rng.randint(0, 0xFFFF)
            qdcnt  = rng.randint(0, 10)
            header = struct.pack(">HHHHHH", txid, flags, qdcnt, 0, 0, 0)
            return header + bytes(rng.randint(0, 255) for _ in range(rng.randint(0, 64)))

        if mode == "compression_loop":
            txid   = rng.randint(0, 0xFFFF)
            header = struct.pack(">HHHHHH", txid, 0x0100, 1, 0, 0, 0)
            offset = rng.randint(0, 11)
            ptr    = struct.pack(">H", 0xC000 | offset)   # pointer to offset
            return header + ptr + b"\x00\x01\x00\x01"

        if mode == "long_name":
            # 500+ byte name
            txid   = rng.randint(0, 0xFFFF)
            labels = [bytes([rng.randint(1, 63)]) + bytes(rng.randint(0, 255) for _ in range(rng.randint(1, 63)))
                      for _ in range(rng.randint(5, 20))]
            name   = b"".join(labels) + b"\x00"
            header = struct.pack(">HHHHHH", txid, 0x0100, 1, 0, 0, 0)
            return header + name + b"\x00\x01\x00\x01"

        # garbage
        return bytes(rng.randint(0, 255) for _ in range(rng.randint(1, 512)))


def _mangled_name(rng: random.Random) -> bytes:
    out = b""
    for _ in range(rng.randint(1, 10)):
        length = rng.choice([0, 1, 63, 64, 128, 255, rng.randint(0, 255)])
        label  = bytes(rng.randint(0, 255) for _ in range(min(length, 255)))
        out   += bytes([length]) + label
    return out + b"\x00"
