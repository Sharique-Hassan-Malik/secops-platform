"""
MQTT v3.1.1 protocol generator.

Wire format: Fixed header (1–2 bytes) + remaining length (variable) + payload.

Fixed header byte:
    [7:4] packet type  (1=CONNECT 2=CONNACK 3=PUBLISH ... 14=DISCONNECT)
    [3]   DUP flag
    [2:1] QoS level
    [0]   RETAIN flag

Remaining length: 1–4 bytes, variable-length encoding (continuation bit in MSB).

Seeds cover:
    - CONNECT with clean session, various client IDs
    - PUBLISH QoS 0/1/2 with various topic and payload sizes
    - SUBSCRIBE / UNSUBSCRIBE
    - PINGREQ
    - DISCONNECT
    - Malformed: wrong remaining length, oversized client ID, null topic,
      negative remaining length (0xFF), truncated packets
"""

from __future__ import annotations

import random
import struct

from protocols import ProtocolGenerator


_PACKET_TYPES = {
    "CONNECT":     1,
    "CONNACK":     2,
    "PUBLISH":     3,
    "PUBACK":      4,
    "PUBREC":      5,
    "PUBREL":      6,
    "PUBCOMP":     7,
    "SUBSCRIBE":   8,
    "SUBACK":      9,
    "UNSUBSCRIBE": 10,
    "UNSUBACK":    11,
    "PINGREQ":     12,
    "PINGRESP":    13,
    "DISCONNECT":  14,
}


def _encode_remaining_length(n: int) -> bytes:
    """MQTT variable-length encoding for remaining length."""
    if n < 0:
        return b"\xff"   # intentionally malformed
    out = b""
    for _ in range(4):
        byte = n & 0x7F
        n  >>= 7
        if n > 0:
            byte |= 0x80
        out += bytes([byte])
        if n == 0:
            break
    return out


def _encode_string(s: str | bytes) -> bytes:
    """MQTT UTF-8 string: 2-byte length prefix + content."""
    if isinstance(s, str):
        enc = s.encode("utf-8", errors="replace")
    else:
        enc = s
    return struct.pack(">H", len(enc)) + enc


def make_connect(
    client_id: str = "fuzz-client",
    clean_session: bool = True,
    keepalive: int = 60,
    username: str | None = None,
    password: bytes | None = None,
) -> bytes:
    payload  = _encode_string(client_id)
    flags    = 0x02 if clean_session else 0x00
    if username:
        flags   |= 0x80
        payload += _encode_string(username)
    if password:
        flags   |= 0x40
        payload += _encode_string(password)

    var_header = (
        _encode_string("MQTT")
        + b"\x04"                           # protocol level 4 = v3.1.1
        + bytes([flags])
        + struct.pack(">H", keepalive)
    )
    body      = var_header + payload
    fixed     = bytes([0x10]) + _encode_remaining_length(len(body))
    return fixed + body


def make_publish(
    topic:   str   = "test/topic",
    message: bytes = b"hello",
    qos:     int   = 0,
    retain:  bool  = False,
    dup:     bool  = False,
) -> bytes:
    flags    = (3 << 4) | ((int(dup) << 3) | (qos << 1) | int(retain))
    body     = _encode_string(topic)
    if qos > 0:
        body += struct.pack(">H", 0x0001)   # packet ID
    body    += message
    fixed    = bytes([flags]) + _encode_remaining_length(len(body))
    return fixed + body


def make_subscribe(topic: str = "test/#", qos: int = 0) -> bytes:
    body  = struct.pack(">H", 0x0001)    # packet ID
    body += _encode_string(topic) + bytes([qos])
    fixed = bytes([0x82]) + _encode_remaining_length(len(body))
    return fixed + body


def make_pingreq() -> bytes:
    return b"\xC0\x00"


def make_disconnect() -> bytes:
    return b"\xE0\x00"


class MQTTGenerator(ProtocolGenerator):

    def seeds(self) -> list[bytes]:
        seeds = [
            make_connect("fuzzer-1"),
            make_connect("fuzzer-2", clean_session=False),
            make_connect("A" * 23),                     # max valid client ID
            # Oversized client ID: manually encode length > 0xFFFF
            (b"\x10\x0b"                     # CONNECT, remaining=11
             + b"\x00\x04MQTT\x04\x02\x00<"  # protocol header
             + b"\xff\xff" + b"A" * 10),    # length=65535 but only 10 bytes follow
            make_connect(""),                            # empty client ID
            make_connect("\x00\xff\xfe"),               # binary client ID
            make_publish("test/topic", b"hello"),
            make_publish("test/topic", b"hello", qos=1),
            make_publish("test/topic", b"hello", qos=2),
            make_publish("", b"hello"),                  # empty topic
            # Oversized topic: manually craft — length field says 65535 but body is short
            (b"\x30\x10"               # PUBLISH fixed header, remaining=16
             + b"\xff\xff"             # topic length = 65535 (malformed)
             + b"/test" + b"hello"),     # only 9 bytes follow
            make_publish("test", b"X" * 65536),          # oversized payload
            make_publish("test/\x00null", b"data"),      # null in topic
            make_subscribe("test/#"),
            make_subscribe("#"),
            make_subscribe("+/+"),
            make_pingreq(),
            make_disconnect(),
            # Truncated CONNECT
            bytes([0x10, 0x05]) + b"MQTT\x04",
            # Wrong packet type / remaining length
            bytes([0x10, 0xFF, 0xFF, 0xFF, 0xFF]) + b"MQTT\x04\x02\x00<fuzz",
            # All zeros
            b"\x00\x00",
            # Garbage
            bytes(range(256)),
        ]
        return seeds

    def generate(self, rng: random.Random) -> bytes:
        mode = rng.choice([
            "connect", "publish", "subscribe", "ping", "disconnect",
            "bad_remaining_len", "bad_packet_type", "truncated", "garbage",
        ])

        if mode == "connect":
            cid      = _rand_client_id(rng)
            keepalive = rng.choice([0, 1, 60, 65535, 0xFFFF])
            return make_connect(cid, rng.choice([True, False]), keepalive)

        if mode == "publish":
            topic   = _rand_topic(rng)
            payload = bytes(rng.randint(0, 255) for _ in range(rng.randint(0, 1024)))
            qos     = rng.choice([0, 1, 2, 3])   # QoS 3 is invalid
            return make_publish(topic, payload, qos)

        if mode == "subscribe":
            topic = _rand_topic(rng)
            qos   = rng.choice([0, 1, 2, 3, 255])
            return make_subscribe(topic, qos)

        if mode == "ping":
            return make_pingreq()

        if mode == "disconnect":
            return make_disconnect()

        if mode == "bad_remaining_len":
            ptype    = rng.choice(list(_PACKET_TYPES.values()))
            rem_len  = rng.choice([0, 1, 0x7F, 0x80, 0xFF, 0xFFFF, 0xFFFFFF, 0xFFFFFFF])
            body     = bytes(rng.randint(0, 255) for _ in range(rng.randint(0, 64)))
            return bytes([ptype << 4]) + _encode_remaining_length(rem_len) + body

        if mode == "bad_packet_type":
            ptype = rng.choice([0, 15, 16])   # 0 and 15+ are reserved/invalid
            body  = bytes(rng.randint(0, 255) for _ in range(rng.randint(0, 64)))
            rem   = min(len(body), 255)
            return bytes([(ptype << 4) & 0xFF, rem]) + body

        if mode == "truncated":
            full = rng.choice([
                make_connect("test"),
                make_publish("t", b"hello"),
            ])
            cut = rng.randint(0, max(1, len(full) - 1))
            return full[:cut]

        # garbage
        return bytes(rng.randint(0, 255) for _ in range(rng.randint(1, 256)))


def _rand_client_id(rng: random.Random) -> str:
    choices = [
        "fuzzer",
        "A" * rng.randint(0, 100),
        "client-" + str(rng.randint(0, 0xFFFF)),
        "",
        "X" * 200,   # large but valid-length client ID
        "\x00\xff",
    ]
    return rng.choice(choices)


def _rand_topic(rng: random.Random) -> str:
    choices = [
        "test/topic",
        "a/" * rng.randint(1, 10) + "b",
        "#",
        "+/+",
        "",
        "/" * rng.randint(1, 10),
        "T" * rng.randint(1, 200),
        "test/\x00null",
    ]
    return rng.choice(choices)
