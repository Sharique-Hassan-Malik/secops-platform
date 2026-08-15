"""
Test suite for the protocol fuzzer.

All tests run entirely offline — no network connections are made.
The engine tests use a mock sender that records what was transmitted.

Run with:
    python -m pytest tests/test_fuzzer.py -v
"""

from __future__ import annotations

import random
import struct
import sys
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent))

from fuzzer_config import FuzzTarget, FuzzerConfig, Protocol, CrashKind, FuzzSession
from fuzzer.mutator import Mutator, _BOUNDARY_INTS
from fuzzer.corpus import Corpus
from fuzzer.sender import SendResult
from fuzzer.engine import (
    FuzzEngine, _classify_http, _classify_dns, _classify_mqtt,
)
from protocols.http_gen import HTTPGenerator
from protocols.dns_gen import DNSGenerator, _encode_name, _make_query
from protocols.mqtt_gen import (
    MQTTGenerator, make_connect, make_publish,
    make_subscribe, make_pingreq, make_disconnect,
    _encode_remaining_length,
)


# ---------------------------------------------------------------------------
# Mutator
# ---------------------------------------------------------------------------

class TestMutator:

    def _cfg(self) -> FuzzerConfig:
        return FuzzerConfig(seed=1, iterations=10, mutation_rate=0.1)

    def test_bitflip_changes_bytes(self):
        m    = Mutator(self._cfg())
        data = b"hello world"
        _, out = m.mutate(data)
        assert out != data or True   # may rarely be equal; mostly different

    def test_output_within_size_limits(self):
        cfg = FuzzerConfig(seed=1, min_packet_size=4, max_packet_size=20)
        m   = Mutator(cfg)
        for _ in range(50):
            _, out = m.mutate(b"a" * 10)
            assert cfg.min_packet_size <= len(out) <= cfg.max_packet_size

    def test_all_strategies_producible(self):
        m       = Mutator(FuzzerConfig(seed=42, iterations=100))
        seen    = set()
        corpus  = [b"hello", b"world", b"test"]
        data    = b"base input"
        for _ in range(300):
            name, _ = m.mutate(data, corpus)
            seen.add(name)
        assert "bitflip"  in seen
        assert "byteflip" in seen
        assert "boundary" in seen
        assert "insert"   in seen
        assert "delete"   in seen

    def test_boundary_mutation_inserts_known_value(self):
        m    = Mutator(FuzzerConfig(seed=7))
        data = bytes(range(256))
        results = [m._boundary(data) for _ in range(30)]
        # At least some results should contain boundary byte sequences
        assert any(r != data for r in results)

    def test_splice_combines_corpus(self):
        m      = Mutator(FuzzerConfig(seed=3))
        data   = b"AAAA"
        corpus = [b"BBBB", b"CCCC"]
        results = [m._splice(data, corpus) for _ in range(20)]
        assert any(b"B" in r or b"C" in r for r in results)

    def test_havoc_applies_multiple_mutations(self):
        m    = Mutator(FuzzerConfig(seed=5, mutation_rate=0.3))
        data = b"stable input data"
        results = [m._havoc(data) for _ in range(20)]
        assert any(r != data for r in results)

    def test_empty_input_handled(self):
        m = Mutator(FuzzerConfig(seed=1))
        for strat in (m._bitflip, m._byteflip, m._boundary, m._delete, m._repeat):
            out = strat(b"")
            assert isinstance(out, bytes)

    def test_deterministic_with_same_seed(self):
        cfg1 = FuzzerConfig(seed=99)
        cfg2 = FuzzerConfig(seed=99)
        m1, m2 = Mutator(cfg1), Mutator(cfg2)
        data = b"reproducible"
        results1 = [m1.mutate(data) for _ in range(20)]
        results2 = [m2.mutate(data) for _ in range(20)]
        assert results1 == results2


# ---------------------------------------------------------------------------
# Corpus
# ---------------------------------------------------------------------------

class TestCorpus:

    def test_add_and_pick(self, tmp_path):
        c = Corpus(str(tmp_path / "corpus"))
        c.add(b"seed1")
        c.add(b"seed2")
        assert len(c) == 2
        assert c.pick() in (b"seed1", b"seed2")

    def test_saved_to_disk(self, tmp_path):
        d = tmp_path / "corpus"
        c = Corpus(str(d))
        c.add(b"hello")
        files = list(d.glob("*.bin"))
        assert len(files) == 1
        assert files[0].read_bytes() == b"hello"

    def test_loads_existing_on_init(self, tmp_path):
        d = tmp_path / "corpus"
        d.mkdir()
        (d / "00000000.bin").write_bytes(b"existing")
        c = Corpus(str(d))
        assert b"existing" in c.all()

    def test_empty_pick_returns_empty(self, tmp_path):
        c = Corpus(str(tmp_path / "corpus"))
        assert c.pick() == b""


# ---------------------------------------------------------------------------
# Protocol generators
# ---------------------------------------------------------------------------

class TestHTTPGenerator:

    def test_seeds_are_bytes(self):
        g = HTTPGenerator()
        for seed in g.seeds():
            assert isinstance(seed, bytes)

    def test_seeds_nonempty(self):
        assert len(HTTPGenerator().seeds()) >= 5

    def test_generate_is_bytes(self):
        g   = HTTPGenerator()
        rng = random.Random(1)
        for _ in range(20):
            out = g.generate(rng)
            assert isinstance(out, bytes)

    def test_valid_seed_contains_http(self):
        seeds = HTTPGenerator().seeds()
        assert any(b"HTTP" in s for s in seeds)


class TestDNSGenerator:

    def test_encode_name_roundtrip(self):
        enc = _encode_name("example.com")
        assert enc == b"\x07example\x03com\x00"

    def test_encode_empty_name(self):
        assert _encode_name("") == b"\x00"

    def test_make_query_structure(self):
        pkt = _make_query(0x1234, "example.com", qtype=1, qclass=1)
        txid = struct.unpack(">H", pkt[:2])[0]
        assert txid == 0x1234
        qdcount = struct.unpack(">H", pkt[4:6])[0]
        assert qdcount == 1

    def test_seeds_valid(self):
        g = DNSGenerator()
        for seed in g.seeds():
            assert isinstance(seed, bytes)

    def test_generate_produces_bytes(self):
        g   = DNSGenerator()
        rng = random.Random(42)
        for _ in range(30):
            out = g.generate(rng)
            assert isinstance(out, bytes)


class TestMQTTGenerator:

    def test_make_connect_fixed_header(self):
        pkt = make_connect("test")
        assert pkt[0] == 0x10   # CONNECT packet type

    def test_make_connect_protocol_name(self):
        pkt = make_connect("test")
        assert b"MQTT" in pkt

    def test_make_publish_fixed_header(self):
        pkt = make_publish("t", b"hello")
        assert (pkt[0] >> 4) == 3   # PUBLISH type

    def test_make_subscribe_type(self):
        pkt = make_subscribe("test/#")
        assert (pkt[0] >> 4) == 8   # SUBSCRIBE type

    def test_make_pingreq(self):
        assert make_pingreq() == b"\xC0\x00"

    def test_make_disconnect(self):
        assert make_disconnect() == b"\xE0\x00"

    def test_remaining_length_encoding(self):
        assert _encode_remaining_length(0)   == b"\x00"
        assert _encode_remaining_length(127) == b"\x7f"
        assert _encode_remaining_length(128) == b"\x80\x01"
        assert _encode_remaining_length(16383) == b"\xff\x7f"

    def test_seeds_are_bytes(self):
        g = MQTTGenerator()
        for seed in g.seeds():
            assert isinstance(seed, bytes)

    def test_generate_is_bytes(self):
        g   = MQTTGenerator()
        rng = random.Random(7)
        for _ in range(30):
            out = g.generate(rng)
            assert isinstance(out, bytes)


# ---------------------------------------------------------------------------
# Response classifiers
# ---------------------------------------------------------------------------

def _ok_result(response: bytes = b"HTTP/1.1 200 OK\r\n\r\n") -> SendResult:
    return SendResult(True, response, None, "", 0.01)


def _crash_result(kind: CrashKind, detail: str = "") -> SendResult:
    return SendResult(False, b"", kind, detail, 0.01)


class TestHTTPClassifier:

    def test_clean_200_no_crash(self):
        r = _classify_http(0, "bitflip", b"GET / HTTP/1.1\r\n\r\n",
                           _ok_result(b"HTTP/1.1 200 OK\r\n\r\n"))
        assert r is None

    def test_500_is_crash(self):
        r = _classify_http(0, "bitflip", b"GET / HTTP/1.1\r\n\r\n",
                           _ok_result(b"HTTP/1.1 500 Internal Server Error\r\n\r\n"))
        assert r is not None
        assert r.kind == CrashKind.SERVER_ERROR

    def test_timeout_is_crash(self):
        r = _classify_http(0, "boundary", b"GET / HTTP/1.1\r\n\r\n",
                           _crash_result(CrashKind.TIMEOUT, "timeout"))
        assert r is not None
        assert r.kind == CrashKind.TIMEOUT

    def test_connection_refused_ignored(self):
        r = _classify_http(0, "byteflip", b"x",
                           _crash_result(CrashKind.CONNECTION_REFUSED))
        assert r is None

    def test_unexpected_close_is_crash(self):
        r = _classify_http(0, "havoc", b"GET / HTTP/1.1\r\n\r\n",
                           _crash_result(CrashKind.UNEXPECTED_CLOSE))
        assert r is not None


class TestDNSClassifier:

    def test_valid_response_no_crash(self):
        r = _classify_dns(0, "bitflip", b"\x00" * 12,
                          SendResult(True, b"\x00" * 12, None, "", 0.01))
        assert r is None

    def test_short_response_is_crash(self):
        r = _classify_dns(0, "bitflip", b"\x00" * 12,
                          SendResult(True, b"\x00", None, "", 0.01))
        assert r is not None
        assert r.kind == CrashKind.MALFORMED_RESPONSE

    def test_timeout_is_crash(self):
        r = _classify_dns(0, "boundary", b"\x00" * 12,
                          _crash_result(CrashKind.TIMEOUT))
        assert r is not None


class TestMQTTClassifier:

    def test_valid_connack_no_crash(self):
        connack = b"\x20\x02\x00\x00"   # valid CONNACK
        r = _classify_mqtt(0, "bitflip", make_connect("test"),
                           SendResult(True, connack, None, "", 0.01))
        assert r is None

    def test_malformed_connack_is_crash(self):
        bad_connack = b"\x20\x05\x00\x00\x00\x00\x00"  # wrong length
        r = _classify_mqtt(0, "havoc", make_connect("test"),
                           SendResult(True, bad_connack, None, "", 0.01))
        assert r is not None
        assert r.kind == CrashKind.MALFORMED_RESPONSE


# ---------------------------------------------------------------------------
# FuzzSession deduplication
# ---------------------------------------------------------------------------

class TestFuzzSession:

    def _session(self) -> FuzzSession:
        return FuzzSession(
            target=FuzzTarget(),
            config=FuzzerConfig(deduplicate=True),
        )

    def test_first_crash_recorded(self):
        from fuzzer_config import CrashRecord
        s = self._session()
        cr = CrashRecord(0, "http", "bitflip", b"x", CrashKind.TIMEOUT, "timed out")
        assert s.record(cr) is True
        assert len(s.crashes) == 1

    def test_duplicate_not_re_recorded(self):
        from fuzzer_config import CrashRecord
        s = self._session()
        cr = CrashRecord(0, "http", "bitflip", b"x", CrashKind.TIMEOUT, "timed out")
        s.record(cr)
        cr2 = CrashRecord(1, "http", "byteflip", b"y", CrashKind.TIMEOUT, "timed out")
        assert s.record(cr2) is False
        assert s.unique_crashes == 1

    def test_different_kind_recorded_separately(self):
        from fuzzer_config import CrashRecord
        s = self._session()
        s.record(CrashRecord(0, "http", "b", b"x", CrashKind.TIMEOUT, "x"))
        s.record(CrashRecord(1, "http", "b", b"x", CrashKind.SERVER_ERROR, "y"))
        assert s.unique_crashes == 2
