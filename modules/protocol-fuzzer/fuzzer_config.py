from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any


class Protocol(Enum):
    HTTP  = "http"
    DNS   = "dns"
    MQTT  = "mqtt"


class CrashKind(Enum):
    CONNECTION_REFUSED = "CONNECTION_REFUSED"
    TIMEOUT            = "TIMEOUT"
    UNEXPECTED_CLOSE   = "UNEXPECTED_CLOSE"
    SERVER_ERROR       = "SERVER_ERROR"      # HTTP 5xx
    MALFORMED_RESPONSE = "MALFORMED_RESPONSE"
    EXCEPTION          = "EXCEPTION"


@dataclass
class FuzzTarget:
    host:     str   = "127.0.0.1"
    port:     int   = 80
    protocol: Protocol = Protocol.HTTP
    timeout:  float = 3.0
    # TLS
    tls:      bool  = False


@dataclass
class FuzzerConfig:
    seed:             int   = 42
    iterations:       int   = 1000
    max_packet_size:  int   = 65535
    min_packet_size:  int   = 1
    mutation_rate:    float = 0.05   # fraction of bytes mutated per packet
    # Mutation strategy weights — relative probabilities
    weight_bitflip:   float = 1.0
    weight_byteflip:  float = 1.0
    weight_boundary:  float = 2.0    # boundary values are higher-value targets
    weight_insert:    float = 0.5
    weight_delete:    float = 0.5
    weight_repeat:    float = 0.5
    weight_splice:    float = 0.5
    # Generation
    generation_ratio: float = 0.2    # fraction of inputs generated from scratch
    # Corpus
    corpus_dir:       str   = "corpus"
    crash_dir:        str   = "crashes"
    # Coverage proxy: track unique (opcode, error) pairs instead of edges
    deduplicate:      bool  = True
    # Delay between test cases (seconds)
    send_delay:       float = 0.0


@dataclass
class CrashRecord:
    iteration:   int
    protocol:    str
    mutation:    str
    payload:     bytes
    kind:        CrashKind
    detail:      str       = ""
    response:    bytes     = b""

    def summary(self) -> str:
        return (
            f"[{self.kind.value}] iter={self.iteration} "
            f"mut={self.mutation} payload={self.payload[:40]!r}"
            + (f" detail={self.detail}" if self.detail else "")
        )


@dataclass
class FuzzSession:
    target:     FuzzTarget
    config:     FuzzerConfig
    crashes:    list[CrashRecord]  = field(default_factory=list)
    iterations: int                = 0
    sent:       int                = 0
    unique_crashes: int            = 0
    # Seen (crash_kind, detail_hash) pairs for deduplication
    _seen_sigs: set                = field(default_factory=set)

    def record(self, crash: CrashRecord) -> bool:
        """Return True if this is a new unique crash signature."""
        sig = (crash.kind, hash(crash.detail[:120]))
        if self.config.deduplicate and sig in self._seen_sigs:
            return False
        self._seen_sigs.add(sig)
        self.crashes.append(crash)
        self.unique_crashes += 1
        return True
