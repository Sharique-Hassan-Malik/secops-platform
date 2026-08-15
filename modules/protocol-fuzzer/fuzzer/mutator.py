"""
Mutation-based fuzzer input generator.

Eight mutation strategies are implemented:

    bitflip   — flip one or more random bits
    byteflip  — replace bytes with random values
    boundary  — insert well-known boundary values (0, 1, 127, 128, 255,
                0xFFFF, 0x7FFFFFFF, 0xFFFFFFFF, etc.)
    insert    — insert random bytes at a random position
    delete    — remove a random byte slice
    repeat    — duplicate a random chunk within the buffer
    splice    — combine two corpus entries
    havoc     — apply multiple random mutations in sequence

A fixed-seed PRNG is used for reproducibility.
"""

from __future__ import annotations

import random
import struct
from typing import Callable

from fuzzer_config import FuzzerConfig


# Well-known boundary integers that commonly trigger bugs
_BOUNDARY_INTS = [
    0, 1, 2, 7, 8, 15, 16, 31, 32, 63, 64, 127, 128,
    255, 256, 511, 512, 1023, 1024, 2047, 2048, 4095, 4096,
    0x7F, 0x80, 0xFF, 0x7FFF, 0x8000, 0xFFFF,
    0x7FFFFF, 0x800000, 0xFFFFFF,
    0x7FFFFFFF, 0x80000000, 0xFFFFFFFF,
]

_BOUNDARY_BYTES: list[bytes] = []
for v in _BOUNDARY_INTS:
    for fmt in (">B", ">H", ">I", ">Q", "<H", "<I", "<Q"):
        size = struct.calcsize(fmt)
        try:
            _BOUNDARY_BYTES.append(struct.pack(fmt, v & ((1 << size * 8) - 1)))
        except struct.error:
            pass


class Mutator:
    """
    Produces mutated variants of a seed byte sequence.

    All mutations are deterministic given the same RNG state, so a crash
    can be reproduced by re-seeding with the same seed and running the
    same iteration index.
    """

    def __init__(self, cfg: FuzzerConfig):
        self.cfg  = cfg
        self.rng  = random.Random(cfg.seed)
        self._strategies: list[tuple[str, Callable[[bytes], bytes], float]] = [
            ("bitflip",  self._bitflip,  cfg.weight_bitflip),
            ("byteflip", self._byteflip, cfg.weight_byteflip),
            ("boundary", self._boundary, cfg.weight_boundary),
            ("insert",   self._insert,   cfg.weight_insert),
            ("delete",   self._delete,   cfg.weight_delete),
            ("repeat",   self._repeat,   cfg.weight_repeat),
            ("splice",   self._splice,   cfg.weight_splice),
            ("havoc",    self._havoc,    1.0),
        ]
        self._names    = [s[0] for s in self._strategies]
        self._fns      = [s[1] for s in self._strategies]
        self._weights  = [s[2] for s in self._strategies]

    def mutate(self, data: bytes, corpus: list[bytes] | None = None) -> tuple[str, bytes]:
        """
        Return (strategy_name, mutated_bytes).
        The corpus is used by the splice strategy.
        """
        fn_idx = self.rng.choices(range(len(self._strategies)), weights=self._weights, k=1)[0]
        name   = self._names[fn_idx]
        fn     = self._fns[fn_idx]

        if name == "splice":
            pool = corpus if corpus else [data]
            result = fn(data, pool)
        else:
            result = fn(data)

        # Clamp to configured packet size limits
        result = result[: self.cfg.max_packet_size]
        if len(result) < self.cfg.min_packet_size:
            result = result + bytes(self.cfg.min_packet_size - len(result))
        return name, result

    def mutate_many(
        self, data: bytes, n: int, corpus: list[bytes] | None = None
    ) -> list[tuple[str, bytes]]:
        return [self.mutate(data, corpus) for _ in range(n)]

    # ── Strategies ────────────────────────────────────────────────────────

    def _bitflip(self, data: bytes) -> bytes:
        if not data:
            return data
        arr  = bytearray(data)
        n_flips = max(1, int(len(arr) * self.cfg.mutation_rate))
        for _ in range(n_flips):
            pos = self.rng.randrange(len(arr))
            bit = 1 << self.rng.randrange(8)
            arr[pos] ^= bit
        return bytes(arr)

    def _byteflip(self, data: bytes) -> bytes:
        if not data:
            return data
        arr  = bytearray(data)
        n    = max(1, int(len(arr) * self.cfg.mutation_rate))
        for _ in range(n):
            pos     = self.rng.randrange(len(arr))
            arr[pos] = self.rng.randint(0, 255)
        return bytes(arr)

    def _boundary(self, data: bytes) -> bytes:
        if not data:
            val = self.rng.choice(_BOUNDARY_BYTES)
            return val
        arr     = bytearray(data)
        chunk   = self.rng.choice(_BOUNDARY_BYTES)
        pos     = self.rng.randrange(len(arr))
        end     = min(pos + len(chunk), len(arr))
        arr[pos:end] = chunk[: end - pos]
        return bytes(arr)

    def _insert(self, data: bytes) -> bytes:
        pos    = self.rng.randint(0, len(data))
        n      = self.rng.randint(1, max(1, int(len(data) * self.cfg.mutation_rate) + 1))
        insert = bytes(self.rng.randint(0, 255) for _ in range(n))
        return data[:pos] + insert + data[pos:]

    def _delete(self, data: bytes) -> bytes:
        if len(data) <= 1:
            return data
        start = self.rng.randrange(len(data))
        n     = self.rng.randint(1, max(1, int(len(data) * self.cfg.mutation_rate) + 1))
        end   = min(start + n, len(data))
        return data[:start] + data[end:]

    def _repeat(self, data: bytes) -> bytes:
        if len(data) < 2:
            return data
        start = self.rng.randrange(len(data))
        n     = self.rng.randint(1, max(1, len(data) // 4))
        end   = min(start + n, len(data))
        chunk = data[start:end]
        times = self.rng.randint(2, 5)
        ins   = self.rng.randint(0, len(data))
        return data[:ins] + chunk * times + data[ins:]

    def _splice(self, data: bytes, corpus: list[bytes] | None = None) -> bytes:
        pool = corpus if corpus else [data]
        if not pool:
            return self._byteflip(data)
        other = self.rng.choice(pool)
        if not other:
            return data
        cut1 = self.rng.randint(0, len(data))
        cut2 = self.rng.randint(0, len(other))
        return data[:cut1] + other[cut2:]

    def _havoc(self, data: bytes) -> bytes:
        n_rounds = self.rng.randint(2, 8)
        result   = data
        for _ in range(n_rounds):
            fn_idx = self.rng.choices(
                range(len(self._strategies) - 1),   # exclude havoc itself
                weights=self._weights[:-1], k=1
            )[0]
            result = self._fns[fn_idx](result)
        return result
