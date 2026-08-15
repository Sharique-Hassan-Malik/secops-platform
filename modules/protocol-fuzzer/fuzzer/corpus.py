from __future__ import annotations

import os
import random
from pathlib import Path


class Corpus:
    """
    Manages a collection of seed inputs stored as binary files.

    The corpus serves two purposes:
        1. Initial seeds loaded from disk before fuzzing begins.
        2. Accumulation of inputs that triggered new coverage signals
           (crash deduplication keys), allowing the mutator's splice
           strategy to combine multiple interesting inputs.

    Files are named by an incrementing counter so they sort correctly.
    """

    def __init__(self, corpus_dir: str, seed: int = 42):
        self._dir   = Path(corpus_dir)
        self._rng   = random.Random(seed)
        self._items: list[bytes] = []
        self._dir.mkdir(parents=True, exist_ok=True)
        self._load()

    # ── Public API ────────────────────────────────────────────────────────

    def __len__(self) -> int:
        return len(self._items)

    def __iter__(self):
        return iter(self._items)

    def pick(self) -> bytes:
        """Return a random corpus entry, or b'' if empty."""
        if not self._items:
            return b""
        return self._rng.choice(self._items)

    def all(self) -> list[bytes]:
        return list(self._items)

    def add(self, data: bytes, save: bool = True) -> int:
        """
        Add a new entry.  Returns the index of the new item.
        Optionally persists to disk.
        """
        idx = len(self._items)
        self._items.append(data)
        if save:
            path = self._dir / f"{idx:08d}.bin"
            path.write_bytes(data)
        return idx

    def add_from_file(self, path: str):
        data = Path(path).read_bytes()
        self.add(data, save=False)

    # ── Internal ──────────────────────────────────────────────────────────

    def _load(self):
        for f in sorted(self._dir.glob("*.bin")):
            try:
                self._items.append(f.read_bytes())
            except OSError:
                pass
