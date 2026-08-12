from __future__ import annotations

import random
from abc import ABC, abstractmethod


class ProtocolGenerator(ABC):
    """
    Produces valid (or near-valid) seed inputs for a protocol.

    Two methods must be implemented:

    seeds()    — return a list of static seed packets that cover
                 common operations in the protocol.
    generate() — produce a single randomly generated valid packet
                 using the provided RNG.
    """

    @abstractmethod
    def seeds(self) -> list[bytes]:
        ...

    @abstractmethod
    def generate(self, rng: random.Random) -> bytes:
        ...
