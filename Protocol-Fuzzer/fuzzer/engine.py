from __future__ import annotations

import json
import os
import random
import time
from pathlib import Path

from config import FuzzSession, FuzzerConfig, FuzzTarget, CrashRecord, CrashKind, Protocol
from fuzzer.corpus import Corpus
from fuzzer.mutator import Mutator
from fuzzer.sender import PacketSender, SendResult


class FuzzEngine:
    """
    Main fuzzing loop.

    For each iteration:
        1. Pick a seed from the corpus (or generate from the protocol grammar).
        2. Apply a random mutation strategy.
        3. Send the mutated packet to the target.
        4. Classify the response.
        5. Record crashes, save payloads, update the corpus.

    The engine supports a callback hook (on_crash, on_iter) for integration
    with logging or UI layers.
    """

    def __init__(
        self,
        target:    FuzzTarget,
        config:    FuzzerConfig,
        generator,   # protocols.base.ProtocolGenerator
    ):
        self.session   = FuzzSession(target=target, config=config)
        self.generator = generator
        self.mutator   = Mutator(config)
        self.sender    = PacketSender(target)
        self.corpus    = Corpus(config.corpus_dir, seed=config.seed)
        self._rng      = random.Random(config.seed)
        self._classifier = _get_classifier(target.protocol)
        self._crash_dir  = Path(config.crash_dir)
        self._crash_dir.mkdir(parents=True, exist_ok=True)

        # Seed corpus with protocol-valid templates if empty
        if len(self.corpus) == 0:
            for seed in generator.seeds():
                self.corpus.add(seed, save=True)

    # ── Public ────────────────────────────────────────────────────────────

    def run(
        self,
        on_crash: callable | None = None,
        on_iter:  callable | None = None,
    ) -> FuzzSession:
        cfg     = self.session.config
        session = self.session

        for i in range(cfg.iterations):
            session.iterations += 1

            # Choose seed: generate or pick from corpus
            if self._rng.random() < cfg.generation_ratio or len(self.corpus) == 0:
                seed = self.generator.generate(self._rng)
                strategy = "generated"
            else:
                seed     = self.corpus.pick()
                strategy, seed = self.mutator.mutate(seed, self.corpus.all())

            session.sent += 1

            # Transmit
            if self.session.target.protocol == Protocol.DNS:
                result = self.sender.send_udp(seed)
            else:
                result = self.sender.send_tcp(seed)

            # Classify
            crash = self._classifier(i, strategy, seed, result)

            if crash is not None:
                is_new = session.record(crash)
                if is_new:
                    self._save_crash(crash)
                    if on_crash:
                        on_crash(crash, session)

            if on_iter:
                on_iter(i, session)

            if cfg.send_delay > 0:
                time.sleep(cfg.send_delay)

        return session

    def run_single(self, payload: bytes) -> tuple[str, SendResult]:
        """Send one specific payload and return the raw result. Useful for replaying crashes."""
        if self.session.target.protocol == Protocol.DNS:
            result = self.sender.send_udp(payload)
        else:
            result = self.sender.send_tcp(payload)
        crash = self._classifier(0, "replay", payload, result)
        return ("crash" if crash else "ok"), result

    # ── Private ───────────────────────────────────────────────────────────

    def _save_crash(self, crash: CrashRecord):
        stem = f"{crash.iteration:08d}_{crash.kind.value}_{crash.mutation}"
        (self._crash_dir / f"{stem}.bin").write_bytes(crash.payload)
        meta = {
            "iteration": crash.iteration,
            "kind":      crash.kind.value,
            "mutation":  crash.mutation,
            "detail":    crash.detail,
            "payload_hex": crash.payload.hex(),
            "response_hex": crash.response[:256].hex(),
        }
        (self._crash_dir / f"{stem}.json").write_text(
            json.dumps(meta, indent=2)
        )


# ---------------------------------------------------------------------------
# Response classifiers per protocol
# ---------------------------------------------------------------------------

def _get_classifier(protocol: Protocol):
    if protocol == Protocol.HTTP:
        return _classify_http
    if protocol == Protocol.DNS:
        return _classify_dns
    if protocol == Protocol.MQTT:
        return _classify_mqtt
    return _classify_generic


def _classify_http(
    iteration: int,
    strategy:  str,
    payload:   bytes,
    result:    SendResult,
) -> CrashRecord | None:
    if result.crash_kind is not None:
        # Only report genuine server-side crashes, not refused connections
        if result.crash_kind == CrashKind.CONNECTION_REFUSED:
            return None
        return CrashRecord(
            iteration=iteration, protocol="http", mutation=strategy,
            payload=payload, kind=result.crash_kind, detail=result.detail,
            response=result.response,
        )
    # HTTP 5xx is a server-side error
    if result.response and result.response[:8].startswith(b"HTTP/"):
        status_line = result.response.split(b"\r\n", 1)[0]
        try:
            code = int(status_line.split(b" ", 2)[1])
        except (IndexError, ValueError):
            code = 0
        if code >= 500:
            return CrashRecord(
                iteration=iteration, protocol="http", mutation=strategy,
                payload=payload, kind=CrashKind.SERVER_ERROR,
                detail=status_line.decode("latin-1", errors="replace"),
                response=result.response,
            )
    # Completely empty response when a non-empty one was expected
    if not result.response and result.success and len(payload) > 4:
        return CrashRecord(
            iteration=iteration, protocol="http", mutation=strategy,
            payload=payload, kind=CrashKind.MALFORMED_RESPONSE,
            detail="Empty response to non-trivial request",
            response=b"",
        )
    return None


def _classify_dns(
    iteration: int,
    strategy:  str,
    payload:   bytes,
    result:    SendResult,
) -> CrashRecord | None:
    if result.crash_kind is not None:
        if result.crash_kind == CrashKind.CONNECTION_REFUSED:
            return None
        return CrashRecord(
            iteration=iteration, protocol="dns", mutation=strategy,
            payload=payload, kind=result.crash_kind, detail=result.detail,
            response=result.response,
        )
    if result.response and len(result.response) < 4:
        return CrashRecord(
            iteration=iteration, protocol="dns", mutation=strategy,
            payload=payload, kind=CrashKind.MALFORMED_RESPONSE,
            detail=f"Response too short: {len(result.response)} bytes",
            response=result.response,
        )
    return None


def _classify_mqtt(
    iteration: int,
    strategy:  str,
    payload:   bytes,
    result:    SendResult,
) -> CrashRecord | None:
    if result.crash_kind is not None:
        if result.crash_kind == CrashKind.CONNECTION_REFUSED:
            return None
        return CrashRecord(
            iteration=iteration, protocol="mqtt", mutation=strategy,
            payload=payload, kind=result.crash_kind, detail=result.detail,
            response=result.response,
        )
    # MQTT CONNACK should be exactly 4 bytes; anything else is suspicious
    if result.response and result.success:
        pkt_type = (result.response[0] >> 4) if result.response else 0
        if pkt_type == 2 and len(result.response) != 4:
            return CrashRecord(
                iteration=iteration, protocol="mqtt", mutation=strategy,
                payload=payload, kind=CrashKind.MALFORMED_RESPONSE,
                detail=f"Malformed CONNACK: {len(result.response)} bytes",
                response=result.response,
            )
    return None


def _classify_generic(
    iteration: int,
    strategy:  str,
    payload:   bytes,
    result:    SendResult,
) -> CrashRecord | None:
    if result.crash_kind is not None and result.crash_kind != CrashKind.CONNECTION_REFUSED:
        return CrashRecord(
            iteration=iteration, protocol="generic", mutation=strategy,
            payload=payload, kind=result.crash_kind, detail=result.detail,
            response=result.response,
        )
    return None
