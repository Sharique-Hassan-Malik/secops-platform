from __future__ import annotations

import json
import sys
import time
from pathlib import Path

from config import FuzzSession, CrashRecord


_RESET  = "\033[0m"
_BOLD   = "\033[1m"
_RED    = "\033[31m"
_YELLOW = "\033[33m"
_GREEN  = "\033[32m"
_CYAN   = "\033[36m"


def _c(text: str, code: str, use_colour: bool) -> str:
    return f"{code}{text}{_RESET}" if use_colour else text


class Reporter:

    def __init__(self, use_colour: bool | None = None):
        self._colour = sys.stdout.isatty() if use_colour is None else use_colour
        self._t_start = time.monotonic()

    def on_crash(self, crash: CrashRecord, session: FuzzSession):
        uc = session.unique_crashes
        elapsed = time.monotonic() - self._t_start
        print(
            _c(f"\n[CRASH #{uc}]", _RED, self._colour)
            + f" iter={crash.iteration}"
            + f" mut={crash.mutation}"
            + f" kind={crash.kind.value}"
        )
        if crash.detail:
            print(f"  detail  : {crash.detail}")
        print(f"  payload : {crash.payload[:80]!r}")
        if crash.response:
            print(f"  response: {crash.response[:80]!r}")
        print(f"  elapsed : {elapsed:.1f}s")

    def on_iter(self, i: int, session: FuzzSession):
        if (i + 1) % 100 == 0:
            elapsed = time.monotonic() - self._t_start
            rate    = session.sent / max(elapsed, 0.001)
            print(
                f"\r{_c('●', _CYAN, self._colour)} "
                f"iter={i+1:>6}"
                f"  sent={session.sent:>6}"
                f"  crashes={session.unique_crashes}"
                f"  rate={rate:.0f}/s"
                f"  elapsed={elapsed:.0f}s",
                end="",
                flush=True,
            )

    def print_summary(self, session: FuzzSession):
        elapsed = time.monotonic() - self._t_start
        rate    = session.sent / max(elapsed, 0.001)
        print(f"\n\n{'─'*55}")
        print(_c("── Fuzz Session Summary", _BOLD, self._colour))
        print(f"  Protocol     : {session.target.protocol.value}")
        print(f"  Target       : {session.target.host}:{session.target.port}")
        print(f"  Iterations   : {session.iterations}")
        print(f"  Sent         : {session.sent}")
        print(f"  Rate         : {rate:.0f} pkt/s")
        print(f"  Elapsed      : {elapsed:.1f}s")

        n = session.unique_crashes
        colour = _RED if n > 0 else _GREEN
        print(f"  Unique crashes: {_c(str(n), colour, self._colour)}")

        if session.crashes:
            print()
            print(_c("  Crashes:", _RED, self._colour))
            for cr in session.crashes:
                print(f"    [{cr.kind.value:<22}] iter={cr.iteration:<6} mut={cr.mutation}")
        print(f"{'─'*55}")

    def crashes_to_json(self, session: FuzzSession) -> str:
        out = []
        for cr in session.crashes:
            out.append({
                "iteration":    cr.iteration,
                "kind":         cr.kind.value,
                "mutation":     cr.mutation,
                "detail":       cr.detail,
                "payload_hex":  cr.payload.hex(),
                "response_hex": cr.response[:256].hex(),
            })
        return json.dumps({
            "target":   f"{session.target.host}:{session.target.port}",
            "protocol": session.target.protocol.value,
            "iterations": session.iterations,
            "sent":       session.sent,
            "unique_crashes": session.unique_crashes,
            "crashes": out,
        }, indent=2)
