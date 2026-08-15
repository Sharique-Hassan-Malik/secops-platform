#!/usr/bin/env python3
"""
Network protocol fuzzer for HTTP, DNS and MQTT.

Usage:
    python fuzz.py http --host 127.0.0.1 --port 8080 --iterations 2000
    python fuzz.py dns  --host 127.0.0.1 --port 5353 --iterations 500
    python fuzz.py mqtt --host 127.0.0.1 --port 1883 --iterations 1000

    python fuzz.py http --host target.local --port 80 --seed 12345
                        --mutation-rate 0.1 --json crashes.json

    python fuzz.py http --replay crashes/00000123_SERVER_ERROR_havoc.bin
"""

import argparse
import sys

from fuzzer_config import FuzzTarget, FuzzerConfig, Protocol
from fuzzer.engine import FuzzEngine
from fuzzer.reporter import Reporter


def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(
        description="Mutation-based network protocol fuzzer",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    p.add_argument("protocol", choices=["http", "dns", "mqtt"],
                   help="Protocol to fuzz")
    p.add_argument("--host",      default="127.0.0.1")
    p.add_argument("--port",      type=int, default=None,
                   help="Target port (defaults: http=80, dns=53, mqtt=1883)")
    p.add_argument("--tls",       action="store_true")
    p.add_argument("--iterations", type=int,   default=1000)
    p.add_argument("--seed",       type=int,   default=42)
    p.add_argument("--timeout",    type=float, default=3.0)
    p.add_argument("--mutation-rate", type=float, default=0.05, dest="mutation_rate")
    p.add_argument("--generation-ratio", type=float, default=0.2, dest="generation_ratio")
    p.add_argument("--delay",     type=float, default=0.0,
                   help="Seconds between test cases")
    p.add_argument("--corpus-dir", default="corpus",  dest="corpus_dir")
    p.add_argument("--crash-dir",  default="crashes", dest="crash_dir")
    p.add_argument("--json",       default=None,
                   help="Write crash report JSON to this path")
    p.add_argument("--no-colour",  action="store_true")
    p.add_argument("--replay",     default=None,
                   help="Replay a single crash payload and exit")
    p.add_argument("--verbose",    action="store_true")
    return p.parse_args()


_DEFAULT_PORTS = {"http": 80, "dns": 53, "mqtt": 1883}


def build_generator(protocol: str):
    if protocol == "http":
        from protocols.http_gen import HTTPGenerator
        return HTTPGenerator()
    if protocol == "dns":
        from protocols.dns_gen import DNSGenerator
        return DNSGenerator()
    if protocol == "mqtt":
        from protocols.mqtt_gen import MQTTGenerator
        return MQTTGenerator()
    raise ValueError(f"Unknown protocol: {protocol}")


def main():
    args = parse_args()

    port     = args.port or _DEFAULT_PORTS[args.protocol]
    protocol = Protocol(args.protocol)

    target = FuzzTarget(
        host=args.host,
        port=port,
        protocol=protocol,
        timeout=args.timeout,
        tls=args.tls,
    )
    config = FuzzerConfig(
        seed=args.seed,
        iterations=args.iterations,
        mutation_rate=args.mutation_rate,
        generation_ratio=args.generation_ratio,
        corpus_dir=args.corpus_dir,
        crash_dir=args.crash_dir,
        send_delay=args.delay,
    )

    generator = build_generator(args.protocol)
    engine    = FuzzEngine(target, config, generator)
    reporter  = Reporter(use_colour=not args.no_colour)

    if args.replay:
        from pathlib import Path
        payload = Path(args.replay).read_bytes()
        status, result = engine.run_single(payload)
        print(f"Status  : {status}")
        print(f"Response: {result.response[:200]!r}")
        print(f"Elapsed : {result.elapsed:.3f}s")
        if result.crash_kind:
            print(f"Crash   : {result.crash_kind.value} — {result.detail}")
        sys.exit(0)

    print(f"Fuzzing {protocol.value.upper()} on {target.host}:{target.port} "
          f"({config.iterations} iterations, seed={config.seed})")
    print(f"Corpus: {config.corpus_dir}  Crashes: {config.crash_dir}")
    print()

    try:
        session = engine.run(
            on_crash=reporter.on_crash,
            on_iter=reporter.on_iter if not args.verbose else None,
        )
    except KeyboardInterrupt:
        print("\n[interrupted]")
        session = engine.session

    reporter.print_summary(session)

    if args.json:
        from pathlib import Path
        Path(args.json).write_text(reporter.crashes_to_json(session))
        print(f"Crash report written to {args.json}")

    sys.exit(1 if session.unique_crashes > 0 else 0)


if __name__ == "__main__":
    main()
