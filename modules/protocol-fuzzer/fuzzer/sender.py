from __future__ import annotations

import socket
import ssl
import time
from dataclasses import dataclass

from fuzzer_config import FuzzTarget, CrashKind


@dataclass
class SendResult:
    success:   bool
    response:  bytes
    crash_kind: CrashKind | None
    detail:    str
    elapsed:   float   # seconds


class PacketSender:
    """
    Sends a raw payload to a target host:port over TCP or UDP and
    captures the response.

    All socket exceptions are caught and converted to CrashKind values —
    the sender never raises.
    """

    def __init__(self, target: FuzzTarget):
        self.target = target

    def send_tcp(self, payload: bytes) -> SendResult:
        t0 = time.monotonic()
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.target.timeout)

            if self.target.tls:
                ctx  = ssl.create_default_context()
                ctx.check_hostname = False
                ctx.verify_mode    = ssl.CERT_NONE
                sock = ctx.wrap_socket(sock, server_hostname=self.target.host)

            sock.connect((self.target.host, self.target.port))
            sock.sendall(payload)

            response = b""
            try:
                while True:
                    chunk = sock.recv(4096)
                    if not chunk:
                        break
                    response += chunk
                    if len(response) > 1_048_576:   # 1 MB cap
                        break
            except socket.timeout:
                pass

            sock.close()
            return SendResult(
                success=True,
                response=response,
                crash_kind=None,
                detail="",
                elapsed=time.monotonic() - t0,
            )

        except ConnectionRefusedError as exc:
            return SendResult(False, b"", CrashKind.CONNECTION_REFUSED,
                              str(exc), time.monotonic() - t0)
        except socket.timeout:
            return SendResult(False, b"", CrashKind.TIMEOUT,
                              "socket timeout", time.monotonic() - t0)
        except (ConnectionResetError, BrokenPipeError) as exc:
            return SendResult(False, b"", CrashKind.UNEXPECTED_CLOSE,
                              str(exc), time.monotonic() - t0)
        except ssl.SSLError as exc:
            return SendResult(False, b"", CrashKind.MALFORMED_RESPONSE,
                              f"SSL error: {exc}", time.monotonic() - t0)
        except OSError as exc:
            return SendResult(False, b"", CrashKind.EXCEPTION,
                              str(exc), time.monotonic() - t0)

    def send_udp(self, payload: bytes) -> SendResult:
        t0 = time.monotonic()
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.settimeout(self.target.timeout)
            sock.sendto(payload, (self.target.host, self.target.port))

            try:
                response, _ = sock.recvfrom(65535)
            except socket.timeout:
                response = b""

            sock.close()
            return SendResult(
                success=True,
                response=response,
                crash_kind=None,
                detail="",
                elapsed=time.monotonic() - t0,
            )
        except OSError as exc:
            return SendResult(False, b"", CrashKind.EXCEPTION,
                              str(exc), time.monotonic() - t0)
