"""AES-128 encryption.

State layout: flat bytearray of 16 bytes in column-major order.
state[i] == state_matrix[i % 4][i // 4] in 2-D notation, which
equals input[i] directly — no reindexing required on load.
"""

from __future__ import annotations
from .constants import SBOX, RCON


def _xtime(a: int) -> int:
    """Multiply by x in GF(2^8) with reduction polynomial x^8+x^4+x^3+x+1."""
    return ((a << 1) ^ 0x1b) & 0xff if a & 0x80 else (a << 1) & 0xff


def _gmul(a: int, b: int) -> int:
    """Multiply two bytes in GF(2^8) using repeated xtime."""
    result = 0
    while b:
        if b & 1:
            result ^= a
        a = _xtime(a)
        b >>= 1
    return result


def _sub_bytes(state: bytearray) -> None:
    for i in range(16):
        state[i] = SBOX[state[i]]


def _shift_rows(state: bytearray) -> None:
    # Row 1: cyclic left shift by 1
    state[1], state[5], state[9],  state[13] = state[5],  state[9],  state[13], state[1]
    # Row 2: cyclic left shift by 2
    state[2], state[6], state[10], state[14] = state[10], state[14], state[2],  state[6]
    # Row 3: cyclic left shift by 3
    state[3], state[7], state[11], state[15] = state[15], state[3],  state[7],  state[11]


def _mix_columns(state: bytearray) -> None:
    for c in range(4):
        s0, s1, s2, s3 = state[c * 4], state[c * 4 + 1], state[c * 4 + 2], state[c * 4 + 3]
        state[c * 4]     = _gmul(s0, 2) ^ _gmul(s1, 3) ^ s2          ^ s3
        state[c * 4 + 1] = s0           ^ _gmul(s1, 2) ^ _gmul(s2, 3) ^ s3
        state[c * 4 + 2] = s0           ^ s1           ^ _gmul(s2, 2) ^ _gmul(s3, 3)
        state[c * 4 + 3] = _gmul(s0, 3) ^ s1           ^ s2           ^ _gmul(s3, 2)


def _add_round_key(state: bytearray, rk: bytes | bytearray, offset: int) -> None:
    for i in range(16):
        state[i] ^= rk[offset + i]


def key_schedule(key: bytes) -> bytes:
    """Expand a 16-byte AES-128 key into 176 bytes of round key material."""
    if len(key) != 16:
        raise ValueError("AES-128 requires a 16-byte key")
    w = bytearray(key)
    for i in range(4, 44):
        temp = bytearray(w[(i - 1) * 4 : i * 4])
        if i % 4 == 0:
            temp = temp[1:] + temp[:1]                    # RotWord
            temp = bytearray(SBOX[b] for b in temp)       # SubWord
            temp[0] ^= RCON[i // 4]
        for j in range(4):
            w.append(w[(i - 4) * 4 + j] ^ temp[j])
    return bytes(w)


def encrypt(plaintext: bytes, key: bytes) -> bytes:
    """Encrypt a single 16-byte block with AES-128."""
    if len(plaintext) != 16:
        raise ValueError("Block must be exactly 16 bytes")
    rk = key_schedule(key)
    state = bytearray(plaintext)
    _add_round_key(state, rk, 0)
    for r in range(1, 10):
        _sub_bytes(state)
        _shift_rows(state)
        _mix_columns(state)
        _add_round_key(state, rk, r * 16)
    _sub_bytes(state)
    _shift_rows(state)
    _add_round_key(state, rk, 160)
    return bytes(state)
