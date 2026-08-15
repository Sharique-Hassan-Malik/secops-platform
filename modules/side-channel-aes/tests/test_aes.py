"""AES-128 correctness — NIST FIPS 197 Appendix B and C.1."""

import pytest
from aes.core import encrypt, key_schedule


# NIST FIPS 197 Appendix B
_B_PT  = bytes.fromhex("3243f6a8885a308d313198a2e0370734")
_B_KEY = bytes.fromhex("2b7e151628aed2a6abf7158809cf4f3c")
_B_CT  = bytes.fromhex("3925841d02dc09fbdc118597196a0b32")

# NIST FIPS 197 Appendix C.1 (128-bit key)
_C1_PT  = bytes.fromhex("00112233445566778899aabbccddeeff")
_C1_KEY = bytes.fromhex("000102030405060708090a0b0c0d0e0f")
_C1_CT  = bytes.fromhex("69c4e0d86a7b0430d8cdb78070b4c55a")


def test_fips_197_appendix_b():
    assert encrypt(_B_PT, _B_KEY) == _B_CT


def test_fips_197_appendix_c1():
    assert encrypt(_C1_PT, _C1_KEY) == _C1_CT


def test_key_schedule_length():
    rk = key_schedule(bytes(range(16)))
    assert len(rk) == 176   # 11 round keys × 16 bytes


def test_zero_key_zero_plaintext():
    # Known result for all-zero inputs
    ct = encrypt(bytes(16), bytes(16))
    assert ct == bytes.fromhex("66e94bd4ef8a2c3b884cfa59ca342b2e")


def test_invalid_key_length():
    with pytest.raises(ValueError, match="16-byte"):
        encrypt(bytes(16), bytes(15))


def test_invalid_block_length():
    with pytest.raises(ValueError, match="16 bytes"):
        encrypt(bytes(15), bytes(16))
