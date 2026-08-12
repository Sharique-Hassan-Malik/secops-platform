# Side-Channel Attack Demo — AES-128

Simulates a Correlation Power Analysis (CPA) attack against an AES-128 implementation
and demonstrates two countermeasures — Boolean masking and shuffling — that break it.

No physical hardware is required. The power consumption of a microcontroller running
AES is modelled using the Hamming-weight leakage model, with Gaussian noise added to
simulate real measurement conditions.

## What it demonstrates

| Device | Bytes recovered (500 traces) | Mean peak \|r\| |
|---|---|---|
| Vulnerable AES | 16/16 | ~0.55 |
| Masked AES | 0/16 | ~0.05 |
| Shuffled AES | 0/16 | ~0.08 |

## The attack in one paragraph

During AES encryption, the power consumed when a microcontroller writes a byte to a
register is proportional to the number of 1 bits in that byte — the Hamming weight.
At round 1, the cipher computes `SBOX[plaintext[i] XOR key[i]]` for each of the 16
key bytes. An attacker who can vary the plaintext and record power traces enumerates
all 256 hypotheses for one key byte at a time, computing the Pearson correlation between
the hypothetical Hamming weights and the observed traces. The correct hypothesis produces
the highest correlation, revealing each key byte independently — a 256×16 exhaustive
search rather than a 2^128 brute force.

## Project structure

```
side-channel-aes-demo/
├── aes/
│   ├── constants.py    # S-box and round constants
│   └── core.py         # AES-128 encryption and key schedule
├── sim/
│   └── device.py       # VulnerableDevice, MaskedDevice, ShuffledDevice
├── attack/
│   └── cpa.py          # Correlation Power Analysis engine
├── analysis/
│   └── plot.py         # Matplotlib visualisations
├── tests/
│   ├── test_aes.py     # NIST FIPS 197 test vectors
│   ├── test_attack.py  # CPA recovers full key from vulnerable device
│   └── test_defense.py # Countermeasures prevent key recovery
├── docs/
│   └── architecture.md
├── demo.py
└── requirements.txt
```

## Setup

```bash
pip install -r requirements.txt
```

## Running the demo

```bash
python demo.py                       # 500 traces, text output only
python demo.py --traces 1000 --plot  # more traces + matplotlib figures
python demo.py --traces 200 --seed 7 # custom trace count and key seed
```

## Running tests

```bash
pytest tests/ -v
```

## How the countermeasures work

**Boolean masking**: before the S-box lookup, XOR the input with a random mask and XOR
the output with a different mask. The power consumed is `HW(SBOX[x] XOR mask_out)`.
For a uniformly random `mask_out`, this is statistically independent of `HW(SBOX[x])`,
so the correct key hypothesis correlates no better than any wrong hypothesis.

**Shuffling**: the 16 SubBytes operations execute in a random order each encryption.
CPA correlates key byte 0 against a fixed time slot but that slot contains leakage
from a different byte in 15 out of 16 traces. The effective signal-to-noise ratio
drops by a factor of 16, preventing convergence regardless of trace count.

## References

- Kocher et al., "Differential Power Analysis", CRYPTO 1999
- Brier et al., "Correlation Power Analysis with a Leakage Model", CHES 2004
- NIST FIPS 197 — Advanced Encryption Standard
