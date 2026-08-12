# Architecture

## Overview

```
aes/        Pure AES-128 — no side effects, verified against NIST FIPS 197
   ↓
sim/        Device simulators — attach power leakage models to AES execution
   ↓
attack/     CPA engine — recovers key bytes from trace-plaintext pairs
   ↓
analysis/   Matplotlib visualisation — traces, heatmaps, convergence curves
```

---

## AES layer (`aes/`)

### `constants.py`

Stores the 256-entry S-box as a `bytes` object and the 11-element RCON table
as a tuple.  Both are compile-time constants; nothing in this module is mutable.

### `core.py`

Implements AES-128 encryption over a flat 16-byte `bytearray` in column-major
order.  The mapping is `state[i] = input[i]` directly — no reindexing on load
or store.

The four round functions operate in-place:

| Function | Operation |
|---|---|
| `_sub_bytes` | Replace every byte with `SBOX[byte]` |
| `_shift_rows` | Cyclic left-shift rows 1, 2 and 3 by 1, 2 and 3 positions |
| `_mix_columns` | Multiply each column by the AES matrix in GF(2^8) |
| `_add_round_key` | XOR state with 16 bytes from the round key array |

`_gmul` implements GF(2^8) multiplication with reduction polynomial
x^8 + x^4 + x^3 + x + 1 using `_xtime` (multiply-by-2) and repeated
doubling.

`key_schedule` expands 16 bytes into 176 bytes (11 round keys × 16 bytes).
For words at multiples of 4: apply RotWord, SubWord and XOR with RCON.
For all other words: XOR with the word four positions back.

`encrypt` runs the standard 10-round schedule — initial key addition, 9 full
rounds and 1 final round without MixColumns.

---

## Simulation layer (`sim/`)

Each device class wraps a correct AES-128 encryption and emits a synthetic
power trace of shape `(TRACE_LEN,) = (200,)`.

### Trace layout

```
Time:  0 ──── 19  20  25  30  35 … 90  95  96 ──── 199
                   │   │   │   │     │   │
                   └───┴───┴───┴─────┴───┘
             Round-1 SubBytes (16 bytes at indices 20, 25, …, 95)
             All other samples: Gaussian noise N(0, σ²)
```

Every sample receives Gaussian noise with σ = 0.5 by default.
The 16 leaky samples additionally receive a Hamming-weight term.

### `VulnerableDevice`

At time `LEAKY_START + i × LEAKY_STEP` for byte index i:

```
trace[t] += HW(SBOX[plaintext[i] XOR key[i]])
```

The leakage is directly correlated with the true S-box output.
CPA recovers all 16 bytes in approximately 300 traces at σ = 0.5.

### `MaskedDevice`

A fresh 16-byte mask is drawn per encryption.  At time `LEAKY_START + i × LEAKY_STEP`:

```
trace[t] += HW(SBOX[plaintext[i] XOR key[i]] XOR mask[i])
```

For a uniformly random mask, `HW(x XOR mask)` is statistically independent
of `HW(x)` — the mask randomises the observable intermediate each trace.
CPA correlations collapse to noise level regardless of trace count.

### `ShuffledDevice`

A random permutation of {0 … 15} is drawn per encryption.  Byte `i` leaks at:

```
trace[LEAKY_START + perm[i] × LEAKY_STEP] += HW(SBOX[plaintext[i] XOR key[i]])
```

The attacker correlates key byte 0 against time `LEAKY_START` but that slot
contains leakage from a different byte (or no leakage) in 15/16 traces.
Effective SNR is reduced by a factor of 16 and CPA fails to converge.

---

## Attack layer (`attack/`)

### `cpa.py` — Correlation Power Analysis

**Hypothesis matrix** for key byte position b:

```
H[n, kh] = HW(SBOX[plaintext_n[b] XOR kh])
```

Shape: (N, 256).  Computed with fully vectorised NumPy fancy indexing —
no Python loop over N.

**Pearson correlation matrix**:

```
corr[kh, t] = pearsonr(H[:, kh], traces[:, t])
```

Computed as a single matrix expression: `(H_c.T @ T_c) / (N × σ_H × σ_T)`.
Shape: (256, TRACE_LEN).

**Key recovery**: for each hypothesis `kh`, take the maximum absolute
correlation over all time samples.  The hypothesis with the highest peak
correlation is the recovered key byte.

**Convergence curve**: `convergence_curve` evaluates the rank of the true
key byte 0 at equally spaced trace counts.  Rank 0 means the correct
hypothesis has the highest peak correlation — the attack has succeeded.

---

## Countermeasure analysis

| Countermeasure | Why CPA fails |
|---|---|
| Boolean masking | The mask randomises `HW(sbox_out XOR mask)` independently of `HW(sbox_out)` so the correct hypothesis correlates no better than any other |
| Shuffling | Leakage for byte i appears at a random time slot each trace; correlating at a fixed time mixes leakage from all 16 bytes, reducing SNR by 16× |

---

## Test coverage

| Suite | What it checks |
|---|---|
| `test_aes.py` | FIPS 197 Appendix B ciphertext, FIPS 197 Appendix C.1 ciphertext, all-zero vector, key schedule output length, invalid input detection |
| `test_attack.py` | Full 16-byte key recovery, peak correlation threshold, correlation matrix shape, rank-0 convergence |
| `test_defense.py` | Masked device success rate < 50 %, shuffled device success rate < 50 %, both peak correlations below 0.3 |

---

## Dependencies

| Package | Role |
|---|---|
| `numpy` | Vectorised hypothesis matrix, Pearson correlation, trace arrays |
| `matplotlib` | Optional — traces, correlation heatmaps, convergence plots |
| `pytest` | Test runner |
