# Architecture

## System Overview

```
Keyboard
  │  (physical keystrokes)
  ▼
MAX9814 electret mic amplifier → Arduino A0
  │
Timer1 ISR @ 8000 S/s
  ├── pre-emphasis: ring buffer (80 samples = 10 ms)
  ├── onset detector: short-term energy / background energy ratio
  └── on onset: copy pre-trigger + capture 320 post-trigger samples
        → serial burst @ 500 kbaud

Python host
  ├── transport.py   — binary packet parser, background reader thread
  ├── features.py    — MFCC extraction (pre-emphasis, mel filterbank, DCT, Δ, ΔΔ)
  ├── collect.py     — guided labelled data collection → data/raw/<key>/*.npy
  ├── extract.py     — batch feature extraction → data/features/X.npy, y.npy
  ├── train.py       — SVM training + 5-fold CV + confusion matrix
  ├── infer.py       — real-time inference on live keystroke stream
  └── visualise.py   — waveform + spectrogram plots (saved or live)
```

---

## Firmware: Onset Detection

The onset detector avoids fixed-threshold triggering (which requires per-room
recalibration) by using an energy ratio:

```
short_term_energy = Σ s[n]²   over last ONSET_WINDOW (16) samples
background_energy = EMA(short_term_energy, α=0.002)  when not capturing

trigger when:  short_term_energy / background_energy >= ONSET_RATIO (6.0)
```

The background EMA adapts to the ambient noise level of the room over
~500 samples (62 ms) of silence. Louder environments automatically raise
the effective threshold.

### Pre-trigger Ring Buffer

A 128-sample power-of-2 ring buffer continuously holds the most recent 80
samples (10 ms). On onset, these are copied into the start of the 400-sample
capture window before the ISR begins filling the remaining 320 post-trigger
samples. This captures the attack transient of the keystroke, which carries
most of the discriminating frequency content.

```
time ──►

  ... [quiet] [onset!] [key noise decays] [quiet] ...
  ←10ms→│←────── 40 ms ──────────────────►│
   pre  │            post                  │
        └──── 400 sample window ───────────┘
```

### Refractory Period

After each capture, the onset detector is suppressed for 400 samples (50 ms)
to prevent re-triggering on the echo or mechanical resonance of the same
keystroke.

---

## Feature Extraction Pipeline

Each 400-sample window (50 ms at 8 kHz) is processed as follows:

```
int16[400]
  │
  ▼  Pre-emphasis: s'[n] = s[n] - 0.97·s[n-1]
     (boosts high-frequency content; improves formant resolution)
  │
  ▼  Frame: 25 ms frames, 10 ms hop → ~3 frames from a 50 ms window
     Hamming window applied per frame
  │
  ▼  FFT: next power of 2 ≥ frame_len (256 points)
     Power spectrum: |FFT|²
  │
  ▼  Mel filterbank: 26 triangular filters, 80–4000 Hz
     Captures perceptually-spaced frequency bands
  │
  ▼  Log compression: log(mel_energy + ε)
  │
  ▼  DCT: first 13 coefficients → MFCCs
     Decorrelates the log mel energies; concentrates energy in low coefficients
  │
  ▼  Δ and ΔΔ: first and second temporal derivatives (±2-frame regression)
     Captures spectral dynamics: attack rate, decay shape
  │
  ▼  Statistics: mean and std across frames for each of 39 coefficients
     Final feature vector: 39 × 2 = 78 dimensions (float32)
```

### Why MFCCs for Keystrokes

Each key has a characteristic transient spectrum shaped by:
- Key cap material and travel distance
- Keyboard frame resonance at the key's position
- Finger contact area and strike velocity

MFCCs compress the power spectrum into perceptually-weighted bands and
decorrelate the coefficients, making the SVM's RBF kernel effective.
The Δ coefficients capture how quickly the spectrum changes — the attack
of a spacebar differs from a home-row key even if their peak spectra are similar.

---

## Classifier

**Model:** SVM with RBF kernel.
**Preprocessing:** StandardScaler → optional PCA whitening (40 components).
**Evaluation:** Stratified 5-fold cross-validation with `cross_val_predict`.

SVM with RBF is the established baseline for MFCC-based audio classification
tasks with small datasets (30–100 samples per class). Neural networks overfit
without hundreds of samples per class.

Typical accuracy on 4 adjacent home-row keys (a, s, d, f) with 30 samples each:
  - Same session: 85–95%
  - Cross-session (different day): 60–80% (keyboard position matters)

---

## Wire Packet Format

```
byte 0: 'K' (0x4B)   — keystroke marker
byte 1: label         — current key label (0 = unlabelled)
bytes 2–3: uint16     — sample count N (little-endian), always 400
bytes 4..(4+2N-1):   — N int16_t samples, little-endian, bias-subtracted
```

Total per keystroke: 4 + 400×2 = 804 bytes.
At 500 kbaud: 804 × 10 bits / 500000 = 16 ms transmission time.
With 50 ms refractory period: well within budget.

---

## Data Directory Layout

```
data/
  raw/
    a/
      1718000000_0000.npy   ← int16[400] raw samples
      1718000000_0001.npy
      …
    s/
    d/
    f/
  features/
    X.npy        ← float32[N_samples × 78]
    y.npy        ← int32[N_samples]
    keys.txt     ← one key per line, index = label - 1
    model.pkl    ← joblib: {pipeline, keys}
    report.txt   ← classification report + confusion matrix
```
