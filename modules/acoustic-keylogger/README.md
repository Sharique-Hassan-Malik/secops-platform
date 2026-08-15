# Acoustic Keylogger Proof-of-Concept

> Part of the [Security Operations Platform](../../README.md). Runs standalone
> from this folder, and reports into the shared event pipeline via `secops`.

A demonstration of an acoustic side-channel attack on a keyboard using minimal
hardware. A MAX9814 electret microphone amplifier on an Arduino captures
50 ms keystroke audio windows triggered by an energy-ratio onset detector.
MFCC features are extracted on the Python host and fed to an SVM classifier
that identifies which key was pressed from sound alone.

This project is a security research demonstration. The same technique
is the basis of published academic attacks (Asonov & Agrawal 2004;
Zhuang et al. 2009) that achieve 80–96% accuracy against membrane and
mechanical keyboards.

---

## The Hard Part

**Energy-ratio onset detection without a fixed threshold.** A naive approach
sets a fixed ADC amplitude threshold and fails when the ambient noise level
changes. This firmware maintains a slow exponential moving average of the
background energy (α = 0.002, ~500-sample time constant) and triggers when the
short-term energy in a 16-sample window exceeds the background by a factor of
6×. The trigger threshold automatically adapts to the room noise floor without
any per-session recalibration.

**Pre-trigger ring buffer at 8 kHz in a Timer1 ISR.** The attack transient of
a keystroke — the sharp spike when the key cap first contacts the switch — lasts
only a few milliseconds and begins before the onset detector fires. A 128-sample
power-of-2 ring buffer running continuously in the ISR holds the last 10 ms of
audio. On trigger, these pre-trigger samples are copied into the start of the
capture window before the ISR begins filling post-trigger samples.

**MFCC extraction from scratch.** `features.py` implements the full pipeline
without `librosa` or any audio library: pre-emphasis filter, Hamming windowing,
FFT, mel filterbank (26 triangular filters on the mel scale, 80–4000 Hz), log
compression, DCT to 13 cepstral coefficients, and Δ/ΔΔ temporal derivatives
via the regression formula. The mel filterbank and DCT matrix are pre-built
once and reused for all keystrokes. The 78-dimensional feature vector is the
concatenation of mean and standard deviation across frames for [MFCC | Δ | ΔΔ].

**ADC timing budget.** The ATmega328P ADC at the default prescaler (128) takes
~104 µs per conversion. At 8 kHz sampling the ISR budget is 125 µs — only 21 µs
margin. The firmware reduces the ADC prescaler to 64 (250 kHz ADC clock, ~52 µs
per conversion) to leave 73 µs margin for the onset computation and ring buffer
update.

---

## Architecture

```
Firmware (Arduino C++)
  acoustic_keylogger.ino  — Timer1 ISR, ring buffer, onset detector, serial framer

Python host
  transport.py   — binary packet parser + background reader thread
  features.py    — MFCC extraction from scratch (mel FB, DCT, delta, statistics)
  collect.py     — guided labelled collection session → data/raw/
  extract.py     — batch feature extraction → data/features/X.npy, y.npy
  train.py       — SVM + PCA pipeline, 5-fold CV, confusion matrix → model.pkl
  infer.py       — real-time classification on live stream
  visualise.py   — waveform and spectrogram plots (saved files or live)
```

See `docs/ARCHITECTURE.md` for the onset detection algorithm, pre-trigger buffer
design, MFCC pipeline diagram and wire packet format.

---

## Hardware

| Component | Notes |
|---|---|
| Arduino Uno or Nano | ATmega328P |
| MAX9814 electret mic amplifier | Auto-gain, 40/50/60 dB selectable |
| Microphone capsule | Included on most MAX9814 breakouts |

See `docs/WIRING.md` for placement guidance, bias calibration and the
complete workflow from flashing to real-time inference.

---

## Workflow

```bash
# 1. Flash firmware
arduino-cli compile --fqbn arduino:avr:uno firmware/acoustic_keylogger
arduino-cli upload  --fqbn arduino:avr:uno --port /dev/ttyACM0 firmware/acoustic_keylogger

# 2. Install dependencies
pip install -r host/requirements.txt

# 3. Check mic placement (waveform viewer)
python host/visualise.py --live --port /dev/ttyACM0

# 4. Collect 30 samples per key for keys a, s, d, f
python host/collect.py --port /dev/ttyACM0 --keys asdf --reps 30

# 5. Extract MFCC features
python host/extract.py

# 6. Train SVM and print accuracy
python host/train.py

# 7. Real-time inference
python host/infer.py --port /dev/ttyACM0
```

---

## Expected Accuracy

| Scenario | Typical accuracy |
|---|---|
| 4 adjacent home-row keys, same session | 85–95% |
| 8 keys (home + top row), same session | 70–85% |
| Cross-session (different day) | 60–75% |
| Cross-keyboard (different model) | 40–60% |

Accuracy degrades for keys with similar actuation force and travel, keys far
from the microphone and across sessions where keyboard position shifts.

---

## Results (MFCC features, SVM-RBF, 5-fold CV)

- Feature vector: 78 dimensions (13 MFCC + 13 Δ + 13 ΔΔ, mean + std)
- Classifier: SVM RBF, C=10, gamma='scale', StandardScaler + PCA(40)
- Dataset: 30 samples × 4 keys = 120 total
- 5-fold cross-validation accuracy: ~88% on home-row keys (a, s, d, f)

---

## File Map

| File | Purpose |
|---|---|
| `firmware/acoustic_keylogger/acoustic_keylogger.ino` | Main sketch |
| `firmware/acoustic_keylogger/config.h` | Sample rate, onset, serial settings |
| `host/transport.py` | Binary packet parser |
| `host/features.py` | MFCC extraction from scratch |
| `host/collect.py` | Guided labelled data collection |
| `host/extract.py` | Batch feature extraction |
| `host/train.py` | SVM training and evaluation |
| `host/infer.py` | Real-time inference |
| `host/visualise.py` | Waveform and spectrogram visualiser |
| `docs/ARCHITECTURE.md` | Onset detection, MFCC pipeline, packet format |
| `docs/WIRING.md` | MAX9814 wiring, bias calibration, complete workflow |
