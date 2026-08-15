# Wiring Guide

## Bill of Materials

| Qty | Component | Notes |
|---|---|---|
| 1 | Arduino Uno or Nano | ATmega328P |
| 1 | MAX9814 electret mic amplifier | Adafruit #1713 or equivalent breakout |
| — | 3.5 mm electret microphone capsule | Most MAX9814 breakouts include one |
| 1 | 10 µF capacitor | Power decoupling for MAX9814 VDD |
| 1 | 100 nF ceramic capacitor | High-frequency decoupling, VDD |

---

## MAX9814 Wiring

The MAX9814 auto-gain amplifier outputs a centred signal biased at VCC/2.
It requires a quiet 3.3 V or 5 V supply — use the Arduino's regulated output
and decouple well.

```
MAX9814 pin    Arduino pin    Notes
──────────────────────────────────────────────
 VDD            5V or 3.3V   decouple with 10µF + 100nF to GND
 GND            GND
 OUT            A0            analog input
 GAIN           GND           sets 60 dB gain (float = 40 dB, VDD = 50 dB)
 AR             (float)       attack/release ratio, leave floating for default
```

The GAIN pin:
| GAIN pin | Gain |
|---|---|
| Float | 40 dB |
| VDD | 50 dB |
| GND | 60 dB |

Start with GAIN = GND (60 dB) for typical quiet-room typing. If the onset
detector fires too easily (ambient noise triggering) switch to 40 dB.

---

## Microphone Placement

Position the microphone as close to the keyboard as practical — ideally resting
on the desk surface 5–15 cm from the key cluster being studied. The keyboard
surface transmits mechanical vibration directly to the desk, which the
microphone picks up via air coupling.

Do not place the microphone directly on the keyboard (risk of damage and
excessive mechanical coupling causing clipping).

---

## ADC Bias

The MAX9814 biases its output at VCC/2 ≈ 2.5 V with a 5 V supply, which maps
to approximately 512 ADC counts (10-bit). The firmware subtracts `ADC_BIAS = 512`
from every reading to centre the signal around zero before onset detection and
feature extraction.

If your MAX9814 supply is 3.3 V, the bias is approximately:
  3.3 / 5.0 × 1023 ≈ 675 ADC counts
Update `ADC_BIAS` in `config.h` accordingly, or measure empirically:

```python
# In a Python terminal with the Arduino connected:
import serial, time
s = serial.Serial('/dev/ttyACM0', 500000, timeout=1)
# Read 1000 quiet samples and average them to find the bias.
```

---

## No Onset Triggers / Too Many Triggers

**No triggers:** The background EMA may have converged to a high value if there
was noise during startup. Reset the Arduino. Also verify the MAX9814 is powered
and the OUT pin is connected to A0. Use `visualise.py --live` to see raw
waveforms without needing a trigger.

**Too many triggers:** Reduce `ONSET_RATIO` in `config.h` is counterintuitive —
a higher ratio is harder to trigger. Check that `ADC_BIAS` matches your supply
voltage. Ambient fan or HVAC noise can keep `st_energy` elevated; position the
microphone away from air vents.

**Triggers on wrong keys / missing keys:** All keys in the target cluster should
be within 20 cm of the microphone. Keys at the edge of the keyboard may require
repositioning the mic.

---

## Complete Workflow

```bash
# 1. Flash firmware
arduino-cli compile --fqbn arduino:avr:uno firmware/acoustic_keylogger
arduino-cli upload  --fqbn arduino:avr:uno --port /dev/ttyACM0 firmware/acoustic_keylogger

# 2. Install Python dependencies
pip install -r host/requirements.txt

# 3. Visualise raw waveforms (check mic placement)
python host/visualise.py --live --port /dev/ttyACM0

# 4. Collect labelled data (30 reps × 4 keys)
python host/collect.py --port /dev/ttyACM0 --keys asdf --reps 30

# 5. Extract MFCC features
python host/extract.py

# 6. Train and evaluate
python host/train.py

# 7. Real-time inference
python host/infer.py --port /dev/ttyACM0
```
