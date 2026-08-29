# Architecture

## Overview

The detector is organized as a Python package with two domain subpackages
(`image` and `audio`), a unified detector that dispatches by file type and
aggregates results, and a CLI layer on top.

```
stegdetect/
├── __init__.py          re-exports detect()
├── __main__.py          python -m stegdetect entry point
├── detector.py          dispatch and score aggregation
├── report.py            terminal formatting
├── cli.py               argument parsing
├── image/
│   ├── chi_square.py    spatial chi-square attack
│   ├── rs_analysis.py   Regular-Singular analysis
│   ├── spa.py           Sample Pair Analysis
│   ├── dct_analysis.py  DCT-domain chi-square (JPEG)
│   └── palette.py       palette ordering and LSB checks (GIF/PNG-P)
└── audio/
    ├── chi_square.py    16-bit sample chi-square attack
    └── spa.py           Sample Pair Analysis on audio
```

## Detection Methods

### Spatial Chi-Square Attack

Applies to: PNG, BMP, TIFF, GIF, WebP.

LSB replacement makes the occurrence counts of each adjacent value pair
(2k, 2k+1) converge toward equality. A chi-square goodness-of-fit test
measures how far the observed histogram is from that equalized state. The
null hypothesis is equalization (consistent with full LSB embedding). A
p-value near 1 means the histogram is consistent with LSB replacement.

A sliding-window variant allows detection of partial embeddings that only
affect a region of the image.

**Reference:** Westfeld and Pfitzmann (2000), *Attacks on Steganographic Systems*.

### RS Analysis

Applies to: PNG, BMP, TIFF, GIF, WebP.

Pixels are grouped into blocks of four and classified as Regular (R),
Singular (S), or Unusable (U) by comparing a smoothness discriminant before
and after flipping designated pixels with a +1 mask and a -1 mask. In clean
images R > S. LSB embedding forces R toward S. The dual-mask construction
enables a quantitative embedding rate estimate.

**Reference:** Fridrich, Goljan, and Du (2001), *Reliable Detection of LSB Steganography*.

### Sample Pair Analysis

Applies to: images (PNG, BMP, TIFF) and WAV audio.

Examines consecutive sample pairs and counts two statistics W and X based on
the parity orientation of near-valued neighbors. LSB replacement equalizes
W and X from their natural W > X state. The rate estimate derives from the
normalized difference. Averaging over horizontal and vertical scan orders
reduces variance.

**Reference:** Dumitrescu, Wu, and Wang (2003), *Detection of LSB Steganography via Sample Pair Analysis*.

### DCT Chi-Square (JPEG only)

Applies to: JPEG.

Tools like JSteg embed in the LSBs of non-zero AC DCT coefficients, producing
the same pair-equalization artifact in the DCT histogram. A calibrated variant
crops the image by 4 pixels and re-saves it at the same quality to obtain a
reference DCT histogram. The detection score is the excess stego probability
over the calibrated baseline, reducing false positives on naturally low-entropy
JPEG content.

**Reference:** Fridrich, Goljan, and Hogea (2002), *Steganalysis of JPEG Images: Breaking the F5 Algorithm*.

### Palette Analysis (GIF and palette PNG)

Applies to: images with a color palette (mode P in Pillow).

Three indicators are checked:

1. **Ordering entropy.** Legitimate quantization tends to produce palettes
   ordered by luminance. A Kendall's tau correlation between index order and
   luminance-sorted order below 0.4 is flagged.
2. **Duplicate entries.** Legitimate quantization rarely produces exact
   duplicate colors. Any duplicate is suspicious.
3. **Palette LSB chi-square.** Applies the same pair-equalization test to the
   palette component values themselves.

## Verdict Aggregation

Each method returns a boolean `detection` field. The unified detector counts
how many methods flagged the file and divides by the total number of methods
applied to produce a score in [0, 1].

| Score range | Verdict        |
|-------------|----------------|
| < 0.34      | clean          |
| 0.34–0.66   | suspicious     |
| ≥ 0.67      | likely_stego   |

Methods are not weighted equally by design. The choice of a simple majority
vote avoids overfitting to the synthetic benchmark dataset.

## Data Flow

```
detect(path)
    └── _detect_image(path) or _detect_audio(path)
            ├── chi_square.analyze()    → {chi2, df, stego_probability, detection}
            ├── rs_analysis.analyze()   → {RM, SM, RN, SN, rs_ratio, estimated_rate, detection}
            ├── spa.analyze_rows_and_cols() → {W, X, estimated_rate, detection}
            ├── dct_analysis.analyze()  → {stego_probability, n_coefficients, detection}   [JPEG only]
            └── palette.analyze()       → {ordering_score, duplicates, lsb_chi_prob, detection}  [palette only]
                                    ↓
                            _build_report()
                                    ↓
                    {file, file_type, methods, detections, score, verdict}
```
