# Steganography Detector

> Part of the [Security Operations Platform](../../README.md). Runs standalone
> from this folder, and reports into the shared event pipeline via `secops`.

Detects hidden data in images and audio files using four independent statistical
methods. Each method targets a different steganographic technique and file type.
Results from all applicable methods are combined into a single verdict.

## What It Detects

| Method | Target | File Types |
|---|---|---|
| Chi-square attack | Spatial LSB replacement | PNG, BMP, TIFF, GIF, WebP |
| RS analysis | Spatial LSB replacement | PNG, BMP, TIFF, GIF, WebP |
| Sample Pair Analysis | LSB replacement | PNG, BMP, TIFF, WAV, FLAC |
| DCT chi-square (calibrated) | JSteg, F5, DCT-domain embedding | JPEG |
| Palette analysis | Index-order and palette-LSB encoding | GIF, palette PNG |

## The Hard Part

Each detection method is a published statistical test with a specific set of
assumptions. The chi-square attack relies on the pair-equalization artifact
that LSB replacement creates in pixel value histograms. RS analysis exploits
the asymmetry between how a +1 mask and a -1 mask classify pixel groups in
stego versus clean images. SPA tracks the orientation of adjacent value pairs.
DCT analysis applies the same chi-square logic to AC coefficient histograms
rather than pixel histograms, with a calibration step that constructs a
reference by cropping and re-saving the image to remove any steganographic
alignment. None of these methods require a clean reference copy of the image.

Implementing all four correctly and making them agree on synthetic benchmark
data required careful attention to boundary conditions: 8-bit vs 16-bit sample
ranges, signed vs unsigned representations, handling palette images whose used
entries are a subset of the full palette and the low-power regime of the
palette chi-square test where degrees of freedom are insufficient.

## Installation

```bash
pip install -r requirements.txt
pip install -e .
```

Requires Python 3.10 or later.

## Usage

### Command line

```bash
# Analyze a single file
stegdetect photo.png

# Verbose output with per-channel breakdown
stegdetect --verbose photo.png

# Test only the green channel
stegdetect --channel green photo.png

# Run windowed chi-square to locate a partial embedding
stegdetect --windowed --window-size 1024 photo.png

# Output JSON
stegdetect --json photo.png

# Analyze multiple files and print a summary table
stegdetect *.png --summary

# Same as above using the module invocation
python -m stegdetect photo.jpg
```

### Python API

```python
from stegdetect.detector import detect

result = detect("photo.png")
print(result["verdict"])          # 'clean', 'suspicious', or 'likely_stego'
print(result["score"])            # fraction of methods that flagged the file
print(result["detections"])       # list of method names that detected

# Access individual method results
chi = result["methods"]["chi_square"]
print(chi["stego_probability"])

rs = result["methods"]["rs_analysis"]
print(rs["estimated_rate"])
```

Individual methods can also be called directly:

```python
from stegdetect.image import chi_square, rs_analysis, spa, dct_analysis

# Single method, single channel
r = chi_square.analyze("photo.png", channel="green")
r = rs_analysis.analyze("photo.png", channel="red")
r = spa.analyze_rows_and_cols("photo.png")
r = dct_analysis.analyze("photo.jpeg", calibrate=True)

# Windowed chi-square for partial embedding detection
windows = chi_square.analyze_windowed("photo.png", channel="green",
                                      window_size=512, step=256)
# windows is a list of {start, end, stego_probability}
```

## Output Format

```
============================================================
  File   : photo.png
  Type   : image
  Verdict: LIKELY STEGANOGRAPHY
  Score  : 100.0%  [##############################]
  (3/3 methods flagged)
------------------------------------------------------------
  [!] Chi Square
       Chi2      : 4521.32  (df=127)
       Stego prob: 97.3%
  [!] Rs Analysis
       Est. rate : 83.1%
       RS ratio  : 0.0041
  [!] Spa
       Est. rate : 79.6%
       W=0.1823  X=0.1819
============================================================
```

## Running Tests

```bash
python -m pytest tests/ -v
```

## Benchmarking

Generate a synthetic dataset and measure detection accuracy at each embedding rate:

```bash
# Generate 20 images and audio files per embedding rate (0%, 10%, 25%, 50%, 75%, 100%)
python benchmarks/generate_stego.py --out-dir benchmarks/data --n 20

# Run all methods and report accuracy, precision and recall per rate
python benchmarks/run_benchmark.py --data-dir benchmarks/data --csv results.csv
```

Expected output (approximate, varies with image content):

```
  Rate  Method          TP     FP     FN     TN    Acc    Rec   Prec
------------------------------------------------------------------------
  0.00  chi_square       0      1     20     19   95.1%    --   0.0%
  0.10  chi_square       6      1      14     19   62.5%  30.0%  85.7%
  0.25  chi_square      15      1       5     19   85.0%  75.0%  93.8%
  0.50  chi_square      20      1       0     19   97.5%  100%  95.2%
  1.00  chi_square      20      1       0     19   97.5%  100%  95.2%
```

At p=0 (clean images) false-positive rates are low. Detection rate increases
sharply above p=0.25 across all three methods.

## File Map

| Path | Description |
|---|---|
| `stegdetect/__init__.py` | Package entry point, re-exports `detect` |
| `stegdetect/detector.py` | File-type dispatch and verdict aggregation |
| `stegdetect/report.py` | Terminal report formatter |
| `stegdetect/cli.py` | Argument parser and main entry point |
| `stegdetect/image/chi_square.py` | Spatial chi-square attack, global and windowed |
| `stegdetect/image/rs_analysis.py` | RS analysis with vectorized group classification |
| `stegdetect/image/spa.py` | Sample Pair Analysis, row and column scan |
| `stegdetect/image/dct_analysis.py` | DCT chi-square with calibration for JPEG |
| `stegdetect/image/palette.py` | Palette ordering, duplicate and LSB checks |
| `stegdetect/audio/chi_square.py` | Chi-square attack on 16-bit PCM audio |
| `stegdetect/audio/spa.py` | SPA on audio sample pairs |
| `benchmarks/generate_stego.py` | Synthetic stego dataset generator |
| `benchmarks/run_benchmark.py` | Accuracy vs embedding rate benchmark |
| `tests/test_chi_square.py` | Unit tests for chi-square module |
| `tests/test_rs_analysis.py` | Unit tests for RS analysis module |
| `tests/test_spa.py` | Unit tests for SPA module |
| `tests/test_dct.py` | Unit tests for DCT analysis module |
| `ARCHITECTURE.md` | Detailed design and method descriptions |

## References

- Westfeld, A. and Pfitzmann, A. (2000). Attacks on Steganographic Systems.
  *3rd International Workshop on Information Hiding.*
- Fridrich, J., Goljan, M. and Du, R. (2001). Reliable Detection of LSB
  Steganography in Color and Grayscale Images. *ACM Workshop on Multimedia
  and Security.*
- Dumitrescu, S., Wu, X. and Wang, Z. (2003). Detection of LSB Steganography
  via Sample Pair Analysis. *IEEE Transactions on Signal Processing, 51(7).*
- Fridrich, J., Goljan, M. and Hogea, D. (2002). Steganalysis of JPEG Images:
  Breaking the F5 Algorithm. *5th International Workshop on Information Hiding.*
- Westfeld, A. (2001). F5 — A Steganographic Algorithm. *4th International
  Workshop on Information Hiding.*

## Coursework Connection

Steganography detection draws directly on concepts from Digital Signal
Processing (statistical properties of signals and noise), Probability Methods
in Engineering (chi-square tests, hypothesis testing) and Communication Systems
(source coding, information capacity). The DCT-domain analysis uses the same
8x8 block DCT that underpins JPEG compression, covered in the DSP module.
